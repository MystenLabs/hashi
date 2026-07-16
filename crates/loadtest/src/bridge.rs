// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The bridge side of a run: deposit-address derivation, request submission and
//! the reads that tell us how far along a run is.
//!
//! This drives the same code paths as the `hashi` CLI, through
//! [`hashi::cli`] and [`hashi::sui_tx_executor`], so a load test cannot drift
//! from what the CLI does.

use std::collections::HashSet;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use hashi::cli::client::HashiClient;
use hashi::cli::commands::deposit::cli_derive_deposit_address;
use hashi::cli::config::CliConfig;
use hashi::config::HashiIds;
use hashi::sui_tx_executor::SuiTxExecutor;
use hashi_types::bitcoin::BitcoinAddress;
use hashi_types::bitcoin::witness_program_from_address;
use sui_rpc::proto::sui::rpc::v2::GetBalanceRequest;
use sui_sdk_types::Address;
use sui_sdk_types::StructTag;

/// Deposits per PTB. Three dynamic-field ops per deposit against the 1000-op
/// object-runtime cap, matching the CLI's `deposit request`.
pub const DEPOSIT_CHUNK: usize = 333;

/// Withdrawal requests per PTB, matching the CLI's `withdraw request`.
pub const WITHDRAW_CHUNK: usize = 250;

pub struct Bridge {
    config: CliConfig,
    hashi_ids: HashiIds,
    btc_network: bitcoin::Network,
}

/// How far this run's withdrawals have progressed.
///
/// Every count is restricted to requests this run submitted. The queues are
/// shared with anything else driving the same deployment, so a run that gated
/// on their totals would wait on strangers' withdrawals.
pub struct WithdrawalProgress {
    /// This run's requests still awaiting a withdrawal transaction.
    pub queued: usize,
    /// Withdrawal transactions carrying this run's requests that have not yet
    /// been confirmed. Confirmed ones leave `withdrawal_txns` for
    /// `confirmed_txns`, so zero means every batch has landed on Bitcoin.
    pub in_flight: usize,
    /// Of those, how many are fully signed.
    pub signed: usize,
}

impl Bridge {
    pub fn new(config: CliConfig, btc_network: bitcoin::Network) -> Result<Self> {
        config.validate()?;
        let hashi_ids = HashiIds {
            package_id: config.package_id(),
            hashi_object_id: config.hashi_object_id(),
        };
        Ok(Self {
            config,
            hashi_ids,
            btc_network,
        })
    }

    /// A fresh snapshot of onchain state.
    ///
    /// [`HashiClient`] reads the Hashi object once on construction and every
    /// `fetch_*` serves that snapshot, so polling means rebuilding it.
    async fn snapshot(&self) -> Result<HashiClient> {
        HashiClient::new(&self.config).await
    }

    fn executor(&self) -> Result<SuiTxExecutor> {
        let signer = self
            .config
            .load_keypair()?
            .context("a signing key is required to submit transactions")?;
        let client = sui_rpc::Client::new(&self.config.sui_rpc_url)?;
        Ok(SuiTxExecutor::new(client, signer, self.hashi_ids))
    }

    /// Derive the 2-of-2 taproot deposit address for `recipient`.
    ///
    /// This exercises the whole read path — the object must exist, DKG must
    /// have produced an MPC key, and the guardian's BTC key must be pinned
    /// onchain — which makes it a good early check that the deployment is
    /// really usable.
    pub async fn deposit_address(&self, recipient: Address) -> Result<BitcoinAddress> {
        let client = self.snapshot().await?;

        let mpc_pubkey = client.fetch_mpc_public_key();
        if mpc_pubkey.is_empty() {
            bail!("no MPC public key onchain; has the committee completed DKG?");
        }
        let guardian_btc_pubkey = client
            .fetch_guardian_btc_public_key()
            .context("no guardian BTC public key onchain; did finish_publish run with one?")?;

        cli_derive_deposit_address(
            &mpc_pubkey,
            &guardian_btc_pubkey,
            Some(&recipient),
            self.btc_network,
        )
    }

    /// Register one PTB worth of deposits.
    ///
    /// `utxos` must be no longer than [`DEPOSIT_CHUNK`] so the call stays a
    /// single atomic transaction, which is what makes a retry a clean unit of
    /// work rather than a partially-applied one.
    pub async fn register_deposits(
        &self,
        txid: bitcoin::Txid,
        utxos: &[(u32, u64)],
        recipient: Address,
    ) -> Result<usize> {
        debug_assert!(utxos.len() <= DEPOSIT_CHUNK);
        let ids = self
            .executor()?
            .execute_create_deposit_requests_batch(txid_to_address(txid), utxos, Some(recipient))
            .await?;
        Ok(ids.len())
    }

    /// Submit `count` identical withdrawal requests in one PTB, returning their
    /// request ids. `count` must be no longer than [`WITHDRAW_CHUNK`].
    pub async fn request_withdrawals(
        &self,
        amount_sats: u64,
        destination: &BitcoinAddress,
        count: usize,
    ) -> Result<Vec<Address>> {
        debug_assert!(count <= WITHDRAW_CHUNK);
        let destination_bytes = witness_program_from_address(destination)?;
        self.executor()?
            .execute_create_withdrawal_requests_batch(amount_sats, destination_bytes, count)
            .await
    }

    /// hBTC held by `address`.
    ///
    /// hBTC lives in Sui's balance accumulator rather than as `Coin<BTC>`
    /// objects, so this is a balance query, not an object listing.
    pub async fn balance_sats(&self, address: Address) -> Result<u64> {
        let btc_type = StructTag::new(
            self.hashi_ids.package_id,
            sui_sdk_types::Identifier::from_static("btc"),
            sui_sdk_types::Identifier::from_static("BTC"),
            vec![],
        );
        let mut client = sui_rpc::Client::new(&self.config.sui_rpc_url)?;
        let response = client
            .state_client()
            .get_balance(
                GetBalanceRequest::default()
                    .with_owner(address.to_string())
                    .with_coin_type(btc_type.to_string()),
            )
            .await
            .context("failed to query hBTC balance")?
            .into_inner();
        Ok(response.balance().balance_opt().unwrap_or(0))
    }

    /// Progress of the requests identified by `mine`.
    pub async fn withdrawal_progress(&self, mine: &HashSet<Address>) -> Result<WithdrawalProgress> {
        let client = self.snapshot().await?;
        let queued = client
            .fetch_withdrawal_requests()
            .iter()
            .filter(|w| mine.contains(&w.id))
            .count();
        let in_flight: Vec<_> = client
            .fetch_withdrawal_txns()
            .into_iter()
            .filter(|t| t.request_ids.iter().any(|id| mine.contains(id)))
            .collect();
        let signed = in_flight.iter().filter(|t| t.is_fully_signed()).count();
        Ok(WithdrawalProgress {
            queued,
            in_flight: in_flight.len(),
            signed,
        })
    }
}

/// Reinterpret a Bitcoin txid as a Sui `Address`.
///
/// Both are bare 32-byte values, and the Move side takes the txid as an
/// address-shaped id. `Txid` is stored in Bitcoin's internal byte order, which
/// is what the Move code and the CLI both expect, so no reversal here.
fn txid_to_address(txid: bitcoin::Txid) -> Address {
    use bitcoin::hashes::Hash;
    Address::new(txid.to_byte_array())
}
