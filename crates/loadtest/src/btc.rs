// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bitcoin Core RPC and the deposit-funding transaction builder.
//!
//! Funding a run means paying N identical outputs to one deposit address, which
//! Bitcoin Core makes awkward in two independent ways:
//!
//! 1. `createrawtransaction` rejects duplicate output addresses outright, so the
//!    unfunded transaction is assembled here instead.
//! 2. `fundrawtransaction`'s coin selection will happily fund a 1 BTC send from
//!    ~1,400 dust inputs, producing a ~95 kvB transaction. Signet's miner caps
//!    blocks near 1M weight, so a transaction that fat is skipped indefinitely
//!    at any fee rate — it never fits the remaining space. We therefore
//!    preselect one large UTXO and pass `add_inputs: false`.
//!
//! Preselecting an input has a useful side effect: rust-bitcoin only switches to
//! SegWit serialization when a transaction has witness data *or* zero inputs, so
//! a one-input witness-less transaction encodes as legacy — which is the only
//! thing `fundrawtransaction` will decode.

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::Witness;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::transaction::Version;
use corepc_client::client_sync::Auth;
use corepc_client::client_sync::v29::Client;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;

/// vB contributed by each part of the funding transaction, used only to size the
/// preselected input. Deliberate over-estimates; the real fee comes from
/// `fundrawtransaction`.
const VB_OVERHEAD: u64 = 11;
const VB_P2WPKH_INPUT: u64 = 68;
const VB_P2TR_OUTPUT: u64 = 43;
const VB_CHANGE_OUTPUT: u64 = 31;

pub struct BitcoinRpc {
    /// Node-scoped, for chain queries and broadcast.
    node: Client,
    /// Wallet-scoped, for coin selection, funding and signing.
    wallet: Client,
    wallet_name: String,
}

#[derive(Debug, Deserialize)]
pub struct ChainInfo {
    pub chain: String,
    pub blocks: u64,
    #[serde(rename = "initialblockdownload")]
    pub initial_block_download: bool,
    #[serde(rename = "verificationprogress")]
    pub verification_progress: f64,
}

#[derive(Debug, Deserialize)]
struct ListUnspent {
    txid: String,
    vout: u32,
    amount: f64,
    spendable: bool,
    solvable: bool,
}

#[derive(Debug, Deserialize)]
struct FundResult {
    hex: String,
    fee: f64,
}

#[derive(Debug, Deserialize)]
struct SignResult {
    hex: String,
    complete: bool,
}

/// One broadcast funding transaction and the outputs paying the deposit
/// address. `vouts` comes from decoding the funded transaction, so it already
/// accounts for wherever Core placed the change.
#[derive(Debug, Clone)]
pub struct FundingTx {
    pub txid: Txid,
    pub vouts: Vec<u32>,
    pub amount_sats: u64,
    pub fee_btc: f64,
}

impl BitcoinRpc {
    pub fn new(url: &str, user: &str, password: &str, wallet: &str) -> Result<Self> {
        let auth = || Auth::UserPass(user.to_string(), password.to_string());
        let base = url.trim_end_matches('/');
        Ok(Self {
            node: hashi::btc_monitor::config::new_rpc_client(base, auth())
                .with_context(|| format!("failed to connect to bitcoind at {base}"))?,
            wallet: hashi::btc_monitor::config::new_rpc_client(
                &format!("{base}/wallet/{wallet}"),
                auth(),
            )
            .with_context(|| format!("failed to open wallet `{wallet}` at {base}"))?,
            wallet_name: wallet.to_string(),
        })
    }

    pub fn chain_info(&self) -> Result<ChainInfo> {
        self.node
            .call("getblockchaininfo", &[])
            .map_err(|e| anyhow!("getblockchaininfo failed: {e}"))
    }

    /// The genesis hash, which is what hashi pins as `bitcoin_chain_id`.
    pub fn genesis_hash(&self) -> Result<String> {
        self.node
            .call("getblockhash", &[json!(0)])
            .map_err(|e| anyhow!("getblockhash 0 failed: {e}"))
    }

    pub fn wallet_balance(&self) -> Result<f64> {
        self.wallet
            .call("getbalance", &[])
            .map_err(|e| anyhow!("getbalance failed: {e}"))
    }

    /// A fresh P2WPKH address from the wallet.
    ///
    /// The type is pinned rather than left to the node's `-addresstype`: a
    /// wallet configured for legacy addresses would hand back a P2PKH address,
    /// which has no witness program and so cannot be a withdrawal destination.
    pub fn new_address(&self, label: &str) -> Result<String> {
        self.wallet
            .call("getnewaddress", &[json!(label), json!("bech32")])
            .map_err(|e| anyhow!("getnewaddress failed: {e}"))
    }

    pub fn received_by_address(&self, address: &Address, minconf: u32) -> Result<f64> {
        self.wallet
            .call(
                "getreceivedbyaddress",
                &[json!(address.to_string()), json!(minconf)],
            )
            .map_err(|e| anyhow!("getreceivedbyaddress failed: {e}"))
    }

    /// Confirmations for `txid`, or `None` if the node has never seen it.
    /// Returns `Some(0)` while it sits in the mempool.
    pub fn confirmations(&self, txid: &Txid) -> Option<u32> {
        let tx: Value = self
            .node
            .call("getrawtransaction", &[json!(txid.to_string()), json!(true)])
            .ok()?;
        Some(tx["confirmations"].as_u64().unwrap_or(0) as u32)
    }

    /// The smallest spendable UTXO that covers `need`.
    ///
    /// Smallest-that-fits keeps the wallet's larger UTXOs intact across runs,
    /// and taking exactly one input is what keeps the transaction small enough
    /// to be mined (see the module docs).
    fn select_input(&self, need: Amount) -> Result<(Txid, u32, Amount)> {
        let utxos: Vec<ListUnspent> = self
            .wallet
            .call("listunspent", &[json!(1), json!(9_999_999)])
            .map_err(|e| anyhow!("listunspent failed: {e}"))?;

        let mut usable: Vec<_> = utxos
            .iter()
            .filter(|u| u.spendable && u.solvable)
            .filter_map(|u| Amount::from_btc(u.amount).ok().map(|a| (u, a)))
            .collect();
        usable.sort_by_key(|(_, amount)| *amount);

        let (utxo, amount) = usable
            .iter()
            .find(|(_, amount)| *amount >= need)
            .ok_or_else(|| {
                let largest = usable
                    .last()
                    .map(|(_, a)| a.to_string())
                    .unwrap_or_else(|| "none".into());
                anyhow!(
                    "wallet `{}` has no single UTXO covering {need} (largest is {largest}, across \
                     {} spendable UTXOs).\nThis run needs one input that big: funding from many \
                     small UTXOs builds a transaction too large for signet to mine. Consolidate \
                     the wallet, or lower --deposits / --deposit-amount-btc.",
                    self.wallet_name,
                    usable.len(),
                )
            })?;

        let txid = utxo
            .txid
            .parse()
            .context("listunspent returned a bad txid")?;
        Ok((txid, utxo.vout, *amount))
    }

    /// Build, fund, sign and broadcast one transaction paying `count` outputs of
    /// `amount` to `address`.
    pub fn fund_deposit_outputs(
        &self,
        address: &Address,
        count: usize,
        amount: Amount,
        fee_rate: f64,
    ) -> Result<FundingTx> {
        let outputs_total = amount
            .checked_mul(count as u64)
            .ok_or_else(|| anyhow!("deposit total overflows"))?;
        let est_vsize =
            VB_OVERHEAD + VB_P2WPKH_INPUT + VB_P2TR_OUTPUT * count as u64 + VB_CHANGE_OUTPUT;
        // Double the fee estimate so a slightly-off vsize guess cannot push the
        // preselected input below what fundrawtransaction actually needs.
        let fee_headroom = Amount::from_sat((est_vsize as f64 * fee_rate * 2.0).ceil() as u64);
        let (in_txid, in_vout, in_amount) = self.select_input(outputs_total + fee_headroom)?;

        let script = address.script_pubkey();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: in_txid,
                    vout: in_vout,
                },
                script_sig: ScriptBuf::new(),
                // Deliberately not replaceable. Deposits are registered onchain
                // against this txid seconds from now, and any replacement
                // changes the txid and strands them. Refusing to signal RBF
                // takes `bumpfee` off the table; a stalled tx gets CPFP'd.
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: amount,
                    script_pubkey: script.clone(),
                };
                count
            ],
        };

        crate::ui::info(&format!(
            "input {in_txid}:{in_vout} ({in_amount}) -> {count} x {amount} (~{est_vsize} vB)"
        ));

        let funded: FundResult = self
            .wallet
            .call(
                "fundrawtransaction",
                &[
                    json!(serialize_hex(&tx)),
                    json!({
                        "add_inputs": false,
                        "fee_rate": fee_rate,
                        // Overrides the wallet's -walletrbf default; see the sequence above.
                        "replaceable": false,
                        // Park change after the deposit outputs so their vouts stay 0..count.
                        "changePosition": count,
                    }),
                ],
            )
            .map_err(|e| anyhow!("fundrawtransaction failed: {e}"))?;

        let signed: SignResult = self
            .wallet
            .call("signrawtransactionwithwallet", &[json!(funded.hex)])
            .map_err(|e| anyhow!("signrawtransactionwithwallet failed: {e}"))?;
        if !signed.complete {
            bail!(
                "wallet `{}` could not fully sign the funding tx",
                self.wallet_name
            );
        }

        let txid: String = self
            .node
            .call("sendrawtransaction", &[json!(signed.hex)])
            .map_err(|e| anyhow!("sendrawtransaction failed: {e}"))?;
        let txid: Txid = txid
            .parse()
            .context("sendrawtransaction returned a bad txid")?;

        // Read the vouts back off the broadcast transaction rather than
        // trusting changePosition.
        let decoded: Value = self
            .node
            .call("decoderawtransaction", &[json!(signed.hex)])
            .map_err(|e| anyhow!("decoderawtransaction failed: {e}"))?;
        let want = script.to_hex_string();
        let vouts: Vec<u32> = decoded["vout"]
            .as_array()
            .map(|outs| {
                outs.iter()
                    .filter(|o| o["scriptPubKey"]["hex"].as_str() == Some(want.as_str()))
                    .filter_map(|o| o["n"].as_u64().map(|n| n as u32))
                    .collect()
            })
            .unwrap_or_default();
        if vouts.len() != count {
            bail!(
                "funded tx {txid} pays {} outputs to the deposit address, expected {count}",
                vouts.len()
            );
        }

        Ok(FundingTx {
            txid,
            vouts,
            amount_sats: amount.to_sat(),
            fee_btc: funded.fee,
        })
    }
}
