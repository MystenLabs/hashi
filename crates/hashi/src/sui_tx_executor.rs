// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sui Transaction Executor
//!
//! Provides a reusable executor for submitting Sui transactions with sensible defaults.
//!
//! # Example
//!
//! ```ignore
//! use hashi::sui_tx_executor::SuiTxExecutor;
//!
//! // Minimal usage with client, signer, and hashi_ids
//! let mut executor = SuiTxExecutor::new(client, signer, hashi_ids);
//!
//! // Or from config and onchain_state (convenience constructor)
//! let mut executor = SuiTxExecutor::from_config(&config, &onchain_state)?;
//!
//! // Or from an Arc<Hashi>
//! let mut executor = SuiTxExecutor::from_hashi(hashi.clone())?;
//!
//! // Execute domain-specific transactions
//! executor.execute_approve_deposit(&deposit_request, signed_message).await?;
//! executor.execute_confirm_deposit(deposit_request.id).await?;
//!
//! // Or build custom transactions
//! let mut builder = TransactionBuilder::new();
//! // ... add inputs and move calls ...
//! let response = executor.execute(builder).await?;
//! ```

use std::sync::Arc;
use std::time::Duration;

use fastcrypto::serde_helpers::ToFromByteArray;
use futures::TryStreamExt;
use hashi_types::committee::CommitteeSignature;
use hashi_types::committee::EncryptionPublicKey;
use hashi_types::committee::SignedMessage;
use hashi_types::move_types::DepositRequestedEvent;
use hashi_types::move_types::WithdrawalRequestedEvent;

/// Construct a `CommitteeSignature` via a Move call in the PTB.
///
/// Custom structs cannot be passed as pure BCS args in a PTB, so we construct
/// the struct via `committee::new_committee_signature()` and use the result.
fn build_committee_signature_arg(
    builder: &mut TransactionBuilder,
    package_id: Address,
    sig: &CommitteeSignature,
) -> sui_transaction_builder::Argument {
    let epoch_arg = builder.pure(&sig.epoch());
    let signature_arg = builder.pure(&sig.signature_bytes().to_vec());
    let bitmap_arg = builder.pure(&sig.signers_bitmap_bytes().to_vec());
    builder.move_call(
        Function::new(
            package_id,
            Identifier::from_static("committee"),
            Identifier::from_static("new_committee_signature"),
        ),
        vec![epoch_arg, signature_arg, bitmap_arg],
    )
}

/// Maximum size in bytes for a single pure argument in a Sui PTB.
///
/// Sui enforces a 16 KiB (16384 byte) limit per pure argument. We use a 4 KiB
/// budget per chunk to stay well within the limit and leave headroom for BCS
/// framing overhead (ULEB128 length prefixes).
const MAX_PURE_ARG_CHUNK_SIZE: usize = 4096;

/// Build a `vector<vector<u8>>` PTB argument from a slice of byte vectors,
/// chunking into multiple pure arguments if the BCS-encoded size would exceed
/// the per-argument limit.
///
/// When the data fits in a single chunk, this is equivalent to
/// `builder.pure(&data)`. Otherwise, the first chunk becomes the base vector
/// and subsequent chunks are appended via `0x1::vector::append<vector<u8>>`.
fn build_chunked_vec_vec_u8_arg(
    builder: &mut TransactionBuilder,
    data: &[Vec<u8>],
) -> sui_transaction_builder::Argument {
    let chunks = chunk_vec_vec_u8(data, MAX_PURE_ARG_CHUNK_SIZE);

    let mut iter = chunks.into_iter();
    let first_chunk = iter.next().unwrap_or_default();
    let combined = builder.pure(&first_chunk);

    let vec_u8_type = TypeTag::Vector(Box::new(TypeTag::U8));
    for chunk in iter {
        let chunk_arg = builder.pure(&chunk);
        builder.move_call(
            Function::new(
                Address::new([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 1,
                ]),
                Identifier::from_static("vector"),
                Identifier::from_static("append"),
            )
            .with_type_args(vec![vec_u8_type.clone()]),
            vec![combined, chunk_arg],
        );
    }

    combined
}

/// Split a `Vec<Vec<u8>>` into chunks whose BCS-serialized size each stays
/// within `max_bytes`.
///
/// BCS encodes `Vec<Vec<u8>>` as: ULEB128(outer_len) followed by each inner
/// vec as ULEB128(inner_len) + raw bytes. This function accumulates entries
/// until adding the next one would push the chunk over the budget.
fn chunk_vec_vec_u8(data: &[Vec<u8>], max_bytes: usize) -> Vec<Vec<Vec<u8>>> {
    if data.is_empty() {
        return vec![vec![]];
    }

    let mut chunks = Vec::new();
    let mut current_chunk: Vec<Vec<u8>> = Vec::new();
    // Start with the ULEB128 length prefix for the outer vector (1 byte for
    // lengths < 128, 2 bytes for < 16384, etc.). We conservatively reserve 3
    // bytes for the outer length prefix.
    let mut current_size: usize = 3;

    for entry in data {
        // BCS size of one inner entry: ULEB128(len) + raw bytes.
        let entry_bcs_size = uleb128_len(entry.len()) + entry.len();

        if !current_chunk.is_empty() && current_size + entry_bcs_size > max_bytes {
            chunks.push(current_chunk);
            current_chunk = Vec::new();
            current_size = 3;
        }

        current_size += entry_bcs_size;
        current_chunk.push(entry.clone());
    }

    chunks.push(current_chunk);
    chunks
}

/// Return the number of bytes needed to encode `value` as a ULEB128 integer.
fn uleb128_len(value: usize) -> usize {
    match value {
        0..=0x7f => 1,
        0x80..=0x3fff => 2,
        0x4000..=0x1f_ffff => 3,
        _ => 4,
    }
}

use sui_crypto::SuiSigner;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionResponse;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_sdk_types::Transaction;
use sui_sdk_types::TypeTag;
use sui_sdk_types::bcs::FromBcs;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;
use sui_transaction_builder::intent::Balance as BalanceIntent;
use sui_transaction_builder::intent::CoinWithBalance;

use crate::Hashi;
use crate::config::Config;
use crate::config::HashiIds;
use crate::mpc::types::CertificateV1;
use crate::onchain;
use crate::onchain::OnchainState;
use crate::onchain::types::DepositConfirmationMessage;
use crate::onchain::types::DepositRequest;
use crate::withdrawals::WithdrawalTxCommitment;

const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Well-known Sui Clock object address (0x6)
pub const SUI_CLOCK_OBJECT_ID: Address = Address::from_static("0x6");
const SUI_SYSTEM_STATE_OBJECT_ID: Address = Address::from_static("0x5");
const SUI_RANDOM_OBJECT_ID: Address = Address::from_static("0x8");

/// A reusable executor for submitting Sui transactions.
///
/// Uses `TransactionBuilder::build()` with the Sui RPC client to handle
/// dry-running, gas selection, budget calculation, and object version resolution
/// automatically.
pub struct SuiTxExecutor {
    client: Client,
    signer: Ed25519PrivateKey,
    hashi_ids: HashiIds,
    timeout: Duration,
}

impl SuiTxExecutor {
    /// Create a new executor with minimal dependencies.
    pub fn new(client: Client, signer: Ed25519PrivateKey, hashi_ids: HashiIds) -> Self {
        Self {
            client,
            signer,
            hashi_ids,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Create a new executor from config and onchain state.
    ///
    /// This is a convenience constructor for use within the Hashi system.
    pub fn from_config(config: &Config, onchain_state: &OnchainState) -> anyhow::Result<Self> {
        let signer = config.operator_private_key()?;
        Ok(Self::new(
            onchain_state.client(),
            signer,
            config.hashi_ids(),
        ))
    }

    /// Create a new executor from an `Arc<Hashi>`.
    ///
    /// This is a convenience constructor that extracts the config and onchain_state
    /// from the Hashi instance.
    pub fn from_hashi(hashi: Arc<Hashi>) -> anyhow::Result<Self> {
        Self::from_config(&hashi.config, hashi.onchain_state())
    }

    /// Override the signer.
    pub fn with_signer(mut self, signer: Ed25519PrivateKey) -> Self {
        self.signer = signer;
        self
    }

    /// Override the execution timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get the sender address (derived from the signer's public key).
    pub fn sender(&self) -> Address {
        self.signer.public_key().derive_address()
    }

    // ========================================================================
    // Generic execution methods
    // ========================================================================

    /// Execute a transaction built with `TransactionBuilder`.
    ///
    /// This method sets the sender on the builder and uses `build()` with the client,
    /// which handles dry-running the transaction, setting a budget, doing coin selection,
    /// and resolving object versions/digests automatically.
    ///
    /// Note: The builder is consumed because `TransactionBuilder::build()` takes ownership.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(sui_digest = tracing::field::Empty),
    )]
    pub async fn execute(
        &mut self,
        mut builder: TransactionBuilder,
    ) -> anyhow::Result<ExecuteTransactionResponse> {
        let sender = self.signer.public_key().derive_address();

        builder.set_sender(sender);

        let transaction = builder.build(&mut self.client).await?;
        let signature = self.signer.sign_transaction(&transaction)?;

        let response = self
            .client
            .execute_transaction_and_wait_for_checkpoint(
                ExecuteTransactionRequest::new(transaction.into())
                    .with_signatures(vec![signature.into()])
                    .with_read_mask(FieldMask::from_str("*")),
                self.timeout,
            )
            .await?
            .into_inner();

        tracing::Span::current().record(
            "sui_digest",
            tracing::field::display(response.transaction().digest()),
        );

        Ok(response)
    }

    // ========================================================================
    // Domain-specific execution methods
    // ========================================================================

    /// Execute the first phase of deposit confirmation: record the
    /// committee certificate against the deposit request via
    /// `deposit::approve_deposit`. The deposit is not yet final — it
    /// must still pass `confirm_deposit` after the configured time-delay
    /// window has elapsed.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(deposit_id = %deposit_request.id),
    )]
    pub async fn execute_approve_deposit(
        &mut self,
        deposit_request: &DepositRequest,
        signed_message: SignedMessage<DepositConfirmationMessage>,
    ) -> anyhow::Result<()> {
        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let request_id_arg = builder.pure(&deposit_request.id);
        let cert_arg = build_committee_signature_arg(
            &mut builder,
            self.hashi_ids.package_id,
            signed_message.committee_signature(),
        );
        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );

        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("deposit"),
                Identifier::from_static("approve_deposit"),
            ),
            vec![hashi_arg, request_id_arg, cert_arg, clock_arg],
        );

        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "Transaction failed to approve deposit for request {:?}",
                deposit_request.id
            );
        }
        Ok(())
    }

    /// Execute the second phase of deposit confirmation: finalize a
    /// previously-approved deposit via `deposit::confirm_deposit`. The
    /// on-chain function re-verifies the stored committee certificate
    /// against the current committee and asserts that the configured
    /// time-delay since approval has elapsed.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(deposit_id = %request_id),
    )]
    pub async fn execute_confirm_deposit(&mut self, request_id: Address) -> anyhow::Result<()> {
        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let request_id_arg = builder.pure(&request_id);
        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );

        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("deposit"),
                Identifier::from_static("confirm_deposit"),
            ),
            vec![hashi_arg, request_id_arg, clock_arg],
        );

        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!("Transaction failed to confirm deposit for request {request_id:?}");
        }
        Ok(())
    }

    /// Execute a batch deletion of expired deposit requests.
    ///
    /// This builds and executes a PTB that calls `deposit::delete_expired_deposit`
    /// for each expired request in the batch.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(expired_count = expired_requests.len()),
    )]
    pub async fn execute_delete_expired_deposit_requests(
        &mut self,
        expired_requests: &[DepositRequest],
    ) -> anyhow::Result<()> {
        // Build a PTB that calls delete_expired_deposit for each expired request
        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );

        // Add a move call for each expired deposit request
        for deposit_request in expired_requests {
            let request_id_arg = builder.pure(&deposit_request.id);

            builder.move_call(
                Function::new(
                    self.hashi_ids.package_id,
                    Identifier::from_static("deposit"),
                    Identifier::from_static("delete_expired_deposit"),
                ),
                vec![hashi_arg, request_id_arg, clock_arg],
            );
        }

        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!("Transaction failed to delete expired deposit requests");
        }
        Ok(())
    }

    /// Execute a deposit request transaction.
    ///
    /// Creates a deposit request on-chain by:
    /// 1. Creating a UTXO object (txid, vout, amount, derivation_path)
    /// 2. Splitting SUI for the deposit fee
    /// 3. Calling deposit(hashi, utxo, fee, clock) which creates the DepositRequest on-chain
    ///
    /// Returns the deposit request ID on success.
    ///
    /// Note: The `txid` parameter should be the Bitcoin transaction ID converted to a Sui Address
    /// (i.e., the 32-byte txid interpreted as a Sui address).
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(bitcoin_txid = %txid, vout, amount = amount_sats),
    )]
    pub async fn execute_create_deposit_request(
        &mut self,
        txid: Address,
        vout: u32,
        amount_sats: u64,
        derivation_path: Option<Address>,
    ) -> anyhow::Result<Address> {
        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );

        // Pure inputs
        let txid_arg = builder.pure(&txid);
        let vout_arg = builder.pure(&vout);
        let amount_arg = builder.pure(&amount_sats);
        let derivation_path_arg = builder.pure(&derivation_path);

        // 1. Create UtxoId: utxo::utxo_id(txid, vout)
        let utxo_id_arg = builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("utxo"),
                Identifier::from_static("utxo_id"),
            ),
            vec![txid_arg, vout_arg],
        );

        // 2. Create Utxo: utxo::utxo(utxo_id, amount, derivation_path)
        let utxo_arg = builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("utxo"),
                Identifier::from_static("utxo"),
            ),
            vec![utxo_id_arg, amount_arg, derivation_path_arg],
        );

        // 3. Call deposit(hashi, utxo, clock)
        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("deposit"),
                Identifier::from_static("deposit"),
            ),
            vec![hashi_arg, utxo_arg, clock_arg],
        );

        let response = self.execute(builder).await?;

        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "Deposit request transaction failed: {:?}",
                response.transaction().effects().status()
            );
        }

        // Parse events to extract the deposit request ID
        let events = response.transaction().events();
        for event in events.events() {
            let event_type = event.contents().name();

            if event_type.contains("DepositRequestedEvent") {
                let event_data = DepositRequestedEvent::from_bcs(event.contents().value())?;
                return Ok(event_data.request_id);
            }
        }

        anyhow::bail!("DepositRequestedEvent not found in transaction events")
    }

    /// Execute a batch deposit request transaction.
    ///
    /// Creates multiple deposit requests on-chain in a single PTB by repeating
    /// the deposit sequence for each UTXO output:
    /// 1. Creating a UTXO object (txid, vout, amount, derivation_path)
    /// 2. Calling deposit(hashi, utxo, clock) which creates the DepositRequest on-chain
    ///
    /// Returns the deposit request IDs on success.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(bitcoin_txid = %txid, utxo_count = utxos.len()),
    )]
    pub async fn execute_create_deposit_requests_batch(
        &mut self,
        txid: Address,
        utxos: &[(u32, u64)],
        derivation_path: Option<Address>,
    ) -> anyhow::Result<Vec<Address>> {
        anyhow::ensure!(!utxos.is_empty(), "No UTXOs to deposit");

        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );

        for &(vout, amount_sats) in utxos {
            let txid_arg = builder.pure(&txid);
            let vout_arg = builder.pure(&vout);
            let amount_arg = builder.pure(&amount_sats);
            let derivation_path_arg = builder.pure(&derivation_path);

            // 1. Create UtxoId
            let utxo_id_arg = builder.move_call(
                Function::new(
                    self.hashi_ids.package_id,
                    Identifier::from_static("utxo"),
                    Identifier::from_static("utxo_id"),
                ),
                vec![txid_arg, vout_arg],
            );

            // 2. Create Utxo
            let utxo_arg = builder.move_call(
                Function::new(
                    self.hashi_ids.package_id,
                    Identifier::from_static("utxo"),
                    Identifier::from_static("utxo"),
                ),
                vec![utxo_id_arg, amount_arg, derivation_path_arg],
            );

            // 3. Call deposit(hashi, utxo, clock)
            builder.move_call(
                Function::new(
                    self.hashi_ids.package_id,
                    Identifier::from_static("deposit"),
                    Identifier::from_static("deposit"),
                ),
                vec![hashi_arg, utxo_arg, clock_arg],
            );
        }

        let response = self.execute(builder).await?;

        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "Batch deposit request transaction failed: {:?}",
                response.transaction().effects().status()
            );
        }

        // Parse events to extract all deposit request IDs
        let events = response.transaction().events();
        let mut request_ids = Vec::new();
        for event in events.events() {
            let event_type = event.contents().name();
            if event_type.contains("DepositRequestedEvent") {
                let event_data = DepositRequestedEvent::from_bcs(event.contents().value())?;
                request_ids.push(event_data.request_id);
            }
        }

        anyhow::ensure!(
            request_ids.len() == utxos.len(),
            "Expected {} DepositRequestedEvents but found {}",
            utxos.len(),
            request_ids.len(),
        );

        Ok(request_ids)
    }

    /// Execute a batch deposit request transaction from multiple Bitcoin txids.
    ///
    /// Each entry is `(txid, vout, amount)`. All deposits share the same
    /// optional `derivation_path`. This packs multiple deposits into a single
    /// PTB, reducing round-trips compared to individual calls.
    ///
    /// Callers must ensure the batch size stays within the PTB command limit
    /// (roughly 300 deposits per PTB due to the 1024-command cap).
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(deposit_count = deposits.len()),
    )]
    pub async fn execute_create_deposit_requests_multi(
        &mut self,
        deposits: &[(Address, u32, u64)],
        derivation_path: Option<Address>,
    ) -> anyhow::Result<Vec<Address>> {
        anyhow::ensure!(!deposits.is_empty(), "No deposits to create");

        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );

        for &(txid, vout, amount_sats) in deposits {
            let txid_arg = builder.pure(&txid);
            let vout_arg = builder.pure(&vout);
            let amount_arg = builder.pure(&amount_sats);
            let derivation_path_arg = builder.pure(&derivation_path);

            let utxo_id_arg = builder.move_call(
                Function::new(
                    self.hashi_ids.package_id,
                    Identifier::from_static("utxo"),
                    Identifier::from_static("utxo_id"),
                ),
                vec![txid_arg, vout_arg],
            );

            let utxo_arg = builder.move_call(
                Function::new(
                    self.hashi_ids.package_id,
                    Identifier::from_static("utxo"),
                    Identifier::from_static("utxo"),
                ),
                vec![utxo_id_arg, amount_arg, derivation_path_arg],
            );

            builder.move_call(
                Function::new(
                    self.hashi_ids.package_id,
                    Identifier::from_static("deposit"),
                    Identifier::from_static("deposit"),
                ),
                vec![hashi_arg, utxo_arg, clock_arg],
            );
        }

        let response = self.execute(builder).await?;

        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "Multi-txid batch deposit failed: {:?}",
                response.transaction().effects().status()
            );
        }

        let events = response.transaction().events();
        let mut request_ids = Vec::new();
        for event in events.events() {
            if event.contents().name().contains("DepositRequestedEvent") {
                let event_data = DepositRequestedEvent::from_bcs(event.contents().value())?;
                request_ids.push(event_data.request_id);
            }
        }

        anyhow::ensure!(
            request_ids.len() == deposits.len(),
            "Expected {} DepositRequestedEvents but found {}",
            deposits.len(),
            request_ids.len(),
        );

        Ok(request_ids)
    }

    /// Execute a withdrawal request transaction.
    ///
    /// Creates a withdrawal request on-chain by:
    /// 1. Using Balance intent to select/merge BTC into a `Balance<BTC>`
    /// 2. Calling `withdraw::request_withdrawal`
    ///
    /// Returns the withdrawal request ID on success.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(amount = withdrawal_amount_sats, request_id = tracing::field::Empty),
    )]
    pub async fn execute_create_withdrawal_request(
        &mut self,
        withdrawal_amount_sats: u64,
        destination_bytes: Vec<u8>,
    ) -> anyhow::Result<Address> {
        let mut builder = TransactionBuilder::new();

        // Shared objects
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );

        // BTC balance via Balance intent.
        let btc_type = StructTag::new(
            self.hashi_ids.package_id,
            Identifier::from_static("btc"),
            Identifier::from_static("BTC"),
            vec![],
        );
        let btc_arg = builder.intent(BalanceIntent::new(btc_type, withdrawal_amount_sats));

        // Pure inputs
        let destination_arg = builder.pure(&destination_bytes);

        // Call withdraw::request_withdrawal(hashi, clock, btc, bitcoin_address)
        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("withdraw"),
                Identifier::from_static("request_withdrawal"),
            ),
            vec![hashi_arg, clock_arg, btc_arg, destination_arg],
        );

        let response = self.execute(builder).await?;

        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "Withdrawal request transaction failed: {:?}",
                response.transaction().effects().status()
            );
        }

        // Parse events to extract the withdrawal request ID
        for event in response.transaction().events().events() {
            if event.contents().name().contains("WithdrawalRequestedEvent") {
                let event_data = WithdrawalRequestedEvent::from_bcs(event.contents().value())?;
                tracing::Span::current().record(
                    "request_id",
                    tracing::field::display(&event_data.request_id),
                );
                return Ok(event_data.request_id);
            }
        }

        anyhow::bail!("WithdrawalRequestedEvent not found in transaction events")
    }

    #[tracing::instrument(level = "info", skip_all)]
    pub async fn execute_start_reconfig(&mut self) -> anyhow::Result<()> {
        let mut builder = TransactionBuilder::new();
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let sui_system_arg = builder.object(
            ObjectInput::new(SUI_SYSTEM_STATE_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );
        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("reconfig"),
                Identifier::from_static("start_reconfig"),
            ),
            vec![hashi_arg, sui_system_arg],
        );
        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "start_reconfig transaction failed: {:?}",
                response.transaction().effects().status()
            );
        }
        Ok(())
    }

    #[tracing::instrument(level = "info", skip_all)]
    pub async fn execute_end_reconfig(
        &mut self,
        mpc_public_key: &[u8],
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        let mut builder = TransactionBuilder::new();
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let mpc_public_key_arg = builder.pure(&mpc_public_key.to_vec());
        let cert_arg = build_committee_signature_arg(&mut builder, self.hashi_ids.package_id, cert);
        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("reconfig"),
                Identifier::from_static("end_reconfig"),
            ),
            vec![hashi_arg, mpc_public_key_arg, cert_arg],
        );
        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "end_reconfig transaction failed: {:?}",
                response.transaction().effects().status()
            );
        }
        Ok(())
    }

    /// Reassign presig indices for a withdrawal transaction from a previous epoch.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(withdrawal_txn_id = %withdrawal_id),
    )]
    pub async fn execute_allocate_presigs_for_withdrawal_txn(
        &mut self,
        withdrawal_id: Address,
    ) -> anyhow::Result<()> {
        let mut builder = TransactionBuilder::new();
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let withdrawal_id_arg = builder.pure(&withdrawal_id);
        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("withdraw"),
                Identifier::from_static("allocate_presigs_for_withdrawal_txn"),
            ),
            vec![hashi_arg, withdrawal_id_arg],
        );
        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "allocate_presigs_for_withdrawal_txn transaction failed: {:?}",
                response.transaction().effects().status()
            );
        }
        Ok(())
    }

    /// Register and/or update validator metadata on-chain.
    ///
    /// Delegates to [`build_register_or_update_validator_tx`] to determine which
    /// move calls are needed, then signs and executes the resulting transaction.
    /// Returns `Ok(false)` if nothing needed to be updated.
    #[tracing::instrument(level = "info", skip_all)]
    pub async fn execute_register_or_update_validator(
        &mut self,
        config: &Config,
        operator_address: Option<Address>,
    ) -> anyhow::Result<bool> {
        let sender = self.signer.public_key().derive_address();
        let transaction = build_register_or_update_validator_tx(
            &mut self.client,
            &self.hashi_ids,
            config,
            operator_address,
            Some(sender),
        )
        .await?;

        let Some(transaction) = transaction else {
            return Ok(false);
        };

        let signature = self.signer.sign_transaction(&transaction)?;
        let response = self
            .client
            .execute_transaction_and_wait_for_checkpoint(
                ExecuteTransactionRequest::new(transaction.into())
                    .with_signatures(vec![signature.into()])
                    .with_read_mask(FieldMask::from_str("*")),
                self.timeout,
            )
            .await?
            .into_inner();

        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "register_validator transaction failed: {:?}",
                response.transaction().effects().status()
            );
        }
        Ok(true)
    }

    /// Update the validator's `next_epoch_encryption_public_key` on-chain.
    ///
    /// Skips the transaction if the on-chain key already matches `encryption_public_key`.
    #[tracing::instrument(level = "info", skip_all)]
    pub async fn execute_update_next_epoch_encryption_key(
        &mut self,
        validator_address: Address,
        encryption_public_key: &EncryptionPublicKey,
    ) -> anyhow::Result<()> {
        let new_bytes = encryption_public_key.as_element().to_byte_array();
        let hashi_object = self
            .client
            .ledger_client()
            .get_object(
                GetObjectRequest::new(&self.hashi_ids.hashi_object_id).with_read_mask(
                    FieldMask::from_paths([
                        Object::path_builder().contents().finish(),
                        Object::path_builder().object_id(),
                    ]),
                ),
            )
            .await?
            .into_inner();
        let hashi_move: hashi_types::move_types::Hashi =
            hashi_object.object().contents().deserialize()?;
        let members_id = hashi_move.committees.members.id;
        let onchain_member =
            onchain::scrape_member_info(self.client.clone(), members_id, validator_address)
                .await
                .ok();
        let already_matches = onchain_member
            .as_ref()
            .and_then(|m| m.next_epoch_encryption_public_key())
            .map(|k| k.as_element().to_byte_array() == new_bytes)
            .unwrap_or(false);
        if already_matches {
            tracing::debug!(
                %validator_address,
                "On-chain next_epoch_encryption_public_key already matches; skipping update"
            );
            return Ok(());
        }
        let mut builder = TransactionBuilder::new();
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let validator_address_arg = builder.pure(&validator_address);
        let encryption_key_arg = builder.pure(&new_bytes.as_slice().to_vec());
        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("validator"),
                Identifier::from_static("update_next_epoch_encryption_public_key"),
            ),
            vec![hashi_arg, validator_address_arg, encryption_key_arg],
        );
        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "update_next_epoch_encryption_public_key transaction failed: {:?}",
                response.transaction().effects().status()
            );
        }
        tracing::info!(
            %validator_address,
            "Registered next_epoch_encryption_public_key on-chain"
        );
        Ok(())
    }

    /// Execute a certificate submission transaction.
    ///
    /// This submits a DKG, rotation, or nonce generation certificate to the on-chain
    /// certificate store. The certificate contains the dealer's message hash and
    /// committee signature.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(cert_kind = tracing::field::Empty),
    )]
    pub async fn execute_submit_certificate(&mut self, cert: &CertificateV1) -> anyhow::Result<()> {
        let (inner_cert, function_name, batch_index) = match cert {
            CertificateV1::Dkg(c) => (c, "submit_dkg_cert", None),
            CertificateV1::Rotation(c) => (c, "submit_rotation_cert", None),
            CertificateV1::NonceGeneration { batch_index, cert } => {
                (cert, "submit_nonce_cert", Some(*batch_index))
            }
        };
        tracing::Span::current().record("cert_kind", function_name);

        let message = inner_cert.message();
        let dealer = message.dealer_address;
        let message_hash = message.messages_hash.inner().to_vec();
        let epoch = inner_cert.epoch();
        let committee_sig = inner_cert.committee_signature();

        let mut builder = TransactionBuilder::new();

        // Build inputs for the move call - server will resolve shared object version
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let epoch_arg = builder.pure(&epoch);
        let mut args = vec![hashi_arg, epoch_arg];
        if let Some(bi) = batch_index {
            args.push(builder.pure(&bi));
        }
        let dealer_arg = builder.pure(&dealer);
        let message_hash_arg = builder.pure(&message_hash);
        let cert_arg =
            build_committee_signature_arg(&mut builder, self.hashi_ids.package_id, committee_sig);
        args.extend([dealer_arg, message_hash_arg, cert_arg]);
        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("cert_submission"),
                Identifier::new(function_name).expect("valid identifier"),
            ),
            args,
        );

        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "Certificate submission failed: {:?}",
                response.transaction().effects().status()
            );
        }
        Ok(())
    }

    /// Execute `withdraw::approve_request` to approve withdrawal requests on-chain.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(batch_size = approvals.len()),
    )]
    pub async fn execute_approve_withdrawal_requests(
        &mut self,
        approvals: &[(Address, &CommitteeSignature)],
    ) -> anyhow::Result<()> {
        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );

        for (request_id, cert) in approvals {
            let request_id_arg = builder.pure(request_id);
            let cert_arg =
                build_committee_signature_arg(&mut builder, self.hashi_ids.package_id, cert);

            builder.move_call(
                Function::new(
                    self.hashi_ids.package_id,
                    Identifier::from_static("withdraw"),
                    Identifier::from_static("approve_request"),
                ),
                vec![hashi_arg, request_id_arg, cert_arg],
            );
        }

        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "approve_request failed: {:?}",
                response.transaction().effects().status()
            );
        }
        Ok(())
    }

    /// Execute `withdraw::commit_withdrawal_tx` to commit to a withdrawal on-chain.
    /// - `r: &Random`
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(
            bitcoin_txid = %approval.txid,
            request_count = approval.request_ids.len(),
        ),
    )]
    pub async fn execute_commit_withdrawal_tx(
        &mut self,
        approval: &WithdrawalTxCommitment,
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );

        let requests_arg = builder.pure(&approval.request_ids);

        let utxo_id_type = StructTag::new(
            self.hashi_ids.package_id,
            Identifier::from_static("utxo"),
            Identifier::from_static("UtxoId"),
            vec![],
        );
        let utxo_elements: Vec<_> = approval
            .selected_utxos
            .iter()
            .map(|utxo_id| {
                let txid_arg = builder.pure(&utxo_id.txid);
                let vout_arg = builder.pure(&utxo_id.vout);
                builder.move_call(
                    Function::new(
                        self.hashi_ids.package_id,
                        Identifier::from_static("utxo"),
                        Identifier::from_static("utxo_id"),
                    ),
                    vec![txid_arg, vout_arg],
                )
            })
            .collect();
        let selected_utxos_arg = builder.make_move_vec(Some(utxo_id_type.into()), utxo_elements);

        let output_utxo_type = StructTag::new(
            self.hashi_ids.package_id,
            Identifier::from_static("withdrawal_queue"),
            Identifier::from_static("OutputUtxo"),
            vec![],
        );
        let output_elements: Vec<_> = approval
            .outputs
            .iter()
            .map(|output| {
                let amount_arg = builder.pure(&output.amount);
                let address_arg = builder.pure(&output.bitcoin_address);
                builder.move_call(
                    Function::new(
                        self.hashi_ids.package_id,
                        Identifier::from_static("withdrawal_queue"),
                        Identifier::from_static("output_utxo"),
                    ),
                    vec![amount_arg, address_arg],
                )
            })
            .collect();
        let outputs_arg = builder.make_move_vec(Some(output_utxo_type.into()), output_elements);

        let txid_arg = builder.pure(&approval.txid);
        let cert_arg = build_committee_signature_arg(&mut builder, self.hashi_ids.package_id, cert);

        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );
        let random_arg = builder.object(
            ObjectInput::new(SUI_RANDOM_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );

        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("withdraw"),
                Identifier::from_static("commit_withdrawal_tx"),
            ),
            vec![
                hashi_arg,
                requests_arg,
                selected_utxos_arg,
                outputs_arg,
                txid_arg,
                cert_arg,
                clock_arg,
                random_arg,
            ],
        );

        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "commit_withdrawal_tx failed: {:?}",
                response.transaction().effects().status()
            );
        }
        Ok(())
    }

    /// Execute `withdraw::sign_withdrawal` to store witness signatures on-chain.
    ///
    /// Sui limits each pure argument to 16 KiB. With many inputs (up to 500),
    /// the BCS-encoded `Vec<Vec<u8>>` of signatures can exceed that limit. To
    /// handle this, the signatures are split into chunks that each fit within
    /// the pure-arg budget and stitched back together via
    /// `0x1::vector::append` calls in the PTB.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(
            withdrawal_txn_id = %withdrawal_id,
            request_count = request_ids.len(),
            input_count = signatures.len(),
        ),
    )]
    pub async fn execute_sign_withdrawal(
        &mut self,
        withdrawal_id: &Address,
        request_ids: &[Address],
        signatures: &[Vec<u8>],
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let withdrawal_id_arg = builder.pure(withdrawal_id);
        let request_ids_vec = request_ids.to_vec();
        let request_ids_arg = builder.pure(&request_ids_vec);
        let signatures_arg = build_chunked_vec_vec_u8_arg(&mut builder, signatures);
        let cert_arg = build_committee_signature_arg(&mut builder, self.hashi_ids.package_id, cert);

        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("withdraw"),
                Identifier::from_static("sign_withdrawal"),
            ),
            vec![
                hashi_arg,
                withdrawal_id_arg,
                request_ids_arg,
                signatures_arg,
                cert_arg,
            ],
        );

        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "sign_withdrawal failed: {:?}",
                response.transaction().effects().status()
            );
        }
        Ok(())
    }

    /// Execute `withdraw::cancel_withdrawal` to cancel a pending withdrawal request.
    ///
    /// The Move function returns a `Balance<BTC>` which is sent back to the
    /// sender's address balance.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(request_id = %withdrawal_id),
    )]
    pub async fn execute_cancel_withdrawal(
        &mut self,
        withdrawal_id: &Address,
    ) -> anyhow::Result<()> {
        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let request_id_arg = builder.pure(withdrawal_id);
        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );

        let refunded_balance = builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("withdraw"),
                Identifier::from_static("cancel_withdrawal"),
            ),
            vec![hashi_arg, request_id_arg, clock_arg],
        );

        // Send the refunded Balance<BTC> back to the sender's address balance.
        let btc_type = StructTag::new(
            self.hashi_ids.package_id,
            Identifier::from_static("btc"),
            Identifier::from_static("BTC"),
            vec![],
        );
        let sender = self.signer.public_key().derive_address();
        let sender_arg = builder.pure(&sender);
        builder.move_call(
            Function::new(
                Address::TWO,
                Identifier::from_static("balance"),
                Identifier::from_static("send_funds"),
            )
            .with_type_args(vec![btc_type.into()]),
            vec![refunded_balance, sender_arg],
        );

        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "cancel_withdrawal failed: {:?}",
                response.transaction().effects().status()
            );
        }
        Ok(())
    }

    /// Execute `withdraw::confirm_withdrawal` to finalize a withdrawal on-chain.
    ///
    /// The Move function expects:
    /// - `hashi: &mut Hashi`
    /// - `withdrawal_id: address`
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(withdrawal_txn_id = %withdrawal_id),
    )]
    pub async fn execute_confirm_withdrawal(
        &mut self,
        withdrawal_id: &Address,
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let withdrawal_id_arg = builder.pure(withdrawal_id);
        let cert_arg = build_committee_signature_arg(&mut builder, self.hashi_ids.package_id, cert);

        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("withdraw"),
                Identifier::from_static("confirm_withdrawal"),
            ),
            vec![hashi_arg, withdrawal_id_arg, cert_arg],
        );

        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "confirm_withdrawal failed: {:?}",
                response.transaction().effects().status()
            );
        }
        Ok(())
    }
}

/// Build a transaction to register and/or update validator metadata.
///
/// Fetches the validator's current onchain state via `client`. If the validator is not yet
/// registered, includes a `validator::register` call and sets the sender to `validator_address`.
/// If already registered, only includes update calls for metadata that differs from what is
/// currently onchain. Returns `None` if no changes are needed.
///
/// When not registering, the sender is set to `sender` if provided (typically the operator
/// address), otherwise falls back to `validator_address`.
pub async fn build_register_or_update_validator_tx(
    client: &mut Client,
    hashi_ids: &HashiIds,
    config: &Config,
    operator_address: Option<Address>,
    sender: Option<Address>,
) -> anyhow::Result<Option<Transaction>> {
    let validator_address = config.validator_address()?;

    // Fetch the Hashi object to get the members Bag ID.
    let hashi_object = client
        .ledger_client()
        .get_object(
            GetObjectRequest::new(&hashi_ids.hashi_object_id).with_read_mask(
                FieldMask::from_paths([
                    Object::path_builder().contents().finish(),
                    Object::path_builder().object_id(),
                ]),
            ),
        )
        .await?
        .into_inner();
    let hashi_move: hashi_types::move_types::Hashi =
        hashi_object.object().contents().deserialize()?;
    let members_id = hashi_move.committees.members.id;

    // Try to fetch existing member info. A missing dynamic field means the validator
    // is not yet registered.
    let onchain_member = onchain::scrape_member_info(client.clone(), members_id, validator_address)
        .await
        .ok();
    let registering = onchain_member.is_none();
    if onchain_member.is_none() {
        tracing::info!(
            %validator_address,
            "Validator not found on-chain, will register"
        );
    } else {
        tracing::info!(
            %validator_address,
            "Validator already registered, will update metadata"
        );
    }

    let mut builder = TransactionBuilder::new();
    let mut has_calls = false;

    let hashi_arg = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    let validator_address_arg = builder.pure(&validator_address);

    // 1. Register if not already registered.
    if registering {
        let sui_system_arg = builder.object(
            ObjectInput::new(SUI_SYSTEM_STATE_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );
        builder.move_call(
            Function::new(
                hashi_ids.package_id,
                Identifier::from_static("validator"),
                Identifier::from_static("register"),
            ),
            vec![hashi_arg, sui_system_arg],
        );
        has_calls = true;
    }

    // 2. Update BLS public key if available and changed.
    if let Some(protocol_key) = config.protocol_private_key()
        && onchain_member
            .as_ref()
            .map(|m| m.next_epoch_public_key().as_ref() != protocol_key.public_key().as_ref())
            .unwrap_or(true)
    {
        let service_info = client
            .clone()
            .ledger_client()
            .get_service_info(GetServiceInfoRequest::default())
            .await?
            .into_inner();
        let current_epoch = service_info.epoch();
        let pop = protocol_key.proof_of_possession(current_epoch, validator_address);

        let public_key_arg = builder.pure(&protocol_key.public_key().as_ref().to_vec());
        let pop_signature_arg = builder.pure(&pop.signature().as_ref().to_vec());
        builder.move_call(
            Function::new(
                hashi_ids.package_id,
                Identifier::from_static("validator"),
                Identifier::from_static("update_next_epoch_public_key"),
            ),
            vec![
                hashi_arg,
                validator_address_arg,
                public_key_arg,
                pop_signature_arg,
            ],
        );
        has_calls = true;
    }

    // 3. Update endpoint URL if available and changed.
    if let Some(config_url) = config.endpoint_url()
        && onchain_member
            .as_ref()
            .and_then(|m| m.endpoint_url())
            .map(|u| config_url != u)
            .unwrap_or(true)
    {
        let endpoint_url_arg = builder.pure(&config_url.to_string());
        builder.move_call(
            Function::new(
                hashi_ids.package_id,
                Identifier::from_static("validator"),
                Identifier::from_static("update_endpoint_url"),
            ),
            vec![hashi_arg, validator_address_arg, endpoint_url_arg],
        );
        has_calls = true;
    }

    // 4. Update TLS key if available and changed.
    if let Ok(tls_key) = config.tls_public_key()
        && onchain_member
            .as_ref()
            .map(|m| m.tls_public_key() != Some(&tls_key))
            .unwrap_or(true)
    {
        let tls_key_arg = builder.pure(&tls_key.as_bytes().to_vec());
        builder.move_call(
            Function::new(
                hashi_ids.package_id,
                Identifier::from_static("validator"),
                Identifier::from_static("update_tls_public_key"),
            ),
            vec![hashi_arg, validator_address_arg, tls_key_arg],
        );
        has_calls = true;
    }

    // 5. Update operator address if provided and changed.
    if let Some(operator) = operator_address
        && onchain_member
            .as_ref()
            .map(|m| *m.operator_address() != operator)
            .unwrap_or(true)
    {
        let operator_arg = builder.pure(&operator);
        builder.move_call(
            Function::new(
                hashi_ids.package_id,
                Identifier::from_static("validator"),
                Identifier::from_static("update_operator_address"),
            ),
            vec![hashi_arg, validator_address_arg, operator_arg],
        );
        has_calls = true;
    }

    if !has_calls {
        return Ok(None);
    }

    let effective_sender = if registering {
        validator_address
    } else {
        sender.unwrap_or(validator_address)
    };
    builder.set_sender(effective_sender);

    let transaction = builder.build(client).await?;
    Ok(Some(transaction))
}

/// Sweeps SUI coins into the account's Address Balance
pub async fn sweep_to_address_balance(client: &mut Client, config: &Config) -> anyhow::Result<()> {
    let signer = config.operator_private_key()?;
    let sender = signer.public_key().derive_address();

    // First we need to sweep any SUI into the account's AB so that subsequent txn can all be done
    // in parallel, using its AB to pay for gas fees.
    let balance = client
        .state_client()
        .get_balance(
            sui_rpc::proto::sui::rpc::v2::GetBalanceRequest::default()
                .with_owner(sender)
                .with_coin_type(StructTag::sui()),
        )
        .await?
        .into_inner()
        .balance
        .take()
        .unwrap_or_default();

    // Bootstrap by ensuring sender has at least 1 SUI in its AB
    if balance.address_balance() < 1_000_000_000 {
        let mut builder = TransactionBuilder::new();
        builder.set_sender(sender);
        let sender_arg = builder.pure(&sender);
        let coin = builder.intent(CoinWithBalance::sui(1_000_000_000));
        builder.move_call(
            Function::new(
                Address::TWO,
                Identifier::from_static("coin"),
                Identifier::from_static("send_funds"),
            )
            .with_type_args(vec![StructTag::sui().into()]),
            vec![coin, sender_arg],
        );

        let transaction = builder.build(client).await?;

        let signature = signer.sign_transaction(&transaction)?;

        let response = client
            .execute_transaction_and_wait_for_checkpoint(
                ExecuteTransactionRequest::new(transaction.into())
                    .with_signatures(vec![signature.into()])
                    .with_read_mask(FieldMask::from_str("effects.status,effects.gas_used")),
                Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            )
            .await?
            .into_inner();

        if !response.transaction().effects().status().success() {
            return Err(anyhow::anyhow!(
                "txn failed {:?}",
                response.transaction().effects().status()
            ));
        }
    }

    let coin_struct = StructTag::coin(StructTag::sui().into());
    let list_request = sui_rpc::proto::sui::rpc::v2::ListOwnedObjectsRequest::default()
        .with_owner(sender)
        .with_object_type(&coin_struct)
        .with_page_size(500u32)
        .with_read_mask(FieldMask::from_paths([
            "object_id",
            "version",
            "digest",
            "balance",
            "owner",
        ]));

    let mut coins: Vec<ObjectInput> = client
        .list_owned_objects(list_request)
        .try_filter_map(|o| async move {
            if let Ok(object_id) = o.object_id().parse() {
                Ok(Some(ObjectInput::new(object_id)))
            } else {
                Ok(None)
            }
        })
        .try_collect()
        .await?;

    while !coins.is_empty() {
        let mut builder = TransactionBuilder::new();
        builder.set_sender(sender);
        let sender_arg = builder.pure(&sender);

        let to_merge = coins.split_off(coins.len().saturating_sub(2000));

        if let [first, rest @ ..] = to_merge
            .into_iter()
            .map(|coin| builder.object(coin))
            .collect::<Vec<_>>()
            .as_slice()
        {
            for chunk in rest.chunks(500) {
                builder.merge_coins(*first, chunk.to_vec());
            }

            builder.move_call(
                Function::new(
                    Address::TWO,
                    Identifier::from_static("coin"),
                    Identifier::from_static("send_funds"),
                )
                .with_type_args(vec![StructTag::sui().into()]),
                vec![*first, sender_arg],
            );
        }

        let transaction = builder.build(client).await?;

        let signature = signer.sign_transaction(&transaction)?;

        let response = client
            .execute_transaction_and_wait_for_checkpoint(
                ExecuteTransactionRequest::new(transaction.into())
                    .with_signatures(vec![signature.into()])
                    .with_read_mask(FieldMask::from_str("effects.status,effects.gas_used")),
                Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            )
            .await?
            .into_inner();

        if !response.transaction().effects().status().success() {
            return Err(anyhow::anyhow!(
                "txn failed {:?}",
                response.transaction().effects().status()
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_empty_input() {
        let chunks = chunk_vec_vec_u8(&[], 4096);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].is_empty());
    }

    #[test]
    fn chunk_single_entry_fits() {
        let data = vec![vec![0u8; 64]];
        let chunks = chunk_vec_vec_u8(&data, 4096);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 1);
    }

    #[test]
    fn chunk_splits_at_budget() {
        // 64-byte signatures: each entry is 1 (ULEB128) + 64 = 65 bytes BCS.
        // With 3 bytes for the outer length prefix, a 4096-byte budget fits
        // (4096 - 3) / 65 = 62.9 -> 62 entries per chunk.
        let sig_count = 500;
        let data: Vec<Vec<u8>> = (0..sig_count).map(|_| vec![0xAB; 64]).collect();
        let chunks = chunk_vec_vec_u8(&data, 4096);

        // Each chunk should have at most 62 entries.
        let max_per_chunk = (4096 - 3) / 65;
        for chunk in &chunks {
            assert!(chunk.len() <= max_per_chunk);
        }

        // All entries are accounted for.
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, sig_count);

        // With 500 entries and 62 per chunk, we need ceil(500/62) = 9 chunks.
        assert_eq!(chunks.len(), 500usize.div_ceil(max_per_chunk));
    }

    #[test]
    fn chunk_large_entries() {
        // Entries larger than what fits many-per-chunk: 2000-byte entries.
        // BCS: 2 (ULEB128 for 2000) + 2000 = 2002 bytes per entry.
        // Budget 4096: only 1 entry per chunk (3 + 2002 = 2005 < 4096, but
        // 3 + 2002 + 2002 = 4007 < 4096... actually 2 fit).
        let data: Vec<Vec<u8>> = (0..10).map(|_| vec![0xFF; 2000]).collect();
        let chunks = chunk_vec_vec_u8(&data, 4096);
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, 10);
        // Each chunk's BCS size should be within budget.
        for chunk in &chunks {
            let bcs_size: usize = 3 + chunk
                .iter()
                .map(|e| uleb128_len(e.len()) + e.len())
                .sum::<usize>();
            assert!(bcs_size <= 4096, "chunk BCS size {bcs_size} > 4096");
        }
    }

    #[test]
    fn uleb128_len_values() {
        assert_eq!(uleb128_len(0), 1);
        assert_eq!(uleb128_len(64), 1);
        assert_eq!(uleb128_len(127), 1);
        assert_eq!(uleb128_len(128), 2);
        assert_eq!(uleb128_len(16383), 2);
        assert_eq!(uleb128_len(16384), 3);
    }
}
