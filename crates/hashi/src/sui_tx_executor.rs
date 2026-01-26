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
//! executor.execute_confirm_deposit(&deposit_request, signed_message).await?;
//!
//! // Or build custom transactions
//! let mut builder = TransactionBuilder::new();
//! // ... add inputs and move calls ...
//! let response = executor.execute(builder).await?;
//! ```

use std::sync::Arc;
use std::time::Duration;

use hashi_types::committee::SignedMessage;
use hashi_types::move_types::DepositRequestedEvent;
use sui_crypto::SuiSigner;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionResponse;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::bcs::FromBcs;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;

use crate::Hashi;
use crate::config::Config;
use crate::config::HashiIds;
use crate::dkg::types::CertificateV1;
use crate::onchain::OnchainState;
use crate::onchain::types::DepositRequest;

const DEFAULT_TIMEOUT_SECS: u64 = 10;
const SUI_CLOCK_OBJECT_ID: Address = Address::from_static("0x6");

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

        Ok(response)
    }

    // ========================================================================
    // Domain-specific execution methods
    // ========================================================================

    /// Execute a deposit confirmation transaction.
    ///
    /// This builds and executes a PTB that:
    /// 1. Calls `committee::new_committee_signature` to construct the CommitteeSignature
    /// 2. Calls `deposit::confirm_deposit` with the Hashi object, request ID, and signature
    pub async fn execute_confirm_deposit(
        &mut self,
        deposit_request: &DepositRequest,
        signed_message: SignedMessage<DepositRequest>,
    ) -> anyhow::Result<()> {
        let committee_sig = signed_message.committee_signature();

        // Build a PTB that:
        // 1. Calls committee::new_committee_signature to construct the CommitteeSignature
        // 2. Passes the result to deposit::confirm_deposit
        let mut builder = TransactionBuilder::new();

        let request_id_arg = builder.pure(&deposit_request.id);
        let epoch_arg = builder.pure(&committee_sig.epoch());
        let signature_arg = builder.pure(&committee_sig.signature_bytes());
        let bitmap_arg = builder.pure(&committee_sig.signers_bitmap_bytes());

        // Call new_committee_signature to get the properly serialized CommitteeSignature
        let committee_sig_arg = builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("committee"),
                Identifier::from_static("new_committee_signature"),
            ),
            vec![epoch_arg, signature_arg, bitmap_arg],
        );

        // Call confirm deposit - server will resolve the shared object version
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("deposit"),
                Identifier::from_static("confirm_deposit"),
            ),
            vec![hashi_arg, request_id_arg, committee_sig_arg],
        );

        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "Transaction failed to confirm deposit for request {:?}",
                deposit_request.id
            );
        }
        Ok(())
    }

    /// Execute a batch deletion of expired deposit requests.
    ///
    /// This builds and executes a PTB that calls `deposit::delete_expired_deposit`
    /// for each expired request in the batch.
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
    /// 2. Creating a DepositRequest using the Clock
    /// 3. Splitting SUI for the deposit fee
    /// 4. Calling the deposit() function on Hashi
    ///
    /// Returns the deposit request ID on success.
    ///
    /// Note: The `txid` parameter should be the Bitcoin transaction ID converted to a Sui Address
    /// (i.e., the 32-byte txid interpreted as a Sui address).
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

        // 3. Create DepositRequest: deposit_queue::deposit_request(utxo, clock)
        let deposit_request_arg = builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("deposit_queue"),
                Identifier::from_static("deposit_request"),
            ),
            vec![utxo_arg, clock_arg],
        );

        // 4. Split zero SUI for fee coin
        let zero_arg = builder.pure(&0u64);
        let gas_arg = builder.gas();
        let fee_coins = builder.split_coins(gas_arg, vec![zero_arg]);
        let fee_coin_arg = fee_coins.into_iter().next().unwrap();

        // 5. Call deposit(hashi, request, fee)
        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("deposit"),
                Identifier::from_static("deposit"),
            ),
            vec![hashi_arg, deposit_request_arg, fee_coin_arg],
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

    /// Execute a DKG certificate submission transaction.
    ///
    /// This submits a DKG certificate to the on-chain certificate store.
    /// The certificate contains the dealer's message hash and committee signature.
    pub async fn execute_submit_dkg_certificate(
        &mut self,
        cert: &CertificateV1,
    ) -> anyhow::Result<()> {
        let CertificateV1::Dkg(dkg_cert) = cert else {
            anyhow::bail!("Rotation certificates not supported yet");
        };

        let message = dkg_cert.message();
        let dealer = message.dealer_address;
        let message_hash = message.message_hash.inner().to_vec();
        let epoch = dkg_cert.epoch();
        let signature = dkg_cert.signature_bytes().to_vec();
        let signers_bitmap = dkg_cert.signers_bitmap_bytes().to_vec();

        let mut builder = TransactionBuilder::new();

        // Build inputs for the move call - server will resolve shared object version
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let epoch_arg = builder.pure(&epoch);
        let dealer_arg = builder.pure(&dealer);
        let message_hash_arg = builder.pure(&message_hash);
        let signature_arg = builder.pure(&signature);
        let signers_bitmap_arg = builder.pure(&signers_bitmap);

        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("cert_submission"),
                Identifier::from_static("submit_dkg_cert"),
            ),
            vec![
                hashi_arg,
                epoch_arg,
                dealer_arg,
                message_hash_arg,
                signature_arg,
                signers_bitmap_arg,
            ],
        );

        let response = self.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!(
                "DKG certificate submission failed: {:?}",
                response.transaction().effects().status()
            );
        }
        Ok(())
    }
}
