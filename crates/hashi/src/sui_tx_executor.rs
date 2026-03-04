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

use fastcrypto::serde_helpers::ToFromByteArray;
use futures::TryStreamExt;
use hashi_types::committee::CommitteeSignature;
use hashi_types::committee::SignedMessage;
use hashi_types::move_types::DepositRequestedEvent;
use hashi_types::move_types::WithdrawalRequestedEvent;
use sui_crypto::SuiSigner;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionResponse;
use sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_sdk_types::Transaction;
use sui_sdk_types::bcs::FromBcs;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;
use sui_transaction_builder::intent::CoinWithBalance;

use crate::Hashi;
use crate::config::Config;
use crate::config::HashiIds;
use crate::mpc::types::CertificateV1;
use crate::onchain::OnchainState;
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

    /// Execute a withdrawal request transaction.
    ///
    /// Creates a withdrawal request on-chain by:
    /// 1. Using CoinWithBalance intent to select/merge BTC coins
    /// 2. Using CoinWithBalance intent for the SUI fee coin
    /// 3. Calling `withdraw::request_withdrawal`
    ///
    /// Returns the withdrawal request ID on success.
    pub async fn execute_create_withdrawal_request(
        &mut self,
        withdrawal_amount_sats: u64,
        destination_bytes: Vec<u8>,
        withdrawal_fee_sui: u64,
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

        // BTC coin via CoinWithBalance intent (replaces FundsWithdrawal)
        let btc_type = StructTag::new(
            self.hashi_ids.package_id,
            Identifier::from_static("btc"),
            Identifier::from_static("BTC"),
            vec![],
        );
        let btc_arg = builder.intent(CoinWithBalance::new(btc_type, withdrawal_amount_sats));

        // Pure inputs
        let destination_arg = builder.pure(&destination_bytes);

        // SUI fee coin via CoinWithBalance intent
        let fee_coin_arg = builder.intent(CoinWithBalance::sui(withdrawal_fee_sui));

        // Call withdraw::request_withdrawal(hashi, clock, btc, bitcoin_address, fee)
        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("withdraw"),
                Identifier::from_static("request_withdrawal"),
            ),
            vec![hashi_arg, clock_arg, btc_arg, destination_arg, fee_coin_arg],
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
                return Ok(event_data.request_id);
            }
        }

        anyhow::bail!("WithdrawalRequestedEvent not found in transaction events")
    }

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

    pub async fn execute_end_reconfig(
        &mut self,
        mpc_public_key: &[u8],
        signature: &[u8],
        signers_bitmap: &[u8],
    ) -> anyhow::Result<()> {
        let mut builder = TransactionBuilder::new();
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let mpc_public_key_arg = builder.pure(&mpc_public_key.to_vec());
        let signature_arg = builder.pure(&signature.to_vec());
        let signers_bitmap_arg = builder.pure(&signers_bitmap.to_vec());
        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("reconfig"),
                Identifier::from_static("end_reconfig"),
            ),
            vec![
                hashi_arg,
                mpc_public_key_arg,
                signature_arg,
                signers_bitmap_arg,
            ],
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

    /// Execute a validator registration transaction.
    ///
    /// This builds and executes a PTB that:
    /// 1. Calls `validator::register` with the BLS public key, proof-of-possession, and encryption key
    /// 2. Calls `validator::update_https_address` to set the validator's HTTPS endpoint
    /// 3. Calls `validator::update_tls_public_key` to set the validator's TLS key
    /// 4. Optionally calls `validator::update_operator_address` if an operator address is provided
    ///
    /// All required fields are read from the provided `Config`.
    pub async fn execute_register_validator(
        &mut self,
        config: &Config,
        operator_address: Option<Address>,
    ) -> anyhow::Result<()> {
        let transaction = build_register_validator_tx(
            &mut self.client,
            &self.hashi_ids,
            config,
            operator_address,
        )
        .await?;

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
        Ok(())
    }

    /// Execute a certificate submission transaction.
    ///
    /// This submits a DKG, rotation, or nonce generation certificate to the on-chain
    /// certificate store. The certificate contains the dealer's message hash and
    /// committee signature.
    pub async fn execute_submit_certificate(&mut self, cert: &CertificateV1) -> anyhow::Result<()> {
        let (inner_cert, function_name, batch_index) = match cert {
            CertificateV1::Dkg(c) => (c, "submit_dkg_cert", None),
            CertificateV1::Rotation(c) => (c, "submit_rotation_cert", None),
            CertificateV1::NonceGeneration { batch_index, cert } => {
                (cert, "submit_nonce_cert", Some(*batch_index))
            }
        };

        let message = inner_cert.message();
        let dealer = message.dealer_address;
        let message_hash = message.messages_hash.inner().to_vec();
        let epoch = inner_cert.epoch();
        let signature = inner_cert.signature_bytes().to_vec();
        let signers_bitmap = inner_cert.signers_bitmap_bytes().to_vec();

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
        let signature_arg = builder.pure(&signature);
        let signers_bitmap_arg = builder.pure(&signers_bitmap);
        args.extend([
            dealer_arg,
            message_hash_arg,
            signature_arg,
            signers_bitmap_arg,
        ]);
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
    pub async fn execute_approve_requests(
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
            let epoch_arg = builder.pure(&cert.epoch());
            let signature_arg = builder.pure(&cert.signature_bytes().to_vec());
            let signers_bitmap_arg = builder.pure(&cert.signers_bitmap_bytes().to_vec());

            builder.move_call(
                Function::new(
                    self.hashi_ids.package_id,
                    Identifier::from_static("withdraw"),
                    Identifier::from_static("approve_request"),
                ),
                vec![
                    hashi_arg,
                    request_id_arg,
                    epoch_arg,
                    signature_arg,
                    signers_bitmap_arg,
                ],
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
    ///
    /// The Move function expects:
    /// - `hashi: &mut Hashi`
    /// - `requests: vector<address>` — withdrawal request IDs
    /// - `selected_utxos: vector<vector<u8>>` — BCS-encoded `UtxoId`s
    /// - `outputs: vector<vector<u8>>` — BCS-encoded `OutputUtxo`s
    /// - `txid: address` — bitcoin transaction ID
    /// - `epoch, signature, signers_bitmap` — committee certificate
    /// - `clock: &Clock`
    /// - `r: &Random`
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

        let selected_utxos_bcs: Vec<Vec<u8>> = approval
            .selected_utxos
            .iter()
            .map(|utxo_id| bcs::to_bytes(utxo_id).unwrap())
            .collect();
        let selected_utxos_arg = builder.pure(&selected_utxos_bcs);

        let outputs_bcs: Vec<Vec<u8>> = approval
            .outputs
            .iter()
            .map(|output| bcs::to_bytes(output).unwrap())
            .collect();
        let outputs_arg = builder.pure(&outputs_bcs);

        let txid_arg = builder.pure(&approval.txid);
        let epoch_arg = builder.pure(&cert.epoch());
        let signers_bitmap_arg = builder.pure(&cert.signers_bitmap_bytes().to_vec());
        let signature_arg = builder.pure(&cert.signature_bytes().to_vec());

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
                epoch_arg,
                signature_arg,
                signers_bitmap_arg,
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
        let signatures_vec = signatures.to_vec();
        let signatures_arg = builder.pure(&signatures_vec);
        let epoch_arg = builder.pure(&cert.epoch());
        let signature_arg = builder.pure(&cert.signature_bytes().to_vec());
        let signers_bitmap_arg = builder.pure(&cert.signers_bitmap_bytes().to_vec());

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
                epoch_arg,
                signature_arg,
                signers_bitmap_arg,
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

    /// Execute `withdraw::confirm_withdrawal` to finalize a withdrawal on-chain.
    ///
    /// The Move function expects:
    /// - `hashi: &mut Hashi`
    /// - `withdrawal_id: address`
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
        let epoch_arg = builder.pure(&cert.epoch());
        let signature_arg = builder.pure(&cert.signature_bytes().to_vec());
        let signers_bitmap_arg = builder.pure(&cert.signers_bitmap_bytes().to_vec());

        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("withdraw"),
                Identifier::from_static("confirm_withdrawal"),
            ),
            vec![
                hashi_arg,
                withdrawal_id_arg,
                epoch_arg,
                signature_arg,
                signers_bitmap_arg,
            ],
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

/// Build a validator registration transaction without signing or executing it.
///
/// This builds a PTB that:
/// 1. Calls `validator::register` with the BLS public key, proof-of-possession, and encryption key
/// 2. Calls `validator::update_https_address` to set the validator's HTTPS endpoint
/// 3. Calls `validator::update_tls_public_key` to set the validator's TLS key
/// 4. Optionally calls `validator::update_operator_address` if an operator address is provided
///
/// The sender is set to `config.validator_address()`. The returned `Transaction` is
/// finalized (dry-run, gas estimation, object resolution) but unsigned.
pub async fn build_register_validator_tx(
    client: &mut Client,
    hashi_ids: &HashiIds,
    config: &Config,
    operator_address: Option<Address>,
) -> anyhow::Result<Transaction> {
    let protocol_key = config
        .protocol_private_key()
        .ok_or_else(|| anyhow::anyhow!("no protocol_private_key configured"))?;
    let protocol_public_key = protocol_key.public_key();
    let encryption_public_key = config.encryption_public_key()?;
    let validator_address = config.validator_address()?;
    let endpoint_url = config.endpoint_url().map(|s| s.to_string());
    let tls_key = config.tls_public_key()?;

    // Fetch current Sui epoch for proof-of-possession
    let service_info = client
        .clone()
        .ledger_client()
        .get_service_info(GetServiceInfoRequest::default())
        .await?
        .into_inner();
    let current_epoch = service_info.epoch.unwrap_or(0);

    // Compute proof-of-possession
    let pop = protocol_key.proof_of_possession(current_epoch, validator_address);

    let mut builder = TransactionBuilder::new();

    let hashi_arg = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    let sui_system_arg = builder.object(
        ObjectInput::new(SUI_SYSTEM_STATE_OBJECT_ID)
            .as_shared()
            .with_mutable(false),
    );

    let public_key_arg = builder.pure(&protocol_public_key.as_ref().to_vec());
    let pop_signature_arg = builder.pure(&pop.signature().as_ref().to_vec());
    let encryption_key_arg = builder.pure(
        &encryption_public_key
            .as_element()
            .to_byte_array()
            .as_slice()
            .to_vec(),
    );
    let validator_address_arg = builder.pure(&validator_address);
    let tls_key_arg = builder.pure(&tls_key.as_bytes().to_vec());

    // 1. validator::register(hashi, sui_system, public_key, pop_signature, encryption_public_key)
    builder.move_call(
        Function::new(
            hashi_ids.package_id,
            Identifier::from_static("validator"),
            Identifier::from_static("register"),
        ),
        vec![
            hashi_arg,
            sui_system_arg,
            public_key_arg,
            pop_signature_arg,
            encryption_key_arg,
        ],
    );

    // 2. validator::update_https_address(hashi, validator_address, endpoint_url)
    if let Some(url) = &endpoint_url {
        let endpoint_url_arg = builder.pure(url);
        builder.move_call(
            Function::new(
                hashi_ids.package_id,
                Identifier::from_static("validator"),
                Identifier::from_static("update_https_address"),
            ),
            vec![hashi_arg, validator_address_arg, endpoint_url_arg],
        );
    }

    // 3. validator::update_tls_public_key(hashi, validator_address, tls_key)
    builder.move_call(
        Function::new(
            hashi_ids.package_id,
            Identifier::from_static("validator"),
            Identifier::from_static("update_tls_public_key"),
        ),
        vec![hashi_arg, validator_address_arg, tls_key_arg],
    );

    // 4. Optionally update_operator_address(hashi, validator_address, operator_address)
    if let Some(operator) = operator_address {
        let operator_arg = builder.pure(&operator);
        builder.move_call(
            Function::new(
                hashi_ids.package_id,
                Identifier::from_static("validator"),
                Identifier::from_static("update_operator_address"),
            ),
            vec![hashi_arg, validator_address_arg, operator_arg],
        );
    }

    builder.set_sender(validator_address);
    let transaction = builder.build(client).await?;

    Ok(transaction)
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
