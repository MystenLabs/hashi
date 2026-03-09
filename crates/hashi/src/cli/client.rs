//! Sui RPC client for interacting with the Hashi on-chain state
//!
//! This module provides a client for reading Hashi state and building/executing
//! proposal-related transactions.
//!
//! Uses `OnchainState` from the hashi crate for reading on-chain data,
//! and `SuiTxExecutor` for transaction execution when a keypair is configured.

use crate::config::HashiIds;
use crate::onchain::OnchainState;
use crate::onchain::types::MemberInfo;
use crate::onchain::types::Proposal;
use crate::sui_tx_executor::SUI_CLOCK_OBJECT_ID;
use crate::sui_tx_executor::SuiTxExecutor;
use anyhow::Context;
use anyhow::Result;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionResponse;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;

use super::config::CliConfig;

/// Parameters for creating different types of proposals
#[derive(Debug, Clone)]
pub enum CreateProposalParams {
    Upgrade {
        digest: Vec<u8>,
        metadata: Vec<(String, String)>,
    },
    UpdateDepositFee {
        fee: u64,
        metadata: Vec<(String, String)>,
    },
    EnableVersion {
        version: u64,
        metadata: Vec<(String, String)>,
    },
    DisableVersion {
        version: u64,
        metadata: Vec<(String, String)>,
    },
}

/// Result of a transaction simulation (dry-run)
#[derive(Debug)]
pub struct SimulationResult {
    /// The sender address that would execute the transaction
    pub sender: Address,
    /// Estimated gas budget (in MIST)
    pub gas_budget: u64,
    /// Gas price (in MIST per unit)
    pub gas_price: u64,
}

/// Client for reading Hashi on-chain state and building/executing transactions.
///
/// Uses `OnchainState` for reading on-chain data (committees, proposals, etc.)
/// and `SuiTxExecutor` for transaction execution when a keypair is configured.
pub struct HashiClient {
    /// On-chain state reader from hashi crate
    onchain_state: OnchainState,
    /// Hashi package and object IDs
    hashi_ids: HashiIds,
    /// Optional executor for signing and submitting transactions
    executor: Option<SuiTxExecutor>,
}

impl HashiClient {
    /// Create a new client
    ///
    /// This scrapes the current on-chain state and optionally sets up
    /// transaction execution if a keypair is configured.
    pub async fn new(config: &CliConfig) -> Result<Self> {
        config.validate()?;

        let hashi_ids = HashiIds {
            package_id: config.package_id(),
            hashi_object_id: config.hashi_object_id(),
        };

        // Create OnchainState which scrapes the current state.
        // Dropping the service immediately aborts the background watcher task, so the
        // OnchainState will have the initial scraped state but won't receive live updates.
        // This is fine for CLI commands for now.
        let (onchain_state, _service) =
            OnchainState::new(&config.sui_rpc_url, hashi_ids, None, None)
                .await
                .context("Failed to initialize on-chain state")?;

        // Try to create executor if keypair is available
        let executor = match config.load_keypair()? {
            Some(signer) => {
                tracing::debug!("Keypair loaded, transaction execution enabled");
                Some(SuiTxExecutor::new(
                    onchain_state.client(),
                    signer,
                    hashi_ids,
                ))
            }
            None => {
                tracing::debug!("No keypair configured, transaction execution disabled");
                None
            }
        };

        Ok(Self {
            onchain_state,
            hashi_ids,
            executor,
        })
    }

    /// Get the Hashi IDs
    pub fn hashi_ids(&self) -> &HashiIds {
        &self.hashi_ids
    }

    /// Check if transaction execution is available (keypair is configured)
    pub fn can_execute(&self) -> bool {
        self.executor.is_some()
    }

    /// Execute a transaction built with `TransactionBuilder`.
    ///
    /// Returns an error if no keypair is configured.
    pub async fn execute(
        &mut self,
        builder: TransactionBuilder,
    ) -> Result<ExecuteTransactionResponse> {
        let executor = self
            .executor
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Cannot execute transactions: no keypair configured"))?;

        executor.execute(builder).await
    }

    /// Simulate a transaction (dry-run) without executing it.
    ///
    /// Returns the estimated gas budget on success.
    /// This performs the same steps as execute but stops before signing/submitting.
    pub async fn simulate(&mut self, mut builder: TransactionBuilder) -> Result<SimulationResult> {
        let executor = self.executor.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Cannot simulate transactions: no keypair configured")
        })?;

        let sender = executor.sender();
        builder.set_sender(sender);

        // Build the transaction - this internally does a dry-run for gas estimation
        let transaction = builder.build(&mut self.onchain_state.client()).await?;

        Ok(SimulationResult {
            sender,
            gas_budget: transaction.gas_payment.budget,
            gas_price: transaction.gas_payment.price,
        })
    }

    // ========================================================================
    // Read operations (delegating to OnchainState)
    // ========================================================================

    /// Fetch current epoch from on-chain state
    pub fn fetch_epoch(&self) -> u64 {
        self.onchain_state.epoch()
    }

    /// Fetch all active proposals
    pub fn fetch_proposals(&self) -> Vec<Proposal> {
        self.onchain_state.proposals()
    }

    /// Fetch a specific proposal by ID
    pub fn fetch_proposal(&self, proposal_id: &Address) -> Option<Proposal> {
        self.onchain_state.proposal(proposal_id)
    }

    /// Fetch committee members for the current epoch
    pub fn fetch_committee_members(&self) -> Vec<MemberInfo> {
        self.onchain_state.committee_members()
    }

    /// Fetch the MPC public key bytes from on-chain state
    pub fn fetch_mpc_public_key(&self) -> Vec<u8> {
        self.onchain_state.mpc_public_key()
    }

    /// Fetch pending deposit requests
    pub fn fetch_deposit_requests(&self) -> Vec<crate::onchain::types::DepositRequest> {
        self.onchain_state.deposit_requests()
    }

    /// Fetch pending withdrawal requests
    pub fn fetch_withdrawal_requests(&self) -> Vec<crate::onchain::types::WithdrawalRequest> {
        self.onchain_state.withdrawal_requests()
    }

    /// Fetch committed/signed withdrawals
    pub fn fetch_pending_withdrawals(&self) -> Vec<crate::onchain::types::PendingWithdrawal> {
        self.onchain_state.pending_withdrawals()
    }

    /// Fetch the withdrawal fee in SUI
    pub fn fetch_withdrawal_fee_sui(&self) -> u64 {
        self.onchain_state.withdrawal_fee_sui()
    }

    // ========================================================================
    // Transaction builders (proposal/governance)
    // ========================================================================

    /// Build a vote transaction for a proposal.
    ///
    /// Calls: `proposal::vote<T>(hashi, proposal_id, clock, ctx)`
    pub fn build_vote_transaction(
        &self,
        proposal_id: Address,
        type_arg: TypeTag,
    ) -> TransactionBuilder {
        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let proposal_id_arg = builder.pure(&proposal_id);
        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .as_shared()
                .with_mutable(false),
        );

        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("proposal"),
                Identifier::from_static("vote"),
            )
            .with_type_args(vec![type_arg]),
            vec![hashi_arg, proposal_id_arg, clock_arg],
        );

        builder
    }

    /// Build a remove_vote transaction for a proposal.
    ///
    /// Calls: `proposal::remove_vote<T>(hashi, proposal_id, ctx)`
    pub fn build_remove_vote_transaction(
        &self,
        proposal_id: Address,
        type_arg: TypeTag,
    ) -> TransactionBuilder {
        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let proposal_id_arg = builder.pure(&proposal_id);

        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("proposal"),
                Identifier::from_static("remove_vote"),
            )
            .with_type_args(vec![type_arg]),
            vec![hashi_arg, proposal_id_arg],
        );

        builder
    }

    /// Build a proposal creation transaction.
    pub fn build_create_proposal_transaction(
        &self,
        params: CreateProposalParams,
    ) -> TransactionBuilder {
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

        match params {
            CreateProposalParams::Upgrade { digest, metadata } => {
                let digest_arg = builder.pure(&digest);
                let metadata_arg = builder.pure(&metadata);
                builder.move_call(
                    Function::new(
                        self.hashi_ids.package_id,
                        Identifier::from_static("upgrade"),
                        Identifier::from_static("propose"),
                    ),
                    vec![hashi_arg, digest_arg, metadata_arg, clock_arg],
                );
            }
            CreateProposalParams::UpdateDepositFee { fee, metadata } => {
                let fee_arg = builder.pure(&fee);
                let metadata_arg = builder.pure(&metadata);
                builder.move_call(
                    Function::new(
                        self.hashi_ids.package_id,
                        Identifier::from_static("update_deposit_fee"),
                        Identifier::from_static("propose"),
                    ),
                    vec![hashi_arg, fee_arg, metadata_arg, clock_arg],
                );
            }
            CreateProposalParams::EnableVersion { version, metadata } => {
                let version_arg = builder.pure(&version);
                let metadata_arg = builder.pure(&metadata);
                builder.move_call(
                    Function::new(
                        self.hashi_ids.package_id,
                        Identifier::from_static("enable_version"),
                        Identifier::from_static("propose"),
                    ),
                    vec![hashi_arg, version_arg, metadata_arg, clock_arg],
                );
            }
            CreateProposalParams::DisableVersion { version, metadata } => {
                let version_arg = builder.pure(&version);
                let metadata_arg = builder.pure(&metadata);
                builder.move_call(
                    Function::new(
                        self.hashi_ids.package_id,
                        Identifier::from_static("disable_version"),
                        Identifier::from_static("propose"),
                    ),
                    vec![hashi_arg, version_arg, metadata_arg, clock_arg],
                );
            }
        }

        builder
    }
}

/// Get the TypeTag for a proposal type (from on-chain type)
///
/// Returns an error if the proposal type is `Unknown`.
pub fn get_proposal_type_arg(
    package_id: Address,
    proposal_type: &crate::onchain::types::ProposalType,
) -> Result<TypeTag> {
    use crate::onchain::types::ProposalType;

    let (module, name) = match proposal_type {
        ProposalType::Upgrade => ("upgrade", "Upgrade"),
        ProposalType::UpdateDepositFee => ("update_deposit_fee", "UpdateDepositFee"),
        ProposalType::EnableVersion => ("enable_version", "EnableVersion"),
        ProposalType::DisableVersion => ("disable_version", "DisableVersion"),
        ProposalType::Unknown(s) => {
            anyhow::bail!(
                "Cannot vote on unknown proposal type '{}'. \
                 This may be a new proposal type not yet supported by this CLI version.",
                s
            );
        }
    };

    Ok(TypeTag::Struct(Box::new(StructTag::new(
        package_id,
        Identifier::new(module).context("Invalid module name")?,
        Identifier::new(name).context("Invalid type name")?,
        vec![],
    ))))
}
