//! Sui RPC client for interacting with the Hashi on-chain state
//!
//! This module provides a client for reading Hashi state and building transactions.
//! It leverages the `hashi` crate's `OnchainState` for reading and `SuiTxExecutor`
//! patterns for transaction execution.

use anyhow::Context;
use anyhow::Result;
use hashi::config::HashiIds;
use hashi::onchain::types::Proposal;
use hashi::onchain::types::ProposalType;
use sui_rpc::Client;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;

use crate::TxOptions;
use crate::config::Config;

/// Default gas budget when estimation fails or is not available
pub const DEFAULT_GAS_BUDGET: u64 = 10_000_000; // 0.01 SUI

/// Well-known Sui Clock object
const SUI_CLOCK_OBJECT_ID: Address = Address::from_static("0x6");

/// Client for interacting with Hashi on-chain state and executing transactions
pub struct HashiClient {
    #[allow(dead_code)] // Will be used for actual RPC calls
    client: Client,
    hashi_ids: HashiIds,
}

impl HashiClient {
    /// Create a new client
    pub async fn new(config: &Config) -> Result<Self> {
        config.validate()?;

        let client = Client::new(&config.sui_rpc_url).context("Failed to create Sui RPC client")?;

        let hashi_ids = HashiIds {
            package_id: config.package_id(),
            hashi_object_id: config.hashi_object_id(),
        };

        Ok(Self { client, hashi_ids })
    }

    /// Get the underlying RPC client
    #[allow(dead_code)]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Get the Hashi IDs
    #[allow(dead_code)]
    pub fn hashi_ids(&self) -> &HashiIds {
        &self.hashi_ids
    }

    // ========================================================================
    // Read operations
    // ========================================================================

    /// Fetch current epoch from on-chain state
    pub async fn fetch_epoch(&self) -> Result<u64> {
        // TODO: Implement using OnchainState patterns from hashi crate
        // For now, return placeholder
        tracing::debug!("Fetching current epoch");
        Ok(0)
    }

    /// Fetch all active proposals
    pub async fn fetch_proposals(&self) -> Result<Vec<Proposal>> {
        // TODO: Implement using OnchainState::scrape patterns
        // Would iterate over the proposals Bag and parse each one
        tracing::debug!("Fetching proposals from Hashi object");
        Ok(vec![])
    }

    /// Fetch a specific proposal by ID
    pub async fn fetch_proposal(&self, proposal_id: &Address) -> Result<Option<Proposal>> {
        // TODO: Implement by fetching the dynamic field from proposals Bag
        tracing::debug!("Fetching proposal {}", proposal_id.to_hex());
        Ok(Some(Proposal {
            id: *proposal_id,
            timestamp_ms: 0,
            proposal_type: ProposalType::Unknown("Fetching...".to_string()),
        }))
    }

    /// Fetch committee members for the specified epoch
    pub async fn fetch_committee(
        &self,
        epoch: Option<u64>,
    ) -> Result<Vec<hashi::onchain::types::MemberInfo>> {
        // TODO: Implement using OnchainState patterns
        tracing::debug!("Fetching committee for epoch {:?}", epoch);
        Ok(vec![])
    }

    // ========================================================================
    // Gas budget resolution
    // ========================================================================

    /// Resolve gas budget - either use provided value or estimate via dry-run
    pub async fn resolve_gas_budget(&self, tx_opts: &TxOptions) -> Result<u64> {
        match tx_opts.gas_budget {
            Some(budget) => {
                tracing::debug!("Using explicit gas budget: {} MIST", budget);
                Ok(budget)
            }
            None => {
                // The SuiTxExecutor/TransactionBuilder.build() handles gas estimation
                // automatically via dry-run. For display purposes, we show default.
                tracing::debug!(
                    "Gas budget will be estimated via dry-run (default: {} MIST)",
                    DEFAULT_GAS_BUDGET
                );
                Ok(DEFAULT_GAS_BUDGET)
            }
        }
    }

    // ========================================================================
    // Transaction builders (following SuiTxExecutor patterns)
    // ========================================================================

    /// Build a vote transaction
    ///
    /// Calls: `proposal::vote<T>(hashi, proposal_id, clock, ctx)`
    pub fn build_vote_transaction(
        &self,
        proposal_id: Address,
        proposal_type: &crate::ProposalType,
    ) -> Result<TransactionBuilder> {
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

        let type_tag = self.get_proposal_type_tag(proposal_type)?;

        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("proposal"),
                Identifier::from_static("vote"),
            )
            .with_type_args(vec![type_tag]),
            vec![hashi_arg, proposal_id_arg, clock_arg],
        );

        Ok(builder)
    }

    /// Build a remove_vote transaction
    ///
    /// Calls: `proposal::remove_vote<T>(hashi, proposal_id, ctx)`
    pub fn build_remove_vote_transaction(
        &self,
        proposal_id: Address,
        proposal_type: &crate::ProposalType,
    ) -> Result<TransactionBuilder> {
        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );
        let proposal_id_arg = builder.pure(&proposal_id);

        let type_tag = self.get_proposal_type_tag(proposal_type)?;

        builder.move_call(
            Function::new(
                self.hashi_ids.package_id,
                Identifier::from_static("proposal"),
                Identifier::from_static("remove_vote"),
            )
            .with_type_args(vec![type_tag]),
            vec![hashi_arg, proposal_id_arg],
        );

        Ok(builder)
    }

    /// Build a proposal creation transaction
    pub fn build_create_proposal_transaction(
        &self,
        proposal_type: CreateProposalParams,
    ) -> Result<TransactionBuilder> {
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

        // Empty metadata for now - could be extended
        let metadata_arg = builder.pure(&Vec::<(String, String)>::new());

        match proposal_type {
            CreateProposalParams::Upgrade { digest } => {
                let digest_arg = builder.pure(&digest);

                builder.move_call(
                    Function::new(
                        self.hashi_ids.package_id,
                        Identifier::from_static("upgrade"),
                        Identifier::from_static("propose"),
                    ),
                    vec![hashi_arg, digest_arg, metadata_arg, clock_arg],
                );
            }
            CreateProposalParams::UpdateDepositFee { fee } => {
                let fee_arg = builder.pure(&fee);

                builder.move_call(
                    Function::new(
                        self.hashi_ids.package_id,
                        Identifier::from_static("update_deposit_fee"),
                        Identifier::from_static("propose"),
                    ),
                    vec![hashi_arg, fee_arg, metadata_arg, clock_arg],
                );
            }
            CreateProposalParams::EnableVersion { version } => {
                let version_arg = builder.pure(&version);

                builder.move_call(
                    Function::new(
                        self.hashi_ids.package_id,
                        Identifier::from_static("enable_version"),
                        Identifier::from_static("propose"),
                    ),
                    vec![hashi_arg, version_arg, metadata_arg, clock_arg],
                );
            }
            CreateProposalParams::DisableVersion { version } => {
                let version_arg = builder.pure(&version);

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

        Ok(builder)
    }

    /// Get the TypeTag for a proposal type
    fn get_proposal_type_tag(
        &self,
        proposal_type: &crate::ProposalType,
    ) -> Result<sui_sdk_types::TypeTag> {
        use sui_sdk_types::StructTag;
        use sui_sdk_types::TypeTag;

        let (module, name) = match proposal_type {
            crate::ProposalType::Upgrade => ("upgrade", "Upgrade"),
            crate::ProposalType::UpdateDepositFee => ("update_deposit_fee", "UpdateDepositFee"),
            crate::ProposalType::EnableVersion => ("enable_version", "EnableVersion"),
            crate::ProposalType::DisableVersion => ("disable_version", "DisableVersion"),
        };

        Ok(TypeTag::Struct(Box::new(StructTag::new(
            self.hashi_ids.package_id,
            Identifier::new(module).context("Invalid module name")?,
            Identifier::new(name).context("Invalid type name")?,
            vec![],
        ))))
    }
}

/// Parameters for creating different types of proposals
#[derive(Debug)]
pub enum CreateProposalParams {
    Upgrade { digest: Vec<u8> },
    UpdateDepositFee { fee: u64 },
    EnableVersion { version: u64 },
    DisableVersion { version: u64 },
}
