// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sui RPC client for interacting with the Hashi on-chain state
//!
//! This module provides a client for reading Hashi state and building/executing
//! proposal-related transactions.
//!
//! Uses `OnchainState` from the hashi crate for reading on-chain data,
//! and `SuiTxExecutor` for transaction execution when a keypair is configured.

use crate::config::HashiIds;
use crate::onchain::OnchainState;
use crate::onchain::ScrapeScope;
use crate::onchain::types::MemberInfo;
use crate::onchain::types::Proposal;
use crate::sui_tx_executor::SUI_CLOCK_OBJECT_ID;
use crate::sui_tx_executor::SuiTxExecutor;
use anyhow::Context;
use anyhow::Result;
use hashi_types::move_types::ConfigValue;
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
        exclusive: bool,
        metadata: Vec<(String, String)>,
    },
    UpdateConfig {
        key: String,
        value: hashi_types::move_types::ConfigValue,
        metadata: Vec<(String, String)>,
    },
    /// Update an existing key in the epoch config.
    UpdateEpochConfig {
        key: String,
        value: hashi_types::move_types::ConfigValue,
        metadata: Vec<(String, String)>,
    },
    /// Add a new key to the epoch (`epoch: true`) or instant config.
    AddConfig {
        epoch: bool,
        key: String,
        value: hashi_types::move_types::ConfigValue,
        metadata: Vec<(String, String)>,
    },
    UpdateMpcConfig {
        max_faulty_bps: Option<u64>,
        weight_reduction_allowed_delta: Option<u64>,
        nonce_generation_protocol: Option<u64>,
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
    AbortReconfig {
        epoch: u64,
        metadata: Vec<(String, String)>,
    },
    UpdateGuardian {
        url: String,
        metadata: Vec<(String, String)>,
    },
    EmergencyPause {
        /// `true` proposes a pause; `false` proposes an unpause.
        pause: bool,
        metadata: Vec<(String, String)>,
    },
    IgnoreMember {
        target_validator_address: Address,
        /// `true` proposes ignoring the member; `false` proposes re-admitting.
        ignored: bool,
        metadata: Vec<(String, String)>,
    },
}

/// Live on-chain proposal detail fields not cached by `OnchainState`.
#[derive(Debug)]
pub struct ProposalDetails {
    pub creator: Address,
    pub votes: Vec<Address>,
    pub quorum_threshold_bps: u64,
    pub metadata: hashi_types::move_types::VecMap<String, String>,
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
    /// The Hashi shared object's initial shared version, fetched once at
    /// construction. Immutable for the object's lifetime, and needed to
    /// build fully-resolved shared inputs (see
    /// [`build_create_proposal_transaction`]).
    hashi_initial_shared_version: u64,
    /// `--sender`, when given: the identity governance commands act as when
    /// there is no keypair to derive one from.
    acting_sender: Option<Address>,
    /// Optional executor for signing and submitting transactions
    executor: Option<SuiTxExecutor>,
    /// The RPC endpoint this client talks to (used for explorer deep-links)
    sui_rpc_url: String,
}

/// Fetch a shared object's initial shared version from its owner field.
///
/// Needed to build fully-resolved shared inputs: pre-resolving a shared input's
/// initial version + mutability keeps sui >= 1.76 fullnodes from having to
/// inspect an upgrade-introduced module's signature at simulate time (that
/// inspection fails with `INVALID_LINKAGE`).
pub async fn fetch_initial_shared_version(
    client: &mut sui_rpc::Client,
    object_id: Address,
) -> Result<u64> {
    use sui_rpc::field::FieldMask;
    use sui_rpc::field::FieldMaskUtil;
    use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;

    let response = client
        .ledger_client()
        .get_object(
            GetObjectRequest::new(&object_id).with_read_mask(FieldMask::from_paths(["owner"])),
        )
        .await
        .with_context(|| format!("fetching owner of shared object {object_id}"))?
        .into_inner();
    Ok(response.object().owner().version())
}

/// Which on-chain proposal bag holds a proposal. Executed proposals are not
/// deleted: `proposal::execute` moves them from the active bag to the
/// executed bag, where they stay for inspection, so a lookup that only asks
/// "does it exist" cannot tell an open proposal from a finished one.
#[derive(Clone, Debug)]
pub enum ProposalLocation {
    Active(Proposal),
    Executed(Proposal),
    /// In neither bag: the id is wrong, or the proposal expired and was
    /// deleted.
    Missing,
}

/// Locate `proposal_id` in the scraped active and executed bags.
pub fn locate_proposal(
    active: &[Proposal],
    executed: &[Proposal],
    proposal_id: &Address,
) -> ProposalLocation {
    if let Some(proposal) = active.iter().find(|p| p.id == *proposal_id) {
        return ProposalLocation::Active(proposal.clone());
    }
    if let Some(proposal) = executed.iter().find(|p| p.id == *proposal_id) {
        return ProposalLocation::Executed(proposal.clone());
    }
    ProposalLocation::Missing
}

/// A gRPC `NotFound` while loading the Hashi object almost always means the
/// configured ids and the RPC URL come from different networks; say so instead
/// of surfacing the bare status.
pub fn explain_missing_object(
    err: anyhow::Error,
    hashi_ids: HashiIds,
    sui_rpc_url: &str,
) -> anyhow::Error {
    let not_found = err.chain().any(|e| {
        matches!(e.downcast_ref::<tonic::Status>(), Some(s) if s.code() == tonic::Code::NotFound)
    });
    if not_found {
        err.context(format!(
            "Hashi object {} (package {}) was not found on {sui_rpc_url}: check that package-id, \
             hashi-object-id and the RPC URL all belong to the same network",
            hashi_ids.hashi_object_id, hashi_ids.package_id
        ))
    } else {
        err
    }
}

impl HashiClient {
    /// Client for governance and config commands. Skips the Bitcoin
    /// collections, which none of them read.
    pub async fn new(config: &CliConfig) -> Result<Self> {
        Self::with_scope(config, ScrapeScope::GovernanceOnly).await
    }

    /// Client that also loads the Bitcoin collections. Much slower — only for
    /// commands that read them.
    pub async fn new_with_bitcoin_state(config: &CliConfig) -> Result<Self> {
        Self::with_scope(config, ScrapeScope::Full).await
    }

    async fn with_scope(config: &CliConfig, scope: ScrapeScope) -> Result<Self> {
        config.validate()?;

        let hashi_ids = HashiIds {
            package_id: config.package_id(),
            hashi_object_id: config.hashi_object_id(),
        };

        // Say which network every command is talking to: the RPC URL defaults
        // to mainnet when no config is found, and a wrong-network object id is
        // otherwise indistinguishable from a typo.
        crate::cli::print_info(&format!("Sui RPC: {}", config.sui_rpc_url));

        let onchain_state = OnchainState::new_reader(
            &config.sui_rpc_url,
            hashi_ids,
            Some(crate::config::DEFAULT_GRPC_MAX_DECODING_MESSAGE_SIZE),
            scope,
        )
        .await
        .map_err(|e| explain_missing_object(e, hashi_ids, &config.sui_rpc_url))
        .context("Failed to initialize on-chain state")?;

        let hashi_initial_shared_version =
            fetch_initial_shared_version(&mut onchain_state.client(), hashi_ids.hashi_object_id)
                .await
                .map_err(|e| explain_missing_object(e, hashi_ids, &config.sui_rpc_url))?;

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
            hashi_initial_shared_version,
            acting_sender: config.acting_sender,
            executor,
            sui_rpc_url: config.sui_rpc_url.clone(),
        })
    }

    /// `OnchainState`'s Bitcoin accessors panic on a governance-only scrape;
    /// surface that as a CLI error instead.
    fn require_bitcoin_state(&self) -> Result<()> {
        anyhow::ensure!(
            self.onchain_state.state().hashi().try_bitcoin().is_some(),
            "this command needs Bitcoin state; build the client with \
             HashiClient::new_with_bitcoin_state",
        );
        Ok(())
    }

    /// Get the Hashi IDs
    pub fn hashi_ids(&self) -> &HashiIds {
        &self.hashi_ids
    }

    /// The RPC endpoint this client talks to
    pub fn sui_rpc_url(&self) -> &str {
        &self.sui_rpc_url
    }

    /// Check if transaction execution is available (keypair is configured)
    pub fn can_execute(&self) -> bool {
        self.executor.is_some()
    }

    /// Finalize `builder` according to `tx_opts`: serialize it unsigned,
    /// dry-run it, or sign and submit it.
    ///
    /// A keypair is required only for [`TxMode::Execute`](crate::sui_tx_executor::TxMode);
    /// the serialize and dry-run paths build with just the sender address
    /// (explicit `--sender`, or the keypair's address when one is configured).
    pub async fn finalize_tx(
        &self,
        builder: TransactionBuilder,
        tx_opts: &crate::cli::TxOptions,
    ) -> Result<crate::sui_tx_executor::TxOutcome> {
        let signer = self.executor.as_ref().map(|e| e.signer());
        let mut client = self.onchain_state.client();
        crate::sui_tx_executor::finalize(
            &mut client,
            signer,
            builder,
            tx_opts.sender,
            &tx_opts.gas_overrides(),
            tx_opts.mode(),
            std::time::Duration::from_secs(10),
        )
        .await
        .map_err(crate::cli::explain_tx_error)
    }

    // ========================================================================
    // Read operations (delegating to OnchainState)
    // ========================================================================

    /// Highest package version currently known on-chain, i.e. the version of
    /// the latest published upgrade (or the original package before any
    /// upgrade). Returns `None` only if the state hasn't been scraped yet,
    /// which shouldn't happen after `HashiClient::new`.
    pub fn highest_package_version(&self) -> Option<u64> {
        self.onchain_state
            .state()
            .package_versions()
            .latest_version()
    }

    /// The latest published package id. Transactions whose type args may name an
    /// upgrade-introduced type must be called through the latest package (v1-era
    /// type args unify fine under a newer call, but not vice versa).
    pub fn latest_package_id(&self) -> anyhow::Result<Address> {
        self.onchain_state
            .package_id()
            .context("no package versions known on-chain")
    }

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

    /// Fetch all executed (archived) proposals
    pub fn fetch_executed_proposals(&self) -> Vec<Proposal> {
        self.onchain_state.executed_proposals()
    }

    /// Where `proposal_id` sits in the two on-chain proposal bags, as of the
    /// scrape this client was built from.
    pub fn locate_proposal(&self, proposal_id: &Address) -> ProposalLocation {
        locate_proposal(
            &self.fetch_proposals(),
            &self.fetch_executed_proposals(),
            proposal_id,
        )
    }

    /// Fetch committee members for the current epoch
    pub fn fetch_committee_members(&self) -> Vec<MemberInfo> {
        self.onchain_state.committee_members()
    }

    /// Fetch the current `Committee` (with weights). Returns `None` before DKG.
    pub fn fetch_current_committee(&self) -> Option<hashi_types::committee::Committee> {
        self.onchain_state.current_committee()
    }

    /// Live-fetch the full on-chain `Proposal<T>` (votes + quorum threshold +
    /// metadata) for a specific proposal via one `list_dynamic_fields` call on
    /// the proposals bag. Separate from the cached `fetch_proposal` because
    /// validators don't need these fields in their in-memory state.
    ///
    /// The proposal type is derived from the matched child object's
    /// `object_type` — callers don't pass it, so they can't pass the wrong one.
    pub async fn fetch_proposal_details(&self, proposal_id: Address) -> Result<ProposalDetails> {
        use crate::onchain::parse_proposal_type;
        use crate::onchain::types::ProposalType;
        use futures::TryStreamExt;
        use hashi_types::move_types;
        use sui_rpc::field::FieldMask;
        use sui_rpc::field::FieldMaskUtil;
        use sui_rpc::proto::sui::rpc::v2::DynamicField;
        use sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsRequest;

        // The proposal could live in either the active or executed bag.
        // Walk active first (the common case), then executed.
        let (active_id, executed_id) = {
            let state = self.onchain_state.state();
            let proposals = &state.hashi().proposals;
            (proposals.active_id(), proposals.executed_id())
        };
        let client = self.onchain_state.client();

        for bag_id in [active_id, executed_id] {
            let mut stream = Box::pin(
                client.list_dynamic_fields(
                    ListDynamicFieldsRequest::default()
                        .with_parent(bag_id)
                        .with_page_size(u32::MAX)
                        .with_read_mask(FieldMask::from_paths([
                            DynamicField::path_builder().name().finish(),
                            DynamicField::path_builder().child_object().object_type(),
                            DynamicField::path_builder()
                                .child_object()
                                .contents()
                                .finish(),
                        ])),
                ),
            );

            while let Some(field) = stream.try_next().await? {
                // The bag key is BCS-encoded `ID`, which is equivalent to `Address`.
                let Ok(key) = bcs::from_bytes::<Address>(field.name().value()) else {
                    continue;
                };
                if key != proposal_id {
                    continue;
                }

                let object_type_str = field.child_object().object_type();
                let type_tag: TypeTag = object_type_str
                    .parse()
                    .with_context(|| format!("parse object_type {object_type_str:?}"))?;
                let proposal_type = parse_proposal_type(&type_tag);

                let value_bytes = field.child_object().contents().value();
                let (creator, votes, quorum_threshold_bps, metadata) = match proposal_type {
                    ProposalType::UpdateConfig => {
                        let p: move_types::Proposal<move_types::UpdateConfig> =
                            bcs::from_bytes(value_bytes).context("deserialize UpdateConfig")?;
                        (p.creator, p.votes, p.quorum_threshold_bps, p.metadata)
                    }
                    ProposalType::UpdateEpochConfig => {
                        let p: move_types::Proposal<move_types::UpdateEpochConfig> =
                            bcs::from_bytes(value_bytes)
                                .context("deserialize UpdateEpochConfig")?;
                        (p.creator, p.votes, p.quorum_threshold_bps, p.metadata)
                    }
                    ProposalType::AddConfig => {
                        let p: move_types::Proposal<move_types::AddConfig> =
                            bcs::from_bytes(value_bytes).context("deserialize AddConfig")?;
                        (p.creator, p.votes, p.quorum_threshold_bps, p.metadata)
                    }
                    ProposalType::EnableVersion => {
                        let p: move_types::Proposal<move_types::EnableVersion> =
                            bcs::from_bytes(value_bytes).context("deserialize EnableVersion")?;
                        (p.creator, p.votes, p.quorum_threshold_bps, p.metadata)
                    }
                    ProposalType::DisableVersion => {
                        let p: move_types::Proposal<move_types::DisableVersion> =
                            bcs::from_bytes(value_bytes).context("deserialize DisableVersion")?;
                        (p.creator, p.votes, p.quorum_threshold_bps, p.metadata)
                    }
                    ProposalType::Upgrade => {
                        let p: move_types::Proposal<move_types::Upgrade> =
                            bcs::from_bytes(value_bytes).context("deserialize Upgrade")?;
                        (p.creator, p.votes, p.quorum_threshold_bps, p.metadata)
                    }
                    ProposalType::EmergencyPause => {
                        let p: move_types::Proposal<move_types::EmergencyPause> =
                            bcs::from_bytes(value_bytes).context("deserialize EmergencyPause")?;
                        (p.creator, p.votes, p.quorum_threshold_bps, p.metadata)
                    }
                    ProposalType::AbortReconfig => {
                        let p: move_types::Proposal<move_types::AbortReconfig> =
                            bcs::from_bytes(value_bytes).context("deserialize AbortReconfig")?;
                        (p.creator, p.votes, p.quorum_threshold_bps, p.metadata)
                    }
                    ProposalType::UpdateGuardian => {
                        let p: move_types::Proposal<move_types::UpdateGuardian> =
                            bcs::from_bytes(value_bytes).context("deserialize UpdateGuardian")?;
                        (p.creator, p.votes, p.quorum_threshold_bps, p.metadata)
                    }
                    ProposalType::IgnoreMember => {
                        let p: move_types::Proposal<move_types::IgnoreMember> =
                            bcs::from_bytes(value_bytes).context("deserialize IgnoreMember")?;
                        (p.creator, p.votes, p.quorum_threshold_bps, p.metadata)
                    }
                    ProposalType::Unknown(s) => {
                        anyhow::bail!("Cannot fetch details for unknown proposal type: {s}")
                    }
                };
                return Ok(ProposalDetails {
                    creator,
                    votes,
                    quorum_threshold_bps,
                    metadata,
                });
            }
        }

        anyhow::bail!("Proposal {proposal_id} not found in proposals bags")
    }

    /// Fetch the MPC public key bytes from on-chain state
    pub fn fetch_mpc_public_key(&self) -> Vec<u8> {
        self.onchain_state.mpc_public_key()
    }

    /// Fetch the guardian's x-only BTC pubkey from on-chain config.
    /// Returns `None` on pre-feature chains where the field is unset.
    pub fn fetch_guardian_btc_public_key(&self) -> Option<Vec<u8>> {
        self.onchain_state
            .state()
            .hashi()
            .config
            .guardian_btc_public_key()
            .map(<[u8]>::to_vec)
    }

    /// Fetch pending deposit requests.
    pub fn fetch_deposit_requests(&self) -> Result<Vec<crate::onchain::types::DepositRequest>> {
        self.require_bitcoin_state()?;
        Ok(self.onchain_state.deposit_requests())
    }

    /// Fetch pending withdrawal requests.
    pub fn fetch_withdrawal_requests(
        &self,
    ) -> Result<Vec<crate::onchain::types::WithdrawalRequest>> {
        self.require_bitcoin_state()?;
        Ok(self.onchain_state.withdrawal_requests())
    }

    /// Fetch committed/signed withdrawal transactions.
    pub fn fetch_withdrawal_txns(
        &self,
    ) -> Result<Vec<crate::onchain::types::WithdrawalTransaction>> {
        self.require_bitcoin_state()?;
        Ok(self.onchain_state.withdrawal_txns())
    }

    // ========================================================================
    // Transaction builders (proposal/governance)
    // ========================================================================

    /// The address of the configured signing keypair, if any.
    pub fn signer_address(&self) -> Option<Address> {
        self.executor.as_ref().map(|e| e.sender())
    }

    /// The address a transaction is built for: `--sender` when given,
    /// otherwise the configured keypair's address. This is also the address
    /// whose committee identity the governance commands act as, so the
    /// serialize-unsigned and dry-run paths work without a keypair. When both
    /// are present and differ, the chain rejects the signature anyway, so the
    /// explicit sender wins here too.
    pub fn acting_address(&self) -> Option<Address> {
        self.acting_sender.or_else(|| self.signer_address())
    }

    /// Resolve the committee member (validator address) the acting address
    /// acts for in governance calls: an exact validator match wins, otherwise
    /// exactly one operator delegation; more than one is an error (see
    /// `resolve_governance_identity`).
    pub fn resolve_validator_address(&self) -> anyhow::Result<Address> {
        let sender = self.acting_address().ok_or_else(|| {
            anyhow::anyhow!("Cannot resolve validator: no keypair configured and no --sender given")
        })?;
        resolve_governance_identity(&self.fetch_committee_members(), sender)
    }

    /// The registration record for `validator`, if it is registered.
    pub fn member_info(&self, validator: &Address) -> Option<MemberInfo> {
        self.fetch_committee_members()
            .into_iter()
            .find(|m| m.validator_address() == validator)
    }

    /// The current on-chain value of `key` in the instant config store.
    pub fn instant_config_value(&self, key: &str) -> Option<ConfigValue> {
        self.onchain_state
            .state()
            .hashi()
            .config
            .config
            .get(key)
            .cloned()
    }

    /// The current on-chain value of `key` in the epoch config store.
    pub fn epoch_config_value(&self, key: &str) -> Option<ConfigValue> {
        self.onchain_state
            .state()
            .hashi()
            .epoch_config
            .entries()
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    }

    /// Build a vote transaction for a proposal.
    ///
    /// Calls: `proposal::vote<T>(hashi, validator_address, proposal_id, clock)`
    pub fn build_vote_transaction(
        &self,
        proposal_id: Address,
        type_arg: TypeTag,
    ) -> anyhow::Result<TransactionBuilder> {
        let validator_address = self.resolve_validator_address()?;
        Ok(build_vote_transaction(
            self.hashi_ids,
            self.hashi_initial_shared_version,
            self.call_package(),
            validator_address,
            proposal_id,
            type_arg,
        ))
    }

    /// Build a remove_vote transaction for a proposal.
    ///
    /// Calls: `proposal::remove_vote<T>(hashi, validator_address, proposal_id)`
    pub fn build_remove_vote_transaction(
        &self,
        proposal_id: Address,
        type_arg: TypeTag,
    ) -> anyhow::Result<TransactionBuilder> {
        let validator_address = self.resolve_validator_address()?;

        let mut builder = TransactionBuilder::new();

        // Fully-resolved shared input: see build_vote_transaction.
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .with_version(self.hashi_initial_shared_version)
                .as_shared()
                .with_mutable(true),
        );
        let validator_address_arg = builder.pure(&validator_address);
        let proposal_id_arg = builder.pure(&proposal_id);

        // Active package for the same linkage reason as build_vote_transaction.
        builder.move_call(
            Function::new(
                self.call_package(),
                Identifier::from_static("proposal"),
                Identifier::from_static("remove_vote"),
            )
            .with_type_args(vec![type_arg]),
            vec![hashi_arg, validator_address_arg, proposal_id_arg],
        );

        Ok(builder)
    }

    /// The full deployed version -> package id history.
    pub fn package_versions(&self) -> hashi_types::move_types::PackageVersions {
        self.onchain_state.state().package_versions().clone()
    }

    /// The scraped on-chain state backing this client.
    pub fn onchain_state(&self) -> &OnchainState {
        &self.onchain_state
    }

    /// Build a proposal creation transaction.
    pub fn build_create_proposal_transaction(
        &self,
        params: CreateProposalParams,
    ) -> anyhow::Result<TransactionBuilder> {
        let validator_address = self.resolve_validator_address()?;
        Ok(build_create_proposal_transaction(
            self.hashi_ids,
            self.hashi_initial_shared_version,
            self.call_package(),
            validator_address,
            params,
        ))
    }

    /// The package governance calls execute on. `disable_version` checks its
    /// guard against the *executing* package's `PACKAGE_VERSION`, so running it
    /// through the original id after an upgrade lets it disable the live one.
    fn call_package(&self) -> Address {
        self.onchain_state
            .active_package()
            .map_or(self.hashi_ids.package_id, |(id, _)| id)
    }

    /// Build a transaction to execute a proposal that has reached quorum.
    ///
    /// Each proposal type has its own `module::execute(hashi, proposal_id, clock)`
    /// entry point. This method dispatches to the correct one based on the
    /// on-chain proposal type.
    pub fn build_execute_proposal_transaction(
        &self,
        proposal_id: Address,
        proposal_type: &crate::onchain::types::ProposalType,
    ) -> anyhow::Result<TransactionBuilder> {
        use crate::onchain::types::ProposalType;

        let module_name = match proposal_type {
            ProposalType::UpdateConfig => "update_config",
            ProposalType::UpdateEpochConfig => "update_epoch_config",
            ProposalType::AddConfig => "add_config",
            ProposalType::EnableVersion => "enable_version",
            ProposalType::DisableVersion => "disable_version",
            ProposalType::EmergencyPause => "emergency_pause",
            ProposalType::AbortReconfig => "abort_reconfig",
            ProposalType::UpdateGuardian => "update_guardian",
            ProposalType::IgnoreMember => "ignore_member",
            ProposalType::Upgrade => {
                anyhow::bail!(
                    "Upgrade proposals require the full upgrade flow (execute + publish + finalize)"
                );
            }
            ProposalType::Unknown(s) => {
                anyhow::bail!("Cannot execute unknown proposal type: {s}");
            }
        };

        let mut builder = TransactionBuilder::new();
        // Fully-resolved shared inputs: see build_create_proposal_transaction.
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .with_version(self.hashi_initial_shared_version)
                .as_shared()
                .with_mutable(true),
        );
        let proposal_id_arg = builder.pure(&proposal_id);
        let clock_arg = builder.object(
            ObjectInput::new(SUI_CLOCK_OBJECT_ID)
                .with_version(1)
                .as_shared()
                .with_mutable(false),
        );

        builder.move_call(
            Function::new(
                self.call_package(),
                Identifier::new(module_name)?,
                Identifier::from_static("execute"),
            ),
            vec![hashi_arg, proposal_id_arg, clock_arg],
        );

        Ok(builder)
    }

    /// Resolve the defining package ID for a proposal payload and construct
    /// the exact Move type argument used by vote/remove-vote.
    pub fn proposal_type_arg(
        &self,
        proposal_type: &crate::onchain::types::ProposalType,
    ) -> anyhow::Result<TypeTag> {
        let package_version = proposal_type.package_version().ok_or_else(|| {
            anyhow::anyhow!("unknown proposal type has no defining package version")
        })?;
        let package_id = self
            .onchain_state
            .state()
            .package_versions()
            .get(package_version)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "package version {package_version} defining proposal type {} is not published",
                    proposal_type.as_str()
                )
            })?;
        get_proposal_type_arg(package_id, proposal_type)
    }
}

/// Build a `TransactionBuilder` for creating a proposal, given `HashiIds` and params.
///
/// This is a standalone function so it can be reused outside `HashiClient` (e.g. in tests).
///
/// `call_package` is the active package id. Proposal modules introduced by an
/// upgrade (such as `ignore_member`) only exist at an upgraded address, and
/// all governance calls use one package generation consistently.
pub fn build_create_proposal_transaction(
    hashi_ids: HashiIds,
    hashi_initial_shared_version: u64,
    call_package: Address,
    validator_address: Address,
    params: CreateProposalParams,
) -> TransactionBuilder {
    let mut builder = TransactionBuilder::new();

    // Shared inputs are fully resolved (initial shared version + mutability)
    // so the fullnode's simulate-time resolver never has to inspect the
    // called function's signature: that inspection fails with
    // INVALID_LINKAGE on sui >= 1.76 fullnodes for modules introduced by a
    // package upgrade (e.g. ignore_member).
    let hashi_arg = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .with_version(hashi_initial_shared_version)
            .as_shared()
            .with_mutable(true),
    );
    let clock_arg = builder.object(
        ObjectInput::new(SUI_CLOCK_OBJECT_ID)
            .with_version(1)
            .as_shared()
            .with_mutable(false),
    );
    let validator_address_arg = builder.pure(&validator_address);

    match params {
        CreateProposalParams::Upgrade {
            digest,
            exclusive,
            metadata,
        } => {
            let digest_arg = builder.pure(&digest);
            let exclusive_arg = builder.pure(&exclusive);
            let metadata_arg = build_metadata(&mut builder, &metadata);
            builder.move_call(
                Function::new(
                    call_package,
                    Identifier::from_static("upgrade"),
                    Identifier::from_static("propose"),
                ),
                vec![
                    hashi_arg,
                    validator_address_arg,
                    digest_arg,
                    exclusive_arg,
                    metadata_arg,
                    clock_arg,
                ],
            );
        }
        CreateProposalParams::UpdateConfig {
            key,
            value,
            metadata,
        } => {
            let entries_arg = build_config_entries(
                &mut builder,
                hashi_ids.package_id,
                call_package,
                &[(key, value)],
            );
            let metadata_arg = build_metadata(&mut builder, &metadata);
            builder.move_call(
                Function::new(
                    call_package,
                    Identifier::from_static("update_config"),
                    Identifier::from_static("propose"),
                ),
                vec![
                    hashi_arg,
                    validator_address_arg,
                    entries_arg,
                    metadata_arg,
                    clock_arg,
                ],
            );
        }
        CreateProposalParams::UpdateEpochConfig {
            key,
            value,
            metadata,
        } => {
            let entries_arg = build_config_entries(
                &mut builder,
                hashi_ids.package_id,
                call_package,
                &[(key, value)],
            );
            let metadata_arg = build_metadata(&mut builder, &metadata);
            builder.move_call(
                Function::new(
                    call_package,
                    Identifier::from_static("update_epoch_config"),
                    Identifier::from_static("propose"),
                ),
                vec![
                    hashi_arg,
                    validator_address_arg,
                    entries_arg,
                    metadata_arg,
                    clock_arg,
                ],
            );
        }
        CreateProposalParams::AddConfig {
            epoch,
            key,
            value,
            metadata,
        } => {
            let epoch_arg = builder.pure(&epoch);
            let entries_arg = build_config_entries(
                &mut builder,
                hashi_ids.package_id,
                call_package,
                &[(key, value)],
            );
            let metadata_arg = build_metadata(&mut builder, &metadata);
            builder.move_call(
                Function::new(
                    call_package,
                    Identifier::from_static("add_config"),
                    Identifier::from_static("propose"),
                ),
                vec![
                    hashi_arg,
                    validator_address_arg,
                    epoch_arg,
                    entries_arg,
                    metadata_arg,
                    clock_arg,
                ],
            );
        }
        CreateProposalParams::UpdateMpcConfig {
            max_faulty_bps,
            weight_reduction_allowed_delta,
            nonce_generation_protocol,
            metadata,
        } => {
            let entries: Vec<(String, ConfigValue)> = [
                ("mpc_max_faulty_in_basis_points", max_faulty_bps),
                (
                    "mpc_weight_reduction_allowed_delta",
                    weight_reduction_allowed_delta,
                ),
                ("mpc_nonce_generation_protocol", nonce_generation_protocol),
            ]
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k.to_string(), ConfigValue::U64(v))))
            .collect();
            let entries_arg =
                build_config_entries(&mut builder, hashi_ids.package_id, call_package, &entries);
            let metadata_arg = build_metadata(&mut builder, &metadata);
            // The MPC parameters live in the epoch config.
            builder.move_call(
                Function::new(
                    call_package,
                    Identifier::from_static("update_epoch_config"),
                    Identifier::from_static("propose"),
                ),
                vec![
                    hashi_arg,
                    validator_address_arg,
                    entries_arg,
                    metadata_arg,
                    clock_arg,
                ],
            );
        }
        CreateProposalParams::EnableVersion { version, metadata } => {
            let version_arg = builder.pure(&version);
            let metadata_arg = build_metadata(&mut builder, &metadata);
            builder.move_call(
                Function::new(
                    call_package,
                    Identifier::from_static("enable_version"),
                    Identifier::from_static("propose"),
                ),
                vec![
                    hashi_arg,
                    validator_address_arg,
                    version_arg,
                    metadata_arg,
                    clock_arg,
                ],
            );
        }
        CreateProposalParams::DisableVersion { version, metadata } => {
            let version_arg = builder.pure(&version);
            let metadata_arg = build_metadata(&mut builder, &metadata);
            builder.move_call(
                Function::new(
                    call_package,
                    Identifier::from_static("disable_version"),
                    Identifier::from_static("propose"),
                ),
                vec![
                    hashi_arg,
                    validator_address_arg,
                    version_arg,
                    metadata_arg,
                    clock_arg,
                ],
            );
        }
        CreateProposalParams::AbortReconfig { epoch, metadata } => {
            let epoch_arg = builder.pure(&epoch);
            let metadata_arg = build_metadata(&mut builder, &metadata);
            builder.move_call(
                Function::new(
                    call_package,
                    Identifier::from_static("abort_reconfig"),
                    Identifier::from_static("propose"),
                ),
                vec![
                    hashi_arg,
                    validator_address_arg,
                    epoch_arg,
                    metadata_arg,
                    clock_arg,
                ],
            );
        }
        CreateProposalParams::UpdateGuardian { url, metadata } => {
            let url_arg = builder.pure(&url);
            let metadata_arg = build_metadata(&mut builder, &metadata);
            builder.move_call(
                Function::new(
                    call_package,
                    Identifier::from_static("update_guardian"),
                    Identifier::from_static("propose"),
                ),
                vec![
                    hashi_arg,
                    validator_address_arg,
                    url_arg,
                    metadata_arg,
                    clock_arg,
                ],
            );
        }
        CreateProposalParams::EmergencyPause { pause, metadata } => {
            let pause_arg = builder.pure(&pause);
            let metadata_arg = build_metadata(&mut builder, &metadata);
            builder.move_call(
                Function::new(
                    call_package,
                    Identifier::from_static("emergency_pause"),
                    Identifier::from_static("propose"),
                ),
                vec![
                    hashi_arg,
                    validator_address_arg,
                    pause_arg,
                    metadata_arg,
                    clock_arg,
                ],
            );
        }
        CreateProposalParams::IgnoreMember {
            target_validator_address,
            ignored,
            metadata,
        } => {
            let target_arg = builder.pure(&target_validator_address);
            let ignored_arg = builder.pure(&ignored);
            let metadata_arg = build_metadata(&mut builder, &metadata);
            builder.move_call(
                Function::new(
                    // Upgrade-introduced modules route through the active package.
                    call_package,
                    Identifier::from_static("ignore_member"),
                    Identifier::from_static("propose"),
                ),
                vec![
                    hashi_arg,
                    validator_address_arg,
                    target_arg,
                    ignored_arg,
                    metadata_arg,
                    clock_arg,
                ],
            );
        }
    }

    builder
}

/// Build a `config_value::Value` enum via a move call (e.g. `config_value::new_u64(v)`).
/// Returns the `Argument` holding the constructed `Value`.
fn build_config_value(
    builder: &mut TransactionBuilder,
    call_package: Address,
    value: &hashi_types::move_types::ConfigValue,
) -> sui_transaction_builder::Argument {
    use hashi_types::move_types::ConfigValue;

    let (func_name, arg) = match value {
        ConfigValue::U64(v) => ("new_u64", builder.pure(v)),
        ConfigValue::Address(v) => ("new_address", builder.pure(v)),
        ConfigValue::String(v) => ("new_string", builder.pure(v)),
        ConfigValue::Bool(v) => ("new_bool", builder.pure(v)),
        ConfigValue::Bytes(v) => ("new_bytes", builder.pure(v)),
        ConfigValue::U128(v) => ("new_u128", builder.pure(v)),
        // The 32 LE bytes BCS-encode identically to a Move `u256` pure arg.
        ConfigValue::U256(v) => ("new_u256", builder.pure(v)),
    };

    builder.move_call(
        Function::new(
            call_package,
            Identifier::from_static("config_value"),
            Identifier::new(func_name).unwrap(),
        ),
        vec![arg],
    )
}

fn build_config_entries(
    builder: &mut TransactionBuilder,
    type_package: Address,
    call_package: Address,
    entries: &[(String, ConfigValue)],
) -> sui_transaction_builder::Argument {
    let sui_framework = Address::from_static("0x2");
    let move_stdlib = Address::from_static("0x1");
    let string_type = TypeTag::Struct(Box::new(StructTag::new(
        move_stdlib,
        Identifier::from_static("string"),
        Identifier::from_static("String"),
        vec![],
    )));
    let value_type = TypeTag::Struct(Box::new(StructTag::new(
        type_package,
        Identifier::from_static("config_value"),
        Identifier::from_static("Value"),
        vec![],
    )));
    let map = builder.move_call(
        Function::new(
            sui_framework,
            Identifier::from_static("vec_map"),
            Identifier::from_static("empty"),
        )
        .with_type_args(vec![string_type.clone(), value_type.clone()]),
        vec![],
    );
    for (key, value) in entries {
        let key_arg = builder.pure(key);
        let value_arg = build_config_value(builder, call_package, value);
        builder.move_call(
            Function::new(
                sui_framework,
                Identifier::from_static("vec_map"),
                Identifier::from_static("insert"),
            )
            .with_type_args(vec![string_type.clone(), value_type.clone()]),
            vec![map, key_arg, value_arg],
        );
    }
    map
}

/// Build a `VecMap<String, String>` for proposal metadata via move calls.
///
/// Move structs like `VecMap` cannot be passed as pure args in PTBs.
/// Instead we construct one via `vec_map::empty()` + `vec_map::insert()`.
fn build_metadata(
    builder: &mut TransactionBuilder,
    metadata: &[(String, String)],
) -> sui_transaction_builder::Argument {
    let sui_framework = Address::from_static("0x2");
    let move_stdlib = Address::from_static("0x1");

    let string_type = TypeTag::Struct(Box::new(StructTag::new(
        move_stdlib,
        Identifier::from_static("string"),
        Identifier::from_static("String"),
        vec![],
    )));

    // vec_map::empty<String, String>()
    let map = builder.move_call(
        Function::new(
            sui_framework,
            Identifier::from_static("vec_map"),
            Identifier::from_static("empty"),
        )
        .with_type_args(vec![string_type.clone(), string_type.clone()]),
        vec![],
    );

    // vec_map::insert(&mut map, key, value) for each entry
    for (key, value) in metadata {
        let key_arg = builder.pure(key);
        let value_arg = builder.pure(value);
        builder.move_call(
            Function::new(
                sui_framework,
                Identifier::from_static("vec_map"),
                Identifier::from_static("insert"),
            )
            .with_type_args(vec![string_type.clone(), string_type.clone()]),
            vec![map, key_arg, value_arg],
        );
    }

    map
}

impl HashiClient {
    /// Build a `validator::resign` transaction. The call targets the latest
    /// package (the rule for every entry an upgrade may introduce), and the
    /// shared inputs are fully resolved (see
    /// `build_create_proposal_transaction`).
    pub fn build_resign_transaction(&self) -> anyhow::Result<TransactionBuilder> {
        self.build_validator_lifecycle_transaction("resign")
    }

    /// Build a `validator::withdraw_resignation` transaction.
    pub fn build_withdraw_resignation_transaction(&self) -> anyhow::Result<TransactionBuilder> {
        self.build_validator_lifecycle_transaction("withdraw_resignation")
    }

    /// Build a `validator::remove_inactive_member` transaction — the
    /// permissionless registry cleanup for a member with no epoch duties who
    /// resigned or left the Sui validator set.
    pub fn build_remove_inactive_member_transaction(
        &self,
        validator: Address,
    ) -> anyhow::Result<TransactionBuilder> {
        let mut builder = TransactionBuilder::new();
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .with_version(self.hashi_initial_shared_version)
                .as_shared()
                .with_mutable(true),
        );
        // Genesis-created system object: its initial shared version is 1 on
        // every Sui chain. Pre-resolved like the Hashi input because the
        // entry is upgrade-introduced surface (unresolved shared inputs fail
        // simulation with INVALID_LINKAGE on sui >= 1.76 fullnodes).
        let sui_system_arg = builder.object(
            ObjectInput::new(crate::sui_tx_executor::SUI_SYSTEM_STATE_OBJECT_ID)
                .with_version(1)
                .as_shared()
                .with_mutable(false),
        );
        let validator_arg = builder.pure(&validator);
        builder.move_call(
            Function::new(
                self.latest_package_id()?,
                Identifier::from_static("validator"),
                Identifier::from_static("remove_inactive_member"),
            ),
            vec![hashi_arg, sui_system_arg, validator_arg],
        );
        Ok(builder)
    }

    fn build_validator_lifecycle_transaction(
        &self,
        function: &'static str,
    ) -> anyhow::Result<TransactionBuilder> {
        let validator_address = self.resolve_validator_address()?;
        let mut builder = TransactionBuilder::new();
        let hashi_arg = builder.object(
            ObjectInput::new(self.hashi_ids.hashi_object_id)
                .with_version(self.hashi_initial_shared_version)
                .as_shared()
                .with_mutable(true),
        );
        let validator_arg = builder.pure(&validator_address);
        builder.move_call(
            Function::new(
                self.latest_package_id()?,
                Identifier::from_static("validator"),
                Identifier::from_static(function),
            ),
            vec![hashi_arg, validator_arg],
        );
        Ok(builder)
    }
}

/// Resolve the committee member `sender` acts for in governance calls
/// (propose, vote, remove_vote, resign, withdraw_resignation).
///
/// An exact validator-address match always wins. Otherwise `sender` may be
/// the delegated operator of exactly one member. On chain,
/// `validator::update_operator_address` only checks that the caller is
/// authorized for the member being updated, so any member can point its
/// operator address at another member's signing address; a first-match scan
/// would then let that stray or malicious delegation redirect the signer's
/// vote to the wrong member (SEC-546). Two or more delegations to the same
/// signer are therefore an error naming the candidates rather than a guess.
fn resolve_governance_identity(members: &[MemberInfo], sender: Address) -> Result<Address> {
    if let Some(member) = members.iter().find(|m| *m.validator_address() == sender) {
        return Ok(*member.validator_address());
    }

    let delegating: Vec<Address> = members
        .iter()
        .filter(|m| *m.operator_address() == sender)
        .map(|m| *m.validator_address())
        .collect();

    match delegating.as_slice() {
        [] => anyhow::bail!("signer {sender} is not a committee member or delegated operator"),
        [validator_address] => Ok(*validator_address),
        candidates => {
            let count = candidates.len();
            let candidates = candidates
                .iter()
                .map(Address::to_hex)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "signer {sender} is the delegated operator of {count} committee members \
                 ({candidates}); the CLI cannot tell which one to act for. Sign with that \
                 member's validator key instead, or have the other members point their \
                 operator address elsewhere (validator::update_operator_address, \
                 `hashi register --operator-address`)."
            )
        }
    }
}

/// Build a `proposal::vote<T>` transaction as a standalone. Reusable outside
/// `HashiClient` — e2e test infra needs to build vote PTBs for every
/// committee member.
pub fn build_vote_transaction(
    hashi_ids: HashiIds,
    hashi_initial_shared_version: u64,
    call_package: Address,
    validator_address: Address,
    proposal_id: Address,
    type_arg: TypeTag,
) -> TransactionBuilder {
    let mut builder = TransactionBuilder::new();
    // Fully-resolved shared inputs: the type arg may name an
    // upgrade-introduced type, and the fullnode's simulate-time resolver
    // fails with INVALID_LINKAGE on those when it has to inspect the call
    // to infer input mutability (sui >= 1.76).
    let hashi_arg = builder.object(
        ObjectInput::new(hashi_ids.hashi_object_id)
            .with_version(hashi_initial_shared_version)
            .as_shared()
            .with_mutable(true),
    );
    let validator_address_arg = builder.pure(&validator_address);
    let proposal_id_arg = builder.pure(&proposal_id);
    let clock_arg = builder.object(
        ObjectInput::new(SUI_CLOCK_OBJECT_ID)
            .with_version(1)
            .as_shared()
            .with_mutable(false),
    );

    // Call through the active package: a transaction's linkage cannot call
    // the original package while a type argument references an
    // upgrade-introduced type (exact-v1 vs at-least-v2 conflict). Every
    // module rides along in an upgrade, and v1-era type args unify fine
    // under a v2 call, so latest is always safe.
    builder.move_call(
        Function::new(
            call_package,
            Identifier::from_static("proposal"),
            Identifier::from_static("vote"),
        )
        .with_type_args(vec![type_arg]),
        vec![hashi_arg, validator_address_arg, proposal_id_arg, clock_arg],
    );

    builder
}

/// Get the TypeTag for a proposal type (from on-chain type)
///
/// `package_id` must be the type's DEFINING package (a Move type's tag
/// carries that address forever) — resolve it via
/// [`HashiClient::proposal_type_arg`], which routes each proposal type to
/// the package version that introduced it.
///
/// Returns an error if the proposal type is `Unknown`.
pub fn get_proposal_type_arg(
    package_id: Address,
    proposal_type: &crate::onchain::types::ProposalType,
) -> Result<TypeTag> {
    use crate::onchain::types::ProposalType;

    let (module, name) = match proposal_type {
        ProposalType::Upgrade => ("upgrade", "Upgrade"),
        ProposalType::UpdateConfig => ("update_config", "UpdateConfig"),
        ProposalType::UpdateEpochConfig => ("update_epoch_config", "UpdateEpochConfig"),
        ProposalType::AddConfig => ("add_config", "AddConfig"),
        ProposalType::EnableVersion => ("enable_version", "EnableVersion"),
        ProposalType::DisableVersion => ("disable_version", "DisableVersion"),
        ProposalType::EmergencyPause => ("emergency_pause", "EmergencyPause"),
        ProposalType::AbortReconfig => ("abort_reconfig", "AbortReconfig"),
        ProposalType::UpdateGuardian => ("update_guardian", "UpdateGuardian"),
        ProposalType::IgnoreMember => ("ignore_member", "IgnoreMember"),
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

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
