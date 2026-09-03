// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Proposal command implementations

use anyhow::Context;
use anyhow::Result;
use colored::Colorize;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionResponse;
use sui_sdk_types::Address;
use tabled::Table;
use tabled::Tabled;

use crate::cli::TxOptions;
use crate::cli::client::CreateProposalParams;
use crate::cli::client::HashiClient;
use crate::cli::client::ProposalLocation;
use crate::cli::config::CliConfig;
use crate::cli::print_detail;
use crate::cli::print_info;
use crate::cli::print_warning;
use crate::cli::types::Proposal;
use crate::cli::types::display;
use crate::cli::upgrade::build_upgrade_execution_transaction;
use crate::cli::upgrade::build_upgrade_package;
use crate::cli::upgrade::extract_new_package_id_from_response;
use crate::onchain::types::ProposalType;

/// Print metadata if present
fn print_metadata(metadata: &[(String, String)]) {
    if !metadata.is_empty() {
        print_detail(&format!("  {}", "Metadata:".bold()));
        for (key, value) in metadata {
            print_detail(&format!("    {}: {}", key.dimmed(), value));
        }
    }
}

/// Resolve and show the committee member the configured keypair acts for, so
/// the operator sees which member the transaction is attributed to before
/// confirming it. The signer may be a member's validator address or an
/// operator address a member delegated to it; see
/// [`HashiClient::resolve_validator_address`] for the rules.
pub(crate) fn print_acting_validator(client: &HashiClient) -> Result<()> {
    let validator_address = client.resolve_validator_address()?;
    let via_operator = match client.signer_address() {
        Some(signer) if signer != validator_address => {
            format!(" (delegated operator {})", signer.to_hex().dimmed())
        }
        _ => String::new(),
    };
    print_detail(&format!(
        "  Acting as validator: {}{via_operator}",
        validator_address.to_hex().cyan()
    ));
    Ok(())
}

/// Mirrors `MAX_PROPOSAL_DURATION_MS` in `proposal.move`: a proposal can be
/// voted on and executed for seven days after creation, then only deleted.
const PROPOSAL_MAX_AGE_MS: u64 = 1000 * 60 * 60 * 24 * 7;

/// What the operator is trying to do to a proposal, for the refusal text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalAction {
    Vote,
    RemoveVote,
    Execute,
}

/// Return the proposal when it is open, and otherwise refuse with a message
/// that names the proposal, its type and why the action cannot happen.
///
/// Executed proposals stay on chain in a second bag, so without this the
/// command finds the proposal, prints its details, prompts, and only then
/// fails in simulation with a framework abort (`dynamic_field` code 1) that
/// never mentions the word "executed" and shares its code with the
/// vote-already-counted error.
pub fn open_proposal(
    location: ProposalLocation,
    proposal_id: &str,
    action: ProposalAction,
    sui_rpc_url: &str,
) -> Result<Proposal> {
    match location {
        ProposalLocation::Active(proposal) => Ok(proposal),
        ProposalLocation::Executed(proposal) => {
            let kind = display::format_proposal_type(&proposal.proposal_type);
            let consequence = match action {
                ProposalAction::Vote => {
                    "voting is closed and there is nothing to submit".to_owned()
                }
                ProposalAction::RemoveVote => {
                    "its votes are final and cannot be removed".to_owned()
                }
                ProposalAction::Execute => {
                    "nothing to execute; its effect is already on chain".to_owned()
                }
            };
            anyhow::bail!(
                "proposal {proposal_id} ({kind}) has already been executed; {consequence}. \
                 Run `hashi proposal view {proposal_id}` for the final tally."
            )
        }
        ProposalLocation::Missing => anyhow::bail!(
            "proposal {proposal_id} was not found in the active or executed proposals on \
             {sui_rpc_url}: either the id is wrong, or the proposal expired (7 days after \
             creation) and was deleted. Run `hashi proposal list` to see the open proposals."
        ),
    }
}

/// One-line lifecycle status for `proposal view`, from bag membership and
/// the seven-day expiry.
pub fn proposal_status(location: &ProposalLocation, now_ms: u64) -> String {
    match location {
        ProposalLocation::Executed(_) => "Executed".to_owned(),
        ProposalLocation::Active(proposal) => {
            let expires_ms = proposal.timestamp_ms.saturating_add(PROPOSAL_MAX_AGE_MS);
            if now_ms > expires_ms {
                format!(
                    "Expired on {} (no longer votable; awaiting deletion)",
                    display::format_timestamp(expires_ms)
                )
            } else {
                format!("Active (expires {})", display::format_timestamp(expires_ms))
            }
        }
        ProposalLocation::Missing => "Not found".to_owned(),
    }
}

/// Vote tally against the quorum threshold, computed once and printed the
/// same way everywhere (view, list --votes, after a vote, before execute).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumProgress {
    pub voters: usize,
    pub voted_weight: u64,
    pub threshold_weight: u64,
    pub total_weight: u64,
}

impl QuorumProgress {
    pub fn new(
        votes: &[Address],
        quorum_threshold_bps: u64,
        committee: &hashi_types::committee::Committee,
    ) -> Self {
        let total_weight = committee.total_weight();
        let voted_weight = votes
            .iter()
            .map(|voter| {
                committee
                    .members()
                    .iter()
                    .find(|m| m.validator_address() == *voter)
                    .map(|m| m.weight())
                    .unwrap_or(0)
            })
            .sum();
        Self {
            voters: votes.len(),
            voted_weight,
            threshold_weight: total_weight
                .saturating_mul(quorum_threshold_bps)
                .div_ceil(10_000),
            total_weight,
        }
    }

    pub fn met(&self) -> bool {
        self.total_weight > 0 && self.voted_weight >= self.threshold_weight
    }

    pub fn missing_weight(&self) -> u64 {
        self.threshold_weight.saturating_sub(self.voted_weight)
    }

    /// `3 voter(s), 120/200 weight (80 more needed)` or
    /// `3 voter(s), 200/200 weight, quorum reached`.
    pub fn describe(&self) -> String {
        if self.met() {
            format!(
                "{} voter(s), {}/{} weight, quorum reached",
                self.voters, self.voted_weight, self.threshold_weight
            )
        } else {
            format!(
                "{} voter(s), {}/{} weight ({} more needed)",
                self.voters,
                self.voted_weight,
                self.threshold_weight,
                self.missing_weight()
            )
        }
    }
}

/// Refuse a proposal past its seven-day window: the chain would abort with
/// `EProposalExpired` after the prompt, and the only remaining action is
/// deletion.
pub fn refuse_if_expired(proposal: &Proposal, proposal_id: &str, now_ms: u64) -> Result<()> {
    let expires_ms = proposal.timestamp_ms.saturating_add(PROPOSAL_MAX_AGE_MS);
    anyhow::ensure!(
        now_ms <= expires_ms,
        "proposal {proposal_id} ({}) expired on {}; it can no longer be voted on or executed, \
         only deleted",
        display::format_proposal_type(&proposal.proposal_type),
        display::format_timestamp(expires_ms)
    );
    Ok(())
}

/// Refuse a validator that is registered but not seated in the current
/// committee: only seated members vote (`ENotCommitteeMember` on chain).
/// `seated` is the current committee's member addresses; `None` before the
/// first DKG, when there is no committee to check against.
pub fn refuse_if_not_seated(validator: Address, seated: Option<(u64, &[Address])>) -> Result<()> {
    if let Some((epoch, members)) = seated {
        anyhow::ensure!(
            members.contains(&validator),
            "validator {} is registered but not seated in the current committee (epoch \
             {epoch}); only seated members can vote",
            validator.to_hex()
        );
    }
    Ok(())
}

/// Refuse a second vote, or the removal of a vote that was never cast, before
/// anything is signed (`EVoteAlreadyCounted` / `ENoVoteFound` on chain).
pub fn refuse_vote_state(
    validator: Address,
    votes: &[Address],
    proposal_id: &str,
    action: ProposalAction,
) -> Result<()> {
    let has_voted = votes.contains(&validator);
    match action {
        ProposalAction::Vote => anyhow::ensure!(
            !has_voted,
            "validator {} has already voted on proposal {proposal_id}; nothing to submit. \
             Use `hashi proposal remove-vote {proposal_id}` to withdraw the vote.",
            validator.to_hex()
        ),
        ProposalAction::RemoveVote => anyhow::ensure!(
            has_voted,
            "validator {} has no vote on proposal {proposal_id} to remove",
            validator.to_hex()
        ),
        ProposalAction::Execute => {}
    }
    Ok(())
}

fn seated_members(
    committee: Option<&hashi_types::committee::Committee>,
) -> Option<(u64, Vec<Address>)> {
    committee.map(|c| {
        (
            c.epoch(),
            c.members().iter().map(|m| m.validator_address()).collect(),
        )
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A human explanation for a governance transaction that failed in
/// simulation or on chain, or `None` when the failure is not a Move abort.
///
/// Two sources: a clever `#[error]` constant from the hashi package, which is
/// named and given a one-line hint; and the one framework abort every
/// governance entry can hit, `dynamic_field` code 1 when the proposal has
/// left the active bag between the pre-flight and the simulate. Matching is
/// on module and constant name, never on the bare code: `1` is also
/// `EVoteAlreadyCounted`, and `0` is both `EVersionDisabled` and
/// `EUnauthorizedCaller`.
pub fn explain_execution_error(
    error: &sui_rpc::proto::sui::rpc::v2::ExecutionError,
) -> Option<String> {
    use sui_rpc::proto::sui::rpc::v2::clever_error::Value;
    use sui_rpc::proto::sui::rpc::v2::execution_error::ExecutionErrorKind;

    if error
        .kind
        .and_then(|kind| ExecutionErrorKind::try_from(kind).ok())
        != Some(ExecutionErrorKind::MoveAbort)
    {
        return None;
    }
    let abort = error.abort_opt()?;
    let module = abort.location().module_opt();
    let clever = abort.clever_error.as_ref();
    let constant = clever.and_then(|c| c.constant_name.as_deref());
    let rendered = clever.and_then(|c| match &c.value {
        Some(Value::Rendered(text)) => Some(text.as_str()),
        _ => None,
    });

    match (module, abort.abort_code, constant) {
        (Some("dynamic_field"), Some(1), None) => Some(
            "the proposal is no longer in the active proposal bag: it was executed, or \
             deleted after expiring, while this command was running. Run \
             `hashi proposal view <proposal-id>` to see its state."
                .to_owned(),
        ),
        (_, _, Some(name)) => {
            let hint = match name {
                "EVoteAlreadyCounted" => Some("this validator has already voted on the proposal"),
                "ENoVoteFound" => Some("this validator has no vote on the proposal to remove"),
                "EQuorumNotReached" => Some(
                    "the proposal has not reached quorum yet; `hashi proposal view` shows the tally",
                ),
                "EProposalExpired" => {
                    Some("proposals expire 7 days after creation; this one can only be deleted")
                }
                "EProposalAlreadyExecuted" => Some("the proposal has already been executed"),
                "ENotCommitteeMember" => {
                    Some("the validator is registered but not seated in the current committee")
                }
                "EUnauthorizedCaller" => {
                    Some("the signer is neither the validator's address nor its delegated operator")
                }
                "EVersionDisabled" => Some(
                    "this binary targets a package version governance has disabled; upgrade hashi",
                ),
                _ => None,
            };
            let mut text = match rendered {
                Some(rendered) => format!("{name}: {rendered}"),
                None => name.to_owned(),
            };
            if let Some(hint) = hint {
                text.push_str(" (");
                text.push_str(hint);
                text.push(')');
            }
            Some(text)
        }
        _ => None,
    }
}

/// [`explain_execution_error`] for the error `finalize_tx` returns, whichever
/// mode produced it: the executor wraps the execute path's build error in
/// `TxFailure::NotSubmitted`, while dry-run and serialize-unsigned return the
/// SDK build error bare, so both shapes are searched.
fn explain_move_abort(err: &anyhow::Error) -> Option<String> {
    let from_executor = crate::sui_tx_executor::transaction_execution_error(err);
    let from_builder =
        err.chain().find_map(
            |e| match e.downcast_ref::<sui_transaction_builder::Error>() {
                Some(sui_transaction_builder::Error::SimulationFailure(failure)) => {
                    Some(failure.execution_error())
                }
                _ => None,
            },
        );
    explain_execution_error(from_executor.or(from_builder)?)
}

/// Finalize a transaction according to `tx_opts`: serialize it unsigned,
/// dry-run it, or sign and submit it.
///
/// Returns `Some(response)` when a real transaction was executed, and `None`
/// for dry-run, serialize-unsigned, or when execution is requested but no
/// keypair is configured.
pub(crate) async fn execute_or_simulate(
    client: &mut HashiClient,
    tx: sui_transaction_builder::TransactionBuilder,
    tx_opts: &TxOptions,
) -> Result<Option<ExecuteTransactionResponse>> {
    use crate::sui_tx_executor::TxMode;

    // Only the execute path needs a keypair; serialize/dry-run build with just
    // the sender address.
    if tx_opts.mode() == TxMode::Execute && !client.can_execute() {
        print_warning(
            "Transaction execution requires a keypair (--keypair). Use \
             --serialize-unsigned-transaction to emit an unsigned transaction, or --dry-run.",
        );
        return Ok(None);
    }

    match tx_opts.mode() {
        TxMode::SerializeUnsigned => print_info("Building unsigned transaction..."),
        TxMode::DryRun => print_info("Simulating transaction (dry-run)..."),
        TxMode::Execute => print_info("Executing transaction..."),
    }

    let outcome =
        client
            .finalize_tx(tx, tx_opts)
            .await
            .map_err(|e| match explain_move_abort(&e) {
                Some(explanation) => e.context(explanation),
                None => e,
            })?;
    Ok(crate::cli::print_tx_outcome(outcome, client.sui_rpc_url()).map(|response| *response))
}

/// Print the newly-created proposal's ID after a `create_*_proposal` call,
/// when the response is available (real execute, not dry-run).
fn print_created_proposal_id(response: Option<&ExecuteTransactionResponse>) {
    let Some(response) = response else {
        return;
    };
    match crate::cli::upgrade::extract_proposal_id_from_response(response) {
        Ok(id) => println!("  {} {}", "Proposal ID:".bold(), id.to_hex().cyan()),
        Err(e) => {
            tracing::warn!("Could not extract proposal ID from response: {e}");
        }
    }
}

/// List all active proposals
pub async fn list_proposals(
    config: &CliConfig,
    type_filter: Option<String>,
    detailed: bool,
    executed: bool,
    votes: bool,
    json: bool,
) -> Result<()> {
    let client = HashiClient::new(config).await?;

    print_info("Fetching proposals...");

    let (proposals, bag) = if executed {
        (client.fetch_executed_proposals(), "executed")
    } else {
        (client.fetch_proposals(), "active")
    };

    // Filter by type if specified
    let proposals: Vec<_> = if let Some(ref filter) = type_filter {
        let filter_lower = filter.to_lowercase();
        proposals
            .into_iter()
            .filter(|p| {
                display::format_proposal_type(&p.proposal_type)
                    .to_lowercase()
                    .contains(&filter_lower)
            })
            .collect()
    } else {
        proposals
    };

    // The optional per-row tally costs one live read per proposal.
    let committee = client.fetch_current_committee();
    let mut tallies: Vec<Option<QuorumProgress>> = Vec::with_capacity(proposals.len());
    if votes {
        for proposal in &proposals {
            let tally = match (client.fetch_proposal_details(proposal.id).await, &committee) {
                (Ok(details), Some(committee)) => Some(QuorumProgress::new(
                    &details.votes,
                    details.quorum_threshold_bps,
                    committee,
                )),
                _ => None,
            };
            tallies.push(tally);
        }
    }

    let now = now_ms();
    let location = |p: &Proposal| {
        if executed {
            ProposalLocation::Executed(p.clone())
        } else {
            ProposalLocation::Active(p.clone())
        }
    };

    if json {
        let rows: Vec<serde_json::Value> = proposals
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut row = serde_json::json!({
                    "id": p.id.to_hex(),
                    "type": display::format_proposal_type(&p.proposal_type),
                    "created_ms": p.timestamp_ms,
                    "status": proposal_status(&location(p), now),
                });
                if let Some(Some(tally)) = tallies.get(i) {
                    row["votes"] = serde_json::json!({
                        "voters": tally.voters,
                        "voted_weight": tally.voted_weight,
                        "threshold_weight": tally.threshold_weight,
                        "total_weight": tally.total_weight,
                        "quorum_reached": tally.met(),
                    });
                }
                row
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    if proposals.is_empty() {
        let what = match &type_filter {
            Some(filter) => format!("No {bag} proposals found matching type filter: {filter}"),
            None => format!("No {bag} proposals found."),
        };
        println!("\n{}", what.dimmed());
        return Ok(());
    }

    println!(
        "\n📋 {} Proposals:\n",
        if executed { "Executed" } else { "Active" }
    );

    if detailed {
        for proposal in &proposals {
            let status = proposal_status(&location(proposal), now);
            print_proposal_detailed(proposal, &status, None, None);
            println!();
        }
    } else {
        #[derive(Tabled)]
        struct ProposalRow {
            #[tabled(rename = "ID")]
            id: String,
            #[tabled(rename = "Type")]
            proposal_type: String,
            #[tabled(rename = "Created")]
            timestamp: String,
            #[tabled(rename = "Status")]
            status: String,
            #[tabled(rename = "Votes")]
            votes: String,
        }

        let rows: Vec<ProposalRow> = proposals
            .iter()
            .enumerate()
            .map(|(i, p)| ProposalRow {
                // Full ids: this is what gets pasted into `vote` and `view`.
                id: display::format_address_full(&p.id),
                proposal_type: display::format_proposal_type(&p.proposal_type),
                timestamp: display::format_timestamp(p.timestamp_ms),
                status: proposal_status(&location(p), now),
                votes: match tallies.get(i) {
                    Some(Some(tally)) => tally.describe(),
                    Some(None) => "unavailable".to_owned(),
                    None => "(pass --votes)".to_owned(),
                },
            })
            .collect();

        let table = Table::new(rows).to_string();
        println!("{}", table);
    }

    println!(
        "\n{} {} {bag} proposal(s) found",
        "ℹ".blue(),
        proposals.len().to_string().bold()
    );

    Ok(())
}

/// View details of a specific proposal
pub async fn view_proposal(config: &CliConfig, proposal_id: &str) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let proposal_addr = Address::from_hex(proposal_id)
        .with_context(|| format!("Invalid proposal ID: {}", proposal_id))?;

    print_info(&format!("Fetching proposal {}...", proposal_id));

    let location = client.locate_proposal(&proposal_addr);
    let proposal = match &location {
        ProposalLocation::Active(proposal) | ProposalLocation::Executed(proposal) => {
            proposal.clone()
        }
        ProposalLocation::Missing => anyhow::bail!(
            "proposal {proposal_id} was not found in the active or executed proposals on {}: \
             either the id is wrong, or the proposal expired (7 days after creation) and \
             was deleted. Run `hashi proposal list` to see the open proposals.",
            client.sui_rpc_url()
        ),
    };
    let status = proposal_status(&location, now_ms());

    let details = client.fetch_proposal_details(proposal_addr).await.ok();
    let committee = client.fetch_current_committee();

    println!();
    print_proposal_detailed(&proposal, &status, details.as_ref(), committee.as_ref());

    Ok(())
}

/// Vote on a proposal, optionally chaining an execute if this vote pushes
/// the proposal over quorum.
pub async fn vote(
    config: &CliConfig,
    proposal_id: &str,
    execute: bool,
    tx_opts: &TxOptions,
) -> Result<()> {
    let mut client = HashiClient::new(config).await?;

    let proposal_addr = Address::from_hex(proposal_id)
        .with_context(|| format!("Invalid proposal ID: {}", proposal_id))?;

    print_info(&format!("Fetching proposal {}...", proposal_id));

    let proposal = open_proposal(
        client.locate_proposal(&proposal_addr),
        proposal_id,
        ProposalAction::Vote,
        client.sui_rpc_url(),
    )?;
    refuse_if_expired(&proposal, proposal_id, now_ms())?;

    // Everything the chain would refuse after the prompt is refused here
    // first, from one live read of the proposal.
    let details = client.fetch_proposal_details(proposal_addr).await?;
    let committee = client.fetch_current_committee();
    if client.signer_address().is_some() {
        let validator = client.resolve_validator_address()?;
        let seated = seated_members(committee.as_ref());
        refuse_if_not_seated(validator, seated.as_ref().map(|(e, m)| (*e, m.as_slice())))?;
        refuse_vote_state(validator, &details.votes, proposal_id, ProposalAction::Vote)?;
    }

    let proposal_type_str = display::format_proposal_type(&proposal.proposal_type);

    print_detail(&format!("\n{}", "Proposal Details:".bold()));
    print_detail(&format!("  Type: {}", proposal_type_str.cyan()));
    if let Some(committee) = &committee {
        let progress = QuorumProgress::new(&details.votes, details.quorum_threshold_bps, committee);
        print_detail(&format!("  Votes so far: {}", progress.describe()));
    }
    print_acting_validator(&client)?;

    if !prompt_continue("vote on this proposal", tx_opts).await? {
        print_warning("Aborted.");
        return Ok(());
    }

    print_info("Building vote transaction...");

    // Infer the type tag from the on-chain proposal type
    let type_arg = client.proposal_type_arg(&proposal.proposal_type)?;
    let tx = client.build_vote_transaction(proposal_addr, type_arg)?;

    print_info(&format!(
        "Transaction: proposal::vote<{}> on {}",
        proposal_type_str, proposal_id
    ));

    let vote_response = execute_or_simulate(&mut client, tx, tx_opts).await?;

    // Nothing landed on chain (dry-run, serialize, or no keypair).
    if vote_response.is_none() {
        return Ok(());
    }

    // Re-fetch live vote state: `HashiClient`'s cached scrape is from CLI
    // start, so this has to be the live `list_dynamic_fields` call.
    let details = client
        .fetch_proposal_details(proposal_addr)
        .await
        .context("failed to re-fetch proposal state after voting")?;
    let Some(committee) = committee else {
        print_info("Vote recorded; no committee is formed yet, so quorum cannot be computed.");
        return Ok(());
    };
    let progress = QuorumProgress::new(&details.votes, details.quorum_threshold_bps, &committee);
    print_info(&format!("Votes: {}", progress.describe()));

    if !progress.met() {
        if execute {
            print_info("Quorum not reached yet; skipping --execute.");
        }
        return Ok(());
    }

    // Upgrade proposals require the dedicated upgrade flow: the generic
    // `<module>::execute` path can't construct an UpgradeTicket.
    if is_upgrade_proposal(&proposal.proposal_type) {
        print_info(&format!(
            "Quorum reached; run `hashi proposal execute-upgrade {proposal_id} \
             --package-path <dir>` to execute it."
        ));
        return Ok(());
    }
    if !execute {
        print_info(&format!(
            "Quorum reached; run `hashi proposal execute {proposal_id}` to execute it \
             (or pass --execute to vote next time)."
        ));
        return Ok(());
    }

    print_info("Quorum reached; executing...");
    let execute_tx =
        client.build_execute_proposal_transaction(proposal_addr, &proposal.proposal_type)?;
    print_info(&format!(
        "Transaction: {}::execute on {}",
        proposal.proposal_type.as_str(),
        proposal_id
    ));
    execute_or_simulate(&mut client, execute_tx, tx_opts).await?;
    Ok(())
}

/// Remove vote from a proposal
pub async fn remove_vote(config: &CliConfig, proposal_id: &str, tx_opts: &TxOptions) -> Result<()> {
    let mut client = HashiClient::new(config).await?;

    let proposal_addr = Address::from_hex(proposal_id)
        .with_context(|| format!("Invalid proposal ID: {}", proposal_id))?;

    print_info(&format!("Fetching proposal {}...", proposal_id));

    let proposal = open_proposal(
        client.locate_proposal(&proposal_addr),
        proposal_id,
        ProposalAction::RemoveVote,
        client.sui_rpc_url(),
    )?;
    refuse_if_expired(&proposal, proposal_id, now_ms())?;
    if client.signer_address().is_some() {
        let validator = client.resolve_validator_address()?;
        let details = client.fetch_proposal_details(proposal_addr).await?;
        refuse_vote_state(
            validator,
            &details.votes,
            proposal_id,
            ProposalAction::RemoveVote,
        )?;
    }

    let proposal_type_str = display::format_proposal_type(&proposal.proposal_type);

    print_detail(&format!("\n{}", "Proposal Details:".bold()));
    print_detail(&format!("  Type: {}", proposal_type_str.cyan()));
    print_acting_validator(&client)?;

    if !prompt_continue("remove your vote from this proposal", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    print_info("Building remove_vote transaction...");

    // Infer the type tag from the on-chain proposal type
    let type_arg = client.proposal_type_arg(&proposal.proposal_type)?;
    let tx = client.build_remove_vote_transaction(proposal_addr, type_arg)?;

    print_info(&format!(
        "Transaction: proposal::remove_vote<{}> on {}",
        proposal_type_str, proposal_id
    ));

    execute_or_simulate(&mut client, tx, tx_opts).await?;
    Ok(())
}

/// Execute a proposal that has reached quorum
pub async fn execute(config: &CliConfig, proposal_id: &str, tx_opts: &TxOptions) -> Result<()> {
    let mut client = HashiClient::new(config).await?;

    let proposal_addr = Address::from_hex(proposal_id)
        .with_context(|| format!("Invalid proposal ID: {}", proposal_id))?;

    print_info(&format!("Fetching proposal {}...", proposal_id));

    let proposal = open_proposal(
        client.locate_proposal(&proposal_addr),
        proposal_id,
        ProposalAction::Execute,
        client.sui_rpc_url(),
    )?;
    refuse_if_expired(&proposal, proposal_id, now_ms())?;

    let proposal_type = &proposal.proposal_type;
    let proposal_type_str = display::format_proposal_type(proposal_type);

    if is_upgrade_proposal(proposal_type) {
        anyhow::bail!(
            "Upgrade proposals publish a package as part of their execution; \
             use `proposal execute-upgrade {proposal_id} --package-path <dir>` instead."
        );
    }

    // The chain aborts with EQuorumNotReached after the prompt; say so first,
    // with the tally.
    let details = client.fetch_proposal_details(proposal_addr).await?;
    let committee = client
        .fetch_current_committee()
        .ok_or_else(|| anyhow::anyhow!("no committee is formed yet, so nothing can execute"))?;
    let progress = QuorumProgress::new(&details.votes, details.quorum_threshold_bps, &committee);
    anyhow::ensure!(
        progress.met(),
        "proposal {proposal_id} ({proposal_type_str}) has not reached quorum: {}. \
         `hashi proposal view {proposal_id}` lists the voters.",
        progress.describe()
    );

    print_detail(&format!("\n{}", "Execute Proposal:".bold()));
    print_detail(&format!("  Type: {}", proposal_type_str.cyan()));
    print_detail(&format!("  ID:   {}", proposal_id));
    print_detail(&format!("  Votes: {}", progress.describe()));
    // Execution is permissionless, so the sender is whoever pays gas.
    if let Some(sender) = tx_opts.sender.or_else(|| client.signer_address()) {
        print_detail(&format!("  Sender: {}", sender.to_hex().cyan()));
    }

    if !prompt_continue("execute this proposal", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let tx = client.build_execute_proposal_transaction(proposal_addr, proposal_type)?;

    print_info(&format!(
        "Transaction: {}::execute on {}",
        proposal_type.as_str(),
        proposal_id
    ));

    execute_or_simulate(&mut client, tx, tx_opts).await?;
    Ok(())
}

/// Which upgrade proposal module an approved proposal executes through.
/// Whether an approved proposal executes through the upgrade flow
/// (execute + publish + finalize) rather than the generic `proposal execute`.
pub fn is_upgrade_proposal(proposal_type: &ProposalType) -> bool {
    matches!(proposal_type, ProposalType::Upgrade)
}

/// Inputs for [`execute_upgrade`]: where to build the package from and which
/// `sui` binary to build it with.
pub struct ExecuteUpgradeArgs<'a> {
    pub package_path: &'a std::path::Path,
    pub sui_binary: &'a std::path::Path,
    pub sui_client_config: Option<&'a std::path::Path>,
}

/// Execute an approved upgrade proposal.
///
/// One programmable transaction: `<module>::execute` consumes the proposal and
/// returns the `UpgradeTicket`, the `Upgrade` command publishes the freshly
/// built modules against that ticket, and `<module>::finalize_upgrade` commits
/// the receipt (which also enables the new version). The ticket and receipt
/// are hot potatoes, so the three steps cannot be split across transactions.
///
/// The package is built here, from `package_path`, and must be byte-identical
/// to the build whose digest went into the proposal: same commit, same `sui`.
/// The chain enforces that when it processes the `Upgrade` command, so a
/// mismatch fails at simulation rather than costing gas.
pub async fn execute_upgrade(
    config: &CliConfig,
    proposal_id: &str,
    args: ExecuteUpgradeArgs<'_>,
    tx_opts: &TxOptions,
) -> Result<()> {
    let ExecuteUpgradeArgs {
        package_path,
        sui_binary,
        sui_client_config,
    } = args;
    let mut client = HashiClient::new(config).await?;

    let proposal_addr = Address::from_hex(proposal_id)
        .with_context(|| format!("Invalid proposal ID: {}", proposal_id))?;

    print_info(&format!("Fetching proposal {}...", proposal_id));

    let proposal = client
        .fetch_proposal(&proposal_addr)
        .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_id))?;

    anyhow::ensure!(
        is_upgrade_proposal(&proposal.proposal_type),
        "{} is a {} proposal, not an upgrade; use `proposal execute` instead",
        proposal_id,
        display::format_proposal_type(&proposal.proposal_type)
    );
    let module = "upgrade";

    let current_version = client.highest_package_version().context(
        "could not determine current package version from on-chain state; \
         is the package deployed?",
    )?;
    let expected_version = current_version + 1;
    let current_package_id = client.latest_package_id()?;

    print_detail(&format!("\n{}", "Execute Upgrade Proposal:".bold()));
    print_detail(&format!(
        "  Type:            {}",
        display::format_proposal_type(&proposal.proposal_type).cyan()
    ));
    print_detail(&format!("  ID:              {}", proposal_id));
    print_detail(&format!("  Module:          {}", module));
    print_detail(&format!(
        "  Current package: v{} at {}",
        current_version,
        current_package_id.to_hex()
    ));
    print_detail(&format!("  Package path:    {}", package_path.display()));
    print_detail(&format!(
        "  Expects:         PACKAGE_VERSION = {expected_version}"
    ));

    print_info(&format!(
        "Building upgrade package at {} with {}",
        package_path.display(),
        sui_binary.display()
    ));
    let (compiled, digest) = build_upgrade_package(
        sui_binary,
        package_path,
        sui_client_config,
        expected_version,
    )
    .context("failed to build upgrade package")?;
    print_detail(&format!("  Built digest:    0x{}", hex::encode(&digest)));
    print_detail(
        "  The publish is accepted only if this digest matches the proposal's; \
         build from the same commit with the same `sui` that produced the proposal.",
    );

    if !prompt_continue(
        "execute this upgrade (execute + publish + finalize in one transaction)",
        tx_opts,
    )
    .await?
    {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let hashi_ids = *client.hashi_ids();
    let tx =
        build_upgrade_execution_transaction(hashi_ids, current_package_id, proposal_addr, compiled);

    print_info(&format!(
        "Transaction: {module}::execute + Upgrade + {module}::finalize_upgrade on {}",
        proposal_id
    ));

    let Some(response) = execute_or_simulate(&mut client, tx, tx_opts).await? else {
        return Ok(());
    };

    let new_package_id = extract_new_package_id_from_response(&response)?;
    println!(
        "  {} {}",
        "New package ID:".bold(),
        new_package_id.to_hex().cyan()
    );

    // Re-read the chain so the operator sees what the commit enabled, rather
    // than the pre-upgrade snapshot this client was built from.
    let refreshed = HashiClient::new(config).await?;
    let mut enabled: Vec<u64> = refreshed
        .onchain_state()
        .state()
        .hashi()
        .config
        .enabled_versions
        .iter()
        .copied()
        .collect();
    enabled.sort_unstable();
    println!("  {} {:?}", "Enabled versions:".bold(), enabled);
    if let Some(latest) = refreshed.highest_package_version() {
        println!("  {} v{latest}", "Latest package:".bold());
    }
    if enabled.contains(&current_version) {
        print_warning(&format!(
            "v{current_version} stays enabled (non-exclusive upgrade): execute a \
             DisableVersion({current_version}) proposal through the new package when \
             the fleet is ready."
        ));
    }
    Ok(())
}

/// Create an upgrade proposal.
///
/// Exactly one of `digest` or `package_path` must be `Some`. When
/// `package_path` is provided, the CLI builds the package via `sui move build`
/// and verifies that its `PACKAGE_VERSION` constant is exactly +1 of the
/// currently published version (pre-flight check) before submitting the
/// proposal. The `--digest` path skips that check and is retained only for
/// callers with a pre-built package; combined with an exclusive upgrade it is
/// refused unless `allow_unverified_exclusive` acknowledges the skipped check.
pub struct CreateUpgradeProposalArgs<'a> {
    pub digest: Option<&'a str>,
    pub package_path: Option<&'a std::path::Path>,
    pub sui_binary: &'a std::path::Path,
    pub sui_client_config: Option<&'a std::path::Path>,
    pub exclusive: bool,
    pub allow_unverified_exclusive: bool,
    pub metadata: Vec<(String, String)>,
}

/// Refuse the brick-capable flag combination: an exclusive upgrade proposed
/// from a pre-built `--digest`, whose `PACKAGE_VERSION` constant was therefore
/// never checked against the chain, unless the operator explicitly
/// acknowledged the bypass.
fn check_exclusive_digest_acknowledged(
    digest: Option<&str>,
    exclusive: bool,
    allow_unverified_exclusive: bool,
) -> Result<()> {
    if digest.is_some() && exclusive && !allow_unverified_exclusive {
        anyhow::bail!(
            "--digest skips the PACKAGE_VERSION pre-flight, and an exclusive upgrade \
             publishing a package whose PACKAGE_VERSION does not match the new \
             on-chain version permanently bricks the contract with no on-chain \
             recovery. Use --package-path so the constant is verified, or pass \
             --allow-unverified-exclusive after manually verifying that the \
             pre-built package declares PACKAGE_VERSION = current on-chain \
             version + 1."
        );
    }
    Ok(())
}

pub async fn create_upgrade_proposal(
    config: &CliConfig,
    args: CreateUpgradeProposalArgs<'_>,
    tx_opts: &TxOptions,
) -> Result<()> {
    let CreateUpgradeProposalArgs {
        digest,
        package_path,
        sui_binary,
        sui_client_config,
        exclusive,
        allow_unverified_exclusive,
        metadata,
    } = args;
    check_exclusive_digest_acknowledged(digest, exclusive, allow_unverified_exclusive)?;
    let mut client = HashiClient::new(config).await?;

    let digest_bytes = match (digest, package_path) {
        (Some(d), None) => {
            print_warning(
                "--digest skips pre-flight checks (PACKAGE_VERSION = current + 1). \
                 Prefer --package-path.",
            );
            hex::decode(d.trim_start_matches("0x")).context("Invalid digest hex")?
        }
        (None, Some(path)) => {
            let current_version = client.highest_package_version().context(
                "could not determine current package version from on-chain state; \
                 is the package deployed?",
            )?;
            let expected_version = current_version + 1;
            print_info(&format!(
                "Building upgrade package at {} (expecting PACKAGE_VERSION = {expected_version})",
                path.display()
            ));
            let (_compiled, digest) = crate::cli::upgrade::build_upgrade_package(
                sui_binary,
                path,
                sui_client_config,
                expected_version,
            )
            .context("failed to build upgrade package")?;
            digest
        }
        (None, None) => {
            anyhow::bail!("must provide either --digest or --package-path");
        }
        (Some(_), Some(_)) => unreachable!("clap enforces mutual exclusion"),
    };

    print_detail(&format!("\n{}", "Creating Upgrade Proposal:".bold()));
    print_detail(&format!("  Digest: 0x{}", hex::encode(&digest_bytes)));
    print_detail(&format!("  Exclusive: {exclusive}"));
    print_metadata(&metadata);
    print_acting_validator(&client)?;

    if !prompt_continue("create this upgrade proposal", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let tx = client.build_create_proposal_transaction(CreateProposalParams::Upgrade {
        digest: digest_bytes,
        exclusive,
        metadata,
    })?;
    let module = "upgrade";

    print_info(&format!("Transaction: {module}::propose"));
    let response = execute_or_simulate(&mut client, tx, tx_opts).await?;
    print_created_proposal_id(response.as_ref());
    Ok(())
}

/// Create an update config proposal
pub async fn create_update_config_proposal(
    config: &CliConfig,
    key: &str,
    value_str: &str,
    metadata: Vec<(String, String)>,
    tx_opts: &TxOptions,
) -> Result<()> {
    let value = parse_config_value(value_str)
        .context("Invalid value format. Use type:value, e.g. u64:1000 or bool:true")?;

    print_detail(&format!("\n{}", "Creating Update Config Proposal:".bold()));
    print_detail(&format!("  Key:   {}", key));
    print_detail(&format!("  Value: {}", value_str));
    print_metadata(&metadata);

    let mut client = HashiClient::new(config).await?;
    print_acting_validator(&client)?;

    if !prompt_continue("create this config update proposal", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let tx = client.build_create_proposal_transaction(CreateProposalParams::UpdateConfig {
        key: key.to_string(),
        value,
        metadata,
    })?;

    print_info("Transaction: update_config::propose");
    let response = execute_or_simulate(&mut client, tx, tx_opts).await?;
    print_created_proposal_id(response.as_ref());
    Ok(())
}

/// Create an update epoch config proposal
pub async fn create_update_epoch_config_proposal(
    config: &CliConfig,
    key: &str,
    value_str: &str,
    metadata: Vec<(String, String)>,
    tx_opts: &TxOptions,
) -> Result<()> {
    let value = parse_config_value(value_str)
        .context("Invalid value format. Use type:value, e.g. u64:1000 or bool:true")?;

    print_detail(&format!(
        "\n{}",
        "Creating Update Epoch Config Proposal:".bold()
    ));
    print_detail(&format!("  Key:   {}", key));
    print_detail(&format!("  Value: {}", value_str));
    print_detail("  Takes effect: next committee formed after execution");
    print_metadata(&metadata);

    if !prompt_continue("create this epoch config update proposal", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let mut client = HashiClient::new(config).await?;
    let tx = client.build_create_proposal_transaction(CreateProposalParams::UpdateEpochConfig {
        key: key.to_string(),
        value,
        metadata,
    })?;

    print_info("Transaction: update_epoch_config::propose");
    let response = execute_or_simulate(&mut client, tx, tx_opts).await?;
    print_created_proposal_id(response.as_ref());
    Ok(())
}

/// Create an add config proposal
pub async fn create_add_config_proposal(
    config: &CliConfig,
    key: &str,
    value_str: &str,
    epoch: bool,
    metadata: Vec<(String, String)>,
    tx_opts: &TxOptions,
) -> Result<()> {
    let value = parse_config_value(value_str)
        .context("Invalid value format. Use type:value, e.g. u64:1000 or bool:true")?;

    print_detail(&format!("\n{}", "Creating Add Config Proposal:".bold()));
    print_detail(&format!("  Key:   {}", key));
    print_detail(&format!("  Value: {}", value_str));
    print_detail(&format!(
        "  Store: {}",
        if epoch {
            "epoch config (copied onto each new committee)"
        } else {
            "instant config (applies on execute)"
        }
    ));
    print_metadata(&metadata);

    if !prompt_continue("create this add config proposal", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let mut client = HashiClient::new(config).await?;
    let tx = client.build_create_proposal_transaction(CreateProposalParams::AddConfig {
        epoch,
        key: key.to_string(),
        value,
        metadata,
    })?;

    print_info("Transaction: add_config::propose");
    let response = execute_or_simulate(&mut client, tx, tx_opts).await?;
    print_created_proposal_id(response.as_ref());
    Ok(())
}

pub async fn create_update_mpc_config_proposal(
    config: &CliConfig,
    max_faulty_bps: Option<u64>,
    weight_reduction_allowed_delta: Option<u64>,
    nonce_generation_protocol: Option<u64>,
    metadata: Vec<(String, String)>,
    tx_opts: &TxOptions,
) -> Result<()> {
    const MAX_BPS: u64 = 10_000;
    const MAX_FAULTY_BPS: u64 = 3_333;
    if let Some(f) = max_faulty_bps {
        anyhow::ensure!(
            (1..=MAX_FAULTY_BPS).contains(&f),
            "--max-faulty-bps must be in 1..={MAX_FAULTY_BPS}, got {f}"
        );
    }
    if let Some(d) = weight_reduction_allowed_delta {
        anyhow::ensure!(
            d <= MAX_BPS,
            "--weight-reduction-allowed-delta must be in 0..={MAX_BPS}, got {d}"
        );
    }
    if let (Some(f), Some(d)) = (max_faulty_bps, weight_reduction_allowed_delta) {
        anyhow::ensure!(
            d < f,
            "--weight-reduction-allowed-delta must be below --max-faulty-bps ({f}), got {d}; \
             pinning would silently clamp it to {}",
            f - 1
        );
    }
    if let Some(p) = nonce_generation_protocol {
        anyhow::ensure!(
            p <= 1,
            "--nonce-generation-protocol must be 0 (vanilla) or 1 (avid), got {p}"
        );
    }

    let count = [
        max_faulty_bps,
        weight_reduction_allowed_delta,
        nonce_generation_protocol,
    ]
    .iter()
    .filter(|v| v.is_some())
    .count();
    if count == 0 {
        anyhow::bail!(
            "must provide at least one of --max-faulty-bps, --weight-reduction-allowed-delta, --nonce-generation-protocol"
        );
    }

    let mut client = HashiClient::new(config).await?;
    print_acting_validator(&client)?;

    if !prompt_continue("create this MPC config update proposal", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let tx = client.build_create_proposal_transaction(CreateProposalParams::UpdateMpcConfig {
        max_faulty_bps,
        weight_reduction_allowed_delta,
        nonce_generation_protocol,
        metadata,
    })?;

    let response = execute_or_simulate(&mut client, tx, tx_opts).await?;
    print_created_proposal_id(response.as_ref());
    Ok(())
}

/// Parse a CLI config value string like "u64:1000" or "bool:true" into a ConfigValueParam.
fn parse_config_value(s: &str) -> Result<hashi_types::move_types::ConfigValue> {
    use hashi_types::move_types::ConfigValue;

    let (type_prefix, raw) = s
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("expected type:value format (e.g. u64:1000)"))?;

    match type_prefix {
        "u64" => Ok(ConfigValue::U64(raw.parse().context("invalid u64")?)),
        "bool" => Ok(ConfigValue::Bool(raw.parse().context("invalid bool")?)),
        "string" => Ok(ConfigValue::String(raw.to_string())),
        "address" => Ok(ConfigValue::Address(
            raw.parse().context("invalid address")?,
        )),
        other => anyhow::bail!(
            "unknown type prefix '{}' (expected u64, bool, string, address)",
            other
        ),
    }
}

/// Create an enable version proposal
pub async fn create_enable_version_proposal(
    config: &CliConfig,
    version: u64,
    metadata: Vec<(String, String)>,
    tx_opts: &TxOptions,
) -> Result<()> {
    print_detail(&format!("\n{}", "Creating Enable Version Proposal:".bold()));
    print_detail(&format!("  Version: {}", version));
    print_metadata(&metadata);

    let mut client = HashiClient::new(config).await?;
    print_acting_validator(&client)?;

    if !prompt_continue("create this enable version proposal", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let tx = client.build_create_proposal_transaction(CreateProposalParams::EnableVersion {
        version,
        metadata,
    })?;

    print_info("Transaction: enable_version::propose");
    let response = execute_or_simulate(&mut client, tx, tx_opts).await?;
    print_created_proposal_id(response.as_ref());
    Ok(())
}

/// Create a disable version proposal
pub async fn create_disable_version_proposal(
    config: &CliConfig,
    version: u64,
    metadata: Vec<(String, String)>,
    tx_opts: &TxOptions,
) -> Result<()> {
    print_detail(&format!(
        "\n{}",
        "Creating Disable Version Proposal:".bold()
    ));
    print_detail(&format!("  Version: {}", version));
    print_metadata(&metadata);

    let mut client = HashiClient::new(config).await?;
    print_acting_validator(&client)?;

    if !prompt_continue("create this disable version proposal", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let tx = client.build_create_proposal_transaction(CreateProposalParams::DisableVersion {
        version,
        metadata,
    })?;

    print_info("Transaction: disable_version::propose");
    let response = execute_or_simulate(&mut client, tx, tx_opts).await?;
    print_created_proposal_id(response.as_ref());
    Ok(())
}

/// Create an abort reconfig proposal
pub async fn create_abort_reconfig_proposal(
    config: &CliConfig,
    epoch: u64,
    metadata: Vec<(String, String)>,
    tx_opts: &TxOptions,
) -> Result<()> {
    print_detail(&format!("\n{}", "Creating Abort Reconfig Proposal:".bold()));
    print_info(&format!("Target epoch: {epoch}"));
    print_metadata(&metadata);

    let mut client = HashiClient::new(config).await?;
    print_acting_validator(&client)?;

    if !prompt_continue("create this abort reconfig proposal", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let tx = client.build_create_proposal_transaction(CreateProposalParams::AbortReconfig {
        epoch,
        metadata,
    })?;

    print_info("Transaction: abort_reconfig::propose");
    let response = execute_or_simulate(&mut client, tx, tx_opts).await?;
    print_created_proposal_id(response.as_ref());
    Ok(())
}

/// Create an update guardian proposal
pub async fn create_update_guardian_proposal(
    config: &CliConfig,
    url: &str,
    metadata: Vec<(String, String)>,
    tx_opts: &TxOptions,
) -> Result<()> {
    print_detail(&format!(
        "\n{}",
        "Creating Update Guardian Proposal:".bold()
    ));
    print_detail(&format!("  URL:        {}", url));
    print_metadata(&metadata);

    let mut client = HashiClient::new(config).await?;
    print_acting_validator(&client)?;

    if !prompt_continue("create this update guardian proposal", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let tx = client.build_create_proposal_transaction(CreateProposalParams::UpdateGuardian {
        url: url.to_string(),
        metadata,
    })?;

    print_info("Transaction: update_guardian::propose");
    let response = execute_or_simulate(&mut client, tx, tx_opts).await?;
    print_created_proposal_id(response.as_ref());
    Ok(())
}

/// Create an emergency pause (or, with `unpause == true`, unpause) proposal.
///
/// Pausing uses a deliberately low quorum (default 5%) so a small fraction of
/// committee weight can halt the protocol quickly; unpausing requires the
/// normal 2/3 supermajority. Both paths target `emergency_pause::propose`.
pub async fn create_emergency_pause_proposal(
    config: &CliConfig,
    unpause: bool,
    metadata: Vec<(String, String)>,
    tx_opts: &TxOptions,
) -> Result<()> {
    let action = if unpause { "Unpause" } else { "Pause" };
    let title = format!("Creating Emergency {action} Proposal:");
    print_detail(&format!("\n{}", title.bold()));
    print_detail(&format!("  Action: {action}"));
    print_metadata(&metadata);

    let mut client = HashiClient::new(config).await?;
    print_acting_validator(&client)?;

    if !prompt_continue(
        &format!("create this emergency {} proposal", action.to_lowercase()),
        tx_opts,
    )
    .await?
    {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let tx = client.build_create_proposal_transaction(CreateProposalParams::EmergencyPause {
        pause: !unpause,
        metadata,
    })?;

    print_info("Transaction: emergency_pause::propose");
    let response = execute_or_simulate(&mut client, tx, tx_opts).await?;
    print_created_proposal_id(response.as_ref());
    Ok(())
}

/// Create a proposal to ignore (or re-admit) a registered committee member.
pub async fn create_ignore_member_proposal(
    config: &CliConfig,
    validator: &str,
    unignore: bool,
    metadata: Vec<(String, String)>,
    tx_opts: &TxOptions,
) -> Result<()> {
    let target: Address = validator
        .parse()
        .with_context(|| format!("invalid validator address: {validator}"))?;
    let action = if unignore { "Un-ignore" } else { "Ignore" };
    let title = format!("Creating {action} Member Proposal:");
    print_detail(&format!("\n{}", title.bold()));
    print_detail(&format!("  Target: {}", target));
    print_metadata(&metadata);

    let client = HashiClient::new(config).await?;

    // The flag is only read at the next committee formation. Tell the
    // operator when the change will actually bite.
    match client.onchain_state().pending_epoch_change() {
        Some(pending) => print_detail(&format!(
            "  Effect: a reconfiguration to epoch {pending} is already in flight — the change \
             takes effect one epoch later, at the formation after it completes",
        )),
        None => print_detail(
            "  Effect: at the next committee formation (start of the next reconfiguration)",
        ),
    }

    if !unignore {
        // Warn when the target carries so much weight that excluding it
        // approaches the BFT bound (see ignore_member.move's module doc).
        if let Some(committee) = client.onchain_state().current_committee() {
            let weight = committee.weight_of(&target).unwrap_or(0);
            let total = committee.total_weight();
            if total > 0 && weight * 10_000 / total > 2_500 {
                print_detail(&format!(
                    "  WARNING: target holds {weight} of {total} committee weight (> 25%). \
                     Exclusion only works while non-participating weight stays at or below \
                     1/3 of the committee — beyond that, governance and reconfiguration are \
                     both blocked."
                ));
            }
        }
    }

    print_acting_validator(&client)?;

    if !prompt_continue(
        &format!("create this {} member proposal", action.to_lowercase()),
        tx_opts,
    )
    .await?
    {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let mut client = client;
    let tx = client.build_create_proposal_transaction(CreateProposalParams::IgnoreMember {
        target_validator_address: target,
        ignored: !unignore,
        metadata,
    })?;

    print_info("Transaction: ignore_member::propose");
    let response = execute_or_simulate(&mut client, tx, tx_opts).await?;
    print_created_proposal_id(response.as_ref());
    Ok(())
}

// ============ Helper Functions ============

fn print_proposal_detailed(
    proposal: &Proposal,
    status: &str,
    details: Option<&crate::cli::client::ProposalDetails>,
    committee: Option<&hashi_types::committee::Committee>,
) {
    println!("{}", "━".repeat(60).dimmed());
    println!(
        "  {} {}",
        "ID:".bold(),
        display::format_address_full(&proposal.id).cyan()
    );
    println!(
        "  {} {}",
        "Type:".bold(),
        display::format_proposal_type(&proposal.proposal_type).green()
    );
    println!("  {} {}", "Status:".bold(), status);
    println!(
        "  {} {}",
        "Created:".bold(),
        display::format_timestamp(proposal.timestamp_ms)
    );

    if let Some(details) = details {
        println!(
            "  {} {}",
            "Creator:".bold(),
            details.creator.to_hex().dimmed()
        );

        // Vote tally + quorum progress.
        let status = match committee {
            Some(committee) => {
                let progress =
                    QuorumProgress::new(&details.votes, details.quorum_threshold_bps, committee);
                if progress.met() {
                    progress.describe().green().bold()
                } else {
                    progress.describe().yellow()
                }
            }
            None => "no committee formed yet".dimmed(),
        };
        println!("  {} {}", "Votes:".bold(), status);
        println!(
            "  {} {} bps ({:.2}%)",
            "Threshold:".bold(),
            details.quorum_threshold_bps,
            details.quorum_threshold_bps as f64 / 100.0
        );
        if !details.votes.is_empty() {
            println!("  {}", "Voters:".bold());
            for voter in &details.votes {
                println!("    - {}", voter.to_hex().dimmed());
            }
        }

        if !details.metadata.contents.is_empty() {
            println!("  {}", "Metadata:".bold());
            for entry in &details.metadata.contents {
                println!("    {}: {}", entry.key.dimmed(), entry.value);
            }
        }
    }

    println!("{}", "━".repeat(60).dimmed());
}

/// Ask the operator to confirm before a real execution. Returns `true` to
/// proceed. Always `true` with `-y/--yes`, or in dry-run and
/// serialize-unsigned mode, which change no on-chain state. Requires an
/// explicit `y`, and refuses when stdin is not a terminal (see
/// [`crate::cli::confirm`]).
pub(crate) async fn prompt_continue(action: &str, tx_opts: &TxOptions) -> Result<bool> {
    use crate::sui_tx_executor::TxMode;

    if tx_opts.skip_confirm || tx_opts.mode() != TxMode::Execute {
        return Ok(true);
    }
    eprintln!("\n{}", format!("About to {action}.").yellow());
    crate::cli::confirm()
}

#[cfg(test)]
#[path = "proposal_tests.rs"]
mod tests;
