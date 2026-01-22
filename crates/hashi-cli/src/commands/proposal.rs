//! Proposal command implementations

use anyhow::Context;
use anyhow::Result;
use colored::Colorize;
use sui_sdk_types::Address;
use tabled::Table;
use tabled::Tabled;

use crate::TxOptions;
use crate::client::CreateProposalParams;
use crate::client::HashiClient;
use crate::config::Config;
use crate::print_info;
use crate::print_warning;
use crate::types::Proposal;
use crate::types::display;

/// List all active proposals
pub async fn list_proposals(
    config: &Config,
    type_filter: Option<String>,
    detailed: bool,
) -> Result<()> {
    let client = HashiClient::new(config).await?;

    print_info("Fetching proposals...");

    let proposals = client.fetch_proposals().await?;

    if proposals.is_empty() {
        println!("\n{}", "No active proposals found.".dimmed());
        return Ok(());
    }

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

    if proposals.is_empty() {
        println!(
            "\n{}",
            format!(
                "No proposals found matching type filter: {}",
                type_filter.unwrap_or_default()
            )
            .dimmed()
        );
        return Ok(());
    }

    println!("\n📋 Active Proposals:\n");

    if detailed {
        for proposal in &proposals {
            print_proposal_detailed(proposal);
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
        }

        let rows: Vec<ProposalRow> = proposals
            .iter()
            .map(|p| ProposalRow {
                id: display::format_address(&p.id),
                proposal_type: display::format_proposal_type(&p.proposal_type),
                timestamp: display::format_timestamp(p.timestamp_ms),
            })
            .collect();

        let table = Table::new(rows).to_string();
        println!("{}", table);
    }

    println!(
        "\n{} {} proposal(s) found",
        "ℹ".blue(),
        proposals.len().to_string().bold()
    );

    Ok(())
}

/// View details of a specific proposal
pub async fn view_proposal(config: &Config, proposal_id: &str) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let proposal_addr = Address::from_hex(proposal_id)
        .with_context(|| format!("Invalid proposal ID: {}", proposal_id))?;

    print_info(&format!("Fetching proposal {}...", proposal_id));

    let proposal = client
        .fetch_proposal(&proposal_addr)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_id))?;

    println!();
    print_proposal_detailed(&proposal);

    Ok(())
}

/// Vote on a proposal
pub async fn vote(
    config: &Config,
    proposal_id: &str,
    proposal_type: crate::ProposalType,
    tx_opts: &TxOptions,
) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let proposal_addr = Address::from_hex(proposal_id)
        .with_context(|| format!("Invalid proposal ID: {}", proposal_id))?;

    print_info(&format!("Fetching proposal {}...", proposal_id));

    let proposal = client
        .fetch_proposal(&proposal_addr)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_id))?;

    println!("\n{}", "Proposal Details:".bold());
    println!(
        "  Type: {}",
        display::format_proposal_type(&proposal.proposal_type).cyan()
    );

    if !tx_opts.skip_confirm && !confirm_action("vote on this proposal")? {
        return Ok(());
    }

    print_info("Building vote transaction...");

    let gas_budget = client.resolve_gas_budget(tx_opts).await?;
    let _tx = client.build_vote_transaction(proposal_addr, &proposal_type)?;

    print_info(&format!("Gas budget: {} MIST", gas_budget));

    // TODO: Execute transaction using SuiTxExecutor pattern
    // Would need to load keypair and call executor.execute(tx)
    print_warning("Transaction built. Execution requires keypair - see SuiTxExecutor.");

    Ok(())
}

/// Remove vote from a proposal
pub async fn remove_vote(
    config: &Config,
    proposal_id: &str,
    proposal_type: crate::ProposalType,
    tx_opts: &TxOptions,
) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let proposal_addr = Address::from_hex(proposal_id)
        .with_context(|| format!("Invalid proposal ID: {}", proposal_id))?;

    print_info(&format!("Fetching proposal {}...", proposal_id));

    let proposal = client
        .fetch_proposal(&proposal_addr)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_id))?;

    println!("\n{}", "Proposal Details:".bold());
    println!(
        "  Type: {}",
        display::format_proposal_type(&proposal.proposal_type).cyan()
    );

    if !tx_opts.skip_confirm && !confirm_action("remove your vote from this proposal")? {
        return Ok(());
    }

    print_info("Building remove_vote transaction...");

    let gas_budget = client.resolve_gas_budget(tx_opts).await?;
    let _tx = client.build_remove_vote_transaction(proposal_addr, &proposal_type)?;

    print_info(&format!("Gas budget: {} MIST", gas_budget));
    print_warning("Transaction built. Execution requires keypair - see SuiTxExecutor.");

    Ok(())
}

/// Create an upgrade proposal
pub async fn create_upgrade_proposal(
    config: &Config,
    digest: &str,
    _metadata: Vec<String>,
    tx_opts: &TxOptions,
) -> Result<()> {
    let digest_bytes =
        hex::decode(digest.trim_start_matches("0x")).context("Invalid digest hex")?;

    println!("\n{}", "Creating Upgrade Proposal:".bold());
    println!("  Digest: 0x{}", hex::encode(&digest_bytes));

    if !tx_opts.skip_confirm && !confirm_action("create this upgrade proposal")? {
        return Ok(());
    }

    let client = HashiClient::new(config).await?;
    let gas_budget = client.resolve_gas_budget(tx_opts).await?;

    let _tx = client.build_create_proposal_transaction(CreateProposalParams::Upgrade {
        digest: digest_bytes,
    })?;

    print_info(&format!("Gas budget: {} MIST", gas_budget));
    print_warning("Transaction built. Execution requires keypair - see SuiTxExecutor.");

    Ok(())
}

/// Create an update deposit fee proposal
pub async fn create_update_deposit_fee_proposal(
    config: &Config,
    fee: u64,
    _metadata: Vec<String>,
    tx_opts: &TxOptions,
) -> Result<()> {
    println!("\n{}", "Creating Update Deposit Fee Proposal:".bold());
    println!("  New fee: {} satoshis", fee);

    if !tx_opts.skip_confirm && !confirm_action("create this deposit fee update proposal")? {
        return Ok(());
    }

    let client = HashiClient::new(config).await?;
    let gas_budget = client.resolve_gas_budget(tx_opts).await?;

    let _tx =
        client.build_create_proposal_transaction(CreateProposalParams::UpdateDepositFee { fee })?;

    print_info(&format!("Gas budget: {} MIST", gas_budget));
    print_warning("Transaction built. Execution requires keypair - see SuiTxExecutor.");

    Ok(())
}

/// Create an enable version proposal
pub async fn create_enable_version_proposal(
    config: &Config,
    version: u64,
    _metadata: Vec<String>,
    tx_opts: &TxOptions,
) -> Result<()> {
    println!("\n{}", "Creating Enable Version Proposal:".bold());
    println!("  Version: {}", version);

    if !tx_opts.skip_confirm && !confirm_action("create this enable version proposal")? {
        return Ok(());
    }

    let client = HashiClient::new(config).await?;
    let gas_budget = client.resolve_gas_budget(tx_opts).await?;

    let _tx = client
        .build_create_proposal_transaction(CreateProposalParams::EnableVersion { version })?;

    print_info(&format!("Gas budget: {} MIST", gas_budget));
    print_warning("Transaction built. Execution requires keypair - see SuiTxExecutor.");

    Ok(())
}

/// Create a disable version proposal
pub async fn create_disable_version_proposal(
    config: &Config,
    version: u64,
    _metadata: Vec<String>,
    tx_opts: &TxOptions,
) -> Result<()> {
    println!("\n{}", "Creating Disable Version Proposal:".bold());
    println!("  Version: {}", version);

    if !tx_opts.skip_confirm && !confirm_action("create this disable version proposal")? {
        return Ok(());
    }

    let client = HashiClient::new(config).await?;
    let gas_budget = client.resolve_gas_budget(tx_opts).await?;

    let _tx = client
        .build_create_proposal_transaction(CreateProposalParams::DisableVersion { version })?;

    print_info(&format!("Gas budget: {} MIST", gas_budget));
    print_warning("Transaction built. Execution requires keypair - see SuiTxExecutor.");

    Ok(())
}

// ============ Helper Functions ============

fn print_proposal_detailed(proposal: &Proposal) {
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
    println!(
        "  {} {}",
        "Created:".bold(),
        display::format_timestamp(proposal.timestamp_ms)
    );
    println!("{}", "━".repeat(60).dimmed());
}

fn confirm_action(action: &str) -> Result<bool> {
    println!(
        "\n{}",
        format!("Are you sure you want to {}? (y/N)", action).yellow()
    );
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("y") {
        Ok(true)
    } else {
        print_warning("Cancelled.");
        Ok(false)
    }
}
