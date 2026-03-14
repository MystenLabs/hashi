//! Proposal command implementations

use anyhow::Context;
use anyhow::Result;
use colored::Colorize;
use sui_sdk_types::Address;
use tabled::Table;
use tabled::Tabled;

use crate::cli::TxOptions;
use crate::cli::client::CreateProposalParams;
use crate::cli::client::HashiClient;
use crate::cli::client::SimulationResult;
use crate::cli::client::get_proposal_type_arg;
use crate::cli::config::CliConfig;
use crate::cli::print_info;
use crate::cli::print_warning;
use crate::cli::types::Proposal;
use crate::cli::types::display;

/// Print metadata if present
fn print_metadata(metadata: &[(String, String)]) {
    if !metadata.is_empty() {
        println!("  {}", "Metadata:".bold());
        for (key, value) in metadata {
            println!("    {}: {}", key.dimmed(), value);
        }
    }
}

/// Print simulation (dry-run) results
fn print_simulation_result(result: &SimulationResult) {
    println!("\n{}", "🔍 Dry-run Results:".bold());
    println!("  {} {}", "Sender:".dimmed(), result.sender.to_hex().cyan());
    println!(
        "  {} {} MIST",
        "Gas Budget:".dimmed(),
        result.gas_budget.to_string().cyan()
    );
    println!(
        "  {} {} MIST/unit",
        "Gas Price:".dimmed(),
        result.gas_price.to_string().cyan()
    );
    let max_cost_sui = (result.gas_budget as f64) / 1_000_000_000.0;
    println!(
        "  {} {:.6} SUI",
        "Max Cost:".dimmed(),
        format!("{:.6}", max_cost_sui).yellow()
    );
    println!(
        "\n  {} Transaction was simulated successfully. Use without --dry-run to execute.",
        "✓".green()
    );
}

/// Execute or simulate a transaction based on tx_opts
///
/// Returns Ok(true) if execution/simulation succeeded, Ok(false) if no keypair configured.
async fn execute_or_simulate(
    client: &mut HashiClient,
    tx: sui_transaction_builder::TransactionBuilder,
    tx_opts: &TxOptions,
) -> Result<bool> {
    if !client.can_execute() {
        print_warning("Transaction execution requires keypair configuration (--keypair).");
        return Ok(false);
    }

    if tx_opts.dry_run {
        print_info("Simulating transaction (dry-run)...");
        let result = client.simulate(tx).await?;
        print_simulation_result(&result);
    } else {
        print_info("Executing transaction...");
        let response = client.execute(tx).await?;
        let digest = response.transaction().digest();
        println!(
            "\n{} Transaction submitted: {}",
            "✓".green(),
            digest.to_string().cyan()
        );
    }

    Ok(true)
}

/// List all active proposals
pub async fn list_proposals(
    config: &CliConfig,
    type_filter: Option<String>,
    detailed: bool,
) -> Result<()> {
    let client = HashiClient::new(config).await?;

    print_info("Fetching proposals...");

    let proposals = client.fetch_proposals();

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
pub async fn view_proposal(config: &CliConfig, proposal_id: &str) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let proposal_addr = Address::from_hex(proposal_id)
        .with_context(|| format!("Invalid proposal ID: {}", proposal_id))?;

    print_info(&format!("Fetching proposal {}...", proposal_id));

    let proposal = client
        .fetch_proposal(&proposal_addr)
        .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_id))?;

    println!();
    print_proposal_detailed(&proposal);

    Ok(())
}

/// Vote on a proposal
pub async fn vote(config: &CliConfig, proposal_id: &str, tx_opts: &TxOptions) -> Result<()> {
    let mut client = HashiClient::new(config).await?;

    let proposal_addr = Address::from_hex(proposal_id)
        .with_context(|| format!("Invalid proposal ID: {}", proposal_id))?;

    print_info(&format!("Fetching proposal {}...", proposal_id));

    let proposal = client
        .fetch_proposal(&proposal_addr)
        .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_id))?;

    let proposal_type_str = display::format_proposal_type(&proposal.proposal_type);

    println!("\n{}", "Proposal Details:".bold());
    println!("  Type: {}", proposal_type_str.cyan());

    if !tx_opts.skip_confirm && !confirm_action("vote on this proposal").await? {
        return Ok(());
    }

    print_info("Building vote transaction...");

    // Infer the type tag from the on-chain proposal type
    let type_arg = get_proposal_type_arg(client.hashi_ids().package_id, &proposal.proposal_type)?;
    let tx = client.build_vote_transaction(proposal_addr, type_arg);

    print_info(&format!(
        "Transaction: proposal::vote<{}> on {}",
        proposal_type_str, proposal_id
    ));

    execute_or_simulate(&mut client, tx, tx_opts).await?;
    Ok(())
}

/// Remove vote from a proposal
pub async fn remove_vote(config: &CliConfig, proposal_id: &str, tx_opts: &TxOptions) -> Result<()> {
    let mut client = HashiClient::new(config).await?;

    let proposal_addr = Address::from_hex(proposal_id)
        .with_context(|| format!("Invalid proposal ID: {}", proposal_id))?;

    print_info(&format!("Fetching proposal {}...", proposal_id));

    let proposal = client
        .fetch_proposal(&proposal_addr)
        .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_id))?;

    let proposal_type_str = display::format_proposal_type(&proposal.proposal_type);

    println!("\n{}", "Proposal Details:".bold());
    println!("  Type: {}", proposal_type_str.cyan());

    if !tx_opts.skip_confirm && !confirm_action("remove your vote from this proposal").await? {
        return Ok(());
    }

    print_info("Building remove_vote transaction...");

    // Infer the type tag from the on-chain proposal type
    let type_arg = get_proposal_type_arg(client.hashi_ids().package_id, &proposal.proposal_type)?;
    let tx = client.build_remove_vote_transaction(proposal_addr, type_arg);

    print_info(&format!(
        "Transaction: proposal::remove_vote<{}> on {}",
        proposal_type_str, proposal_id
    ));

    execute_or_simulate(&mut client, tx, tx_opts).await?;
    Ok(())
}

/// Create an upgrade proposal
pub async fn create_upgrade_proposal(
    config: &CliConfig,
    digest: &str,
    metadata: Vec<(String, String)>,
    tx_opts: &TxOptions,
) -> Result<()> {
    let digest_bytes =
        hex::decode(digest.trim_start_matches("0x")).context("Invalid digest hex")?;

    println!("\n{}", "Creating Upgrade Proposal:".bold());
    println!("  Digest: 0x{}", hex::encode(&digest_bytes));
    print_metadata(&metadata);

    if !tx_opts.skip_confirm && !confirm_action("create this upgrade proposal").await? {
        return Ok(());
    }

    let mut client = HashiClient::new(config).await?;
    let tx = client.build_create_proposal_transaction(CreateProposalParams::Upgrade {
        digest: digest_bytes,
        metadata,
    });

    print_info("Transaction: upgrade::propose");
    execute_or_simulate(&mut client, tx, tx_opts).await?;
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

    println!("\n{}", "Creating Update Config Proposal:".bold());
    println!("  Key:   {}", key);
    println!("  Value: {}", value_str);
    print_metadata(&metadata);

    if !tx_opts.skip_confirm && !confirm_action("create this config update proposal").await? {
        return Ok(());
    }

    let mut client = HashiClient::new(config).await?;
    let tx = client.build_create_proposal_transaction(CreateProposalParams::UpdateConfig {
        key: key.to_string(),
        value,
        metadata,
    });

    print_info("Transaction: update_config::propose");
    execute_or_simulate(&mut client, tx, tx_opts).await?;
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
    println!("\n{}", "Creating Enable Version Proposal:".bold());
    println!("  Version: {}", version);
    print_metadata(&metadata);

    if !tx_opts.skip_confirm && !confirm_action("create this enable version proposal").await? {
        return Ok(());
    }

    let mut client = HashiClient::new(config).await?;
    let tx = client.build_create_proposal_transaction(CreateProposalParams::EnableVersion {
        version,
        metadata,
    });

    print_info("Transaction: enable_version::propose");
    execute_or_simulate(&mut client, tx, tx_opts).await?;
    Ok(())
}

/// Create a disable version proposal
pub async fn create_disable_version_proposal(
    config: &CliConfig,
    version: u64,
    metadata: Vec<(String, String)>,
    tx_opts: &TxOptions,
) -> Result<()> {
    println!("\n{}", "Creating Disable Version Proposal:".bold());
    println!("  Version: {}", version);
    print_metadata(&metadata);

    if !tx_opts.skip_confirm && !confirm_action("create this disable version proposal").await? {
        return Ok(());
    }

    let mut client = HashiClient::new(config).await?;
    let tx = client.build_create_proposal_transaction(CreateProposalParams::DisableVersion {
        version,
        metadata,
    });

    print_info("Transaction: disable_version::propose");
    execute_or_simulate(&mut client, tx, tx_opts).await?;
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

async fn confirm_action(action: &str) -> Result<bool> {
    use tokio::io::AsyncBufReadExt;
    use tokio::io::BufReader;

    println!(
        "\n{}",
        format!("Are you sure you want to {}? (y/N)", action).yellow()
    );

    let mut reader = BufReader::new(tokio::io::stdin());
    let mut input = String::new();
    reader.read_line(&mut input).await?;

    if input.trim().eq_ignore_ascii_case("y") {
        Ok(true)
    } else {
        print_warning("Cancelled.");
        Ok(false)
    }
}
