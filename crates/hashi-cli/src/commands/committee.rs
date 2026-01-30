//! Committee command implementations

use anyhow::Context;
use anyhow::Result;
use colored::Colorize;
use sui_sdk_types::Address;
use tabled::Table;
use tabled::Tabled;

use crate::client::HashiClient;
use crate::config::Config;
use crate::print_info;
use crate::print_warning;
use crate::types::display;

/// List committee members
pub async fn list_members(config: &Config, epoch: Option<u64>) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let current_epoch = client.fetch_epoch();

    // Note: Currently only the current epoch's members are available
    if let Some(requested_epoch) = epoch
        && requested_epoch != current_epoch
    {
        print_warning(&format!(
            "Only current epoch ({}) data is available. Showing current epoch.",
            current_epoch
        ));
    }

    print_info(&format!(
        "Fetching committee for epoch {}...",
        current_epoch
    ));

    let members = client.fetch_committee_members();

    if members.is_empty() {
        println!("\n{}", "No committee members found.".dimmed());
        print_warning("This may indicate the committee data could not be fetched.");
        return Ok(());
    }

    println!("\n👥 Committee Members (Epoch {}):\n", current_epoch);

    #[derive(Tabled)]
    struct MemberRow {
        #[tabled(rename = "Validator Address")]
        validator: String,
        #[tabled(rename = "Operator Address")]
        operator: String,
    }

    let rows: Vec<MemberRow> = members
        .iter()
        .map(|m| MemberRow {
            validator: display::format_address(&m.validator_address),
            operator: display::format_address(&m.operator_address),
        })
        .collect();

    let table = Table::new(rows).to_string();
    println!("{}", table);

    println!(
        "\n  {} {} member(s)",
        "ℹ".blue(),
        members.len().to_string().bold()
    );

    Ok(())
}

/// View a specific committee member
pub async fn view_member(config: &Config, address: &str) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let member_addr =
        Address::from_hex(address).with_context(|| format!("Invalid address: {}", address))?;

    print_info(&format!("Fetching member info for {}...", address));

    let members = client.fetch_committee_members();

    let member = members.iter().find(|m| m.validator_address == member_addr);

    match member {
        Some(m) => {
            println!("\n{}", "Committee Member Details:".bold());
            println!("{}", "━".repeat(60).dimmed());
            println!(
                "  {} {}",
                "Validator:".bold(),
                display::format_address_full(&m.validator_address).cyan()
            );
            println!(
                "  {} {}",
                "Operator:".bold(),
                display::format_address_full(&m.operator_address)
            );
            if let Some(uri) = &m.https_address {
                println!("  {} {}", "HTTPS:".bold(), uri);
            }
            println!("{}", "━".repeat(60).dimmed());
        }
        None => {
            print_warning(&format!(
                "Address {} is not a member of the current committee.",
                display::format_address(&member_addr)
            ));
        }
    }

    Ok(())
}

/// Show current epoch information
pub async fn show_epoch(config: &Config) -> Result<()> {
    let client = HashiClient::new(config).await?;

    print_info("Fetching epoch information...");

    let epoch = client.fetch_epoch();

    println!("\n{}", "Epoch Information:".bold());
    println!("{}", "━".repeat(50).dimmed());
    println!(
        "  {} {}",
        "Hashi Object:".bold(),
        display::format_address_full(&config.hashi_object_id()).cyan()
    );
    println!(
        "  {} {}",
        "Current Epoch:".bold(),
        epoch.to_string().green()
    );
    println!("{}", "━".repeat(50).dimmed());

    Ok(())
}
