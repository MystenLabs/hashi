// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Committee command implementations

use anyhow::Context;
use anyhow::Result;
use colored::Colorize;
use sui_sdk_types::Address;
use tabled::Table;
use tabled::Tabled;

use crate::cli::TxOptions;
use crate::cli::client::HashiClient;
use crate::cli::commands::proposal::execute_or_simulate;
use crate::cli::commands::proposal::prompt_continue;
use crate::cli::config::CliConfig;
use crate::cli::print_detail;
use crate::cli::print_info;
use crate::cli::print_warning;
use crate::cli::types::display;

/// List committee members
pub async fn list_members(config: &CliConfig, epoch: Option<u64>) -> Result<()> {
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
        #[tabled(rename = "Ignored")]
        ignored: String,
        #[tabled(rename = "Resigned")]
        resigned: String,
    }

    let rows: Vec<MemberRow> = members
        .iter()
        .map(|m| MemberRow {
            validator: display::format_address(&m.validator_address),
            operator: display::format_address(&m.operator_address),
            // Registry view: shows the governance flag as soon as it is set,
            // before the epoch-boundary effect on the committee.
            ignored: if m.ignored {
                "yes".to_string()
            } else {
                String::new()
            },
            resigned: if m.resigned {
                "yes".to_string()
            } else {
                String::new()
            },
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
pub async fn view_member(config: &CliConfig, address: &str) -> Result<()> {
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
            if let Some(uri) = &m.endpoint_url {
                println!("  {} {}", "Endpoint:".bold(), uri);
            }
            if m.ignored {
                println!(
                    "  {} yes (excluded from the next committee formation)",
                    "Ignored:".bold()
                );
            }
            if m.resigned {
                println!(
                    "  {} yes (removed at the next epoch transition)",
                    "Resigned:".bold()
                );
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
pub async fn show_epoch(config: &CliConfig) -> Result<()> {
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

/// Refuse an abort the chain would reject, from the scraped pending epoch and
/// Sui's current epoch: nothing pending (`reconfig::ENotReconfiguring`), or a
/// pending epoch that is still Sui's current epoch
/// (`committee_set::EPendingEpochStillCurrent`). Returns the epoch the abort
/// would tear down.
pub fn refuse_unabortable_reconfig(pending_epoch: Option<u64>, sui_epoch: u64) -> Result<u64> {
    let Some(pending_epoch) = pending_epoch else {
        anyhow::bail!("no reconfiguration is in progress; there is nothing to abort");
    };
    anyhow::ensure!(
        pending_epoch != sui_epoch,
        "the pending reconfiguration targets Sui's current epoch ({sui_epoch}), so it may still \
         complete; the chain refuses the abort until Sui's epoch moves past it"
    );
    Ok(pending_epoch)
}

/// Abort a reconfiguration that has overrun its Sui epoch
/// (`reconfig::abort_reconfig`). Permissionless: any funded signer may send
/// it, and no vote is involved.
pub async fn abort_reconfig(config: &CliConfig, tx_opts: &TxOptions) -> Result<()> {
    let mut client = HashiClient::new(config).await?;
    let sui_epoch = client.fetch_sui_epoch().await?;
    let pending_epoch =
        refuse_unabortable_reconfig(client.onchain_state().pending_epoch_change(), sui_epoch)?;

    print_detail(&format!(
        "\n{}",
        "Aborting the pending reconfiguration:".bold()
    ));
    print_detail(&format!("  Pending Hashi epoch: {pending_epoch}"));
    print_detail(&format!("  Current Sui epoch:   {sui_epoch}"));
    print_detail(&format!(
        "  Effect: the pending committee is discarded. Hashi stays at epoch {} under its current \
         committee, and a fresh reconfiguration can then form a new committee from the current \
         validator set.",
        client.fetch_epoch()
    ));

    if !prompt_continue("abort the pending reconfiguration", tx_opts).await? {
        print_warning("Aborted.");
        return Ok(());
    }

    let tx = client.build_abort_reconfig_transaction()?;
    print_info("Transaction: reconfig::abort_reconfig");
    execute_or_simulate(&mut client, tx, tx_opts).await?;
    Ok(())
}

#[cfg(test)]
#[path = "committee_tests.rs"]
mod tests;
