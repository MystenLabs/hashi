//! Config command implementations

use anyhow::Result;
use colored::Colorize;
use std::path::Path;

use crate::client::HashiClient;
use crate::config::Config;
use crate::print_info;
use crate::print_success;
use crate::print_warning;
use crate::types::display;

/// Generate a configuration template file
pub fn generate_template(output: &Path) -> Result<()> {
    let template = Config::generate_template();

    if output.exists() {
        print_warning(&format!(
            "File {} already exists. Overwrite? (y/N)",
            output.display()
        ));
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            print_info("Cancelled.");
            return Ok(());
        }
    }

    std::fs::write(output, &template)?;
    print_success(&format!(
        "Configuration template written to {}",
        output.display()
    ));

    println!("\n{}", "Next steps:".bold());
    println!("  1. Edit {} with your settings", output.display());
    println!("  2. Set your Sui RPC URL");
    println!("  3. Add the Hashi package and object IDs");
    println!("  4. Configure your keypair path");

    Ok(())
}

/// Show the current effective configuration
pub fn show_config(config: &Config) -> Result<()> {
    println!("\n{}", "Current Configuration:".bold());
    println!("{}", "━".repeat(50).dimmed());

    println!("  {} {}", "Sui RPC URL:".bold(), config.sui_rpc_url.cyan());

    if let Some(ref package_id) = config.package_id {
        println!(
            "  {} {}",
            "Package ID:".bold(),
            display::format_address_full(package_id).green()
        );
    } else {
        println!("  {} {}", "Package ID:".bold(), "(not set)".red());
    }

    if let Some(ref hashi_id) = config.hashi_object_id {
        println!(
            "  {} {}",
            "Hashi Object ID:".bold(),
            display::format_address_full(hashi_id).green()
        );
    } else {
        println!("  {} {}", "Hashi Object ID:".bold(), "(not set)".red());
    }

    if let Some(ref keypair_path) = config.keypair_path {
        println!(
            "  {} {}",
            "Keypair Path:".bold(),
            keypair_path.display().to_string().green()
        );
    } else {
        println!("  {} {}", "Keypair Path:".bold(), "(not set)".yellow());
    }

    if let Some(ref gas_coin) = config.gas_coin {
        println!(
            "  {} {}",
            "Gas Coin:".bold(),
            display::format_address_full(gas_coin)
        );
    }

    println!("{}", "━".repeat(50).dimmed());

    // Validation
    if config.package_id.is_none() || config.hashi_object_id.is_none() {
        println!();
        print_warning(
            "Configuration is incomplete. Set package_id and hashi_object_id to use the CLI.",
        );
    }

    Ok(())
}

/// Show on-chain configuration values
pub async fn show_onchain_config(config: &Config) -> Result<()> {
    let client = HashiClient::new(config).await?;

    print_info("Fetching on-chain configuration...");

    let epoch = client.fetch_epoch();

    println!("\n{}", "On-chain Hashi Configuration:".bold());
    println!("{}", "━".repeat(60).dimmed());
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

    // TODO: Fetch and display more configuration details using hashi::onchain::OnchainState:
    // - Enabled versions
    // - Deposit fee
    // - Paused state
    // - Committee info
    // - etc.

    println!("{}", "━".repeat(60).dimmed());

    print_info("Full configuration fetching is a TODO - will use OnchainState for more details.");

    Ok(())
}
