// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Config command implementations

use age::Encryptor;
use age::x25519;
use anyhow::Result;
use colored::Colorize;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use crate::cli::client::HashiClient;
use crate::cli::config::CliConfig;
use crate::cli::print_info;
use crate::cli::print_success;
use crate::cli::print_warning;
use crate::cli::types::display;

/// Generate a configuration template file
pub fn generate_template(output: &Path) -> Result<()> {
    let template = CliConfig::generate_template();

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
pub fn show_config(config: &CliConfig) -> Result<()> {
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

    if let Some(ref btc) = config.bitcoin {
        println!();
        println!("  {}", "[bitcoin]".bold().dimmed());
        if let Some(ref url) = btc.rpc_url {
            println!("  {} {}", "RPC URL:".bold(), url.cyan());
        }
        if let Some(ref user) = btc.rpc_user {
            println!("  {} {}", "RPC User:".bold(), user);
        }
        if btc.rpc_password.is_some() {
            println!("  {} {}", "RPC Password:".bold(), "***".dimmed());
        }
        if let Some(ref network) = btc.network {
            println!("  {} {}", "Network:".bold(), network);
        }
        if let Some(ref key_path) = btc.private_key_path {
            println!(
                "  {} {}",
                "Private Key:".bold(),
                key_path.display().to_string().green()
            );
        }
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

/// Save an encrypted backup of the current config and referenced files
pub fn backup(config: &CliConfig, backup_age_pubkey_override: Option<String>) -> Result<()> {
    let age_pubkey = backup_age_pubkey_override
        .map(|value| x25519::Recipient::from_str(&value).map_err(anyhow::Error::msg))
        .transpose()?
        .or_else(|| config.backup_age_pubkey.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No age public key configured. Pass --backup-age-pubkey or set backup_age_pubkey in the config file."
            )
        })?;

    if config.loaded_from_path.is_none() {
        anyhow::bail!(
            "No config file is currently in use. Pass --config with a config file path before running backup."
        );
    }

    let files = config.backup_file_paths();

    for file in &files {
        if !file.exists() {
            anyhow::bail!("Backup input does not exist: {}", file.display());
        }
    }

    print_info(&format!(
        "Backing up {} file(s) using age recipient {}",
        files.len(),
        age_pubkey
    ));

    let output_path = encrypt_files_to_age_archive(&files, &age_pubkey)?;

    print_success(&format!("Backup completed: {}", output_path.display()));

    Ok(())
}

fn encrypt_files_to_age_archive(
    files: &[PathBuf],
    age_pubkey: &x25519::Recipient,
) -> Result<PathBuf> {
    let output_path = encrypted_backup_output_path();
    let output = File::create(&output_path)?;
    let encryptor = Encryptor::with_recipients(std::iter::once(age_pubkey as _))?;
    let mut encrypted = encryptor.wrap_output(output)?;
    let mut archive = tar::Builder::new(&mut encrypted);

    for file in files {
        let archive_path = PathBuf::from(file.file_name().ok_or_else(|| {
            anyhow::anyhow!("Backup input does not have a file name: {}", file.display())
        })?);
        archive.append_path_with_name(file, &archive_path)?;
        print_info(&format!(
            "Added {} to {}",
            file.display(),
            archive_path.display()
        ));
    }

    archive.finish()?;
    drop(archive);
    encrypted.finish()?;

    Ok(output_path)
}

fn encrypted_backup_output_path() -> PathBuf {
    let timestamp = jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .strftime("%Y-%m-%d-%H-%M-%S-%Z")
        .to_string();
    PathBuf::from(format!("hashi-config-backup-{timestamp}.tar.age"))
}

/// Show on-chain configuration values
pub async fn show_onchain_config(config: &CliConfig) -> Result<()> {
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
