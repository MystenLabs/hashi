// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Deposit command implementations

use anyhow::Context;
use anyhow::Result;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::XOnlyPublicKey;
use colored::Colorize;
use hashi_types::bitcoin::BitcoinAddress;

use crate::cli::DepositCommands;
use crate::cli::OutputFormat;
use crate::cli::TxOptions;
use crate::cli::client::HashiClient;
use crate::cli::config::CliConfig;
use crate::cli::print_info;
use crate::cli::print_success;
use crate::cli::types::display;

pub async fn run(action: DepositCommands, config: &CliConfig, tx_opts: &TxOptions) -> Result<()> {
    match action {
        DepositCommands::GenerateAddress { recipient } => {
            generate_address(config, &recipient).await
        }
        DepositCommands::Request {
            txid,
            outputs,
            recipient,
        } => {
            request_all(
                config,
                tx_opts,
                &txid,
                outputs.as_deref(),
                recipient.as_deref(),
            )
            .await
        }
        DepositCommands::RequestSingle {
            txid,
            vout,
            amount,
            recipient,
        } => request(config, tx_opts, &txid, vout, amount, recipient.as_deref()).await,
        DepositCommands::Status { request_id } => status(config, &request_id).await,
        DepositCommands::List {
            output_format,
            json,
        } => {
            let output_format = if json {
                OutputFormat::Json
            } else {
                output_format
            };
            list(config, output_format).await
        }
    }
}

/// Parse raw on-chain MPC public key bytes and derive the 2-of-2 deposit address.
pub fn cli_derive_deposit_address(
    mpc_pubkey_bytes: &[u8],
    guardian_btc_pubkey_bytes: &[u8],
    recipient: Option<&sui_sdk_types::Address>,
    btc_network: bitcoin::Network,
) -> Result<BitcoinAddress> {
    use fastcrypto::groups::secp256k1::ProjectivePoint;
    use fastcrypto::serde_helpers::ToFromByteArray;

    anyhow::ensure!(
        mpc_pubkey_bytes.len() == 33,
        "MPC key must be 33 bytes (compressed), got {}",
        mpc_pubkey_bytes.len(),
    );
    let mpc_key = <ProjectivePoint as ToFromByteArray<33>>::from_byte_array(
        mpc_pubkey_bytes
            .try_into()
            .context("MPC key must be 33 bytes")?,
    )
    .context("Failed to parse MPC key as ProjectivePoint")?;

    let guardian_btc_pubkey = XOnlyPublicKey::from_slice(guardian_btc_pubkey_bytes)
        .context("Guardian BTC pubkey must be 32 bytes (x-only)")?;

    crate::deposits::derive_deposit_address(&mpc_key, &guardian_btc_pubkey, recipient, btc_network)
}

async fn generate_address(config: &CliConfig, recipient: &str) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let mpc_pubkey = client.fetch_mpc_public_key();
    if mpc_pubkey.is_empty() {
        anyhow::bail!("MPC public key not available on-chain. Has the committee completed DKG?");
    }
    let guardian_btc_pubkey = client.fetch_guardian_btc_public_key().context(
        "Guardian BTC pubkey is not yet on-chain. Did finish_publish run with --guardian-btc-public-key?",
    )?;

    let is_change = recipient.is_empty();
    let recipient_addr = if is_change {
        None
    } else {
        Some(
            recipient
                .parse::<sui_sdk_types::Address>()
                .context("Invalid recipient Sui address")?,
        )
    };

    let btc_network = crate::btc_monitor::config::parse_btc_network(
        config.bitcoin.as_ref().and_then(|b| b.network.as_deref()),
    )?;

    let address = cli_derive_deposit_address(
        &mpc_pubkey,
        &guardian_btc_pubkey,
        recipient_addr.as_ref(),
        btc_network,
    )?;

    let title = if is_change {
        "Deposit Address (Change Address)"
    } else {
        "Deposit Address"
    };

    println!("\n{}", title.bold());
    println!("{}", "━".repeat(50).dimmed());
    println!("  {} {}", "Address:".bold(), address.to_string().green());
    println!("  {} {:?}", "Network:".bold(), btc_network);
    if !is_change {
        println!("  {} {}", "hBTC Recipient:".bold(), recipient);
    }
    println!("{}", "━".repeat(50).dimmed());

    Ok(())
}

async fn request(
    config: &CliConfig,
    tx_opts: &TxOptions,
    txid: &str,
    vout: u32,
    amount: u64,
    recipient: Option<&str>,
) -> Result<()> {
    use crate::sui_tx_executor::TxMode;

    config.validate()?;

    let hashi_ids = crate::config::HashiIds {
        package_id: config.package_id(),
        hashi_object_id: config.hashi_object_id(),
    };

    // A keypair is optional: serialize/dry-run only need the sender address.
    let signer = config.load_keypair()?;
    if tx_opts.mode() == TxMode::Execute && signer.is_none() {
        anyhow::bail!(
            "Keypair required to submit a deposit request (set keypair_path in config), \
             or use --serialize-unsigned-transaction to emit an unsigned transaction."
        );
    }

    // Sender: explicit --sender (e.g. a multisig), else the keypair's address.
    let sender = tx_opts
        .sender
        .or_else(|| signer.as_ref().map(|s| s.verifying_key().derive_address()));

    // hBTC recipient defaults to the sender when not given explicitly.
    let derivation_path = match recipient {
        Some(r) => Some(
            r.parse::<sui_sdk_types::Address>()
                .context("Invalid recipient Sui address")?,
        ),
        None => {
            let addr = sender.context(
                "No --recipient given and no sender to default to; pass --recipient, \
                 --sender, or configure a keypair",
            )?;
            print_info(&format!("No --recipient specified, defaulting to {addr}"));
            Some(addr)
        }
    };

    let parsed_txid: bitcoin::Txid = txid.parse().context("Invalid txid")?;
    let txid_address = sui_sdk_types::Address::new(parsed_txid.to_byte_array());

    let builder = crate::sui_tx_executor::build_create_deposit_request(
        hashi_ids,
        txid_address,
        vout,
        amount,
        derivation_path,
    );

    match tx_opts.mode() {
        TxMode::SerializeUnsigned => print_info("Building unsigned deposit request..."),
        TxMode::DryRun => print_info("Simulating deposit request (dry-run)..."),
        TxMode::Execute => print_info("Submitting deposit request on Sui..."),
    }

    let mut client = crate::sui_rpc_client::new_sui_rpc_client(&config.sui_rpc_url)?;
    let outcome = crate::sui_tx_executor::finalize(
        &mut client,
        signer.as_ref(),
        builder,
        sender,
        &tx_opts.gas_overrides(),
        tx_opts.mode(),
        std::time::Duration::from_secs(10),
    )
    .await?;

    if let Some(response) = crate::cli::print_tx_outcome(outcome, &config.sui_rpc_url) {
        let request_id = crate::sui_tx_executor::deposit_request_id_from_response(&response)?;
        print_success(&format!("Deposit request created: {request_id}"));
    }

    Ok(())
}

async fn request_all(
    config: &CliConfig,
    tx_opts: &TxOptions,
    txid: &str,
    outputs: Option<&str>,
    recipient: Option<&str>,
) -> Result<()> {
    // This batches outputs into one transaction per ~333 deposits, so it can't
    // emit a single unsigned/dry-run transaction. Direct the user to the
    // per-output command for those modes.
    if tx_opts.mode() != crate::sui_tx_executor::TxMode::Execute {
        anyhow::bail!(
            "`deposit request` builds one transaction per batch of outputs and cannot emit a \
             single unsigned or dry-run transaction. Use `deposit request-single` per output \
             with --serialize-unsigned-transaction or --dry-run."
        );
    }

    config.validate()?;

    let hashi_ids = crate::config::HashiIds {
        package_id: config.package_id(),
        hashi_object_id: config.hashi_object_id(),
    };

    let signer = config
        .load_keypair()?
        .context("Keypair required for deposit request. Set keypair_path in config.")?;

    let derivation_path = match recipient {
        Some(r) => Some(
            r.parse::<sui_sdk_types::Address>()
                .context("Invalid recipient Sui address")?,
        ),
        None => {
            let addr = signer.verifying_key().derive_address();
            print_info(&format!(
                "No --recipient specified, defaulting to signer address {}",
                addr
            ));
            Some(addr)
        }
    };

    let parsed_txid: bitcoin::Txid = txid.parse().context("Invalid txid")?;

    let matching_utxos: Vec<(u32, u64)> = if let Some(outputs) = outputs {
        serde_json::from_str(outputs).context("Failed to parse --outputs JSON")?
    } else {
        let btc_rpc = config.require_btc_rpc_client()?;

        // Fetch the MPC public key and derive the deposit address
        let client = HashiClient::new(config).await?;
        let mpc_pubkey = client.fetch_mpc_public_key();
        if mpc_pubkey.is_empty() {
            anyhow::bail!(
                "MPC public key not available on-chain. Has the committee completed DKG?"
            );
        }
        let guardian_btc_pubkey = client.fetch_guardian_btc_public_key().context(
            "Guardian BTC pubkey is not yet on-chain. Did finish_publish run with --guardian-btc-public-key?",
        )?;

        let btc_network = crate::btc_monitor::config::parse_btc_network(
            config.bitcoin.as_ref().and_then(|b| b.network.as_deref()),
        )?;

        let deposit_address = cli_derive_deposit_address(
            &mpc_pubkey,
            &guardian_btc_pubkey,
            derivation_path.as_ref(),
            btc_network,
        )?;

        // Look up the transaction and find all matching outputs
        let raw_tx = btc_rpc
            .get_raw_transaction(parsed_txid)
            .map_err(anyhow::Error::from)
            .and_then(|resp| resp.transaction().map_err(anyhow::Error::from))
            .context("Failed to fetch transaction from Bitcoin RPC")?;

        raw_tx
            .output
            .iter()
            .enumerate()
            .filter(|(_, output)| output.script_pubkey == deposit_address.script_pubkey())
            .map(|(i, output)| (i as u32, output.value.to_sat()))
            .collect()
    };

    if matching_utxos.is_empty() {
        anyhow::bail!("No deposit outputs found for transaction {}", txid);
    }

    let total_sats: u64 = matching_utxos.iter().map(|(_, amount)| amount).sum();
    println!("\n{}", "Found matching outputs".bold());
    println!("{}", "━".repeat(50).dimmed());
    for (vout, amount) in &matching_utxos {
        println!(
            "  vout {}: {} sats ({:.8} BTC)",
            vout,
            amount,
            *amount as f64 / 1e8
        );
    }
    println!(
        "  {} {} outputs, {} total sats ({:.8} BTC)",
        "Summary:".bold(),
        matching_utxos.len(),
        total_sats,
        total_sats as f64 / 1e8
    );
    println!("{}", "━".repeat(50).dimmed());

    // 3 dynamic-field ops per deposit × 1000 object-runtime cap = 333/PTB.
    const CHUNK_SIZE: usize = 333;

    let sui_client = crate::sui_rpc_client::new_sui_rpc_client(&config.sui_rpc_url)?;
    let mut executor = crate::sui_tx_executor::SuiTxExecutor::new(sui_client, signer, hashi_ids);

    let txid_address =
        sui_sdk_types::Address::new(bitcoin::hashes::Hash::to_byte_array(parsed_txid));

    let total = matching_utxos.len();
    let mut all_request_ids: Vec<sui_sdk_types::Address> = Vec::with_capacity(total);

    for (chunk_idx, chunk) in matching_utxos.chunks(CHUNK_SIZE).enumerate() {
        print_info(&format!(
            "Submitting batch {}/{} ({} deposits) on Sui...",
            chunk_idx + 1,
            total.div_ceil(CHUNK_SIZE),
            chunk.len()
        ));

        let request_ids = executor
            .execute_create_deposit_requests_batch(txid_address, chunk, derivation_path)
            .await?;
        all_request_ids.extend(request_ids);
    }

    println!("\n{}", "Deposit requests created".bold().green());
    println!("{}", "━".repeat(50).dimmed());
    for (i, request_id) in all_request_ids.iter().enumerate() {
        let (vout, amount) = matching_utxos[i];
        println!("  vout {}: {} sats -> request {}", vout, amount, request_id);
    }
    println!("{}", "━".repeat(50).dimmed());

    Ok(())
}

async fn status(config: &CliConfig, request_id: &str) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let req_addr = request_id
        .parse::<sui_sdk_types::Address>()
        .context("Invalid request ID")?;

    let deposits = client.fetch_deposit_requests();
    let deposit = deposits.iter().find(|d| d.id == req_addr);

    println!("\n{}", "Deposit Request Status".bold());
    println!("{}", "━".repeat(60).dimmed());

    let Some(dep) = deposit else {
        print_info("Deposit request not found in pending queue (may be confirmed or expired).");
        println!("{}", "━".repeat(60).dimmed());
        return Ok(());
    };

    let txid = dep.utxo.id.txid;
    println!(
        "  {} {}",
        "Request ID:".bold(),
        display::format_address_full(&dep.id)
    );
    println!("  {} {}:{}", "UTXO:".bold(), txid, dep.utxo.id.vout);
    println!("  {} {} sats", "Amount:".bold(), dep.utxo.amount);
    println!(
        "  {} {}",
        "Requested:".bold(),
        display::format_timestamp(dep.created_timestamp_ms)
    );
    println!("  {} {}", "Status:".bold(), "Pending".yellow());

    // BTC context if available
    if let Ok(Some(btc_rpc)) = config.btc_rpc_client() {
        println!();
        println!("  {}", "BTC Context:".bold());
        match btc_rpc.get_raw_transaction_verbose(txid.into()) {
            Ok(info) => {
                let confirmations = info.confirmations.unwrap_or(0);
                println!("    {} {}", "Confirmations:".bold(), confirmations);
                if let Some(ref blockhash) = info.block_hash {
                    println!("    {} {}", "Block:".bold(), blockhash);
                }
            }
            Err(_) => {
                println!("    {}", "(transaction not found on BTC node)".dimmed());
            }
        }
    }

    println!("{}", "━".repeat(60).dimmed());
    Ok(())
}

async fn list(config: &CliConfig, output_format: OutputFormat) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let deposits = client.fetch_deposit_requests();

    match output_format {
        OutputFormat::Json => {
            let rows: Vec<_> = deposits
                .iter()
                .map(|dep| {
                    serde_json::json!({
                        "request_id": dep.id.to_string(),
                        "amount_sats": dep.utxo.amount,
                        "utxo": {
                            "txid": dep.utxo.id.txid.to_string(),
                            "vout": dep.utxo.id.vout,
                        },
                        "status": "pending",
                        "caller": dep.sender.to_string(),
                        "requested_ms": dep.created_timestamp_ms,
                    })
                })
                .collect();

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "deposits": rows,
                    "count": deposits.len(),
                }))?
            );
        }
        OutputFormat::HumanTable => {
            println!("\n{}", "Deposit Requests".bold());
            println!("{}", "━".repeat(100).dimmed());

            if deposits.is_empty() {
                print_info("No pending deposit requests.");
            } else {
                println!(
                    "  {:<20} {:<14} {:<12} {:<10} {:<20} {}",
                    "Request ID".bold(),
                    "Amount (sats)".bold(),
                    "UTXO".bold(),
                    "Status".bold(),
                    "Caller".bold(),
                    "Requested".bold()
                );
                for dep in &deposits {
                    println!(
                        "  {:<20} {:<14} {}:{:<3} {:<10} {:<20} {}",
                        display::format_address_full(&dep.id),
                        dep.utxo.amount,
                        dep.utxo.id.txid,
                        dep.utxo.id.vout,
                        "Pending".yellow(),
                        display::format_address_full(&dep.sender),
                        display::format_timestamp(dep.created_timestamp_ms)
                    );
                }
                println!("\n  {} deposit(s)", deposits.len());
            }

            println!("{}", "━".repeat(100).dimmed());
        }
    }

    Ok(())
}
