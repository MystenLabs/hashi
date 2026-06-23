// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Withdrawal command implementations

use anyhow::Context;
use anyhow::Result;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use colored::Colorize;
use hashi_types::bitcoin::BitcoinAddress;
use hashi_types::bitcoin::witness_program_from_address;

use crate::cli::OutputFormat;
use crate::cli::TxOptions;
use crate::cli::WithdrawCommands;
use crate::cli::client::HashiClient;
use crate::cli::config::CliConfig;
use crate::cli::print_info;
use crate::cli::print_success;
use crate::cli::types::display;

pub async fn run(action: WithdrawCommands, config: &CliConfig, tx_opts: &TxOptions) -> Result<()> {
    match action {
        WithdrawCommands::Request {
            amount,
            btc_address,
            count,
        } => request(config, tx_opts, amount, &btc_address, count).await,
        WithdrawCommands::Cancel { request_id } => cancel(config, tx_opts, &request_id).await,
        WithdrawCommands::Status { request_id } => status(config, &request_id).await,
        WithdrawCommands::List {
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

async fn request(
    config: &CliConfig,
    tx_opts: &TxOptions,
    amount: u64,
    btc_address: &str,
    count: usize,
) -> Result<()> {
    use crate::sui_tx_executor::TxMode;

    config.validate()?;
    anyhow::ensure!(count >= 1, "--count must be at least 1");

    let hashi_ids = crate::config::HashiIds {
        package_id: config.package_id(),
        hashi_object_id: config.hashi_object_id(),
    };

    // A keypair is optional: serialize/dry-run only need the sender address.
    let signer = config.load_keypair()?;
    if tx_opts.mode() == TxMode::Execute && signer.is_none() {
        anyhow::bail!(
            "Keypair required to submit a withdrawal request (set keypair_path in config), \
             or use --serialize-unsigned-transaction to emit an unsigned transaction."
        );
    }

    // Sender: explicit --sender (e.g. a multisig), else the keypair's address.
    // The BTC balance is drawn from this sender during the build.
    let sender = tx_opts
        .sender
        .or_else(|| signer.as_ref().map(|s| s.public_key().derive_address()));

    // Parse the BTC destination address and verify it matches the configured network
    let btc_network = crate::btc_monitor::config::parse_btc_network(
        config.bitcoin.as_ref().and_then(|b| b.network.as_deref()),
    )?;
    let btc_addr: BitcoinAddress<NetworkUnchecked> =
        btc_address.parse().context("Invalid Bitcoin address")?;
    let btc_addr = btc_addr
        .require_network(btc_network)
        .context("Withdrawal address does not match the configured Bitcoin network")?;
    let destination_bytes = witness_program_from_address(&btc_addr)?;

    let mut client = sui_rpc::Client::new(&config.sui_rpc_url)?;

    // A single request supports all tx modes (execute / dry-run /
    // serialize-unsigned) via the builder + finalize path.
    if count == 1 {
        print_info(&format!("Withdrawal amount: {amount} sats"));
        print_info(&format!("BTC destination: {btc_address}"));

        let builder = crate::sui_tx_executor::build_create_withdrawal_request(
            hashi_ids,
            amount,
            destination_bytes,
        );

        match tx_opts.mode() {
            TxMode::SerializeUnsigned => print_info("Building unsigned withdrawal request..."),
            TxMode::DryRun => print_info("Simulating withdrawal request (dry-run)..."),
            TxMode::Execute => print_info("Submitting withdrawal request on Sui..."),
        }

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

        if let Some(response) = crate::cli::print_tx_outcome(outcome) {
            let request_id =
                crate::sui_tx_executor::withdrawal_request_id_from_response(&response)?;
            print_success(&format!("Withdrawal request created: {request_id}"));
        }
        return Ok(());
    }

    // `--count > 1` bulk-submits many requests across PTBs and only makes sense
    // for direct execution: there is no batch builder to emit or simulate, so
    // --serialize-unsigned-transaction / --dry-run apply to a single request.
    anyhow::ensure!(
        tx_opts.mode() == TxMode::Execute,
        "--count > 1 only supports execute mode; --serialize-unsigned-transaction \
         and --dry-run apply to a single withdrawal request"
    );

    // Execute mode guarantees a signer (rejected above otherwise).
    let signer = signer.expect("execute mode requires a signer");
    let mut executor = crate::sui_tx_executor::SuiTxExecutor::new(client, signer, hashi_ids);

    // ~3 PTB commands per request (split + call) vs the 1024 command cap.
    const CHUNK_SIZE: usize = 250;

    print_info(&format!(
        "Submitting {count} withdrawal requests of {amount} sats to {btc_address} ({CHUNK_SIZE} per PTB)...",
    ));

    let total_chunks = count.div_ceil(CHUNK_SIZE);
    let mut chunk_idx = 0usize;
    let mut submitted = 0usize;
    let mut remaining = count;
    while remaining > 0 {
        chunk_idx += 1;
        let this_batch = remaining.min(CHUNK_SIZE);
        print_info(&format!(
            "Batch {chunk_idx}/{total_chunks} ({this_batch} requests)...",
        ));
        let ids = executor
            .execute_create_withdrawal_requests_batch(amount, destination_bytes.clone(), this_batch)
            .await?;
        submitted += ids.len();
        remaining -= this_batch;
    }

    print_success(&format!("Created {submitted} withdrawal requests"));

    Ok(())
}

async fn cancel(config: &CliConfig, tx_opts: &TxOptions, request_id: &str) -> Result<()> {
    use crate::sui_tx_executor::TxMode;

    config.validate()?;

    let req_addr = request_id
        .parse::<sui_sdk_types::Address>()
        .context("Invalid request ID")?;

    let hashi_ids = crate::config::HashiIds {
        package_id: config.package_id(),
        hashi_object_id: config.hashi_object_id(),
    };

    let signer = config.load_keypair()?;
    if tx_opts.mode() == TxMode::Execute && signer.is_none() {
        anyhow::bail!(
            "Keypair required to cancel a withdrawal, or use \
             --serialize-unsigned-transaction to emit an unsigned transaction."
        );
    }

    // The refunded Balance<BTC> is sent to `sender`, which must equal the
    // transaction sender. Required up front so the PTB can address the refund.
    let sender = tx_opts
        .sender
        .or_else(|| signer.as_ref().map(|s| s.public_key().derive_address()))
        .context(
            "No sender available: pass --sender (the refund recipient) or configure a keypair",
        )?;

    let builder = crate::sui_tx_executor::build_cancel_withdrawal(hashi_ids, &req_addr, sender);

    match tx_opts.mode() {
        TxMode::SerializeUnsigned => print_info("Building unsigned withdrawal cancellation..."),
        TxMode::DryRun => print_info("Simulating withdrawal cancellation (dry-run)..."),
        TxMode::Execute => print_info("Cancelling withdrawal..."),
    }

    let mut client = sui_rpc::Client::new(&config.sui_rpc_url)?;
    let outcome = crate::sui_tx_executor::finalize(
        &mut client,
        signer.as_ref(),
        builder,
        Some(sender),
        &tx_opts.gas_overrides(),
        tx_opts.mode(),
        std::time::Duration::from_secs(10),
    )
    .await?;

    if crate::cli::print_tx_outcome(outcome).is_some() {
        print_success("Withdrawal cancelled.");
    }

    Ok(())
}

async fn status(config: &CliConfig, request_id: &str) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let req_addr = request_id
        .parse::<sui_sdk_types::Address>()
        .context("Invalid request ID")?;

    let withdrawal_requests = client.fetch_withdrawal_requests();
    let withdrawal_txns = client.fetch_withdrawal_txns();

    println!("\n{}", "Withdrawal Status".bold());
    println!("{}", "━".repeat(60).dimmed());

    // Check pending request queue first
    if let Some(wr) = withdrawal_requests.iter().find(|w| w.id == req_addr) {
        println!(
            "  {} {}",
            "Request ID:".bold(),
            display::format_address_full(&wr.id)
        );
        println!("  {} {} sats", "Amount:".bold(), wr.btc_amount);
        println!(
            "  {} {}",
            "BTC Address:".bold(),
            hex::encode(&wr.bitcoin_address)
        );
        println!(
            "  {} {}",
            "Requester:".bold(),
            display::format_address(&wr.sender)
        );
        println!(
            "  {} {}",
            "Requested:".bold(),
            display::format_timestamp(wr.timestamp_ms)
        );
        println!();

        let status_label = if wr.status.is_approved() {
            "Approved".green()
        } else {
            "Requested".yellow()
        };

        let step = if wr.status.is_approved() { 2 } else { 1 };
        println!("  {} {} ({}/6)", "Progress:".bold(), status_label, step);
        println!(
            "    {} Requested",
            if step >= 1 {
                "[done]".green()
            } else {
                "[    ]".dimmed()
            }
        );
        println!(
            "    {} Approved",
            if step >= 2 {
                "[done]".green()
            } else {
                "[    ]".dimmed()
            }
        );
        println!("    {} Committed", "[    ]".dimmed());
        println!("    {} Signed", "[    ]".dimmed());
        println!("    {} Broadcast", "[    ]".dimmed());
        println!("    {} Confirmed", "[    ]".dimmed());
    }
    // Check committed/signed withdrawal transactions
    else if let Some(pw) = withdrawal_txns
        .iter()
        .find(|p| p.request_ids.contains(&req_addr))
    {
        let txid_bytes: [u8; 32] = pw.id.into();
        let txid = bitcoin::Txid::from_byte_array(txid_bytes);
        let is_signed = pw.is_fully_signed();
        let signed_inputs = pw.signing.signed_count();
        let num_inputs = pw.signing.num_inputs();
        let step = if is_signed { 4 } else { 3 };
        // Distinguish the multi-checkpoint signing window: an in-progress txn
        // shows "Signing (X/N)" rather than a flat "Committed".
        let status_label = if is_signed {
            "Signed".green()
        } else if signed_inputs > 0 {
            format!("Signing ({signed_inputs}/{num_inputs})").cyan()
        } else {
            "Committed".cyan()
        };

        println!(
            "  {} {}",
            "Request ID:".bold(),
            display::format_address_full(&req_addr)
        );
        println!("  {} {}", "BTC txid:".bold(), txid);
        println!();
        println!("  {} {} ({}/6)", "Progress:".bold(), status_label, step);
        println!("    {} Requested", "[done]".green());
        println!("    {} Approved", "[done]".green());
        println!("    {} Committed          txid: {}", "[done]".green(), txid);
        println!(
            "    {} Signed",
            if is_signed {
                "[done]".green()
            } else {
                "[    ]".dimmed()
            }
        );
        println!("    {} Broadcast", "[    ]".dimmed());
        println!("    {} Confirmed", "[    ]".dimmed());

        // BTC context
        if let Ok(Some(btc_rpc)) = config.btc_rpc_client() {
            println!();
            println!("  {}", "BTC Context:".bold());
            match btc_rpc.get_raw_transaction_verbose(txid) {
                Ok(info) => {
                    let confirmations = info.confirmations.unwrap_or(0) as u32;
                    let tx_status = if confirmations > 0 {
                        "Confirmed".to_string()
                    } else {
                        "In Mempool".to_string()
                    };
                    println!("    {} {}", "TX Status:".bold(), tx_status);
                    println!("    {} {}/6", "Confirmations:".bold(), confirmations);
                }
                Err(_) => {
                    println!("    {}", "(transaction not found on BTC node)".dimmed());
                }
            }
        }
    } else {
        print_info(
            "Withdrawal request not found in pending queues (may be confirmed or cancelled).",
        );
    }

    println!("{}", "━".repeat(60).dimmed());
    Ok(())
}

async fn list(config: &CliConfig, output_format: OutputFormat) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let requests = client.fetch_withdrawal_requests();
    let pending = client.fetch_withdrawal_txns();
    let signed_count = pending.iter().filter(|pw| pw.is_fully_signed()).count();
    let committed_count = pending.len() - signed_count;

    match output_format {
        OutputFormat::Json => {
            let queued: Vec<_> = requests
                .iter()
                .map(|wr| {
                    serde_json::json!({
                        "request_id": wr.id.to_string(),
                        "amount_sats": wr.btc_amount,
                        "status": if wr.status.is_approved() { "approved" } else { "requested" },
                        "caller": wr.sender.to_string(),
                        "requested_ms": wr.timestamp_ms,
                    })
                })
                .collect();

            let withdrawal_txns: Vec<_> = pending
                .iter()
                .map(|pw| {
                    let txid_bytes: [u8; 32] = pw.id.into();
                    let txid = bitcoin::Txid::from_byte_array(txid_bytes);
                    serde_json::json!({
                        "txid": txid.to_string(),
                        "status": if pw.is_fully_signed() { "signed" } else { "committed" },
                        "request_count": pw.request_ids.len(),
                    })
                })
                .collect();

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "queued": queued,
                    "withdrawal_txns": withdrawal_txns,
                    "queued_count": requests.len(),
                    "committed_count": committed_count,
                    "signed_count": signed_count,
                }))?
            );
        }
        OutputFormat::HumanTable => {
            println!("\n{}", "Withdrawal Requests".bold());
            println!("{}", "━".repeat(100).dimmed());

            if requests.is_empty() && pending.is_empty() {
                print_info("No withdrawal requests found.");
            } else {
                if !requests.is_empty() {
                    println!("  {}", "Queued:".bold().underline());
                    println!(
                        "  {:<20} {:<14} {:<10} {:<20} {}",
                        "Request ID".bold(),
                        "Amount (sats)".bold(),
                        "Status".bold(),
                        "Caller".bold(),
                        "Requested".bold()
                    );
                    for wr in &requests {
                        let status = if wr.status.is_approved() {
                            "Approved"
                        } else {
                            "Requested"
                        };
                        println!(
                            "  {:<20} {:<14} {:<10} {:<20} {}",
                            display::format_address_full(&wr.id),
                            wr.btc_amount,
                            status,
                            display::format_address_full(&wr.sender),
                            display::format_timestamp(wr.timestamp_ms)
                        );
                    }
                }

                if !pending.is_empty() {
                    if !requests.is_empty() {
                        println!();
                    }
                    println!("  {}", "Pending Broadcast:".bold().underline());
                    for pw in &pending {
                        let txid_bytes: [u8; 32] = pw.id.into();
                        let txid = bitcoin::Txid::from_byte_array(txid_bytes);
                        let status = if pw.is_fully_signed() {
                            "Signed"
                        } else {
                            "Committed"
                        };
                        println!(
                            "  txid: {}  status: {}  requests: {}",
                            txid,
                            status,
                            pw.request_ids.len()
                        );
                    }
                }

                println!(
                    "\n  {} queued, {} committed, {} signed",
                    requests.len(),
                    committed_count,
                    signed_count
                );
            }

            println!("{}", "━".repeat(100).dimmed());
        }
    }

    Ok(())
}
