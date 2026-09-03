// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Withdrawal command implementations

use anyhow::Context;
use anyhow::Result;
use bitcoin::address::NetworkUnchecked;
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
use crate::onchain::types::WithdrawalRequest;
use crate::onchain::types::WithdrawalTransaction;

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
        .or_else(|| signer.as_ref().map(|s| s.verifying_key().derive_address()));

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

    // `request_withdrawal` gates on `assert_version_enabled`, so the call
    // must target the active version's package (a retired version's entry
    // aborts). The resolved state also routes the batch executor below.
    let (onchain, call_package) = super::resolve_active_call_package(config, hashi_ids).await?;

    let mut client = crate::sui_rpc_client::new_sui_rpc_client(&config.sui_rpc_url)?;

    // A single request supports all tx modes (execute / dry-run /
    // serialize-unsigned) via the builder + finalize path.
    if count == 1 {
        print_info(&format!("Withdrawal amount: {amount} sats"));
        print_info(&format!("BTC destination: {btc_address}"));

        let builder = crate::sui_tx_executor::build_create_withdrawal_request(
            hashi_ids,
            call_package,
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

        if let Some(response) = crate::cli::print_tx_outcome(outcome, &config.sui_rpc_url) {
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

    // Execute mode guarantees a signer (rejected above otherwise). The
    // attached reader state makes the executor route its withdrawal calls
    // through the withdrawal-effective version's package.
    let signer = signer.expect("execute mode requires a signer");
    let mut executor = crate::sui_tx_executor::SuiTxExecutor::new(client, signer, hashi_ids)
        .with_onchain_state(&onchain);

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
        .or_else(|| signer.as_ref().map(|s| s.verifying_key().derive_address()))
        .context(
            "No sender available: pass --sender (the refund recipient) or configure a keypair",
        )?;

    // Resolve the active version's package so the cancel runs the bytecode
    // generation the flow is committing under. A resolution failure
    // must abort the command, not fall back: a v1-routed cancel aimed at a
    // v2-committed request would destroy a request its live withdrawal txn
    // still references.
    let (_onchain, call_package) = super::resolve_active_call_package(config, hashi_ids).await?;
    let builder =
        crate::sui_tx_executor::build_cancel_withdrawal(hashi_ids, call_package, &req_addr, sender);

    match tx_opts.mode() {
        TxMode::SerializeUnsigned => print_info("Building unsigned withdrawal cancellation..."),
        TxMode::DryRun => print_info("Simulating withdrawal cancellation (dry-run)..."),
        TxMode::Execute => print_info("Cancelling withdrawal..."),
    }

    let mut client = crate::sui_rpc_client::new_sui_rpc_client(&config.sui_rpc_url)?;
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

    if crate::cli::print_tx_outcome(outcome, &config.sui_rpc_url).is_some() {
        print_success("Withdrawal cancelled.");
    }

    Ok(())
}

async fn status(config: &CliConfig, request_id: &str) -> Result<()> {
    let client = HashiClient::new_with_bitcoin_state(config).await?;

    let req_addr = request_id
        .parse::<sui_sdk_types::Address>()
        .context("Invalid request ID")?;

    let withdrawal_requests = client.fetch_withdrawal_requests()?;
    let withdrawal_txns = client.fetch_withdrawal_txns()?;

    println!("\n{}", "Withdrawal Status".bold());
    println!("{}", "━".repeat(60).dimmed());

    // Check the mirrored request map first. With deferred archival a request
    // stays here for its whole live lifecycle — awaiting approval, then
    // commitment, then committed into a withdrawal txn until the archival GC
    // moves it to the processed archive.
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
            display::format_timestamp(wr.created_timestamp_ms)
        );

        // Committed into a withdrawal txn (BTC drained): render the txn's
        // signing progress, looked up by the request's withdrawal_txn_id.
        if let Some(txn_id) = wr.withdrawal_txn_id {
            if let Some(pw) = withdrawal_txns.iter().find(|p| p.id == txn_id) {
                print_txn_progress(config, pw);
            } else {
                println!();
                print_info(&format!(
                    "Request is committed to withdrawal transaction {} but that \
                     transaction was not found in the pending queues.",
                    display::format_address_full(&txn_id)
                ));
            }
        } else {
            println!();
            let status_label = if wr.is_approved() {
                "Approved".green()
            } else {
                "Requested".yellow()
            };

            let step = if wr.is_approved() { 2 } else { 1 };
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
    }
    // Check committed/signed withdrawal transactions
    else if let Some(pw) = withdrawal_txns
        .iter()
        .find(|p| p.request_ids.contains(&req_addr))
    {
        println!(
            "  {} {}",
            "Request ID:".bold(),
            display::format_address_full(&req_addr)
        );
        print_txn_progress(config, pw);
    } else {
        print_info(
            "Withdrawal request not found in pending queues (may be confirmed or cancelled).",
        );
    }

    println!("{}", "━".repeat(60).dimmed());
    Ok(())
}

/// Render the committed-phase progress checklist (steps 3-6) and Bitcoin-side
/// context for a withdrawal transaction. Shared by the request-map lookup
/// (committed requests point at their txn via `withdrawal_txn_id`) and the
/// txn-map fallback lookup.
fn print_txn_progress(config: &CliConfig, pw: &WithdrawalTransaction) {
    let txid: bitcoin::Txid = pw.txid.into();
    let is_confirmed = pw.is_confirmed();
    let is_signed = pw.is_fully_signed();
    let signed_inputs = pw.signing.signed_count();
    let num_inputs = pw.signing.num_inputs();
    let step = if is_confirmed {
        6
    } else if is_signed {
        4
    } else {
        3
    };
    // Distinguish the multi-checkpoint signing window: an in-progress txn
    // shows "Signing (X/N)" rather than a flat "Committed". A confirmed txn
    // lingers in the pending map until the archival GC sweeps it, so it must
    // render as complete rather than broadcast-ready.
    let status_label = if is_confirmed {
        "Confirmed (archival pending)".green()
    } else if is_signed {
        "Signed".green()
    } else if signed_inputs > 0 {
        format!("Signing ({signed_inputs}/{num_inputs})").cyan()
    } else {
        "Committed".cyan()
    };

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
    println!(
        "    {} Broadcast",
        if is_confirmed {
            "[done]".green()
        } else {
            "[    ]".dimmed()
        }
    );
    println!(
        "    {} Confirmed",
        if is_confirmed {
            "[done]".green()
        } else {
            "[    ]".dimmed()
        }
    );

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
}

async fn list(config: &CliConfig, output_format: OutputFormat) -> Result<()> {
    let client = HashiClient::new_with_bitcoin_state(config).await?;

    let requests = client.fetch_withdrawal_requests()?;
    let pending = client.fetch_withdrawal_txns()?;
    // The v2 flow commits requests in place, so the mirrored map holds both
    // the actionable queue and requests already committed into a withdrawal
    // txn (those linger until the archival GC sweeps them and are counted
    // through their txn's request_count).
    let (queued, committed_in_place) = partition_queued(&requests);
    // Confirmed txns linger in the pending map until the archival GC sweeps
    // them; classify them first so they are never counted as actionable
    // "signed" (they are also fully signed).
    let confirmed_count = pending.iter().filter(|pw| pw.is_confirmed()).count();
    let signed_count = pending
        .iter()
        .filter(|pw| !pw.is_confirmed() && pw.is_fully_signed())
        .count();
    let committed_count = pending.len() - confirmed_count - signed_count;

    match output_format {
        OutputFormat::Json => {
            let queued_rows: Vec<_> = queued
                .iter()
                .map(|wr| {
                    serde_json::json!({
                        "request_id": wr.id.to_string(),
                        "amount_sats": wr.btc_amount,
                        "status": queued_status(wr),
                        "caller": wr.sender.to_string(),
                        "requested_ms": wr.created_timestamp_ms,
                    })
                })
                .collect();

            let withdrawal_txns: Vec<_> = pending.iter().map(withdrawal_txn_row).collect();

            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "queued": queued_rows,
                    "withdrawal_txns": withdrawal_txns,
                    "queued_count": queued.len(),
                    "committed_in_place_count": committed_in_place.len(),
                    "committed_count": committed_count,
                    "signed_count": signed_count,
                    "confirmed_count": confirmed_count,
                }))?
            );
        }
        OutputFormat::HumanTable => {
            println!("\n{}", "Withdrawal Requests".bold());
            println!("{}", "━".repeat(100).dimmed());

            if requests.is_empty() && pending.is_empty() {
                print_info("No withdrawal requests found.");
            } else {
                if !queued.is_empty() {
                    println!("  {}", "Queued:".bold().underline());
                    println!(
                        "  {:<20} {:<14} {:<10} {:<20} {}",
                        "Request ID".bold(),
                        "Amount (sats)".bold(),
                        "Status".bold(),
                        "Caller".bold(),
                        "Requested".bold()
                    );
                    for wr in &queued {
                        println!(
                            "  {:<20} {:<14} {:<10} {:<20} {}",
                            display::format_address_full(&wr.id),
                            wr.btc_amount,
                            queued_status(wr),
                            display::format_address_full(&wr.sender),
                            display::format_timestamp(wr.created_timestamp_ms)
                        );
                    }
                }

                if !pending.is_empty() {
                    if !queued.is_empty() {
                        println!();
                    }
                    println!("  {}", "Withdrawal Transactions:".bold().underline());
                    for pw in &pending {
                        let txid: bitcoin::Txid = pw.txid.into();
                        let status = if pw.is_confirmed() {
                            "Confirmed (archival pending)"
                        } else if pw.is_fully_signed() {
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
                    "\n  {} queued, {} committed in place; txns: {} committed, {} signed, \
                     {} confirmed awaiting archival",
                    queued.len(),
                    committed_in_place.len(),
                    committed_count,
                    signed_count,
                    confirmed_count
                );
            }

            println!("{}", "━".repeat(100).dimmed());
        }
    }

    Ok(())
}

/// Split the mirrored request map into the actionable queue (awaiting
/// approval or commitment) and the requests the v2 flow committed in place.
/// The latter must not report as queued backlog: their BTC is already
/// drained into a withdrawal txn, which the txn view counts.
fn partition_queued(
    requests: &[WithdrawalRequest],
) -> (Vec<&WithdrawalRequest>, Vec<&WithdrawalRequest>) {
    requests.iter().partition(|wr| !wr.is_committed())
}

/// Lowercase state of a request in the actionable queue, for JSON rows and
/// the table. Only meaningful for uncommitted requests (see
/// `partition_queued`).
fn queued_status(wr: &WithdrawalRequest) -> &'static str {
    if wr.is_approved() {
        "approved"
    } else {
        "requested"
    }
}

/// The JSON row for one in-flight withdrawal transaction.
///
/// The Bitcoin txid comes from the `txid` field; `pw.id` is the Sui object ID
/// of the `WithdrawalTransaction` and is unrelated to the Bitcoin txid.
fn withdrawal_txn_row(pw: &WithdrawalTransaction) -> serde_json::Value {
    let txid: bitcoin::Txid = pw.txid.into();
    // A confirmed txn is also fully signed, so check confirmation first: it
    // lingers only until the archival GC sweeps it and must not be reported
    // as an actionable "signed" txn.
    let status = if pw.is_confirmed() {
        "confirmed"
    } else if pw.is_fully_signed() {
        "signed"
    } else {
        "committed"
    };
    serde_json::json!({
        "txid": txid.to_string(),
        "status": status,
        "request_count": pw.request_ids.len(),
    })
}

#[cfg(test)]
mod tests {
    use hashi_types::move_types::CommitteeSignature;
    use hashi_types::move_types::MpcSig;
    use hashi_types::move_types::SigningBatch;

    use super::*;

    /// A withdrawal transaction whose Sui object ID and Bitcoin txid are
    /// distinct, so a mix-up between the two shows up in assertions.
    fn withdrawal_txn(fully_signed: bool) -> WithdrawalTransaction {
        let txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2fc77ab847d46d3298b06f"
            .parse()
            .unwrap();
        WithdrawalTransaction {
            id: sui_sdk_types::Address::new([0xAA; 32]),
            txid,
            request_ids: vec![
                sui_sdk_types::Address::new([0x01; 32]),
                sui_sdk_types::Address::new([0x02; 32]),
            ],
            inputs: vec![],
            withdrawal_outputs: vec![],
            change_outputs: vec![],
            created_timestamp_ms: 0,
            signed_timestamp_ms: fully_signed.then_some(1),
            confirmed_timestamp_ms: None,
            randomness: vec![],
            signing: SigningBatch {
                signatures: vec![if fully_signed {
                    MpcSig::Signed(vec![0u8; 64])
                } else {
                    MpcSig::Pending(0)
                }],
                epoch: 0,
            },
            guardian_signatures: fully_signed.then(|| vec![vec![0u8; 64]]),
        }
    }

    #[test]
    fn withdrawal_txn_row_reports_bitcoin_txid_not_object_id() {
        let row = withdrawal_txn_row(&withdrawal_txn(true));
        assert_eq!(
            row["txid"],
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2fc77ab847d46d3298b06f"
        );
        assert_eq!(row["status"], "signed");
        assert_eq!(row["request_count"], 2);
    }

    #[test]
    fn withdrawal_txn_row_reports_committed_until_fully_signed() {
        let row = withdrawal_txn_row(&withdrawal_txn(false));
        assert_eq!(row["status"], "committed");
    }

    /// A confirmed txn lingering until the archival GC must classify as
    /// "confirmed", not fall through to "signed" (it is also fully signed).
    #[test]
    fn withdrawal_txn_row_reports_confirmed_over_signed() {
        let mut txn = withdrawal_txn(true);
        txn.confirmed_timestamp_ms = Some(2);
        let row = withdrawal_txn_row(&txn);
        assert_eq!(row["status"], "confirmed");
    }

    /// A request at one of the three mirrored lifecycle points: requested,
    /// approved (cert recorded), or committed (linked to a withdrawal txn,
    /// BTC drained).
    fn request(id: u8, approved: bool, committed: bool) -> WithdrawalRequest {
        WithdrawalRequest {
            id: sui_sdk_types::Address::new([id; 32]),
            sender: sui_sdk_types::Address::new([2; 32]),
            btc_amount: 1,
            bitcoin_address: vec![0; 20],
            created_timestamp_ms: 0,
            approval_cert: approved.then(|| CommitteeSignature {
                epoch: 0,
                signature: Vec::new(),
                signers_bitmap: Vec::new(),
            }),
            approved_timestamp_ms: approved.then_some(1),
            withdrawal_txn_id: committed.then(|| sui_sdk_types::Address::new([9; 32])),
            sui_tx_digest: sui_sdk_types::Digest::new([0; 32]),
            btc: if committed { 0 } else { 1 },
        }
    }

    /// Requests the v2 flow committed in place linger in the mirrored map
    /// until the archival GC sweeps them; the queued view must exclude them
    /// (they are already counted through their withdrawal txn).
    #[test]
    fn queued_view_excludes_committed_in_place_requests() {
        let requests = vec![
            request(1, false, false),
            request(2, true, false),
            request(3, true, true),
        ];

        let (queued, committed_in_place) = partition_queued(&requests);
        let ids = |group: &[&WithdrawalRequest]| group.iter().map(|wr| wr.id).collect::<Vec<_>>();
        assert_eq!(ids(&queued), [requests[0].id, requests[1].id]);
        assert_eq!(ids(&committed_in_place), [requests[2].id]);
        assert_eq!(
            queued
                .iter()
                .map(|wr| queued_status(wr))
                .collect::<Vec<_>>(),
            ["requested", "approved"]
        );
    }
}
