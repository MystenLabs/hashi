//! Withdrawal command implementations

use anyhow::Context;
use anyhow::Result;
use bitcoin::hashes::Hash;
use colored::Colorize;

use crate::cli::TxOptions;
use crate::cli::WithdrawCommands;
use crate::cli::client::HashiClient;
use crate::cli::config::CliConfig;
use crate::cli::print_info;
use crate::cli::print_success;
use crate::cli::types::display;
use crate::withdrawals::witness_program_from_address;

pub async fn run(action: WithdrawCommands, config: &CliConfig, tx_opts: &TxOptions) -> Result<()> {
    match action {
        WithdrawCommands::Request {
            amount,
            btc_address,
        } => request(config, tx_opts, amount, &btc_address).await,
        WithdrawCommands::Cancel { request_id } => cancel(config, tx_opts, &request_id).await,
        WithdrawCommands::Status { request_id } => status(config, &request_id).await,
        WithdrawCommands::List => list(config).await,
    }
}

async fn request(
    config: &CliConfig,
    _tx_opts: &TxOptions,
    amount: u64,
    btc_address: &str,
) -> Result<()> {
    config.validate()?;

    let hashi_ids = crate::config::HashiIds {
        package_id: config.package_id(),
        hashi_object_id: config.hashi_object_id(),
    };

    let signer = config
        .load_keypair()?
        .context("Keypair required for withdrawal request. Set keypair_path in config.")?;

    // Parse the BTC destination address and verify it matches the configured network
    let btc_network = crate::btc_monitor::config::parse_btc_network(
        config.bitcoin.as_ref().and_then(|b| b.network.as_deref()),
    )?;
    let btc_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        btc_address.parse().context("Invalid Bitcoin address")?;
    let btc_addr = btc_addr
        .require_network(btc_network)
        .context("Withdrawal address does not match the configured Bitcoin network")?;
    let destination_bytes = witness_program_from_address(&btc_addr)?;

    // Get withdrawal fee from on-chain state
    let client_for_fee = HashiClient::new(config).await?;
    let withdrawal_fee_sui = client_for_fee.fetch_withdrawal_fee_sui();

    print_info(&format!("Withdrawal amount: {} sats", amount));
    print_info(&format!("BTC destination: {}", btc_address));
    print_info(&format!("Withdrawal fee: {} MIST", withdrawal_fee_sui));

    let client = sui_rpc::Client::new(&config.sui_rpc_url)?;
    let mut executor = crate::sui_tx_executor::SuiTxExecutor::new(client, signer, hashi_ids);

    print_info("Submitting withdrawal request on Sui...");

    let request_id = executor
        .execute_create_withdrawal_request(amount, destination_bytes, withdrawal_fee_sui)
        .await?;

    print_success(&format!("Withdrawal request created: {}", request_id));

    Ok(())
}

async fn cancel(config: &CliConfig, _tx_opts: &TxOptions, request_id: &str) -> Result<()> {
    config.validate()?;

    let req_addr = request_id
        .parse::<sui_sdk_types::Address>()
        .context("Invalid request ID")?;

    let signer = config
        .load_keypair()?
        .context("Keypair required to cancel withdrawal.")?;

    let hashi_ids = crate::config::HashiIds {
        package_id: config.package_id(),
        hashi_object_id: config.hashi_object_id(),
    };

    let client = sui_rpc::Client::new(&config.sui_rpc_url)?;
    let mut executor = crate::sui_tx_executor::SuiTxExecutor::new(client, signer, hashi_ids);

    print_info("Cancelling withdrawal...");
    executor.execute_cancel_withdrawal(&req_addr).await?;
    print_success("Withdrawal cancelled.");

    Ok(())
}

async fn status(config: &CliConfig, request_id: &str) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let req_addr = request_id
        .parse::<sui_sdk_types::Address>()
        .context("Invalid request ID")?;

    let withdrawal_requests = client.fetch_withdrawal_requests();
    let pending_withdrawals = client.fetch_pending_withdrawals();

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
            display::format_address(&wr.requester_address)
        );
        println!(
            "  {} {}",
            "Requested:".bold(),
            display::format_timestamp(wr.timestamp_ms)
        );
        println!();

        let status_label = if wr.approved {
            "Approved".green()
        } else {
            "Requested".yellow()
        };

        let step = if wr.approved { 2 } else { 1 };
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
    // Check committed/signed pending withdrawals
    else if let Some(pw) = pending_withdrawals
        .iter()
        .find(|p| p.request_ids.contains(&req_addr))
    {
        let txid_bytes: [u8; 32] = pw.id.into();
        let txid = bitcoin::Txid::from_byte_array(txid_bytes);
        let is_signed = pw.signatures.is_some();
        let step = if is_signed { 4 } else { 3 };
        let status_label = if is_signed {
            "Signed".green()
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
            use bitcoincore_rpc::RpcApi;
            match btc_rpc.get_raw_transaction_info(&txid, None) {
                Ok(info) => {
                    let confirmations = info.confirmations.unwrap_or(0);
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

async fn list(config: &CliConfig) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let requests = client.fetch_withdrawal_requests();
    let pending = client.fetch_pending_withdrawals();

    println!("\n{}", "Withdrawal Requests".bold());
    println!("{}", "━".repeat(80).dimmed());

    if requests.is_empty() && pending.is_empty() {
        print_info("No withdrawal requests found.");
    } else {
        if !requests.is_empty() {
            println!("  {}", "Queued:".bold().underline());
            println!(
                "  {:<20} {:<14} {:<10} {}",
                "Request ID".bold(),
                "Amount (sats)".bold(),
                "Status".bold(),
                "Requested".bold()
            );
            for wr in &requests {
                let status = if wr.approved { "Approved" } else { "Requested" };
                println!(
                    "  {:<20} {:<14} {:<10} {}",
                    display::format_address(&wr.id),
                    wr.btc_amount,
                    status,
                    display::format_timestamp(wr.timestamp_ms)
                );
            }
        }

        if !pending.is_empty() {
            if !requests.is_empty() {
                println!();
            }
            println!("  {}", "Committed/Signed:".bold().underline());
            for pw in &pending {
                let txid_bytes: [u8; 32] = pw.id.into();
                let txid = bitcoin::Txid::from_byte_array(txid_bytes);
                let status = if pw.signatures.is_some() {
                    "Signed"
                } else {
                    "Committed"
                };
                println!(
                    "  txid: {}  status: {}  requests: {}",
                    &txid.to_string()[..16],
                    status,
                    pw.request_ids.len()
                );
            }
        }

        println!(
            "\n  {} queued, {} committed/signed",
            requests.len(),
            pending.len()
        );
    }

    println!("{}", "━".repeat(80).dimmed());
    Ok(())
}
