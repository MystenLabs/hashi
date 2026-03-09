//! Deposit command implementations

use anyhow::Context;
use anyhow::Result;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::XOnlyPublicKey;
use colored::Colorize;

use crate::cli::DepositCommands;
use crate::cli::TxOptions;
use crate::cli::client::HashiClient;
use crate::cli::config::CliConfig;
use crate::cli::print_info;
use crate::cli::print_success;
use crate::cli::types::display;

pub async fn run(action: DepositCommands, config: &CliConfig, tx_opts: &TxOptions) -> Result<()> {
    match action {
        DepositCommands::GenerateAddress { recipient } => {
            generate_address(config, recipient.as_deref()).await
        }
        DepositCommands::SendBtc { amount, recipient } => {
            send_btc(config, amount, recipient.as_deref())
                .await
                .map(|_| ())
        }
        DepositCommands::Request {
            txid,
            vout,
            amount,
            recipient,
        } => request(config, tx_opts, &txid, vout, amount, recipient.as_deref()).await,
        DepositCommands::Execute { amount, recipient } => {
            execute(config, tx_opts, amount, recipient.as_deref()).await
        }
        DepositCommands::Status { request_id } => status(config, &request_id).await,
        DepositCommands::List => list(config).await,
    }
}

/// Parse raw on-chain MPC public key bytes and derive the deposit address.
fn cli_derive_deposit_address(
    mpc_pubkey_bytes: &[u8],
    recipient: Option<&sui_sdk_types::Address>,
    btc_network: bitcoin::Network,
) -> Result<bitcoin::Address> {
    use fastcrypto::groups::secp256k1::ProjectivePoint;
    use fastcrypto::serde_helpers::ToFromByteArray;

    let mpc_key = match mpc_pubkey_bytes.len() {
        33 => <ProjectivePoint as ToFromByteArray<33>>::from_byte_array(
            mpc_pubkey_bytes
                .try_into()
                .context("MPC key must be 33 bytes")?,
        )
        .context("Failed to parse MPC key as ProjectivePoint")?,
        32 => {
            if recipient.is_some() {
                anyhow::bail!(
                    "Key derivation requires the full 33-byte compressed MPC key, \
                     but only 32-byte x-only key is available"
                );
            }
            let xonly = XOnlyPublicKey::from_slice(mpc_pubkey_bytes)
                .context("Failed to parse 32-byte MPC key")?;
            return Ok(
                hashi_types::guardian::bitcoin_utils::single_key_taproot_script_path_address(
                    &xonly,
                    btc_network,
                ),
            );
        }
        n => anyhow::bail!("Unexpected MPC public key length: {} bytes", n),
    };

    crate::deposits::derive_deposit_address(&mpc_key, recipient, btc_network)
}

async fn generate_address(config: &CliConfig, recipient: Option<&str>) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let mpc_pubkey = client.fetch_mpc_public_key();
    if mpc_pubkey.is_empty() {
        anyhow::bail!("MPC public key not available on-chain. Has the committee completed DKG?");
    }

    let recipient_addr = recipient
        .map(|r| r.parse::<sui_sdk_types::Address>())
        .transpose()
        .context("Invalid recipient Sui address")?;

    let btc_network = crate::btc_monitor::config::parse_btc_network(
        config.bitcoin.as_ref().and_then(|b| b.network.as_deref()),
    );

    let address = cli_derive_deposit_address(&mpc_pubkey, recipient_addr.as_ref(), btc_network)?;

    println!("\n{}", "Deposit Address".bold());
    println!("{}", "━".repeat(50).dimmed());
    println!("  {} {}", "Address:".bold(), address.to_string().green());
    println!("  {} {:?}", "Network:".bold(), btc_network);
    if let Some(r) = recipient {
        println!("  {} {}", "hBTC Recipient:".bold(), r);
    }
    println!("{}", "━".repeat(50).dimmed());

    Ok(())
}

/// Send BTC to the deposit address. Returns the (txid, vout).
async fn send_btc(
    config: &CliConfig,
    amount: u64,
    recipient: Option<&str>,
) -> Result<(bitcoin::Txid, u32)> {
    let client = HashiClient::new(config).await?;

    let mpc_pubkey = client.fetch_mpc_public_key();
    if mpc_pubkey.is_empty() {
        anyhow::bail!("MPC public key not available on-chain.");
    }

    let recipient_addr = recipient
        .map(|r| r.parse::<sui_sdk_types::Address>())
        .transpose()
        .context("Invalid recipient Sui address")?;

    let btc_network = crate::btc_monitor::config::parse_btc_network(
        config.bitcoin.as_ref().and_then(|b| b.network.as_deref()),
    );

    let deposit_address =
        cli_derive_deposit_address(&mpc_pubkey, recipient_addr.as_ref(), btc_network)?;

    print_info(&format!(
        "Sending {} sats to deposit address {}",
        amount, deposit_address
    ));

    let btc_rpc = config.require_btc_rpc_client()?;

    use bitcoincore_rpc::RpcApi;
    let txid = btc_rpc.send_to_address(
        &deposit_address,
        bitcoin::Amount::from_sat(amount),
        None,
        None,
        None,
        None,
        None,
        None,
    )?;

    print_success(&format!("BTC sent! txid: {}", txid));

    // Find the vout
    let tx = btc_rpc.get_raw_transaction(&txid, None)?;
    let vout = tx
        .output
        .iter()
        .position(|output| {
            output.value == bitcoin::Amount::from_sat(amount)
                && output.script_pubkey == deposit_address.script_pubkey()
        })
        .context("Could not find matching output in transaction")? as u32;

    println!("  {} {}", "txid:".bold(), txid);
    println!("  {} {}", "vout:".bold(), vout);
    println!("  {} {} sats", "amount:".bold(), amount);

    Ok((txid, vout))
}

async fn request(
    config: &CliConfig,
    _tx_opts: &TxOptions,
    txid: &str,
    vout: u32,
    amount: u64,
    recipient: Option<&str>,
) -> Result<()> {
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
            let addr = signer.public_key().derive_address();
            print_info(&format!(
                "No --recipient specified, defaulting to signer address {}",
                addr
            ));
            Some(addr)
        }
    };

    let client = sui_rpc::Client::new(&config.sui_rpc_url)?;
    let mut executor = crate::sui_tx_executor::SuiTxExecutor::new(client, signer, hashi_ids);

    let mut txid_bytes: [u8; 32] = hex::decode(txid)
        .context("Invalid txid hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("txid must be 32 bytes (64 hex chars)"))?;
    // Bitcoin displays txids in reversed byte order. The on-chain storage and
    // validator code use bitcoin::Txid::from_byte_array which expects internal
    // (reversed) order, so we must reverse the display-order hex bytes.
    txid_bytes.reverse();
    let txid_address = sui_sdk_types::Address::new(txid_bytes);

    print_info("Submitting deposit request on Sui...");

    let request_id = executor
        .execute_create_deposit_request(txid_address, vout, amount, derivation_path)
        .await?;

    print_success(&format!("Deposit request created: {}", request_id));

    Ok(())
}

async fn execute(
    config: &CliConfig,
    _tx_opts: &TxOptions,
    amount: u64,
    recipient: Option<&str>,
) -> Result<()> {
    print_info("Executing combined deposit flow...");

    // Step 1: Send BTC
    let (txid, vout) = send_btc(config, amount, recipient).await?;

    // Step 2: Mine blocks if localnet is detected
    if let Some(btc_client) = config.btc_rpc_client()? {
        print_info("Bitcoin RPC available, mining 10 blocks...");
        use bitcoincore_rpc::RpcApi;
        let addr = btc_client.get_new_address(None, None)?.assume_checked();
        btc_client.generate_to_address(10, &addr)?;
        print_success("Mined 10 blocks");
    }

    // Step 3: Submit the deposit request on Sui
    request(config, _tx_opts, &txid.to_string(), vout, amount, recipient).await?;

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

    let mut txid_bytes: [u8; 32] = dep.utxo.id.txid.into();
    txid_bytes.reverse();
    let txid = bitcoin::Txid::from_byte_array(txid_bytes);
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
        display::format_timestamp(dep.timestamp_ms)
    );
    println!("  {} {}", "Status:".bold(), "Pending".yellow());

    // BTC context if available
    if let Ok(Some(btc_rpc)) = config.btc_rpc_client() {
        println!();
        println!("  {}", "BTC Context:".bold());
        use bitcoincore_rpc::RpcApi;
        match btc_rpc.get_raw_transaction_info(&txid, None) {
            Ok(info) => {
                let confirmations = info.confirmations.unwrap_or(0);
                println!("    {} {}", "Confirmations:".bold(), confirmations);
                if let Some(ref blockhash) = info.blockhash {
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

async fn list(config: &CliConfig) -> Result<()> {
    let client = HashiClient::new(config).await?;

    let deposits = client.fetch_deposit_requests();

    println!("\n{}", "Deposit Requests".bold());
    println!("{}", "━".repeat(80).dimmed());

    if deposits.is_empty() {
        print_info("No pending deposit requests.");
    } else {
        println!(
            "  {:<20} {:<14} {:<12} {:<10} {}",
            "Request ID".bold(),
            "Amount (sats)".bold(),
            "UTXO".bold(),
            "Status".bold(),
            "Requested".bold()
        );
        for dep in &deposits {
            let mut txid_bytes: [u8; 32] = dep.utxo.id.txid.into();
            txid_bytes.reverse();
            let txid_hex = hex::encode(txid_bytes);
            println!(
                "  {:<20} {:<14} {}:{:<3} {:<10} {}",
                display::format_address(&dep.id),
                dep.utxo.amount,
                &txid_hex[..8],
                dep.utxo.id.vout,
                "Pending".yellow(),
                display::format_timestamp(dep.timestamp_ms)
            );
        }
        println!("\n  {} deposit(s)", deposits.len());
    }

    println!("{}", "━".repeat(80).dimmed());
    Ok(())
}
