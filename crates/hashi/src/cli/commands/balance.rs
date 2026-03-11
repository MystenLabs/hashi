//! Balance command implementation

use anyhow::Context;
use anyhow::Result;
use colored::Colorize;
use sui_rpc::proto::sui::rpc::v2::GetBalanceRequest;
use sui_sdk_types::StructTag;

use crate::cli::config::CliConfig;

pub async fn run(config: &CliConfig, address: &str) -> Result<()> {
    config.validate()?;

    let address = address
        .parse::<sui_sdk_types::Address>()
        .context("Invalid Sui address")?;

    let btc_type = format!("{}::btc::BTC", config.package_id());
    let btc_struct_tag: StructTag = btc_type.parse().context("Failed to parse hBTC coin type")?;

    let mut client = sui_rpc::Client::new(&config.sui_rpc_url)?;

    let response = client
        .state_client()
        .get_balance(
            GetBalanceRequest::default()
                .with_owner(address.to_string())
                .with_coin_type(btc_struct_tag.to_string()),
        )
        .await
        .context("Failed to query hBTC balance")?
        .into_inner();

    let balance_sats = response.balance().balance_opt().unwrap_or(0);

    let btc = balance_sats as f64 / 100_000_000.0;

    println!("\n{}", "hBTC Balance".bold());
    println!("{}", "━".repeat(50).dimmed());
    println!("  {} {}", "Address:".bold(), address);
    println!(
        "  {} {} sats ({:.8} BTC)",
        "Balance:".bold(),
        balance_sats.to_string().green(),
        btc
    );
    println!("{}", "━".repeat(50).dimmed());

    Ok(())
}
