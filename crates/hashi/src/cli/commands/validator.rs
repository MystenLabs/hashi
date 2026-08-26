// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Validator lifecycle command implementations (resign / withdraw).

use anyhow::Result;
use colored::Colorize;

use crate::cli::TxOptions;
use crate::cli::client::HashiClient;
use crate::cli::commands::proposal::execute_or_simulate;
use crate::cli::commands::proposal::prompt_continue;
use crate::cli::config::CliConfig;
use crate::cli::print_detail;
use crate::cli::print_info;

/// Voluntarily resign from the committee.
pub async fn resign(config: &CliConfig, tx_opts: &TxOptions) -> Result<()> {
    let mut client = HashiClient::new(config).await?;

    print_detail(&format!("\n{}", "Resigning from the committee:".bold()));
    match client.onchain_state().pending_epoch_change() {
        Some(pending) => print_detail(&format!(
            "  Effect: a reconfiguration to epoch {pending} is in flight — if this node is in \
             the pending committee, the resignation takes effect one epoch later",
        )),
        None => print_detail(
            "  Effect: at the next committee formation, which will exclude this node; the \
             registration can then be removed by anyone via `validator remove-inactive`",
        ),
    }
    print_detail(
        "  Keep the node RUNNING until then: it still owes the current epoch its signing \
         duties. The node suppresses its own auto-registration while the resignation is \
         pending; after removal, re-joining requires `hashi register` again.",
    );

    prompt_continue("resign from the committee", tx_opts).await?;

    let tx = client.build_resign_transaction()?;
    print_info("Transaction: validator::resign");
    execute_or_simulate(&mut client, tx, tx_opts).await?;
    Ok(())
}

/// Withdraw a pending resignation.
pub async fn withdraw_resignation(config: &CliConfig, tx_opts: &TxOptions) -> Result<()> {
    let mut client = HashiClient::new(config).await?;

    print_detail(&format!(
        "\n{}",
        "Withdrawing the pending resignation:".bold()
    ));
    print_detail(
        "  If the next committee was already formed without this node, it keeps its \
         registration but sits out that one epoch.",
    );

    prompt_continue("withdraw the resignation", tx_opts).await?;

    let tx = client.build_withdraw_resignation_transaction()?;
    print_info("Transaction: validator::withdraw_resignation");
    execute_or_simulate(&mut client, tx, tx_opts).await?;
    Ok(())
}

/// Permissionlessly remove an inactive member's registration.
pub async fn remove_inactive(
    config: &CliConfig,
    validator: &str,
    tx_opts: &TxOptions,
) -> Result<()> {
    use anyhow::Context as _;
    let validator = sui_sdk_types::Address::from_hex(validator)
        .with_context(|| format!("invalid validator address: {validator}"))?;
    let mut client = HashiClient::new(config).await?;

    print_detail(&format!(
        "\n{}",
        "Removing an inactive member's registration:".bold()
    ));
    print_detail(&format!("  Member: {validator}"));
    print_detail(
        "  Eligibility (checked on-chain): not in the current or pending \
         committee, not governance-ignored, and either resigned or no longer \
         in Sui's active validator set.",
    );

    prompt_continue("remove this member's registration", tx_opts).await?;

    let tx = client.build_remove_inactive_member_transaction(validator)?;
    print_info("Transaction: validator::remove_inactive_member");
    execute_or_simulate(&mut client, tx, tx_opts).await?;
    Ok(())
}
