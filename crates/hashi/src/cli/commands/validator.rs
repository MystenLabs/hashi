// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Validator lifecycle command implementations (resign / withdraw).

use anyhow::Result;
use colored::Colorize;

use crate::cli::TxOptions;
use crate::cli::client::HashiClient;
use crate::cli::commands::proposal::execute_or_simulate;
use crate::cli::commands::proposal::print_acting_validator;
use crate::cli::commands::proposal::prompt_continue;
use crate::cli::config::CliConfig;
use crate::cli::print_detail;
use crate::cli::print_info;

/// What a resign-family command is about to do, for the pre-check text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResignationAction {
    Resign,
    Withdraw,
}

/// Refuse a resign or withdrawal the chain would reject (`EAlreadyResigned`
/// / `ENotResigned`), from the registration record already in the scrape.
/// `resigned` is `None` when the validator is not registered at all.
pub fn refuse_resignation_state(
    validator: sui_sdk_types::Address,
    resigned: Option<bool>,
    action: ResignationAction,
) -> Result<()> {
    let Some(resigned) = resigned else {
        anyhow::bail!(
            "validator {} is not registered, so there is nothing to resign from or withdraw",
            validator.to_hex()
        );
    };
    match action {
        ResignationAction::Resign => anyhow::ensure!(
            !resigned,
            "validator {} has already resigned; nothing to do. Use `hashi validator \
             withdraw-resignation` to cancel it.",
            validator.to_hex()
        ),
        ResignationAction::Withdraw => anyhow::ensure!(
            resigned,
            "validator {} has no pending resignation to withdraw",
            validator.to_hex()
        ),
    }
    Ok(())
}

fn refuse_from_registration(client: &HashiClient, action: ResignationAction) -> Result<()> {
    let validator = client.resolve_validator_address()?;
    let resigned = client.member_info(&validator).map(|m| m.resigned);
    refuse_resignation_state(validator, resigned, action)
}

/// Voluntarily resign from the committee.
pub async fn resign(config: &CliConfig, tx_opts: &TxOptions) -> Result<()> {
    let mut client = HashiClient::new(config).await?;
    refuse_from_registration(&client, ResignationAction::Resign)?;

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
    print_acting_validator(&client)?;

    if !prompt_continue("resign from the committee", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let tx = client.build_resign_transaction()?;
    print_info("Transaction: validator::resign");
    execute_or_simulate(&mut client, tx, tx_opts).await?;
    Ok(())
}

/// Withdraw a pending resignation.
pub async fn withdraw_resignation(config: &CliConfig, tx_opts: &TxOptions) -> Result<()> {
    let mut client = HashiClient::new(config).await?;
    refuse_from_registration(&client, ResignationAction::Withdraw)?;

    print_detail(&format!(
        "\n{}",
        "Withdrawing the pending resignation:".bold()
    ));
    print_detail(
        "  If the next committee was already formed without this node, it keeps its \
         registration but sits out that one epoch.",
    );
    print_acting_validator(&client)?;

    if !prompt_continue("withdraw the resignation", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

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

    if !prompt_continue("remove this member's registration", tx_opts).await? {
        crate::cli::print_warning("Aborted.");
        return Ok(());
    }

    let tx = client.build_remove_inactive_member_transaction(validator)?;
    print_info("Transaction: validator::remove_inactive_member");
    execute_or_simulate(&mut client, tx, tx_opts).await?;
    Ok(())
}

#[cfg(test)]
#[path = "validator_tests.rs"]
mod tests;
