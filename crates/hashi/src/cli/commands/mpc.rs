// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! MPC command implementations

use anyhow::Result;
use colored::Colorize;
use tabled::Table;
use tabled::Tabled;

use crate::cli::client::HashiClient;
use crate::cli::config::CliConfig;
use crate::cli::print_info;
use crate::cli::types::display;
use crate::mpc::MpcError;
use crate::mpc::build_reduced_nodes;
use crate::mpc::manager_committees;
use crate::mpc::reduction_digest;
use crate::mpc::signing_version;

/// Print the reduction of each committee a node reads now; fails if any
/// committee cannot be reduced.
pub async fn show_reduction(config: &CliConfig, version_override: Option<u64>) -> Result<()> {
    let client = HashiClient::new(config).await?;
    let chain_id =
        crate::sui_rpc_client::fetch_sui_chain_id(&mut client.onchain_state().client()).await?;
    print_info(&format!("Sui chain ID: {chain_id}"));

    let state = client.onchain_state().state();
    let committee_set = &state.hashi().committees;
    let current = committee_set.epoch();
    let pending = committee_set.pending_epoch_change();
    print_info(&format!(
        "Current epoch {current}, pending epoch change {pending:?}"
    ));
    let committees = manager_committees(committee_set, pending.unwrap_or(current))?;
    let label = |epoch: u64, role: &'static str| {
        if Some(epoch) == pending {
            "pending"
        } else if epoch == current {
            "current"
        } else {
            role
        }
    };

    #[derive(Tabled)]
    struct MemberRow {
        #[tabled(rename = "Validator Address")]
        validator: String,
        #[tabled(rename = "Weight")]
        weight: u64,
        #[tabled(rename = "Reduced Weight")]
        reduced_weight: u16,
        #[tabled(rename = "Share IDs")]
        share_ids: String,
    }

    let mut printed = std::collections::BTreeSet::new();
    let mut failed = 0;
    for (committee, role) in std::iter::once((committees.current, "current"))
        .chain(committees.previous.map(|c| (c, "previous")))
        .chain(committees.input.map(|c| (c, "input")))
    {
        let epoch = committee.epoch();
        if !printed.insert(epoch) {
            continue;
        }
        println!(
            "\n{}",
            format!("Epoch {epoch} ({})", label(epoch, role)).bold()
        );
        let reduction = version_override
            .map_or_else(
                || signing_version(committee.config()).map_err(MpcError::SigningVersionRefused),
                Ok,
            )
            .and_then(|version| {
                build_reduced_nodes(committee, version, 1, &chain_id)
                    .map(|(nodes, threshold, max_faulty)| (version, nodes, threshold, max_faulty))
            });
        let (version, nodes, threshold, max_faulty) = match reduction {
            Ok(reduction) => reduction,
            Err(error) => {
                println!("  {} {error}", "error:".red().bold());
                failed += 1;
                continue;
            }
        };
        println!(
            "  version {version}, W' {}, t' {threshold}, f' {max_faulty}, digest {}",
            nodes.total_weight(),
            reduction_digest(version, &nodes, threshold, max_faulty)
        );
        let rows: Vec<MemberRow> = committee
            .members()
            .iter()
            .zip(nodes.iter())
            .map(|(member, node)| MemberRow {
                validator: display::format_address(&member.validator_address()),
                weight: member.weight(),
                reduced_weight: node.weight,
                share_ids: nodes
                    .share_ids_of(node.id)
                    .map(|ids| format_share_ids(ids.iter().map(|id| id.get())))
                    .unwrap_or_default(),
            })
            .collect();
        println!("{}", Table::new(rows));
    }
    anyhow::ensure!(failed == 0, "{failed} committee(s) could not be reduced");
    Ok(())
}

fn format_share_ids(ids: impl IntoIterator<Item = u16>) -> String {
    let mut runs: Vec<(u16, u16)> = Vec::new();
    for id in ids {
        match runs.last_mut() {
            Some((_, end)) if end.checked_add(1) == Some(id) => *end = id,
            _ => runs.push((id, id)),
        }
    }
    runs.iter()
        .map(|&(start, end)| {
            if start == end {
                start.to_string()
            } else {
                format!("{start}-{end}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}
