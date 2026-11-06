// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::ensure;
use hashi::cli::TxOptions;
use hashi::cli::client::CreateProposalParams;
use hashi::cli::client::HashiClient;
use hashi::cli::config::CliConfig;
use hashi::cli::upgrade::extract_proposal_id_from_response;
use hashi::onchain::types::ProposalType;
use hashi::sui_tx_executor::TxOutcome;

use crate::config::Config;

/// Explicitly pause Hashi using the configured governance identities.
///
/// Nothing calls this on monitor startup. Success means the on-chain paused flag
/// was observed, not that nodes acknowledged it or Bitcoin broadcasts stopped.
/// Errors after submission can mean a transaction landed: inspect the chain
/// before retrying. This function neither resumes proposals nor unpauses Hashi.
pub async fn initiate_pause(config: &Config) -> anyhow::Result<()> {
    let pause = config
        .pause
        .as_ref()
        .context("pause configuration is required to initiate a pause")?;
    // Check on-chain state before loading any signing credentials.
    let read_config = CliConfig {
        sui_rpc_url: pause.transaction_rpc_url.clone(),
        package_id: Some(config.sui.package_id()),
        hashi_object_id: Some(pause.object_id()),
        ..CliConfig::default()
    };
    let reader = HashiClient::new(&read_config).await?;
    if reader.onchain_state().state().hashi().config.paused() {
        return Ok(());
    }
    // The first configured operator creates the proposal and automatically votes.
    let (first_path, remaining_paths) = pause
        .operator_key_paths
        .split_first()
        .context("at least one pause operator key must be configured")?;
    let first_config = CliConfig {
        keypair_path: Some(first_path.clone()),
        ..read_config.clone()
    };
    let first = HashiClient::new(&first_config).await?;

    let options = TxOptions {
        gas_budget: None,
        skip_confirm: true,
        dry_run: false,
        serialize_unsigned: false,
        sender: None,
        gas_object: None,
        gas_price: None,
    };
    let create = first.build_create_proposal_transaction(CreateProposalParams::EmergencyPause {
        pause: true,
        metadata: vec![],
    })?;
    let TxOutcome::Executed(response) = first
        .finalize_tx(create, &options)
        .await
        .context("creating pause proposal; submission may have landed")?
    else {
        anyhow::bail!("pause proposal was not executed");
    };
    let proposal_id = extract_proposal_id_from_response(&response)
        .context("pause proposal creation succeeded but its ID could not be read")?;
    let proposal_context = || {
        format!(
            "pause proposal {proposal_id} did not complete confirmation; submitted transactions may have landed"
        )
    };

    // Collect approvals from the remaining configured operators.
    for path in remaining_paths {
        let voter = HashiClient::new(&CliConfig {
            keypair_path: Some(path.clone()),
            ..read_config.clone()
        })
        .await
        .with_context(proposal_context)?;
        let vote = voter
            .build_vote_transaction(
                proposal_id,
                voter
                    .proposal_type_arg(&ProposalType::EmergencyPause)
                    .with_context(proposal_context)?,
            )
            .with_context(proposal_context)?;
        voter
            .finalize_tx(vote, &options)
            .await
            .with_context(proposal_context)?;
    }

    // Execute the approved proposal using the proposer's credentials.
    let executor = HashiClient::new(&first_config)
        .await
        .with_context(proposal_context)?;
    let execute = executor
        .build_execute_proposal_transaction(proposal_id, &ProposalType::EmergencyPause)
        .with_context(proposal_context)?;
    executor
        .finalize_tx(execute, &options)
        .await
        .with_context(proposal_context)?;

    // Read fresh state so success means the paused flag was actually observed.
    let confirmed = HashiClient::new(&read_config)
        .await
        .with_context(proposal_context)?;
    ensure!(
        confirmed.onchain_state().state().hashi().config.paused(),
        "on-chain paused flag was not observed after executing pause proposal {proposal_id}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use e2e_tests::TestNetworksBuilder;
    use hashi_types::move_types::ConfigValue;

    use crate::config::PauseConfig;

    #[tokio::test]
    async fn pause_requires_configuration() {
        let error = initiate_pause(&Config::for_tests()).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "pause configuration is required to initiate a pause"
        );
    }

    #[tokio::test]
    async fn pause_with_three_operators() -> anyhow::Result<()> {
        assert_pause_with_operators(3, 4000).await
    }

    #[tokio::test]
    async fn pause_with_one_operator() -> anyhow::Result<()> {
        assert_pause_with_operators(1, 2000).await
    }

    async fn assert_pause_with_operators(count: usize, threshold: u64) -> anyhow::Result<()> {
        let networks = TestNetworksBuilder::new()
            .with_nodes(4)
            .with_onchain_config(
                "governance_emergency_pause_threshold_bps",
                ConfigValue::U64(threshold),
            )
            .build()
            .await?;
        let ids = networks.hashi_network().ids();
        let keys = tempfile::tempdir()?;
        let paths: Vec<_> = (0..count)
            .map(|index| keys.path().join(format!("operator-{index}.pem")))
            .collect();
        for (node, path) in networks.hashi_network().nodes().iter().zip(&paths) {
            std::fs::write(path, node.config().operator_private_key.as_ref().unwrap())?;
        }
        let mut config = Config::for_tests();
        // Keep the default unreachable audit RPC to prove pause uses only the fullnode.
        config.sui.package_id = Some(ids.package_id);
        config.pause = Some(PauseConfig {
            transaction_rpc_url: networks.sui_network().rpc_url.clone(),
            operator_key_paths: paths,
            object_id: Some(ids.hashi_object_id),
        });
        let read_config = CliConfig {
            sui_rpc_url: networks.sui_network().rpc_url.clone(),
            package_id: Some(ids.package_id),
            hashi_object_id: Some(ids.hashi_object_id),
            ..CliConfig::default()
        };
        let before = HashiClient::new(&read_config).await?;
        assert!(!before.onchain_state().state().hashi().config.paused());
        initiate_pause(&config).await?;
        let paused = HashiClient::new(&read_config).await?;
        assert!(paused.onchain_state().state().hashi().config.paused());
        let executed = paused.fetch_executed_proposals();
        let proposal = executed
            .iter()
            .find(|proposal| proposal.proposal_type == ProposalType::EmergencyPause)
            .context("executed pause proposal not found")?;
        let details = paused.fetch_proposal_details(proposal.id).await?;
        assert_eq!(details.votes.len(), count);

        // An already-paused bridge needs no signing credentials.
        keys.close()?;
        config.pause.as_mut().unwrap().operator_key_paths.clear();
        initiate_pause(&config).await?;
        Ok(())
    }
}
