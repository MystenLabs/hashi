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
use sui_sdk_types::Address;

use crate::config::Config;

/// Explicitly pause Hashi using the configured governance identities.
///
/// Each configured operator is used once, in order. The first that succeeds
/// creates the proposal, which also votes for it, and the rest vote. An
/// operator that fails is logged and skipped, so one bad key cannot block the
/// pause. The chain checks the quorum on execution.
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
    ensure!(
        !pause.operator_key_paths.is_empty(),
        "at least one pause operator key must be configured"
    );

    // The proposal and the operator that created it, who executes it.
    let mut proposal: Option<(Address, CliConfig)> = None;
    for path in &pause.operator_key_paths {
        let operator = CliConfig {
            keypair_path: Some(path.clone()),
            ..read_config.clone()
        };
        let step = match &proposal {
            None => create_proposal(&operator)
                .await
                .map(|proposal_id| proposal = Some((proposal_id, operator))),
            Some((proposal_id, _)) => vote(&operator, *proposal_id).await,
        };
        if let Err(error) = step {
            tracing::warn!(key = %path.display(), "pause operator failed: {error:#}");
        }
    }
    let (proposal_id, creator) =
        proposal.context("no configured operator could create a pause proposal")?;
    let proposal_context = || {
        format!(
            "pause proposal {proposal_id} did not complete confirmation; submitted transactions may have landed"
        )
    };

    // Execute the approved proposal using the proposer's credentials.
    let executor = HashiClient::new(&creator)
        .await
        .with_context(proposal_context)?;
    let execute = executor
        .build_execute_proposal_transaction(proposal_id, &ProposalType::EmergencyPause)
        .with_context(proposal_context)?;
    executor
        .finalize_tx(execute, &TX_OPTIONS)
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

const TX_OPTIONS: TxOptions = TxOptions {
    gas_budget: None,
    skip_confirm: true,
    dry_run: false,
    serialize_unsigned: false,
    sender: None,
    gas_object: None,
    gas_price: None,
};

/// Create a pause proposal, which also votes for it.
async fn create_proposal(operator: &CliConfig) -> anyhow::Result<Address> {
    let client = HashiClient::new(operator).await?;
    let create =
        client.build_create_proposal_transaction(CreateProposalParams::EmergencyPause {
            pause: true,
            metadata: vec![],
        })?;
    let TxOutcome::Executed(response) = client
        .finalize_tx(create, &TX_OPTIONS)
        .await
        .context("creating pause proposal; submission may have landed")?
    else {
        anyhow::bail!("pause proposal was not executed");
    };
    extract_proposal_id_from_response(&response)
        .context("pause proposal creation succeeded but its ID could not be read")
}

async fn vote(operator: &CliConfig, proposal_id: Address) -> anyhow::Result<()> {
    let client = HashiClient::new(operator).await?;
    let vote = client.build_vote_transaction(
        proposal_id,
        client.proposal_type_arg(&ProposalType::EmergencyPause)?,
    )?;
    client.finalize_tx(vote, &TX_OPTIONS).await?;
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
    async fn pause_with_one_operator() -> anyhow::Result<()> {
        assert_pause(&[Some(0)], 2000, 1).await
    }

    #[tokio::test]
    async fn pause_skips_failing_operators() -> anyhow::Result<()> {
        assert_pause(&[None, Some(0), None, Some(1)], 4000, 2).await
    }

    /// Each operator is a node's key, or `None` for an unreadable key file.
    async fn assert_pause(
        operators: &[Option<usize>],
        threshold: u64,
        expected_votes: usize,
    ) -> anyhow::Result<()> {
        let networks = TestNetworksBuilder::new()
            .with_nodes(4)
            .with_onchain_config(
                "governance_emergency_pause_threshold_bps",
                ConfigValue::U64(threshold),
            )
            .build()
            .await?;
        let ids = networks.hashi_network().ids();
        let nodes = networks.hashi_network().nodes();
        let keys = tempfile::tempdir()?;
        let mut paths = Vec::new();
        for (index, operator) in operators.iter().enumerate() {
            let path = keys.path().join(format!("operator-{index}.pem"));
            let key = match operator {
                Some(node) => nodes[*node].config().operator_private_key.clone().unwrap(),
                None => "not a key".to_owned(),
            };
            std::fs::write(&path, key)?;
            paths.push(path);
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
        assert_eq!(details.votes.len(), expected_votes);

        // An already-paused bridge needs no signing credentials.
        keys.close()?;
        config.pause.as_mut().unwrap().operator_key_paths.clear();
        initiate_pause(&config).await?;
        Ok(())
    }
}
