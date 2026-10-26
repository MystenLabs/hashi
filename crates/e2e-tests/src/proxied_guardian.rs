// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A fresh guardian behind a guardian proxy, for tests that send requests the
//! nodes would never send.

use anyhow::Result;
use std::sync::Arc;

use crate::TestNetworks;

/// A fresh guardian behind a guardian proxy with its Sui gates. The guardian
/// starts at the current committee. Nodes do not call it, so a test can send
/// it requests that the nodes would never send.
pub struct ProxiedGuardian {
    pub guardian: crate::guardian_harness::GuardianHarness,
    pub client: hashi_types::proto::guardian_service_client::GuardianServiceClient<
        tonic::transport::Channel,
    >,
    pub metrics: Arc<hashi_guardian_proxy::metrics::ProxyMetrics>,
    _server: tokio::task::JoinSet<std::result::Result<(), tonic::transport::Error>>,
}

pub async fn spawn_proxied_guardian(networks: &TestNetworks) -> Result<ProxiedGuardian> {
    use crate::guardian_harness::GuardianHarness;
    use crate::guardian_harness::default_test_limiter_config;
    use hashi_guardian_proxy::Forwarding;
    use hashi_guardian_proxy::kp::roster::RosterCache;
    use hashi_guardian_proxy::log_store::LogStore;
    use hashi_guardian_proxy::metrics::ProxyMetrics;
    use hashi_guardian_proxy::node::handoffs::HandoffGate;
    use hashi_guardian_proxy::node::members::ChainSource;
    use hashi_guardian_proxy::node::withdrawals::WithdrawalGate;
    use hashi_types::guardian::LimiterState;
    use hashi_types::proto::guardian_service_client::GuardianServiceClient;
    use hashi_types::proto::guardian_service_server::GuardianServiceServer;
    use tokio_stream::wrappers::TcpListenerStream;

    /// The KP-signed RPCs read logs. These tests do not send them.
    struct NoLogs;

    #[tonic::async_trait]
    impl LogStore for NoLogs {
        async fn list_dirs(&self, _: &str) -> Result<Vec<String>> {
            anyhow::bail!("node RPCs must not read logs")
        }
        async fn list_keys(&self, _: &str) -> Result<Vec<String>> {
            anyhow::bail!("node RPCs must not read logs")
        }
        async fn get(&self, _: &str) -> Result<Vec<u8>> {
            anyhow::bail!("node RPCs must not read logs")
        }
    }

    let node = networks.hashi_network().nodes()[0].hashi();
    let committee = node.onchain_state().current_committee().unwrap();
    let guardian = GuardianHarness::start(bitcoin::Network::Regtest).await?;
    let limiter_config = default_test_limiter_config();
    guardian
        .finalize(
            committee,
            node.onchain_state().onchain_verifying_key_g()?,
            limiter_config,
            LimiterState::genesis(&limiter_config),
            networks.hashi_network().ids().hashi_object_id,
        )
        .await?;
    let channel = tonic::transport::Endpoint::from_shared(guardian.endpoint().to_owned())?
        .connect()
        .await?;
    let sui_rpc_url = &networks.sui_network.rpc_url;
    let metrics = Arc::new(ProxyMetrics::new());
    let handoffs = Arc::new(HandoffGate::new(
        ChainSource::new(channel.clone(), sui_rpc_url)?,
        metrics.clone(),
    ));
    let withdrawals = Arc::new(WithdrawalGate::new(
        ChainSource::new(channel.clone(), sui_rpc_url)?,
        bitcoin::Network::Regtest,
        metrics.clone(),
    ));
    let proxy = Forwarding::new(
        channel.clone(),
        channel,
        Arc::new(RosterCache::new(NoLogs)),
        handoffs,
        withdrawals,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let mut server = tokio::task::JoinSet::new();
    server.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(GuardianServiceServer::new(proxy))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
    });
    let client = GuardianServiceClient::connect(endpoint).await?;
    Ok(ProxiedGuardian {
        guardian,
        client,
        metrics,
        _server: server,
    })
}

/// Certify `message` with the keys of every node in `committee`. This models
/// a compromised quorum.
pub fn certify<T: hashi_types::intent::IntentMessage + Clone>(
    networks: &TestNetworks,
    committee: &hashi_types::committee::RuntimeCommittee,
    message: T,
) -> Result<hashi_types::committee::SignedMessage<T>> {
    use anyhow::Context;

    let hashi_object_id = networks.hashi_network().ids().hashi_object_id;
    let mut aggregator = committee.signature_aggregator(hashi_object_id, message.clone());
    for node in networks.hashi_network().nodes() {
        let address = node.hashi().config.validator_address()?;
        let member = committee
            .members()
            .iter()
            .find(|member| member.validator_address() == address)
            .context("node is not in the committee")?;
        let key = node
            .hashi()
            .db
            .find_signing_key_matching(member.public_key())?
            .context("committee signing key is missing")?;
        aggregator.add_signature(key.sign(
            hashi_object_id,
            committee.epoch(),
            address,
            &message,
        ))?;
    }
    let signed = aggregator.finish()?;
    committee.verify_signature_and_weight(
        hashi_object_id,
        &signed,
        hashi_types::committee::certificate_threshold(committee.total_weight()),
    )?;
    Ok(signed)
}
