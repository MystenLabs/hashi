// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::Result;
use hashi_guardian_proxy::config::Config;
use hashi_guardian_proxy::forward::Forwarding;
use hashi_guardian_proxy::kp::relay::Relay;
use hashi_guardian_proxy::kp::roster::RosterCache;
use hashi_guardian_proxy::log_store::S3LogStore;
use hashi_guardian_proxy::metrics::ProxyMetrics;
use hashi_guardian_proxy::node::cache::CachingGuardianGrpc;
use hashi_guardian_proxy::node::member_auth::MemberGate;
use hashi_guardian_proxy::node::members::ChainMemberSource;
use hashi_guardian_proxy::node::members::MemberAllowlist;
use hashi_guardian_proxy::node::widlog::WidLogIndex;
use hashi_guardian_proxy::public::info;
use hashi_guardian_proxy::remote_write;
use hashi_guardian_proxy::tls;
use hashi_guardian_proxy::tls::ServerCert;
use hashi_types::guardian::time::now_timestamp_secs;
use hashi_types::proto::guardian_relay_service_server::GuardianRelayServiceServer;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use hashi_types::proto::guardian_service_server::GuardianServiceServer;
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::Endpoint;
use tonic_health::server::health_reporter;
use tracing::error;
use tracing::info;
use tracing::warn;

#[tokio::main]
async fn main() -> Result<()> {
    hashi_types::telemetry::TelemetryConfig::new()
        .with_file_line(true)
        .with_env()
        .init();

    abort_on_panic();

    let mut config = Config::from_env()?;
    info!(
        backend = %config.backend_url,
        standby = config.standby_backend_url.as_deref().unwrap_or("<none>"),
        listen = %config.listen_addr,
        log_bucket = %config.log_bucket,
        network = %config.btc_network,
        sui_rpc = %config.sui_rpc_url,
        "Starting hashi-guardian-proxy (wid-keyed cache + node forwarder + provisioning relay)."
    );

    // The source of the wid index and the roster source of the relay. Prove
    // bucket access before you serve: a proxy that cannot read the log fails
    // each withdrawal closed.
    let log_store = S3LogStore::connect(config.log_bucket.clone(), config.log_region.clone()).await;
    probe_with_retries(&log_store).await?;

    let metrics = Arc::new(ProxyMetrics::new());
    tokio::spawn({
        let metrics = metrics.clone();
        let addr = config.metrics_listen_addr;
        async move {
            if let Err(e) = metrics.serve(addr).await {
                error!(error = %e, "Metrics server exited.");
            }
        }
    });
    match config.remote_write.take() {
        Some(remote_write) => remote_write::start(remote_write, metrics.registry())?,
        None => warn!("MIMIR_URL is unset: guardian_proxy_* metrics will not leave this task."),
    }

    // Lazy channel to the active enclave guardian, shared by the forwarder and
    // the /info reader. Mirrors the node-side client
    // (crates/hashi/src/grpc/guardian_client.rs): same timeout + keepalive.
    let channel = lazy_channel(&config.backend_url, &config)?;
    // The relay provisions the standby when one is configured; the node-facing
    // forwarder, wid cache, and /info always front the active guardian.
    let relay_channel = match &config.standby_backend_url {
        Some(url) => lazy_channel(url, &config)?,
        None => channel.clone(),
    };

    // The member gate's allowlist follows the committee of the Hashi object the
    // active guardian serves.
    let allowlist = Arc::new(MemberAllowlist::new(metrics.clone()));
    tokio::spawn(allowlist.clone().refresh_forever(ChainMemberSource::new(
        channel.clone(),
        &config.sui_rpc_url,
    )?));
    let gate = Arc::new(MemberGate::new(allowlist, metrics.clone()));

    // One roster cache, shared: the relay authorizes submissions against it and
    // a cert rotation through the forwarder invalidates it.
    let roster = Arc::new(RosterCache::new(log_store.clone()));
    let relay_svc = Relay::new(relay_channel.clone(), roster.clone());
    let info_state = info::InfoState::new(
        GuardianServiceClient::new(channel.clone()),
        config.info_cache_ttl,
    );
    // Fill the wid index before the listeners open, so a miss is definite
    // from the first request. The tail keeps it current.
    let widlog = Arc::new(WidLogIndex::new(
        log_store,
        metrics.clone(),
        now_timestamp_secs(),
    ));
    widlog
        .tick(now_timestamp_secs())
        .await
        .context("backfill the wid index")?;
    info!("Wid index backfilled.");
    tokio::spawn(widlog.clone().tail_forever());
    // KPs confirm a ceremony to the guardian they are provisioning, so that
    // RPC follows the relay's backend.
    let guardian_svc = CachingGuardianGrpc::new(
        Forwarding::new(channel, relay_channel, roster),
        widlog,
        metrics.clone(),
    );

    // Standard gRPC health service (`grpc.health.v1.Health`) for gRPC
    // health-checkers; the HTTP `/health` route below covers plain-HTTP liveness.
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<GuardianServiceServer<CachingGuardianGrpc<Forwarding<S3LogStore>, S3LogStore>>>()
        .await;
    health_reporter
        .set_serving::<GuardianRelayServiceServer<Relay<S3LogStore>>>()
        .await;
    // A gRPC health check may query the empty ("") service, so mark it serving
    // too — otherwise such a check flaps the proxy as unhealthy.
    health_reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;

    let router =
        hashi_guardian_proxy::router(guardian_svc, relay_svc, health_service, info_state, gate);

    let node_server = match config.node_tls.clone() {
        Some(source) => {
            let cert = ServerCert::load(&source, &metrics)
                .await
                .context("load the TLS certificate")?;
            tokio::spawn(cert.clone().reload_forever(source, metrics.clone()));
            // As the node's server does: pings find the connections a TCP load
            // balancer dropped silently, and the age limit closes ones that never
            // send a request, which nothing else times out.
            let server = sui_http::Builder::new()
                .config(
                    sui_http::Config::default()
                        .http2_keepalive_interval(Some(Duration::from_secs(30)))
                        .max_connection_age(Duration::from_secs(120))
                        .max_connection_age_grace(Duration::from_secs(120)),
                )
                .tls_config(tls::server_config(cert)?)
                .serve(config.node_listen_addr, router.clone())
                .map_err(|e| {
                    anyhow::anyhow!("bind node listener to {}: {e}", config.node_listen_addr)
                })?;
            info!("Node listener on {} (TLS).", config.node_listen_addr);
            Some(server)
        }
        None => {
            warn!("No TLS certificate is configured, so there is no node listener.");
            None
        }
    };

    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("bind proxy server to {}", config.listen_addr))?;
    info!(
        "Proxy listening on {} (gRPC + HTTP /info + /health).",
        config.listen_addr
    );
    // If either listener stops, exit so the supervisor restarts a clean task
    // rather than leaving the surface silently dead.
    let node_stopped = async {
        match &node_server {
            Some(server) => server.wait_for_shutdown().await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        served = axum::serve(listener, router) => {
            served.map_err(|e| anyhow::anyhow!("proxy server error: {e}"))?;
        }
        () = node_stopped => {}
    }
    anyhow::bail!("proxy server stopped")
}

fn lazy_channel(url: &str, config: &Config) -> Result<tonic::transport::Channel> {
    Ok(Endpoint::from_shared(url.to_string())?
        .connect_timeout(config.connect_timeout)
        .http2_keep_alive_interval(config.keepalive_interval)
        .connect_lazy())
}

/// Retry transient S3 blips at boot (no target-group crash-loop), but fail
/// fast on real misconfiguration (bad bucket, missing role).
async fn probe_with_retries(log_store: &S3LogStore) -> Result<()> {
    const ATTEMPTS: u32 = 5;
    for attempt in 1..=ATTEMPTS {
        match log_store.probe().await {
            Ok(()) => return Ok(()),
            Err(e) if attempt < ATTEMPTS => {
                warn!(attempt, error = %e, "Wid log bucket probe failed; retrying.");
                tokio::time::sleep(Duration::from_secs(2 * u64::from(attempt))).await;
            }
            Err(e) => return Err(e.context("wid log bucket is not readable")),
        }
    }
    unreachable!("loop returns on success or final error")
}

/// Make each panic abort the process instead of an unwind. The wid index
/// uses a std `Mutex`. Its `.expect("wid index mutex poisoned")` assumes that
/// a poisoned lock does not occur. This is true only if a panic aborts and
/// does not unwind past the lock guard. (Same rationale as the `main` of the enclave.)
fn abort_on_panic() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info);
        std::process::abort();
    }));
}
