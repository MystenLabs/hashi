// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use hashi_guardian::heartbeat::HeartbeatWriter;
use hashi_guardian::rpc::GuardianGrpc;
use hashi_guardian::setup::check_yubikey_age_plugin;
use hashi_guardian::Enclave;
use hashi_guardian::HEARTBEAT_INTERVAL;
use hashi_guardian::HEARTBEAT_RETRY_INTERVAL;
use hashi_guardian::MAX_HEARTBEAT_FAILURES_INTERVAL;
use hashi_types::guardian::GuardianEncKeyPair;
use hashi_types::guardian::GuardianSignKeyPair;
use hashi_types::proto::guardian_service_server::GuardianServiceServer;
use std::sync::Arc;
use tonic::transport::Server;
use tonic_health::server::health_reporter;
use tracing::info;

/// Enclave initialization.
/// `setup_new_key` is gated to SETUP_MODE=true; `provisioner_init` and
/// `standard_withdrawal` are gated to SETUP_MODE=false. Everything else
/// (operator_init, get_guardian_info, …) is available in both modes. See the
/// per-route gates in `rpc.rs`.
#[tokio::main]
async fn main() -> Result<()> {
    hashi_types::telemetry::TelemetryConfig::new()
        .with_file_line(true)
        .with_env()
        .init();

    check_yubikey_age_plugin()?;

    // Check if SETUP_MODE is enabled (defaults to false)
    let setup_mode = std::env::var("SETUP_MODE")
        .ok()
        .and_then(|v| v.parse::<bool>().ok())
        .unwrap_or(false);

    if setup_mode {
        info!("Setup mode: setup_new_key enabled; provisioner_init/standard_withdrawal disabled.");
    } else {
        info!("Normal mode: provisioner_init/standard_withdrawal enabled; setup_new_key disabled.");
    }

    let signing_keys = GuardianSignKeyPair::new(rand::thread_rng());
    let encryption_keys = GuardianEncKeyPair::random(&mut rand::thread_rng());
    let enclave = Arc::new(Enclave::new(signing_keys, encryption_keys));

    let svc = GuardianGrpc {
        enclave: enclave.clone(),
        setup_mode,
    };

    let addr = "0.0.0.0:3000".parse()?;
    info!("gRPC server listening on {}.", addr);

    // gRPC health reporter — used by the K8s gRPC probe and GKE HealthCheckPolicy.
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<GuardianServiceServer<GuardianGrpc>>()
        .await;

    let server_future = Server::builder()
        .add_service(health_service)
        .add_service(GuardianServiceServer::new(svc))
        .serve(addr);

    let heartbeat_future = HeartbeatWriter::new(enclave, MAX_HEARTBEAT_FAILURES_INTERVAL)
        .run(HEARTBEAT_INTERVAL, HEARTBEAT_RETRY_INTERVAL);

    tokio::select! {
        res = server_future => {
            res.map_err(|e| anyhow::anyhow!("Server error: {}", e))
        }
        res = heartbeat_future => {
            panic!("Heartbeat failed: {:?}", res)
        }
    }
}
