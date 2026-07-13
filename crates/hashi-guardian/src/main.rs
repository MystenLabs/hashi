// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use hashi_guardian::rpc::GuardianGrpc;
use hashi_guardian::withdraw_mode::heartbeat::HeartbeatWriter;
use hashi_guardian::Enclave;
use hashi_guardian::HEARTBEAT_INTERVAL;
use hashi_types::guardian::EnclaveMode;
use hashi_types::guardian::GuardianEncKeyPair;
use hashi_types::guardian::GuardianSignKeyPair;
use hashi_types::proto::guardian_service_server::GuardianServiceServer;
use std::sync::Arc;
use tonic::transport::Server;
use tonic_health::server::health_reporter;
use tracing::info;

/// Enclave initialization.
/// `setup_new_key` and `rotate_kps` are gated to CEREMONY_MODE=true;
/// `provisioner_init` and `standard_withdrawal` are gated to CEREMONY_MODE=false.
/// Everything else (operator_init, get_guardian_info, …) is available in
/// both modes. See the per-route gates in `rpc.rs`.
#[tokio::main]
async fn main() -> Result<()> {
    hashi_types::telemetry::TelemetryConfig::new()
        .with_file_line(true)
        .with_env()
        .init();

    abort_on_panic();

    // Check if CEREMONY_MODE is enabled (defaults to false)
    let ceremony_mode = std::env::var("CEREMONY_MODE")
        .ok()
        .and_then(|v| v.parse::<bool>().ok())
        .unwrap_or(false);
    let mode = if ceremony_mode {
        EnclaveMode::Ceremony
    } else {
        EnclaveMode::Withdraw
    };

    if ceremony_mode {
        info!("Ceremony mode: setup_new_key/rotate_kps enabled; provisioner_init/standard_withdrawal disabled.");
    } else {
        info!("Withdraw mode: provisioner_init/standard_withdrawal enabled; setup_new_key/rotate_kps disabled.");
    }

    let mut rng = rand::thread_rng();
    let signing_keys = GuardianSignKeyPair::new(&mut rng);
    let encryption_keys = GuardianEncKeyPair::random(&mut rng);
    let enclave = Arc::new(Enclave::new(signing_keys, encryption_keys, mode));

    // The StandardWithdrawal idempotency cache now lives out-of-enclave in
    // `hashi-guardian-proxy`; the enclave serves the bare handler.
    let svc = GuardianGrpc {
        enclave: enclave.clone(),
    };

    let addr = "0.0.0.0:3000".parse()?;
    info!("gRPC server listening on {}.", addr);

    // gRPC health reporter — used by the K8s gRPC probe and GKE HealthCheckPolicy.
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<GuardianServiceServer<GuardianGrpc>>()
        .await;

    // Don't emit heartbeats in ceremony mode: their primary function is
    // to allow KPs to detect old sessions that might still be running
    // in order to bypass limiter. Not a concern for ceremony mode.
    if !ceremony_mode {
        drop(tokio::spawn(
            HeartbeatWriter::new(enclave).run(HEARTBEAT_INTERVAL),
        ));
    }

    Server::builder()
        .add_service(health_service)
        .add_service(GuardianServiceServer::new(svc))
        .serve(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}

/// Make any panic abort the process instead of unwinding to the tokio task
/// boundary. The enclave holds key material that must never be served from a
/// state where an invariant has already been violated, and a contained unwind
/// can leave half-applied init state behind that a retry would then trip over.
/// Fail fast and let the enclave be relaunched clean.
fn abort_on_panic() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info); // keep the standard panic message + backtrace
        std::process::abort();
    }));
}
