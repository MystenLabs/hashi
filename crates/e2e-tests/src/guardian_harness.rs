// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! In-process `hashi-guardian` for integration tests. Started in two
//! stages because hashi-side DKG is a prerequisite for provisioner-init:
//! [`GuardianHarness::start`] serves gRPC immediately; [`GuardianHarness::finalize`]
//! completes provisioner-init once DKG output is on chain.

use anyhow::Context;
use anyhow::Result;
use bitcoin::Network;
use hashi_guardian::Enclave;
use hashi_guardian::OperatorInitTestArgs;
use hashi_guardian::create_operator_initialized_enclave;
use hashi_guardian::rpc::GuardianGrpc;
use hashi_types::committee::Committee as HashiCommittee;
use hashi_types::guardian::BitcoinPubkey;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::WithdrawalConfig;
use hashi_types::proto::guardian_service_server::GuardianServiceServer;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tonic::transport::Server;

/// In-process guardian reachable over gRPC on a local TCP socket. Drop
/// shuts the server down.
pub struct GuardianHarness {
    enclave: Arc<Enclave>,
    endpoint: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_handle: Option<JoinHandle<()>>,
}

impl GuardianHarness {
    /// Start an operator-init'd guardian. Withdrawal RPCs stay gated
    /// on [`Self::finalize`] completing provisioner-init.
    pub async fn start(network: Network) -> Result<Self> {
        let enclave = create_operator_initialized_enclave(
            OperatorInitTestArgs::default().with_network(network),
        )
        .await;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind guardian harness listener")?;
        let addr: SocketAddr = listener.local_addr()?;
        let endpoint = format!("http://{addr}");

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let svc = GuardianGrpc {
            enclave: enclave.clone(),
            setup_mode: false,
        };
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let server_handle = tokio::spawn(async move {
            let result = Server::builder()
                .add_service(GuardianServiceServer::new(svc))
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = shutdown_rx.await;
                })
                .await;
            if let Err(e) = result {
                tracing::warn!("guardian harness server exited: {e}");
            }
        });

        Ok(Self {
            enclave,
            endpoint,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
        })
    }

    /// Complete provisioner-init with the committee + BTC master pubkey
    /// from hashi's DKG.
    pub async fn finalize(
        &self,
        committee: HashiCommittee,
        master_pubkey: BitcoinPubkey,
        withdrawal_config: WithdrawalConfig,
        limiter_state: LimiterState,
    ) -> Result<()> {
        hashi_guardian::test_utils::finalize_enclave(
            &self.enclave,
            committee,
            master_pubkey,
            withdrawal_config,
            limiter_state,
        )
        .map_err(|e| anyhow::anyhow!("finalize guardian enclave: {e:?}"))?;

        anyhow::ensure!(
            self.enclave.is_fully_initialized(),
            "guardian did not reach fully-initialized state"
        );
        Ok(())
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn enclave(&self) -> &Arc<Enclave> {
        &self.enclave
    }
}

impl Drop for GuardianHarness {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
    }
}

pub fn default_test_withdrawal_config(committee: &HashiCommittee) -> WithdrawalConfig {
    let total_weight = committee.total_weight();
    let committee_threshold = total_weight.div_ceil(3) * 2;
    WithdrawalConfig {
        committee_threshold,
        refill_rate_sats_per_sec: 0,
        max_bucket_capacity_sats: 100_000_000,
    }
}

pub fn full_bucket(config: &WithdrawalConfig) -> LimiterState {
    LimiterState {
        num_tokens_available: config.max_bucket_capacity_sats,
        last_updated_at: 0,
        next_seq: 0,
    }
}
