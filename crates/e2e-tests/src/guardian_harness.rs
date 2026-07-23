// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! In-process `hashi-guardian` for integration tests. Two stages:
//! [`GuardianHarness::start`] serves gRPC; [`GuardianHarness::finalize`]
//! runs operator- and provisioner-init once hashi DKG output is on chain.

use anyhow::Context;
use anyhow::Result;
use bitcoin::Network;
use hashi_guardian::Enclave;
use hashi_guardian::OperatorInitTestArgs;
use hashi_guardian::activate_enclave_for_testing;
use hashi_guardian::rpc::GuardianGrpc;
use hashi_types::bitcoin::BitcoinPubkey;
use hashi_types::bitcoin::HashiMasterG;
use hashi_types::committee::Committee as HashiCommittee;
use hashi_types::guardian::InitConfig;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;
use hashi_types::proto::guardian_service_server::GuardianServiceServer;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tonic::transport::Server;

/// In-process guardian reachable over gRPC on a local TCP socket.
pub struct GuardianHarness {
    enclave: Arc<Enclave>,
    endpoint: String,
    network: Network,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_handle: Option<JoinHandle<()>>,
}

impl GuardianHarness {
    /// Start a guardian serving gRPC. The enclave is uninitialized; operator-
    /// and provisioner-init both run in [`Self::finalize`] once DKG output exists
    /// (operator-init now carries the committee + BTC master key).
    pub async fn start(network: Network) -> Result<Self> {
        let enclave = Enclave::create_with_random_keys();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind guardian harness listener")?;
        let addr: SocketAddr = listener.local_addr()?;
        let endpoint = format!("http://{addr}");

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let svc = GuardianGrpc {
            enclave: enclave.clone(),
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
            network,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
        })
    }

    /// Operator-init, provisioner-init, then activate the served enclave.
    pub async fn finalize(
        &self,
        committee: HashiCommittee,
        master_pubkey: HashiMasterG,
        limiter_config: LimiterConfig,
        limiter_state: LimiterState,
    ) -> Result<()> {
        let config =
            InitConfig::from_parts_for_testing(limiter_config, master_pubkey, self.network);
        self.enclave
            .install_operator_init_for_testing(OperatorInitTestArgs::default().with_config(config));
        hashi_guardian::test_utils::finalize_enclave(&self.enclave)
            .map_err(|e| anyhow::anyhow!("finalize guardian enclave: {e:?}"))?;
        activate_enclave_for_testing(&self.enclave, committee, limiter_config, limiter_state)
            .map_err(|e| anyhow::anyhow!("activate guardian enclave: {e:?}"))?;

        anyhow::ensure!(
            self.enclave.require_fully_initialized().is_ok(),
            "guardian did not reach active state"
        );
        Ok(())
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn enclave(&self) -> &Arc<Enclave> {
        &self.enclave
    }

    /// Generate (or return the already-generated) enclave BTC pubkey
    /// without running provisioner-init. Used by e2e setup to publish
    /// the pubkey on-chain before hashi DKG completes.
    pub fn ensure_btc_pubkey(&self) -> Result<BitcoinPubkey> {
        hashi_guardian::test_utils::set_or_get_enclave_btc_pubkey(&self.enclave)
            .map_err(|e| anyhow::anyhow!("set_or_get_enclave_btc_pubkey: {e:?}"))
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

pub fn default_test_limiter_config() -> LimiterConfig {
    LimiterConfig {
        refill_rate: 0,
        max_bucket_capacity: 100_000_000,
    }
}
