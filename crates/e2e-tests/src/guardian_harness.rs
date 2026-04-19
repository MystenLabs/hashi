// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! In-process `hashi-guardian` for integration tests.
//!
//! Run in two stages because hashi-side DKG is a prerequisite for
//! provisioner-init:
//!
//! 1. [`GuardianHarness::start`] spins up an operator-init'd enclave and
//!    serves gRPC on an ephemeral port. `GetGuardianInfo` returns a
//!    valid signing pubkey here, so any future hashi-side startup probe
//!    can cache it without waiting on DKG.
//! 2. [`GuardianHarness::finalize`] is called after the test network
//!    completes DKG and the hashi committee + BTC master pubkey are on
//!    chain. Finishes provisioner-init so the guardian starts serving
//!    `StandardWithdrawal` and friends.
//!
//! Dropped harnesses send a graceful shutdown signal to the spawned
//! tonic server task.

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
use hashi_types::guardian::ProvisionerInitState;
use hashi_types::guardian::WithdrawalConfig;
use hashi_types::proto::guardian_service_server::GuardianServiceServer;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tonic::transport::Server;

/// An in-process guardian reachable over real gRPC on a local TCP
/// socket. Keep the harness alive for the lifetime of the test — drop
/// shuts the server down.
pub struct GuardianHarness {
    enclave: Arc<Enclave>,
    endpoint: String,
    network: Network,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_handle: Option<JoinHandle<()>>,
}

impl GuardianHarness {
    /// Start an operator-init'd guardian. The returned endpoint is
    /// ready to answer `GetGuardianInfo` immediately; withdrawal RPCs
    /// stay gated on [`Self::finalize`] completing provisioner-init.
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
            network,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
        })
    }

    /// Complete provisioner-init with the committee + BTC master pubkey
    /// that hashi's DKG produced. After this returns the guardian is
    /// fully initialized.
    pub async fn finalize(
        &self,
        committee: HashiCommittee,
        master_pubkey: BitcoinPubkey,
        withdrawal_config: WithdrawalConfig,
        limiter_state: LimiterState,
    ) -> Result<()> {
        // Same thing `create_fully_initialized_enclave` does, but
        // applied to the already-running enclave instance so the live
        // gRPC server observes the finalized state.
        use bitcoin::secp256k1::Keypair;
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::secp256k1::SecretKey;
        use rand::RngCore;

        let secp = Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sk_bytes);
        let enclave_btc_keypair = Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&sk_bytes).expect("random bytes form a valid secp256k1 key"),
        );
        self.enclave
            .config
            .set_btc_keypair(enclave_btc_keypair)
            .context("set enclave btc keypair")?;
        self.enclave
            .config
            .set_hashi_btc_pk(master_pubkey)
            .context("set hashi btc master pubkey")?;
        self.enclave
            .config
            .set_withdrawal_config(withdrawal_config)
            .context("set withdrawal config")?;

        let init_state =
            ProvisionerInitState::new(committee, withdrawal_config, limiter_state, master_pubkey)
                .context("valid ProvisionerInitState")?;
        self.enclave
            .state
            .init(init_state)
            .context("init enclave state")?;

        self.enclave
            .scratchpad
            .provisioner_init_logging_complete
            .set(())
            .map_err(|_| anyhow::anyhow!("provisioner_init already finalized"))?;

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

    #[allow(dead_code)]
    pub fn network(&self) -> Network {
        self.network
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

/// Default withdrawal config for test networks. Generous bucket +
/// committee threshold pegged to roughly 2/3 of the provided committee
/// weight — this PR's tests don't actually hit the signing path, but
/// subsequent PRs will, so keep the threshold BFT-shaped from day 1.
pub fn default_test_withdrawal_config(committee: &HashiCommittee) -> WithdrawalConfig {
    let total_weight = committee.total_weight();
    // ceil(2/3 * total_weight) — matches the Sui BFT convention.
    let committee_threshold = total_weight.div_ceil(3) * 2;
    WithdrawalConfig {
        committee_threshold,
        refill_rate_sats_per_sec: 0,
        // 1 BTC per cycle — larger than any test withdrawal amount.
        max_bucket_capacity_sats: 100_000_000,
    }
}

/// Build a full-bucket `LimiterState` matching `config`.
pub fn full_bucket(config: &WithdrawalConfig) -> LimiterState {
    LimiterState {
        num_tokens_available: config.max_bucket_capacity_sats,
        last_updated_at: 0,
        next_seq: 0,
    }
}
