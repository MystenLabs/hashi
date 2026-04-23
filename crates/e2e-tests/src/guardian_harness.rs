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
use hashi_types::guardian::ProvisionerInitState;
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
    network: Network,
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
            network,
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
