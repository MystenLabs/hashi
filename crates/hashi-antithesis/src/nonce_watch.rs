// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Watches everything hashi's signers emit and feeds it to the presignature
//! reuse detector in [`crate::nonce`]:
//!
//! - Every node's partial signatures, by calling `GetPartialSignatures` on it
//!   as one of its peers. This is the only path by which partials leave a
//!   node, and a node serves each partial from its cache until it restarts, so
//!   polling catches a reuse with non-zero probability even if it is never
//!   published.
//! - Every MPC and guardian signature committed to Sui, and every hashi spend
//!   on Bitcoin, whose sighash is computed from the broadcast transaction.
//!
//! Signing contexts are rebuilt from on-chain data alone; nothing a node
//! records is trusted.

use std::collections::HashMap;
use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use antithesis_sdk::assert_always;
use antithesis_sdk::assert_sometimes;
use anyhow::Context;
use anyhow::Result;
use bitcoin::Amount;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::hashes::Hash;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::ControlBlock;
use bitcoin::taproot::TapLeafHash;
use corepc_client::client_sync::v29::Client as BtcClient;
use hashi::grpc::BoxedChannel;
use hashi_types::bitcoin as hashi_bitcoin;
use hashi_types::move_types::MpcSig;
use hashi_types::move_types::WithdrawalTransaction;
use hashi_types::proto::mpc_service_client::MpcServiceClient;
use serde_json::json;
use sui_sdk_types::Address;

use crate::env::CommonArgs;
use crate::nonce::Nonce;
use crate::nonce::NonceLedger;
use crate::nonce::Session;
use crate::nonce::SigningContext;
use crate::nonce::Violation;

#[derive(clap::Args)]
pub struct Args {
    /// Hashi node hosts, whose configs the bootstrap writes to the shared volume.
    #[arg(
        long,
        env = "HASHI_NODES",
        default_value = "hashi1,hashi2,hashi3,hashi4",
        value_delimiter = ','
    )]
    nodes: Vec<String>,

    #[arg(long, env = "NONCE_WATCH_POLL_INTERVAL_MS", default_value_t = 1_000)]
    poll_interval_ms: u64,
}

pub async fn run(common: &CommonArgs, args: Args) -> Result<()> {
    let shared = common.shared();
    crate::env::wait_for_file(&shared.bootstrap_done_path()).await;
    let deployment = shared.wait_for_deployment().await?;
    let (onchain, _onchain_service) = crate::env::onchain_view(&common.sui_rpc, &deployment).await;

    let configs = args
        .nodes
        .iter()
        .map(|host| {
            let path = shared.node_config_path(host);
            hashi::config::Config::load(&path)
                .with_context(|| format!("failed to load {}", path.display()))
                .map(|config| (host.clone(), config))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut watcher = Watcher {
        ledger: NonceLedger::default(),
        nodes: node_clients(&configs)?,
        btc: BtcClient::new_with_auth(&common.btc_rpc, common.btc_auth())?,
        withdrawals: HashMap::new(),
        contexts: HashMap::new(),
        withdrawal_by_txid: HashMap::new(),
        scanned_height: 0,
        inspected_txids: HashSet::new(),
    };
    tracing::info!("nonce watch started on {} nodes", watcher.nodes.len());

    let interval = Duration::from_millis(args.poll_interval_ms);
    loop {
        if let Err(e) = watcher.refresh_contexts(&onchain) {
            tracing::warn!("rebuilding signing contexts failed: {e:#}");
        }
        watcher.poll_nodes().await;
        watcher.check_sui(&onchain);
        if let Err(e) = tokio::task::block_in_place(|| watcher.scan_bitcoin()) {
            tracing::warn!("scanning bitcoin failed: {e:#}");
        }
        tokio::time::sleep(interval).await;
    }
}

struct NodeClient {
    host: String,
    client: MpcServiceClient<BoxedChannel>,
}

/// Each node is queried as the next node in the list. The node authenticates
/// callers by the TLS key registered on-chain, so this is exactly what an
/// adversarial peer could ask of it.
fn node_clients(configs: &[(String, hashi::config::Config)]) -> Result<Vec<NodeClient>> {
    configs
        .iter()
        .enumerate()
        .map(|(i, (host, config))| {
            let (_, caller) = &configs[(i + 1) % configs.len()];
            let tls = hashi::tls::make_client_config_with_client_auth(
                &caller.tls_private_key()?,
                &config.tls_public_key()?,
            );
            let endpoint = config
                .endpoint_url()
                .with_context(|| format!("{host} has no endpoint-url"))?
                .to_owned();
            Ok(NodeClient {
                host: host.clone(),
                client: hashi::grpc::Client::new(endpoint, tls)?.mpc_service_client(),
            })
        })
        .collect()
}

/// What the watcher derived for one withdrawal transaction.
struct WithdrawalView {
    sighashes: Vec<[u8; 32]>,
    /// Randomness of each epoch the inputs were (re)allocated in.
    randomness_by_epoch: HashMap<u64, [u8; 32]>,
}

struct Watcher {
    ledger: NonceLedger,
    nodes: Vec<NodeClient>,
    btc: BtcClient,
    withdrawals: HashMap<Address, WithdrawalView>,
    contexts: HashMap<Session, SigningContext>,
    withdrawal_by_txid: HashMap<Txid, Address>,
    scanned_height: u64,
    inspected_txids: HashSet<Txid>,
}

impl Watcher {
    /// Adds signing contexts for withdrawals, and epochs of known withdrawals,
    /// that the watcher has not seen yet.
    fn refresh_contexts(&mut self, onchain: &hashi::onchain::OnchainState) -> Result<()> {
        let mut keys = None;
        for txn in onchain.withdrawal_txns() {
            let randomness: [u8; 32] = match txn.randomness.as_slice().try_into() {
                Ok(randomness) => randomness,
                Err(_) => continue,
            };
            let epoch = txn.signing.epoch;
            if let Some(view) = self.withdrawals.get(&txn.id)
                && view.randomness_by_epoch.get(&epoch) == Some(&randomness)
            {
                continue;
            }
            if !self.withdrawals.contains_key(&txn.id) {
                if keys.is_none() {
                    keys = Some(signing_keys(onchain)?);
                }
                let (mpc_g, guardian) = keys.as_ref().unwrap();
                let rebuilt = sighashes(&txn, mpc_g, guardian);
                assert_always!(
                    rebuilt.is_ok(),
                    "nonce watch rebuilds every withdrawal's sighashes from Sui",
                    &json!({
                        "withdrawal": txn.id.to_string(),
                        "error": rebuilt.as_ref().err().map(|e| format!("{e:#}")),
                    })
                );
                let Ok((txid, sighashes)) = rebuilt else {
                    continue;
                };
                self.withdrawal_by_txid.insert(txid, txn.id);
                self.withdrawals.insert(
                    txn.id,
                    WithdrawalView {
                        sighashes,
                        randomness_by_epoch: HashMap::new(),
                    },
                );
            }
            let view = self.withdrawals.get_mut(&txn.id).unwrap();
            view.randomness_by_epoch.insert(epoch, randomness);
            for (input_index, sighash) in view.sighashes.iter().enumerate() {
                let context =
                    SigningContext::new(txn.id, input_index as u32, epoch, &randomness, *sighash);
                self.contexts.insert(context.session, context);
            }
        }
        Ok(())
    }

    /// Asks every node, as a peer would, for the partial signatures of every
    /// known signing session.
    async fn poll_nodes(&mut self) {
        let mut sessions_by_epoch: HashMap<u64, Vec<Session>> = HashMap::new();
        for session in self.contexts.keys() {
            sessions_by_epoch
                .entry(session.epoch)
                .or_default()
                .push(*session);
        }
        for node in &mut self.nodes {
            for (epoch, sessions) in &sessions_by_epoch {
                let request = hashi_types::proto::GetPartialSignaturesRequest {
                    epoch: Some(*epoch),
                    signing_ids: sessions.iter().map(|s| s.signing_id.to_string()).collect(),
                };
                let response = match node.client.get_partial_signatures(request).await {
                    Ok(response) => response.into_inner(),
                    // Unreachable or faulted nodes, and epochs a node has no
                    // signer for, are routine under Antithesis.
                    Err(status) => {
                        tracing::debug!("{}: GetPartialSignatures failed: {status}", node.host);
                        continue;
                    }
                };
                for (id, partial) in &response.partial_sigs {
                    let Some(context) = Address::from_str(id).ok().and_then(|signing_id| {
                        self.contexts.get(&Session {
                            signing_id,
                            epoch: *epoch,
                        })
                    }) else {
                        continue;
                    };
                    let Some(nonce) = response.signing_nonces.get(id) else {
                        tracing::warn!("{}: partial for {id} came without its nonce", node.host);
                        continue;
                    };
                    let nonce = nonce.value.as_deref().unwrap_or_default();
                    let partial = partial.value.as_deref().unwrap_or_default();
                    match self
                        .ledger
                        .record_partial(&node.host, context, nonce, partial)
                    {
                        Ok(violations) => {
                            assert_sometimes!(
                                true,
                                "nonce watch read a partial signature from a node",
                                &json!({"node": node.host})
                            );
                            report_partial(&node.host, context, &violations);
                        }
                        Err(e) => tracing::warn!("{}: bad nonce for {id}: {e:#}", node.host),
                    }
                }
            }
        }
    }

    /// Checks the MPC and guardian signatures each withdrawal has committed to Sui.
    fn check_sui(&mut self, onchain: &hashi::onchain::OnchainState) {
        for txn in onchain.withdrawal_txns() {
            let Some(sighashes) = self.withdrawals.get(&txn.id).map(|v| v.sighashes.clone()) else {
                continue;
            };
            for (input_index, signature) in txn.signing.signatures.iter().enumerate() {
                let MpcSig::Signed(signature) = signature else {
                    continue;
                };
                self.check_mpc_signature("sui", txn.id, input_index as u32, signature);
            }
            for (input_index, signature) in txn.guardian_signatures.iter().flatten().enumerate() {
                if let Some(sighash) = sighashes.get(input_index) {
                    self.check_guardian_signature("sui", *sighash, signature);
                }
            }
        }
    }

    /// Records an aggregate MPC signature against its signing session. Sui and
    /// Bitcoin do not say which epoch an input was signed in, so this picks the
    /// session whose served nonce matches, else the latest known one.
    fn check_mpc_signature(
        &mut self,
        source: &str,
        withdrawal: Address,
        input_index: u32,
        signature: &[u8],
    ) {
        let nonce = match Nonce::from_signature(signature) {
            Ok(nonce) => nonce,
            Err(e) => {
                tracing::warn!("{source}: malformed MPC signature on {withdrawal}: {e:#}");
                return;
            }
        };
        let signing_id = crate::nonce::signing_id(&withdrawal, input_index);
        let mut candidates: Vec<&SigningContext> = self
            .contexts
            .values()
            .filter(|c| c.session.signing_id == signing_id)
            .collect();
        candidates.sort_by_key(|c| c.session.epoch);
        let context = candidates
            .iter()
            .find(|c| self.ledger.session_nonce(&c.session) == Some(nonce.x_only()))
            .or(candidates.last())
            .map(|c| (*c).clone());
        let Some(context) = context else {
            return;
        };
        let violations = self.ledger.record_nonce(source, &context, nonce);
        report_nonce(source, &context, &violations);
    }

    fn check_guardian_signature(&mut self, source: &str, sighash: [u8; 32], signature: &[u8]) {
        match self.ledger.record_guardian_signature(sighash, signature) {
            Ok(violation) => assert_always!(
                violation.is_none(),
                "the guardian never signs two messages with one nonce",
                &json!({"source": source, "violation": format!("{violation:?}")})
            ),
            Err(e) => tracing::warn!("{source}: malformed guardian signature: {e:#}"),
        }
    }

    /// Inspects every transaction mined since the last scan, and the mempool.
    fn scan_bitcoin(&mut self) -> Result<()> {
        let height = self.btc.get_block_count()?.0;
        while self.scanned_height < height {
            let next = self.scanned_height + 1;
            let hash = self.btc.get_block_hash(next)?.block_hash()?;
            let block = self.btc.get_block_verbose_zero(hash)?.block()?;
            for tx in &block.txdata {
                self.inspect_bitcoin_tx(tx)?;
            }
            self.scanned_height = next;
        }
        for txid in self.btc.get_raw_mempool()?.0 {
            let Ok(txid) = Txid::from_str(&txid) else {
                continue;
            };
            if self.inspected_txids.contains(&txid) {
                continue;
            }
            // A mempool transaction may be mined or evicted between the two calls.
            if let Ok(tx) = self
                .btc
                .get_raw_transaction(txid)
                .map_err(anyhow::Error::from)
                .and_then(|r| Ok(r.transaction()?))
            {
                self.inspect_bitcoin_tx(&tx)?;
            }
        }
        Ok(())
    }

    /// Checks the signatures of every hashi script-path spend in `tx`, with
    /// sighashes computed from the transaction itself.
    fn inspect_bitcoin_tx(&mut self, tx: &Transaction) -> Result<()> {
        let txid = tx.compute_txid();
        if !self.inspected_txids.insert(txid) {
            return Ok(());
        }
        let spends: Vec<usize> = (0..tx.input.len())
            .filter(|&i| hashi_spend(tx, i).is_some())
            .collect();
        if spends.is_empty() {
            return Ok(());
        }
        let prevouts = tx
            .input
            .iter()
            .map(|input| {
                let parent = self
                    .btc
                    .get_raw_transaction(input.previous_output.txid)?
                    .transaction()?;
                parent
                    .output
                    .get(input.previous_output.vout as usize)
                    .cloned()
                    .context("prevout index out of range")
            })
            .collect::<Result<Vec<TxOut>>>()?;
        let mut sighasher = SighashCache::new(tx);
        let withdrawal = self.withdrawal_by_txid.get(&txid).copied();
        for input_index in spends {
            let (mpc_sig, guardian_sig, leaf_hash) = hashi_spend(tx, input_index).unwrap();
            let sighash = *sighasher
                .taproot_script_spend_signature_hash(
                    input_index,
                    &Prevouts::All(&prevouts),
                    leaf_hash,
                    TapSighashType::Default,
                )?
                .as_byte_array();
            assert_sometimes!(
                true,
                "nonce watch checked a hashi spend on bitcoin",
                &json!({"txid": txid.to_string()})
            );
            self.check_guardian_signature("bitcoin", sighash, &guardian_sig);
            let Some(withdrawal) = withdrawal else {
                continue;
            };
            let expected = self
                .withdrawals
                .get(&withdrawal)
                .and_then(|view| view.sighashes.get(input_index).copied());
            assert_always!(
                expected == Some(sighash),
                "the sighash rebuilt from Sui matches the broadcast transaction",
                &json!({"txid": txid.to_string(), "input": input_index})
            );
            self.check_mpc_signature("bitcoin", withdrawal, input_index as u32, &mpc_sig);
        }
        Ok(())
    }
}

/// The MPC signature, guardian signature and leaf hash of `tx`'s input
/// `index`, if it spends a hashi output through the 2-of-2 leaf. The witness
/// is `[mpc_sig, guardian_sig, leaf_script, control_block]`
/// (hashi `leader::withdrawal_transactions`).
fn hashi_spend(tx: &Transaction, index: usize) -> Option<(Vec<u8>, Vec<u8>, TapLeafHash)> {
    let witness = &tx.input[index].witness;
    if witness.len() != 4 {
        return None;
    }
    let (mpc_sig, guardian_sig) = (witness.nth(0)?, witness.nth(1)?);
    if mpc_sig.len() != 64 || guardian_sig.len() != 64 {
        return None;
    }
    let control = ControlBlock::decode(witness.nth(3)?).ok()?;
    let leaf_script = ScriptBuf::from_bytes(witness.nth(2)?.to_vec());
    Some((
        mpc_sig.to_vec(),
        guardian_sig.to_vec(),
        TapLeafHash::from_script(&leaf_script, control.leaf_version),
    ))
}

/// The MPC master key and guardian key the deposit addresses are built from.
fn signing_keys(
    onchain: &hashi::onchain::OnchainState,
) -> Result<(hashi_bitcoin::HashiMasterG, hashi_bitcoin::BitcoinPubkey)> {
    let mpc_g = onchain.onchain_verifying_key_g()?;
    let guardian = onchain
        .guardian_btc_public_key()
        .context("guardian key not on-chain")?;
    Ok((
        mpc_g,
        hashi_bitcoin::BitcoinPubkey::from_slice(&guardian).context("bad guardian key")?,
    ))
}

/// Per-input sighashes of `txn`, rebuilt from its on-chain description. The
/// rebuilt txid must match the one Sui committed to.
fn sighashes(
    txn: &WithdrawalTransaction,
    mpc_g: &hashi_bitcoin::HashiMasterG,
    guardian: &hashi_bitcoin::BitcoinPubkey,
) -> Result<(Txid, Vec<[u8; 32]>)> {
    let inputs = txn
        .inputs
        .iter()
        .map(|utxo| hashi_bitcoin::InputUTXO::from(utxo).txin())
        .collect();
    let outputs = txn
        .all_outputs()
        .iter()
        .map(|output| {
            Ok(TxOut {
                value: Amount::from_sat(output.amount),
                script_pubkey: hashi_bitcoin::script_pubkey_from_witness_program(
                    &output.bitcoin_address,
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let tx = hashi_bitcoin::construct_tx(inputs, outputs);
    let txid = tx.compute_txid();
    anyhow::ensure!(
        txid == Txid::from(txn.txid),
        "rebuilt txid {txid} differs from {} committed for {}",
        Txid::from(txn.txid),
        txn.id
    );
    let (prevouts, leaf_hashes): (Vec<TxOut>, Vec<TapLeafHash>) = txn
        .inputs
        .iter()
        .map(|utxo| {
            let path = utxo.derivation_path.unwrap_or(Address::ZERO);
            let address =
                hashi_bitcoin::taproot_address(guardian, mpc_g, &path, bitcoin::Network::Regtest);
            let (_, _, leaf_hash) =
                hashi_bitcoin::taproot_2of2_witness_artifacts(guardian, mpc_g, &path);
            (
                TxOut {
                    value: Amount::from_sat(utxo.amount),
                    script_pubkey: address.script_pubkey(),
                },
                leaf_hash,
            )
        })
        .unzip();
    Ok((
        txid,
        hashi_bitcoin::taproot_script_spend_sighashes(&tx, &prevouts, &leaf_hashes),
    ))
}

fn report_partial(node: &str, context: &SigningContext, violations: &[Violation]) {
    let changed = violations
        .iter()
        .find(|v| matches!(v, Violation::PartialChanged { .. }));
    assert_always!(
        changed.is_none(),
        "a node serves one nonce and partial signature per signing session",
        &details(node, context, changed)
    );
    report_nonce(node, context, violations);
}

fn report_nonce(source: &str, context: &SigningContext, violations: &[Violation]) {
    let disagreement = violations
        .iter()
        .find(|v| matches!(v, Violation::NonceDisagreement { .. }));
    assert_always!(
        disagreement.is_none(),
        "nodes and chains agree on each signing session's nonce",
        &details(source, context, disagreement)
    );
    let reuse = violations
        .iter()
        .find(|v| matches!(v, Violation::PresignatureReused { .. }));
    assert_always!(
        reuse.is_none(),
        "no presignature signs two different messages",
        &details(source, context, reuse)
    );
}

fn details(
    source: &str,
    context: &SigningContext,
    violation: Option<&Violation>,
) -> serde_json::Value {
    json!({
        "source": source,
        "withdrawal": context.withdrawal.to_string(),
        "input_index": context.input_index,
        "epoch": context.session.epoch,
        "signing_id": context.session.signing_id.to_string(),
        "violation": violation.map(|v| format!("{v:?}")),
    })
}
