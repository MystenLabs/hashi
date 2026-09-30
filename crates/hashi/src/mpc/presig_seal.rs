// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use fastcrypto::traits::ToFromBytes;
use futures::future::join_all;
use hashi_types::committee::BLS12381Signature;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::Committee;
use hashi_types::committee::SignedMessage;
use hashi_types::committee::certificate_threshold;
use hashi_types::move_types::PresigCompletedMessage;
use sui_sdk_types::Address;
use tokio::task::JoinSet;
use tracing::info;
use tracing::warn;

use crate::Hashi;

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(30);
const RPC_TIMEOUT: Duration = Duration::from_secs(5);
const SUBMIT_STAGGER: Duration = Duration::from_secs(5);

pub(crate) fn start(
    inner: &Arc<Hashi>,
    tasks: &Mutex<JoinSet<()>>,
    epoch: u64,
    batch_index: u32,
    dealer_set_digest: [u8; 32],
) {
    let message = PresigCompletedMessage {
        epoch,
        batch_index,
        dealer_set_digest: dealer_set_digest.to_vec(),
    };
    let signature = match sign(inner, &message) {
        Ok(signature) => signature,
        Err(e) => {
            warn!("Cannot sign PresigCompleted for epoch {epoch} batch {batch_index}: {e:#}");
            return;
        }
    };
    if !inner.store_presig_completed_signature_if_absent(
        epoch,
        batch_index,
        signature.as_bytes().to_vec(),
    ) {
        return;
    }
    let inner = Arc::clone(inner);
    let mut tasks = tasks.lock().unwrap();
    while tasks.try_join_next().is_some() {}
    tasks.spawn(async move { seal(&inner, &message, signature).await });
}

fn sign(inner: &Hashi, message: &PresigCompletedMessage) -> anyhow::Result<BLS12381Signature> {
    let committee = committee(inner, message.epoch)?;
    let my_address = inner.config.validator_address()?;
    let key = inner.find_signing_key_for_committee(&committee, my_address, message.epoch)?;
    Ok(key
        .sign(
            inner.config.hashi_ids().hashi_object_id,
            message.epoch,
            my_address,
            message,
        )
        .signature()
        .clone())
}

async fn seal(inner: &Arc<Hashi>, message: &PresigCompletedMessage, signature: BLS12381Signature) {
    let (epoch, batch_index) = (message.epoch, message.batch_index);
    let mut retry_interval = POLL_INTERVAL;
    while let Err(e) = try_seal(inner, message, &signature).await {
        warn!("Sealing presig batch {batch_index} of epoch {epoch} failed: {e:#}");
        retry_interval = (retry_interval * 2).min(MAX_RETRY_INTERVAL);
        tokio::time::sleep(retry_interval).await;
    }
}

async fn try_seal(
    inner: &Arc<Hashi>,
    message: &PresigCompletedMessage,
    signature: &BLS12381Signature,
) -> anyhow::Result<()> {
    if done(inner, message) {
        return Ok(());
    }
    let committee = committee(inner, message.epoch)?;
    let Some(cert) = collect(inner, &committee, message, signature).await? else {
        return Ok(());
    };
    let my_address = inner.config.validator_address()?;
    tokio::time::sleep(submit_delay(&committee, my_address, message.batch_index)).await;
    if done(inner, message) {
        return Ok(());
    }
    let mut executor = crate::sui_tx_executor::SuiTxExecutor::from_hashi(Arc::clone(inner))?;
    executor
        .execute_submit_presig_completed(message, cert.committee_signature())
        .await?;
    info!(
        "Submitted PresigCompleted for epoch {} batch {}",
        message.epoch, message.batch_index
    );
    Ok(())
}

fn done(inner: &Hashi, message: &PresigCompletedMessage) -> bool {
    let onchain_state = inner.onchain_state();
    if onchain_state.epoch() > message.epoch {
        return true;
    }
    match onchain_state
        .presig_seals(message.epoch)
        .remove(&message.batch_index)
    {
        Some(seal) => {
            if seal.dealer_set_digest != message.dealer_set_digest {
                warn!(
                    "Presig batch {} of epoch {} was sealed over a dealer set this node did \
                     not build",
                    message.batch_index, message.epoch,
                );
            }
            true
        }
        None => false,
    }
}

async fn collect(
    inner: &Hashi,
    committee: &Committee,
    message: &PresigCompletedMessage,
    signature: &BLS12381Signature,
) -> anyhow::Result<Option<SignedMessage<PresigCompletedMessage>>> {
    let my_address = inner.config.validator_address()?;
    let mut aggregator = BlsSignatureAggregator::new(
        inner.config.hashi_ids().hashi_object_id,
        committee,
        message.clone(),
    );
    aggregator
        .add_signature_from(my_address, signature.clone())
        .map_err(|e| anyhow::anyhow!("failed to add own signature: {e}"))?;
    let mut missing: HashSet<Address> = committee
        .members()
        .iter()
        .map(|m| m.validator_address())
        .filter(|address| *address != my_address)
        .collect();
    let required_weight = certificate_threshold(committee.total_weight());
    let mut rejected: HashSet<Address> = HashSet::new();
    let mut poll_interval = POLL_INTERVAL;
    while aggregator.weight() < required_weight {
        if done(inner, message) {
            return Ok(None);
        }
        let fetched = join_all(missing.iter().map(|&address| async move {
            let signature = tokio::time::timeout(RPC_TIMEOUT, async {
                let client = inner
                    .onchain_state()
                    .state()
                    .hashi()
                    .committees
                    .client(&address)?;
                client
                    .get_presig_completed_signature(message.epoch, message.batch_index)
                    .await
                    .ok()
                    .flatten()
            })
            .await
            .ok()
            .flatten();
            (address, signature)
        }))
        .await;
        for (address, signature) in fetched {
            let Some(bytes) = signature else {
                continue;
            };
            match BLS12381Signature::from_bytes(&bytes)
                .map_err(|e| e.to_string())
                .and_then(|signature| {
                    aggregator
                        .add_signature_from(address, signature)
                        .map_err(|e| e.to_string())
                }) {
                Ok(()) => {
                    missing.remove(&address);
                }
                Err(e) => {
                    if rejected.insert(address) {
                        info!("PresigCompleted signature from {address} rejected: {e}");
                    }
                }
            }
        }
        if aggregator.weight() < required_weight {
            tokio::time::sleep(poll_interval).await;
            poll_interval = (poll_interval * 2).min(MAX_RETRY_INTERVAL);
        }
    }
    aggregator
        .finish()
        .map(Some)
        .map_err(|e| anyhow::anyhow!("failed to finalize PresigCompleted certificate: {e}"))
}

fn committee(inner: &Hashi, epoch: u64) -> anyhow::Result<Committee> {
    inner
        .onchain_state()
        .state()
        .hashi()
        .committees
        .committees()
        .get(&epoch)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no committee found for epoch {epoch}"))
}

fn submit_delay(committee: &Committee, my_address: Address, batch_index: u32) -> Duration {
    let members = committee.members();
    let Some(position) = members
        .iter()
        .position(|m| m.validator_address() == my_address)
    else {
        return SUBMIT_STAGGER;
    };
    let rank = (position + members.len() - batch_index as usize % members.len()) % members.len();
    SUBMIT_STAGGER * rank as u32
}
