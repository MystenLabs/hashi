// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::polynomial::Eval;
use fastcrypto_tbls::polynomial::Poly;
use fastcrypto_tbls::threshold_schnorr::Address as DerivationAddress;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::S;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::presigning::Presignatures;
use fastcrypto_tbls::threshold_schnorr::reed_solomon::RSDecoder;
use fastcrypto_tbls::threshold_schnorr::signing::aggregate_signatures;
use fastcrypto_tbls::threshold_schnorr::signing::generate_partial_signatures;
use hashi_types::committee::Committee;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use sui_sdk_types::Address;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::communication::P2PChannel;
use crate::communication::send_to_many;
use crate::mpc::types::GetPartialSignaturesRequest;
use crate::mpc::types::GetPartialSignaturesResponse;
use crate::mpc::types::PartialSigningOutput;
use crate::mpc::types::SigningError;
use crate::mpc::types::SigningResult;

pub struct SigningManager {
    address: Address,
    committee: Committee,
    threshold: u16,
    key_shares: avss::SharesForNode,
    verifying_key: G,
    /// Each presig is wrapped in Option so it can be taken exactly once,
    /// preventing nonce reuse even if the same index is assigned twice.
    presig_pool: Vec<Option<(Vec<S>, G)>>,
    /// Key: Sui address identifying the signing request
    partial_signing_outputs: HashMap<Address, PartialSigningOutput>,
    batch_index: u32,
    batch_start_index: u64,
    batch_size: usize,
    refill_divisor: usize,
    refill_tx: Arc<watch::Sender<u32>>,
    next_batch: Option<Presignatures>,
}

impl SigningManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: Address,
        committee: Committee,
        threshold: u16,
        key_shares: avss::SharesForNode,
        verifying_key: G,
        presignatures: Presignatures,
        batch_index: u32,
        batch_start_index: u64,
        refill_divisor: usize,
        refill_tx: Arc<watch::Sender<u32>>,
    ) -> Self {
        let presig_pool: Vec<Option<(Vec<S>, G)>> = presignatures.map(Some).collect();
        let batch_size = presig_pool.len();
        Self {
            address,
            committee,
            threshold,
            key_shares,
            verifying_key,
            presig_pool,
            partial_signing_outputs: HashMap::new(),
            batch_index,
            batch_start_index,
            batch_size,
            refill_divisor,
            refill_tx,
            next_batch: None,
        }
    }

    pub fn set_next_batch(&mut self, presignatures: Presignatures) {
        self.next_batch = Some(presignatures);
    }

    pub fn has_next_batch(&self) -> bool {
        self.next_batch.is_some()
    }

    pub fn initial_presig_count(&self) -> usize {
        self.batch_size
    }

    pub fn presignatures_remaining(&self) -> usize {
        self.presig_pool.iter().filter(|s| s.is_some()).count()
    }

    pub fn batch_index(&self) -> u32 {
        self.batch_index
    }

    pub fn epoch(&self) -> u64 {
        self.committee.epoch()
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn key_shares(&self) -> &avss::SharesForNode {
        &self.key_shares
    }

    pub fn verifying_key(&self) -> G {
        self.verifying_key
    }

    pub fn handle_get_partial_signatures_request(
        &self,
        request: &GetPartialSignaturesRequest,
    ) -> SigningResult<GetPartialSignaturesResponse> {
        let output = self
            .partial_signing_outputs
            .get(&request.sui_request_id)
            .ok_or_else(|| {
                SigningError::NotFound(format!(
                    "Partial signing output for request {}",
                    request.sui_request_id
                ))
            })?;
        Ok(GetPartialSignaturesResponse {
            partial_sigs: output.partial_sigs.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn sign(
        signing_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        sui_request_id: Address,
        message: &[u8],
        global_presig_index: u64,
        beacon_value: &S,
        derivation_address: Option<&DerivationAddress>,
        timeout: Duration,
    ) -> SigningResult<SchnorrSignature> {
        let (public_nonce, partial_sigs, threshold, address, committee, verifying_key) = {
            let mut mgr = signing_manager.write().unwrap();
            let mgr = &mut *mgr;
            let (public_nonce, partial_sigs) = if let Some(existing) =
                mgr.partial_signing_outputs.get(&sui_request_id)
            {
                tracing::info!(
                    "Cache hit for {sui_request_id} (global_presig_index={global_presig_index}), \
                     reusing cached partial sigs (batch_index={})",
                    mgr.batch_index,
                );
                (existing.public_nonce, existing.partial_sigs.clone())
            } else {
                if global_presig_index < mgr.batch_start_index {
                    tracing::error!(
                        "Presig index {global_presig_index} is behind current batch start {}. \
                         The presig for this withdrawal is no longer available.",
                        mgr.batch_start_index,
                    );
                    return Err(SigningError::StalePresigBatch {
                        presig_index: global_presig_index,
                        current_batch: mgr.batch_index,
                        batch_start: mgr.batch_start_index,
                    });
                }
                let batch_end = mgr.batch_start_index + mgr.batch_size as u64;
                if global_presig_index >= batch_end {
                    if let Some(next) = mgr.next_batch.take() {
                        mgr.batch_start_index += mgr.batch_size as u64;
                        mgr.presig_pool = next.map(Some).collect();
                        mgr.batch_index += 1;
                        mgr.batch_size = mgr.presig_pool.len();
                    } else {
                        tracing::error!(
                            "Presig index {global_presig_index} is beyond current batch \
                             (batch {}, range {}..{}) and no next batch available.",
                            mgr.batch_index,
                            mgr.batch_start_index,
                            batch_end,
                        );
                        return Err(SigningError::PoolExhausted);
                    }
                    let new_batch_end = mgr.batch_start_index + mgr.batch_size as u64;
                    if global_presig_index >= new_batch_end {
                        tracing::error!(
                            "Presig index {global_presig_index} is beyond swapped batch \
                             (batch {}, range {}..{}). Cannot skip batches.",
                            mgr.batch_index,
                            mgr.batch_start_index,
                            new_batch_end,
                        );
                        return Err(SigningError::PoolExhausted);
                    }
                }
                let target_position = (global_presig_index - mgr.batch_start_index) as usize;
                let presig = mgr
                    .presig_pool
                    .get_mut(target_position)
                    .and_then(|slot| slot.take())
                    .ok_or_else(|| {
                        tracing::error!(
                            "Presig at position {target_position} unavailable for batch {} \
                             (already consumed or out of range).",
                            mgr.batch_index,
                        );
                        SigningError::PoolExhausted
                    })?;
                tracing::info!(
                    "Cache miss for {sui_request_id}, using presig \
                     (global_presig_index={global_presig_index}, batch_index={}, \
                     position={target_position}, pool_size={})",
                    mgr.batch_index,
                    mgr.presig_pool.len(),
                );
                let result = generate_partial_signatures(
                    message,
                    presig,
                    beacon_value,
                    &mgr.key_shares,
                    &mgr.verifying_key,
                    derivation_address,
                )
                .map_err(|e| SigningError::CryptoError(e.to_string()))?;
                let remaining = mgr.presig_pool.iter().filter(|s| s.is_some()).count();
                let refill_at = mgr.batch_size / mgr.refill_divisor;
                if remaining <= refill_at {
                    let _ = mgr.refill_tx.send(mgr.batch_index + 1);
                }
                mgr.partial_signing_outputs.insert(
                    sui_request_id,
                    PartialSigningOutput {
                        public_nonce: result.0,
                        partial_sigs: result.1.clone(),
                    },
                );
                result
            };
            tracing::info!(
                "sign({sui_request_id}): public_nonce={public_nonce:?}, message_hash={}, \
                 verifying_key={}, first_partial_sig_index={}, first_partial_sig_value={:?}",
                hex::encode(message),
                hex::encode(mgr.verifying_key.to_byte_array()),
                partial_sigs[0].index,
                partial_sigs[0].value,
            );
            let threshold = mgr.threshold;
            let address = mgr.address;
            let committee = mgr.committee.clone();
            let verifying_key = mgr.verifying_key;
            (
                public_nonce,
                partial_sigs,
                threshold,
                address,
                committee,
                verifying_key,
            )
        }; // write lock released
        let mut all_partial_sigs = partial_sigs;
        let mut remaining_peers: HashSet<Address> = committee
            .members()
            .iter()
            .map(|m| m.validator_address())
            .filter(|addr| *addr != address)
            .collect();
        let request = GetPartialSignaturesRequest { sui_request_id };
        let deadline = Instant::now() + timeout;
        loop {
            if all_partial_sigs.len() >= threshold as usize {
                break;
            }
            if Instant::now() >= deadline {
                return Err(SigningError::Timeout {
                    collected: all_partial_sigs.len(),
                    threshold,
                });
            }
            collect_from_peers(
                p2p_channel,
                &request,
                &mut all_partial_sigs,
                &mut remaining_peers,
            )
            .await;
        }
        let params = AggregationParams {
            message,
            public_nonce: &public_nonce,
            beacon_value,
            threshold,
            verifying_key: &verifying_key,
            derivation_address,
        };
        let result = match aggregate_signatures(
            params.message,
            params.public_nonce,
            params.beacon_value,
            &all_partial_sigs,
            params.threshold,
            params.verifying_key,
            params.derivation_address,
        ) {
            Ok(sig) => Ok(sig),
            Err(FastCryptoError::InvalidSignature) => {
                tracing::info!(
                    "Initial signature aggregation failed for {}, entering recovery",
                    sui_request_id,
                );
                recover_signature_with_reed_solomon(
                    p2p_channel,
                    sui_request_id,
                    &params,
                    &request,
                    deadline,
                    &mut all_partial_sigs,
                    &mut remaining_peers,
                )
                .await
            }
            Err(e) => Err(SigningError::CryptoError(e.to_string())),
        };
        match &result {
            Ok(_) => {}
            Err(e) => {
                let mgr = signing_manager.read().unwrap();
                tracing::error!(
                    "Signing failed for {sui_request_id}: {e}, \
                     presigs_remaining={}, batch_index={}",
                    mgr.presig_pool.iter().filter(|s| s.is_some()).count(),
                    mgr.batch_index,
                );
            }
        }
        result
    }
}

struct AggregationParams<'a> {
    message: &'a [u8],
    public_nonce: &'a G,
    beacon_value: &'a S,
    threshold: u16,
    verifying_key: &'a G,
    derivation_address: Option<&'a DerivationAddress>,
}

async fn recover_signature_with_reed_solomon(
    p2p_channel: &impl P2PChannel,
    sui_request_id: Address,
    params: &AggregationParams<'_>,
    request: &GetPartialSignaturesRequest,
    deadline: Instant,
    all_partial_sigs: &mut Vec<Eval<S>>,
    remaining_peers: &mut HashSet<Address>,
) -> SigningResult<SchnorrSignature> {
    loop {
        let rs_correction_capacity = (all_partial_sigs
            .len()
            .saturating_sub(params.threshold as usize))
            / 2;
        if rs_correction_capacity >= 1 {
            match aggregate_signatures_with_recovery(
                params.message,
                params.public_nonce,
                params.beacon_value,
                all_partial_sigs,
                params.threshold,
                params.verifying_key,
                params.derivation_address,
            ) {
                Ok(sig) => return Ok(sig),
                Err(FastCryptoError::TooManyErrors(max)) => {
                    tracing::info!(
                        "RS recovery failed for {}: too many errors (max correctable: {}), \
                         collecting more sigs (have {})",
                        sui_request_id,
                        max,
                        all_partial_sigs.len(),
                    );
                }
                Err(e) => return Err(SigningError::CryptoError(e.to_string())),
            }
        }
        if remaining_peers.is_empty() {
            return Err(SigningError::TooManyInvalidSignatures {
                collected: all_partial_sigs.len(),
                threshold: params.threshold,
            });
        }
        if Instant::now() >= deadline {
            return Err(SigningError::Timeout {
                collected: all_partial_sigs.len(),
                threshold: params.threshold,
            });
        }
        collect_from_peers(p2p_channel, request, all_partial_sigs, remaining_peers).await;
    }
}

fn aggregate_signatures_with_recovery(
    message: &[u8],
    public_presig: &G,
    beacon_value: &S,
    partial_signatures: &[Eval<S>],
    threshold: u16,
    verifying_key: &G,
    derivation_address: Option<&DerivationAddress>,
) -> Result<SchnorrSignature, FastCryptoError> {
    let indices: Vec<_> = partial_signatures.iter().map(|e| e.index).collect();
    let values: Vec<_> = partial_signatures.iter().map(|e| e.value).collect();
    let decoder = RSDecoder::new(indices.clone(), threshold as usize);
    let coefficients = decoder.decode(&values)?;
    // TODO: This re-interpolates a polynomial we have already decoded. Refactor `fastcrypto` to
    // expose the constant term directly from the RS decoded message, avoiding redundant work.
    let poly = Poly::from(coefficients);
    let corrected_sigs: Vec<Eval<S>> = indices
        .iter()
        .take(threshold as usize)
        .map(|&idx| poly.eval(idx))
        .collect();
    aggregate_signatures(
        message,
        public_presig,
        beacon_value,
        &corrected_sigs,
        threshold,
        verifying_key,
        derivation_address,
    )
}

async fn collect_from_peers(
    p2p_channel: &impl P2PChannel,
    request: &GetPartialSignaturesRequest,
    all_partial_sigs: &mut Vec<Eval<S>>,
    remaining_peers: &mut HashSet<Address>,
) {
    let results = send_to_many(
        remaining_peers.iter().copied(),
        request.clone(),
        |addr, req| async move { p2p_channel.get_partial_signatures(&addr, &req).await },
    )
    .await;
    for (addr, result) in results {
        match result {
            Ok(response) => {
                remaining_peers.remove(&addr);
                all_partial_sigs.extend(response.partial_sigs);
            }
            Err(e) => {
                tracing::info!("Failed to get partial signatures from {}: {}", addr, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communication::ChannelError;
    use crate::communication::ChannelResult;
    use crate::mpc::types::ComplainRequest;
    use crate::mpc::types::ComplaintResponses;
    use crate::mpc::types::GetPublicDkgOutputRequest;
    use crate::mpc::types::GetPublicDkgOutputResponse;
    use crate::mpc::types::RetrieveMessagesRequest;
    use crate::mpc::types::RetrieveMessagesResponse;
    use crate::mpc::types::SendMessagesRequest;
    use crate::mpc::types::SendMessagesResponse;
    use fastcrypto::groups::GroupElement;
    use fastcrypto::groups::Scalar;
    use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
    use fastcrypto::serde_helpers::ToFromByteArray;
    use fastcrypto::traits::AllowedRng;
    use fastcrypto_tbls::threshold_schnorr::batch_avss;
    use fastcrypto_tbls::types::ShareIndex;
    use hashi_types::committee::CommitteeMember;
    use hashi_types::committee::EncryptionPrivateKey;
    use hashi_types::committee::EncryptionPublicKey;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn mock_shares(rng: &mut impl AllowedRng, secret: S, t: u16, n: u16) -> Vec<Eval<S>> {
        let p = Poly::rand_fixed_c0(t - 1, secret, rng);
        (1..=n)
            .map(|i| p.eval(ShareIndex::new(i).unwrap()))
            .collect()
    }

    fn test_address(i: usize) -> Address {
        Address::new([i as u8; 32])
    }

    fn test_request_id() -> Address {
        Address::new([0xAA; 32])
    }

    fn verify_schnorr(vk: &G, message: &[u8], sig: &SchnorrSignature) {
        SchnorrPublicKey::try_from(vk)
            .unwrap()
            .verify(message, sig)
            .unwrap();
    }

    struct MockSigningP2PChannel {
        managers: HashMap<Address, Arc<RwLock<SigningManager>>>,
    }

    #[async_trait::async_trait]
    impl P2PChannel for MockSigningP2PChannel {
        async fn send_messages(
            &self,
            _: &Address,
            _: &SendMessagesRequest,
        ) -> ChannelResult<SendMessagesResponse> {
            unimplemented!()
        }

        async fn retrieve_messages(
            &self,
            _: &Address,
            _: &RetrieveMessagesRequest,
        ) -> ChannelResult<RetrieveMessagesResponse> {
            unimplemented!()
        }
        async fn complain(
            &self,
            _: &Address,
            _: &ComplainRequest,
        ) -> ChannelResult<ComplaintResponses> {
            unimplemented!()
        }
        async fn get_public_dkg_output(
            &self,
            _: &Address,
            _: &GetPublicDkgOutputRequest,
        ) -> ChannelResult<GetPublicDkgOutputResponse> {
            unimplemented!()
        }
        async fn get_partial_signatures(
            &self,
            party: &Address,
            request: &GetPartialSignaturesRequest,
        ) -> ChannelResult<GetPartialSignaturesResponse> {
            let mgr = self
                .managers
                .get(party)
                .ok_or(ChannelError::ClientNotFound(*party))?;
            mgr.read()
                .unwrap()
                .handle_get_partial_signatures_request(request)
                .map_err(|e| ChannelError::RequestFailed(e.to_string()))
        }
    }

    struct CannedP2PChannel {
        responses: HashMap<Address, ChannelResult<GetPartialSignaturesResponse>>,
    }

    #[async_trait::async_trait]
    impl P2PChannel for CannedP2PChannel {
        async fn send_messages(
            &self,
            _: &Address,
            _: &SendMessagesRequest,
        ) -> ChannelResult<SendMessagesResponse> {
            unimplemented!()
        }

        async fn retrieve_messages(
            &self,
            _: &Address,
            _: &RetrieveMessagesRequest,
        ) -> ChannelResult<RetrieveMessagesResponse> {
            unimplemented!()
        }
        async fn complain(
            &self,
            _: &Address,
            _: &ComplainRequest,
        ) -> ChannelResult<ComplaintResponses> {
            unimplemented!()
        }
        async fn get_public_dkg_output(
            &self,
            _: &Address,
            _: &GetPublicDkgOutputRequest,
        ) -> ChannelResult<GetPublicDkgOutputResponse> {
            unimplemented!()
        }
        async fn get_partial_signatures(
            &self,
            party: &Address,
            _request: &GetPartialSignaturesRequest,
        ) -> ChannelResult<GetPartialSignaturesResponse> {
            match self.responses.get(party) {
                Some(Ok(resp)) => Ok(resp.clone()),
                Some(Err(_)) => Err(ChannelError::RequestFailed(format!(
                    "canned error for {}",
                    party
                ))),
                None => Err(ChannelError::ClientNotFound(*party)),
            }
        }
    }

    fn canned_p2p_with_corruptions(
        all_sigs: &[Vec<Eval<S>>],
        corrupt_indices: &[usize],
        rng: &mut impl AllowedRng,
    ) -> CannedP2PChannel {
        let mut responses = HashMap::new();
        for (i, peer_sigs) in all_sigs.iter().enumerate().skip(1) {
            let sigs = if corrupt_indices.contains(&i) {
                peer_sigs
                    .iter()
                    .map(|e| Eval {
                        index: e.index,
                        value: S::rand(rng),
                    })
                    .collect()
            } else {
                peer_sigs.clone()
            };
            responses.insert(
                test_address(i),
                Ok(GetPartialSignaturesResponse { partial_sigs: sigs }),
            );
        }
        CannedP2PChannel { responses }
    }

    struct SigningTestSetup {
        managers: Vec<Arc<RwLock<SigningManager>>>,
        verifying_key: G,
        refill_rx: watch::Receiver<u32>,
        n: u16,
        f: u16,
        t: u16,
    }

    impl SigningTestSetup {
        fn new(n: u16) -> Self {
            let f = (n - 1) / 3;
            let t = f + 1;
            let mut rng = StdRng::seed_from_u64(42);

            // Committee
            let encryption_keys: Vec<_> = (0..n)
                .map(|_| EncryptionPrivateKey::new(&mut rng))
                .collect();
            let members: Vec<_> = (0..n as usize)
                .map(|i| {
                    CommitteeMember::new(
                        test_address(i),
                        hashi_types::committee::Bls12381PrivateKey::generate(&mut rng).public_key(),
                        EncryptionPublicKey::from_private_key(&encryption_keys[i]),
                        1,
                    )
                })
                .collect();
            let committee = Committee::new(members, 100);

            // Fake DKG
            let sk = S::rand(&mut rng);
            let vk = G::generator() * sk;
            let sk_shares = mock_shares(&mut rng, sk, t, n);

            // Fake presigning (same as fastcrypto test_signing)
            let batch_size_per_weight: u16 = 10;
            let nonces_for_dealer: Vec<_> = (0..n)
                .map(|_| {
                    let nonces: Vec<S> = (0..batch_size_per_weight)
                        .map(|_| S::rand(&mut rng))
                        .collect();
                    let public_keys: Vec<G> = nonces.iter().map(|s| G::generator() * *s).collect();
                    let nonce_shares: Vec<Vec<S>> = nonces
                        .iter()
                        .map(|&nonce| {
                            mock_shares(&mut rng, nonce, t, n)
                                .iter()
                                .map(|e| e.value)
                                .collect()
                        })
                        .collect();
                    (public_keys, nonce_shares)
                })
                .collect();

            let (refill_tx, refill_rx) = watch::channel(0u32);
            let refill_tx = Arc::new(refill_tx);

            let managers: Vec<_> = (0..n as usize)
                .map(|i| {
                    let index = ShareIndex::new(i as u16 + 1).unwrap();
                    let key_shares = avss::SharesForNode {
                        shares: vec![sk_shares[i].clone()],
                    };
                    let outputs: Vec<batch_avss::ReceiverOutput> = (0..n as usize)
                        .map(|j| batch_avss::ReceiverOutput {
                            my_shares: batch_avss::SharesForNode {
                                shares: vec![batch_avss::ShareBatch {
                                    index,
                                    batch: (0..batch_size_per_weight as usize)
                                        .map(|l| nonces_for_dealer[j].1[l][i])
                                        .collect(),
                                    blinding_share: S::zero(),
                                }],
                            },
                            public_keys: nonces_for_dealer[j].0.clone(),
                        })
                        .collect();
                    let presignatures =
                        Presignatures::new(outputs, batch_size_per_weight, f as usize).unwrap();
                    let mgr = SigningManager::new(
                        test_address(i),
                        committee.clone(),
                        t,
                        key_shares,
                        vk,
                        presignatures,
                        0, // batch_index
                        0, // batch_start_index
                        crate::constants::PRESIG_REFILL_DIVISOR,
                        refill_tx.clone(),
                    );
                    Arc::new(RwLock::new(mgr))
                })
                .collect();

            Self {
                managers,
                verifying_key: vk,
                refill_rx,
                n,
                f,
                t,
            }
        }

        /// Have peers generate + store partial sigs so their RPC handlers work.
        /// If `skip` is Some(i), that manager is skipped (use for the caller who
        /// will generate its own sigs inside `sign()`).
        /// Returns (public_nonce, Vec of per-party partial sigs).
        fn prepare_all(
            &self,
            message: &[u8],
            beacon_value: &S,
            request_id: Address,
            presig_index: usize,
            skip: Option<usize>,
        ) -> (G, Vec<Vec<Eval<S>>>) {
            let mut public_nonce = None;
            let mut all_sigs = Vec::new();
            for (idx, mgr_lock) in self.managers.iter().enumerate() {
                if skip == Some(idx) {
                    all_sigs.push(Vec::new());
                    continue;
                }
                let mgr = mgr_lock.read().unwrap();
                let presig = mgr.presig_pool[presig_index].clone().unwrap();
                let (pn, sigs) = generate_partial_signatures(
                    message,
                    presig,
                    beacon_value,
                    &mgr.key_shares,
                    &mgr.verifying_key,
                    None,
                )
                .unwrap();
                drop(mgr);
                let mut mgr = mgr_lock.write().unwrap();
                mgr.partial_signing_outputs.insert(
                    request_id,
                    PartialSigningOutput {
                        public_nonce: pn,
                        partial_sigs: sigs.clone(),
                    },
                );
                if public_nonce.is_none() {
                    public_nonce = Some(pn);
                }
                all_sigs.push(sigs);
            }
            (public_nonce.unwrap(), all_sigs)
        }

        /// Build a MockSigningP2PChannel containing all peers except `caller_index`.
        fn mock_p2p_for(&self, caller_index: usize) -> MockSigningP2PChannel {
            let managers = self
                .managers
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != caller_index)
                .map(|(i, m)| (test_address(i), m.clone()))
                .collect();
            MockSigningP2PChannel { managers }
        }

        /// Exhaust all presignatures on all managers.
        fn exhaust_pool(&self) {
            for mgr_lock in &self.managers {
                mgr_lock.write().unwrap().presig_pool.clear();
            }
        }

        /// Build fresh presignatures and set as next_batch on all managers.
        fn set_next_batch_on_all(&self) {
            let batch_size_per_weight: u16 = 10;
            let mut rng = StdRng::seed_from_u64(99);
            let nonces_for_dealer: Vec<_> = (0..self.n)
                .map(|_| {
                    let nonces: Vec<S> = (0..batch_size_per_weight)
                        .map(|_| S::rand(&mut rng))
                        .collect();
                    let public_keys: Vec<G> = nonces.iter().map(|s| G::generator() * *s).collect();
                    let nonce_shares: Vec<Vec<S>> = nonces
                        .iter()
                        .map(|&nonce| {
                            mock_shares(&mut rng, nonce, self.t, self.n)
                                .iter()
                                .map(|e| e.value)
                                .collect()
                        })
                        .collect();
                    (public_keys, nonce_shares)
                })
                .collect();
            for (i, mgr_lock) in self.managers.iter().enumerate() {
                let index = ShareIndex::new(i as u16 + 1).unwrap();
                let outputs: Vec<batch_avss::ReceiverOutput> = (0..self.n as usize)
                    .map(|j| batch_avss::ReceiverOutput {
                        my_shares: batch_avss::SharesForNode {
                            shares: vec![batch_avss::ShareBatch {
                                index,
                                batch: (0..batch_size_per_weight as usize)
                                    .map(|l| nonces_for_dealer[j].1[l][i])
                                    .collect(),
                                blinding_share: S::zero(),
                            }],
                        },
                        public_keys: nonces_for_dealer[j].0.clone(),
                    })
                    .collect();
                let presignatures =
                    Presignatures::new(outputs, batch_size_per_weight, self.f as usize).unwrap();
                mgr_lock.write().unwrap().set_next_batch(presignatures);
            }
        }

        /// Manually swap peers (skip manager at `caller_index`) to next_batch.
        /// Needed because prepare_all calls generate_partial_signatures directly
        /// (not sign()), so it doesn't have the OutOfPresigs swap logic.
        fn swap_peers_to_next_batch(&self, caller_index: usize) {
            for (i, mgr_lock) in self.managers.iter().enumerate() {
                if i == caller_index {
                    continue;
                }
                let mut mgr = mgr_lock.write().unwrap();
                mgr.batch_start_index += mgr.batch_size as u64;
                let next = mgr.next_batch.take().unwrap();
                mgr.presig_pool = next.map(Some).collect();
                mgr.batch_index += 1;
                mgr.batch_size = mgr.presig_pool.len();
            }
        }
    }

    /// Pre-built partial sigs for aggregate_signatures_with_recovery tests.
    struct AggregateTestData {
        partial_sigs: Vec<Eval<S>>,
        public_nonce: G,
        vk: G,
        beacon: S,
        t: u16,
        rng: StdRng,
    }

    /// Build 5 partial sigs from a (n=7, t=3, f=2) setup for RS recovery tests.
    fn build_aggregate_test_data(seed: u64, message: &[u8]) -> AggregateTestData {
        let mut rng = StdRng::seed_from_u64(seed);
        let f: u16 = 2;
        let t: u16 = f + 1;
        let n: u16 = 7;

        let sk = S::rand(&mut rng);
        let vk = G::generator() * sk;
        let sk_shares = mock_shares(&mut rng, sk, t, n);

        let batch_size_per_weight: u16 = 2;
        let nonces_for_dealer: Vec<_> = (0..n)
            .map(|_| {
                let nonces: Vec<S> = (0..batch_size_per_weight)
                    .map(|_| S::rand(&mut rng))
                    .collect();
                let public_keys: Vec<G> = nonces.iter().map(|s| G::generator() * *s).collect();
                let nonce_shares: Vec<Vec<S>> = nonces
                    .iter()
                    .map(|&nonce| {
                        mock_shares(&mut rng, nonce, t, n)
                            .iter()
                            .map(|e| e.value)
                            .collect()
                    })
                    .collect();
                (public_keys, nonce_shares)
            })
            .collect();

        let beacon = S::rand(&mut rng);

        let mut public_nonce = None;
        let mut partial_sigs: Vec<Eval<S>> = Vec::new();
        for (i, sk_share) in sk_shares.iter().enumerate().take(5) {
            let index = ShareIndex::new(i as u16 + 1).unwrap();
            let key_shares = avss::SharesForNode {
                shares: vec![sk_share.clone()],
            };
            let outputs: Vec<batch_avss::ReceiverOutput> = (0..n as usize)
                .map(|j| batch_avss::ReceiverOutput {
                    my_shares: batch_avss::SharesForNode {
                        shares: vec![batch_avss::ShareBatch {
                            index,
                            batch: (0..batch_size_per_weight as usize)
                                .map(|l| nonces_for_dealer[j].1[l][i])
                                .collect(),
                            blinding_share: S::zero(),
                        }],
                    },
                    public_keys: nonces_for_dealer[j].0.clone(),
                })
                .collect();
            let presigs: Vec<(Vec<S>, G)> =
                Presignatures::new(outputs, batch_size_per_weight, f as usize)
                    .unwrap()
                    .collect();
            let (pn, sigs) = generate_partial_signatures(
                message,
                presigs[0].clone(),
                &beacon,
                &key_shares,
                &vk,
                None,
            )
            .unwrap();
            if public_nonce.is_none() {
                public_nonce = Some(pn);
            }
            partial_sigs.extend(sigs);
        }

        AggregateTestData {
            partial_sigs,
            public_nonce: public_nonce.unwrap(),
            vk,
            beacon,
            t,
            rng,
        }
    }

    #[test]
    fn test_handle_get_partial_signatures_found() {
        let setup = SigningTestSetup::new(4);
        let message = b"test";
        let beacon = S::zero();
        let req_id = test_request_id();

        setup.prepare_all(message, &beacon, req_id, 0, None);

        let mgr = setup.managers[0].read().unwrap();
        let resp = mgr
            .handle_get_partial_signatures_request(&GetPartialSignaturesRequest {
                sui_request_id: req_id,
            })
            .unwrap();
        assert!(!resp.partial_sigs.is_empty());
    }

    #[test]
    fn test_handle_get_partial_signatures_not_found() {
        let setup = SigningTestSetup::new(4);
        let mgr = setup.managers[0].read().unwrap();
        let result = mgr.handle_get_partial_signatures_request(&GetPartialSignaturesRequest {
            sui_request_id: test_request_id(),
        });
        assert!(matches!(result, Err(SigningError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_sign_happy_path() {
        let setup = SigningTestSetup::new(7); // n=7, t=3, f=2
        let message = b"hello world";
        let beacon = S::zero();
        let req_id = test_request_id();

        // All peers (except caller) prepare their partial sigs first.
        setup.prepare_all(message, &beacon, req_id, 0, Some(0));

        let p2p = setup.mock_p2p_for(0);
        let sig = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        verify_schnorr(&setup.verifying_key, message, &sig);
    }

    #[tokio::test]
    async fn test_sign_threshold_exact() {
        // n=7, t=3, f=2. Caller has 1 share, needs 2 more from peers.
        // Give exactly 2 peers partial sigs, rest return errors.
        let setup = SigningTestSetup::new(7);
        let message = b"threshold";
        let beacon = S::zero();
        let req_id = test_request_id();

        // Only peers 1 and 2 prepare partial sigs.
        for i in [1, 2] {
            let mgr = setup.managers[i].read().unwrap();
            let presig = mgr.presig_pool[0].clone().unwrap();
            let (pn, sigs) = generate_partial_signatures(
                message,
                presig,
                &beacon,
                &mgr.key_shares,
                &mgr.verifying_key,
                None,
            )
            .unwrap();
            drop(mgr);
            let mut mgr = setup.managers[i].write().unwrap();
            mgr.partial_signing_outputs.insert(
                req_id,
                PartialSigningOutput {
                    public_nonce: pn,
                    partial_sigs: sigs,
                },
            );
        }

        // Peers 3-6 are in the mock but have no stored sigs → NotFound → ChannelError
        let p2p = setup.mock_p2p_for(0);
        let sig = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        verify_schnorr(&setup.verifying_key, message, &sig);
    }

    #[tokio::test]
    async fn test_sign_one_corrupted_rs_recovery() {
        // n=7, t=3, f=2. One peer returns corrupted partial sig.
        // Caller's 1 + 6 peers = 7 total, 1 bad → RS capacity (7-3)/2=2 → corrects 1.
        let setup = SigningTestSetup::new(7);
        let message = b"recovery";
        let beacon = S::zero();
        let req_id = test_request_id();

        let (_, all_sigs) = setup.prepare_all(message, &beacon, req_id, 0, Some(0));
        let p2p = canned_p2p_with_corruptions(&all_sigs, &[1], &mut StdRng::seed_from_u64(999));

        let sig = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        verify_schnorr(&setup.verifying_key, message, &sig);
    }

    #[tokio::test]
    async fn test_sign_multiple_corrupted_rs_recovery() {
        // n=10, t=4, f=3. Two peers return corrupted sigs.
        // Caller's 1 + 9 peers = 10 total, 2 bad → RS capacity (10-4)/2=3 → corrects 2.
        let setup = SigningTestSetup::new(10);
        let message = b"multi-recovery";
        let beacon = S::zero();
        let req_id = test_request_id();

        let (_, all_sigs) = setup.prepare_all(message, &beacon, req_id, 0, Some(0));
        let p2p = canned_p2p_with_corruptions(&all_sigs, &[1, 2], &mut StdRng::seed_from_u64(888));

        let sig = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        verify_schnorr(&setup.verifying_key, message, &sig);
    }

    #[tokio::test]
    async fn test_sign_too_many_invalid() {
        // n=4, t=2, f=1. All 3 peers return corrupt sigs.
        // aggregate_signatures uses first `threshold` sigs, so caller(valid) +
        // any_peer(corrupted) → InvalidSignature.
        // RS: 4 sigs, 3 bad, capacity=(4-2)/2=1 → TooManyErrors.
        // No remaining peers → TooManyInvalidSignatures.
        let setup = SigningTestSetup::new(4);
        let message = b"too-many";
        let beacon = S::zero();
        let req_id = test_request_id();

        let (_, all_sigs) = setup.prepare_all(message, &beacon, req_id, 0, Some(0));
        let p2p =
            canned_p2p_with_corruptions(&all_sigs, &[1, 2, 3], &mut StdRng::seed_from_u64(777));

        let result = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
        )
        .await;

        assert!(
            matches!(result, Err(SigningError::TooManyInvalidSignatures { .. })),
            "expected TooManyInvalidSignatures, got: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_sign_timeout() {
        // All peers fail → never reach threshold → timeout.
        let setup = SigningTestSetup::new(4);
        let message = b"timeout";
        let beacon = S::zero();
        let req_id = test_request_id();

        let mut responses = HashMap::new();
        for i in 1..4usize {
            responses.insert(
                test_address(i),
                Err(ChannelError::RequestFailed("unavailable".into())),
            );
        }
        let p2p = CannedP2PChannel { responses };

        let result = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_millis(1), // very short timeout
        )
        .await;

        assert!(
            matches!(result, Err(SigningError::Timeout { .. })),
            "expected Timeout, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_aggregate_with_recovery_correctable() {
        // t=3, 5 sigs with 1 corrupted → RS corrects.
        let message = b"rs-test";
        let mut data = build_aggregate_test_data(123, message);

        data.partial_sigs[0].value = S::rand(&mut data.rng);

        let sig = aggregate_signatures_with_recovery(
            message,
            &data.public_nonce,
            &data.beacon,
            &data.partial_sigs,
            data.t,
            &data.vk,
            None,
        )
        .unwrap();

        verify_schnorr(&data.vk, message, &sig);
    }

    #[test]
    fn test_aggregate_with_recovery_too_many_errors() {
        // t=3, 5 sigs with 2 corrupted → RS capacity (5-3)/2=1, can't correct 2.
        let message = b"rs-fail";
        let mut data = build_aggregate_test_data(456, message);

        data.partial_sigs[0].value = S::rand(&mut data.rng);
        data.partial_sigs[1].value = S::rand(&mut data.rng);

        let result = aggregate_signatures_with_recovery(
            message,
            &data.public_nonce,
            &data.beacon,
            &data.partial_sigs,
            data.t,
            &data.vk,
            None,
        );

        assert!(
            matches!(result, Err(FastCryptoError::TooManyErrors(_))),
            "expected TooManyErrors, got: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_sign_pool_exhausted_with_next_batch() {
        // Exhaust batch 0, set next_batch, verify sign() swaps to batch 1.
        let setup = SigningTestSetup::new(4);
        setup.exhaust_pool();
        setup.set_next_batch_on_all();
        setup.swap_peers_to_next_batch(0);

        let req_id = Address::new([0xFF; 32]);
        let batch_size = setup.managers[0].read().unwrap().initial_presig_count() as u64;
        setup.prepare_all(b"swap", &S::zero(), req_id, 0, Some(0));
        let p2p = setup.mock_p2p_for(0);
        let sig = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req_id,
            b"swap",
            batch_size, // first presig of batch 1
            &S::zero(),
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        verify_schnorr(&setup.verifying_key, b"swap", &sig);
        let mgr = setup.managers[0].read().unwrap();
        assert_eq!(mgr.batch_index(), 1);
        assert!(!mgr.has_next_batch());
    }

    #[tokio::test]
    async fn test_sign_pool_exhausted_no_next_batch() {
        // Exhaust pool without setting next_batch → PoolExhausted.
        let setup = SigningTestSetup::new(4);
        setup.exhaust_pool();

        let p2p = setup.mock_p2p_for(0);
        let result = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            Address::new([0xFF; 32]),
            b"fail",
            0,
            &S::zero(),
            None,
            Duration::from_secs(30),
        )
        .await;

        assert!(matches!(result, Err(SigningError::PoolExhausted)));
    }

    #[test]
    fn test_refill_threshold_triggers_signal() {
        // Consuming past 50% threshold sends refill signal via watch channel.
        let setup = SigningTestSetup::new(4);
        let pool_size = setup.managers[0].read().unwrap().initial_presig_count();
        let refill_at = pool_size / crate::constants::PRESIG_REFILL_DIVISOR;
        let beacon = S::zero();

        // Consume presignatures on manager 0 until we cross the threshold.
        for i in 0..(pool_size - refill_at) {
            let mut mgr = setup.managers[0].write().unwrap();
            let presig = mgr.presig_pool[i].take().unwrap();
            let _ = generate_partial_signatures(
                b"msg",
                presig,
                &beacon,
                &mgr.key_shares,
                &mgr.verifying_key,
                None,
            )
            .unwrap();
            // Simulate the threshold check that sign() does.
            let remaining = mgr.presig_pool.iter().filter(|s| s.is_some()).count();
            let threshold = mgr.batch_size / mgr.refill_divisor;
            if remaining <= threshold {
                let _ = mgr.refill_tx.send(mgr.batch_index + 1);
            }
        }

        assert!(setup.refill_rx.has_changed().unwrap());
        assert_eq!(*setup.refill_rx.borrow(), 1);
    }

    #[tokio::test]
    async fn test_pool_exhausted() {
        let setup = SigningTestSetup::new(4);
        setup.exhaust_pool();

        let p2p = setup.mock_p2p_for(0);
        let result = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            Address::new([0xFF; 32]),
            b"fail",
            0,
            &S::zero(),
            None,
            Duration::from_secs(30),
        )
        .await;

        assert!(matches!(result, Err(SigningError::PoolExhausted)));
    }

    #[tokio::test]
    async fn test_sign_stale_batch_error() {
        let setup = SigningTestSetup::new(4);

        // Move all managers to batch 1.
        setup.set_next_batch_on_all();
        setup.swap_peers_to_next_batch(0);
        {
            let mut mgr = setup.managers[0].write().unwrap();
            mgr.batch_start_index += mgr.batch_size as u64;
            let next = mgr.next_batch.take().unwrap();
            mgr.presig_pool = next.map(Some).collect();
            mgr.batch_index += 1;
            mgr.batch_size = mgr.presig_pool.len();
        }

        // Try to sign with an index from batch 0.
        let p2p = setup.mock_p2p_for(0);
        let result = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            Address::new([0x01; 32]),
            b"stale",
            0, // batch 0, but manager is on batch 1
            &S::zero(),
            None,
            Duration::from_secs(30),
        )
        .await;

        assert!(matches!(
            result,
            Err(SigningError::StalePresigBatch {
                presig_index: 0,
                current_batch: 1,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn test_sign_presig_already_consumed() {
        let setup = SigningTestSetup::new(4);
        let beacon = S::zero();

        // First sign with presig 0 — succeeds.
        let req1 = Address::new([0x01; 32]);
        setup.prepare_all(b"msg1", &beacon, req1, 0, Some(0));
        let p2p = setup.mock_p2p_for(0);
        let result1 = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req1,
            b"msg1",
            0,
            &beacon,
            None,
            Duration::from_secs(30),
        )
        .await;
        assert!(result1.is_ok());

        // Second sign with same presig index 0 but different request ID.
        // Presig was already taken — should fail.
        let req2 = Address::new([0x02; 32]);
        let result2 = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req2,
            b"msg2",
            0, // same index, already consumed
            &beacon,
            None,
            Duration::from_secs(30),
        )
        .await;
        assert!(matches!(result2, Err(SigningError::PoolExhausted)));
    }

    #[tokio::test]
    async fn test_sign_batch_too_far_ahead() {
        let setup = SigningTestSetup::new(4);
        let batch_size = setup.managers[0].read().unwrap().initial_presig_count() as u64;

        // Target index maps to batch 2, but manager is on batch 0 with no next_batch.
        let p2p = setup.mock_p2p_for(0);
        let result = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            Address::new([0x01; 32]),
            b"far-ahead",
            batch_size * 2, // batch 2
            &S::zero(),
            None,
            Duration::from_secs(30),
        )
        .await;

        assert!(matches!(result, Err(SigningError::PoolExhausted)));
    }

    #[tokio::test]
    async fn test_sign_retry_reuses_cached_partial_sigs() {
        let setup = SigningTestSetup::new(4);
        let message = b"retry-test";
        let beacon = S::zero();
        let req_id = test_request_id();

        // Record presig pool size before first sign.
        let pool_before = setup.managers[0].read().unwrap().presignatures_remaining();

        // First sign — consumes one presig, caches partial sigs.
        setup.prepare_all(message, &beacon, req_id, 0, Some(0));
        let p2p = setup.mock_p2p_for(0);
        let sig1 = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        let pool_after_first = setup.managers[0].read().unwrap().presignatures_remaining();
        assert_eq!(
            pool_after_first,
            pool_before - 1,
            "first sign should consume one presig"
        );

        // Second sign with SAME request_id — should reuse cached partial sigs.
        let sig2 = SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        let pool_after_second = setup.managers[0].read().unwrap().presignatures_remaining();
        assert_eq!(
            pool_after_second, pool_after_first,
            "retry should NOT consume another presig"
        );

        // Both calls produce the same signature.
        assert_eq!(
            sig1.to_byte_array(),
            sig2.to_byte_array(),
            "retry should produce identical signature"
        );

        // Verify the signature is valid.
        verify_schnorr(&setup.verifying_key, message, &sig1);
    }

    #[tokio::test]
    async fn test_sign_different_request_consumes_new_presig() {
        let setup = SigningTestSetup::new(4);
        let beacon = S::zero();

        let req1 = Address::new([0x10; 32]);
        let req2 = Address::new([0x20; 32]);

        let pool_before = setup.managers[0].read().unwrap().presignatures_remaining();

        // First request.
        setup.prepare_all(b"msg1", &beacon, req1, 0, Some(0));
        let p2p = setup.mock_p2p_for(0);
        SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req1,
            b"msg1",
            0,
            &beacon,
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        // Second request with different ID.
        setup.prepare_all(b"msg2", &beacon, req2, 1, Some(0));
        SigningManager::sign(
            &setup.managers[0],
            &p2p,
            req2,
            b"msg2",
            1,
            &beacon,
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        let pool_after = setup.managers[0].read().unwrap().presignatures_remaining();
        assert_eq!(
            pool_after,
            pool_before - 2,
            "two different requests should consume two presigs"
        );
    }
}
