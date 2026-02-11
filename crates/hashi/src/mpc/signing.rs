use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
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
    presignatures: Presignatures,
    /// Key: Sui address identifying the signing request
    partial_signing_outputs: HashMap<Address, PartialSigningOutput>,
}

impl SigningManager {
    pub fn new(
        address: Address,
        committee: Committee,
        threshold: u16,
        key_shares: avss::SharesForNode,
        verifying_key: G,
        presignatures: Presignatures,
    ) -> Self {
        Self {
            address,
            committee,
            threshold,
            key_shares,
            verifying_key,
            presignatures,
            partial_signing_outputs: HashMap::new(),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.committee.epoch()
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

    pub async fn sign(
        signing_manager: &Arc<RwLock<Self>>,
        p2p_channel: &impl P2PChannel,
        sui_request_id: Address,
        message: &[u8],
        beacon_value: &S,
        derivation_address: Option<&DerivationAddress>,
        timeout: Duration,
    ) -> SigningResult<SchnorrSignature> {
        let (public_nonce, partial_sigs, threshold, address, committee, verifying_key) = {
            let mut mgr = signing_manager.write().unwrap();
            let mgr = &mut *mgr;
            let (public_nonce, partial_sigs) = generate_partial_signatures(
                message,
                &mut mgr.presignatures,
                beacon_value,
                &mgr.key_shares,
                &mgr.verifying_key,
                derivation_address,
            )
            .map_err(|e| SigningError::CryptoError(e.to_string()))?;
            mgr.partial_signing_outputs.insert(
                sui_request_id,
                PartialSigningOutput {
                    public_nonce,
                    partial_sigs: partial_sigs.clone(),
                },
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
        match aggregate_signatures(
            params.message,
            params.public_nonce,
            params.beacon_value,
            &all_partial_sigs,
            params.threshold,
            params.verifying_key,
            params.derivation_address,
        ) {
            Ok(sig) => return Ok(sig),
            Err(FastCryptoError::InvalidSignature) => {
                tracing::info!(
                    "Initial signature aggregation failed for {}, entering recovery",
                    sui_request_id,
                );
            }
            Err(e) => return Err(SigningError::CryptoError(e.to_string())),
        }
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
