use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
use fastcrypto_tbls::threshold_schnorr::Address as DerivationAddress;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::S;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::presigning::Presignatures;
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
        aggregate_signatures(
            message,
            &public_nonce,
            beacon_value,
            &all_partial_sigs,
            threshold,
            &verifying_key,
            derivation_address,
        )
        .map_err(|e| SigningError::CryptoError(e.to_string()))
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
}
