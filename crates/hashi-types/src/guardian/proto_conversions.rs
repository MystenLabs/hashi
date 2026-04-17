// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// ---------------------------------
//    Protobuf RPC conversions
// ---------------------------------

use super::BitcoinSignature;
use super::Ciphertext;
use super::CommitteeSignatureWire;
use super::EncPubKey;
use super::EncryptedShare;
use super::GetGuardianInfoResponse;
use super::GuardianError;
use super::GuardianError::InvalidInputs;
use super::GuardianInfo;
use super::GuardianPubKey;
use super::GuardianResult;
use super::GuardianSignature;
use super::GuardianSigned;
use super::HashiCommittee;
use super::HashiCommitteeMember;
use super::HashiSigned;
use super::LimiterState;
use super::OperatorInitRequest;
use super::ProvisionerInitRequest;
use super::ProvisionerInitState;
use super::SetupNewKeyRequest;
use super::SetupNewKeyResponse;
use super::ShareCommitment;
use super::ShareCommitments;
use super::ShareID;
use super::SignedStandardWithdrawalRequestWire;
use super::StandardWithdrawalRequest;
use super::StandardWithdrawalRequestWire;
use super::StandardWithdrawalResponse;
use super::WithdrawalConfig;
use super::bitcoin_utils::ExternalOutputUTXOWire;
use super::bitcoin_utils::InputUTXOWire;
use super::bitcoin_utils::InternalOutputUTXO;
use super::bitcoin_utils::OutputUTXOWire;
use super::bitcoin_utils::TxUTXOsWire;
use crate::proto as pb;
use bitcoin::Address as BitcoinAddress;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::TapLeafHash;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash as _;
use hpke::Deserializable;
use hpke::Serializable;
use std::num::NonZeroU16;
use std::str::FromStr;

use crate::committee::DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS;
use crate::committee::DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS;
use crate::committee::DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA;

// --------------------------------------------
//      Proto -> Domain (deserialization)
// --------------------------------------------

impl TryFrom<pb::SetupNewKeyRequest> for SetupNewKeyRequest {
    type Error = GuardianError;

    fn try_from(req: pb::SetupNewKeyRequest) -> Result<Self, Self::Error> {
        let pks = req
            .key_provisioner_public_keys
            .iter()
            .map(|b| EncPubKey::from_bytes(b))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| InvalidInputs(format!("invalid key_provisioner_public_key: {e}")))?;

        SetupNewKeyRequest::new(pks)
    }
}

impl TryFrom<pb::SignedSetupNewKeyResponse> for GuardianSigned<SetupNewKeyResponse> {
    type Error = GuardianError;

    fn try_from(resp: pb::SignedSetupNewKeyResponse) -> Result<Self, Self::Error> {
        let signature_bytes = resp.signature.ok_or_else(|| missing("signature"))?;

        let signature = GuardianSignature::try_from(signature_bytes.as_ref())
            .map_err(|e| InvalidInputs(format!("invalid signature: {e}")))?;

        let data = resp.data.ok_or_else(|| missing("data"))?;

        let encrypted_shares: Vec<EncryptedShare> = data
            .encrypted_shares
            .iter()
            .map(|b| {
                Ok(EncryptedShare {
                    id: pb_to_share_id(b.id)?,
                    ciphertext: pb_to_ciphertext(b.ciphertext.clone())?,
                })
            })
            .collect::<GuardianResult<Vec<_>>>()?;

        let share_commitments = pb_share_commitments_to_domain(&data.share_commitments)?;

        let timestamp_ms = resp.timestamp_ms.ok_or_else(|| missing("timestamp_ms"))?;

        Ok(GuardianSigned {
            data: SetupNewKeyResponse {
                encrypted_shares,
                share_commitments,
            },
            timestamp_ms,
            signature,
        })
    }
}

impl TryFrom<pb::OperatorInitRequest> for OperatorInitRequest {
    type Error = GuardianError;

    fn try_from(req: pb::OperatorInitRequest) -> Result<Self, Self::Error> {
        let s3_config_pb = req.s3_config.ok_or_else(|| missing("s3_config"))?;
        let s3_config = pb_to_s3_config(s3_config_pb)?;

        let share_commitments = pb_share_commitments_to_domain(&req.share_commitments)?;

        let network = pb_to_network(req.network.ok_or_else(|| missing("network"))?)?;

        OperatorInitRequest::new(s3_config, share_commitments, network)
    }
}

impl TryFrom<pb::ProvisionerInitRequest> for ProvisionerInitRequest {
    type Error = GuardianError;

    fn try_from(req: pb::ProvisionerInitRequest) -> Result<Self, Self::Error> {
        // Encrypted share
        let encrypted_share_pb = req
            .encrypted_share
            .ok_or_else(|| missing("encrypted_share"))?;

        let encrypted_share = EncryptedShare {
            id: pb_to_share_id(encrypted_share_pb.id)?,
            ciphertext: pb_to_ciphertext(encrypted_share_pb.ciphertext)?,
        };

        // State
        let state_pb = req.state.ok_or_else(|| missing("state"))?;
        let state = ProvisionerInitState::try_from(state_pb)?;

        Ok(ProvisionerInitRequest::new(encrypted_share, state))
    }
}

impl TryFrom<pb::ProvisionerInitState> for ProvisionerInitState {
    type Error = GuardianError;

    fn try_from(state_pb: pb::ProvisionerInitState) -> Result<Self, Self::Error> {
        let committee_pb = state_pb.committee.ok_or_else(|| missing("committee"))?;
        let committee = pb_to_hashi_committee(committee_pb)?;

        let withdrawal_config_pb = state_pb
            .withdrawal_config
            .ok_or_else(|| missing("withdrawal_config"))?;
        let withdrawal_config = pb_to_withdrawal_config(withdrawal_config_pb)?;

        let limiter_state = pb_to_limiter_state(
            state_pb
                .limiter_state
                .ok_or_else(|| missing("limiter_state"))?,
        )?;

        let master_pk_bytes = state_pb
            .hashi_btc_master_pubkey
            .ok_or_else(|| missing("hashi_btc_master_pubkey"))?;

        let hashi_btc_master_pubkey = XOnlyPublicKey::from_slice(master_pk_bytes.as_ref())
            .map_err(|e| InvalidInputs(format!("invalid hashi_btc_master_pubkey: {e}")))?;

        ProvisionerInitState::new(
            committee,
            withdrawal_config,
            limiter_state,
            hashi_btc_master_pubkey,
        )
    }
}

impl TryFrom<pb::GetGuardianInfoResponse> for GetGuardianInfoResponse {
    type Error = GuardianError;

    fn try_from(resp: pb::GetGuardianInfoResponse) -> Result<Self, Self::Error> {
        let attestation = resp.attestation.ok_or_else(|| missing("attestation"))?;

        let signing_pub_key_bytes = resp
            .signing_pub_key
            .ok_or_else(|| missing("signing_pub_key"))?;
        let signing_pub_key = GuardianPubKey::try_from(signing_pub_key_bytes.as_ref())
            .map_err(|e| InvalidInputs(format!("invalid signing_pub_key: {e}")))?;

        let signed_info_pb = resp.signed_info.ok_or_else(|| missing("signed_info"))?;
        let signed_info = pb_to_signed_guardian_info(signed_info_pb)?;

        let limiter_state = resp.limiter_state.map(pb_to_limiter_state).transpose()?;

        Ok(GetGuardianInfoResponse {
            attestation: attestation.to_vec(),
            signing_pub_key,
            signed_info,
            limiter_state,
        })
    }
}

// TODO: Replace with TryFrom<> after moving it to hashi-types.
pub fn pb_to_signed_standard_withdrawal_request_wire(
    req: pb::SignedStandardWithdrawalRequest,
) -> GuardianResult<SignedStandardWithdrawalRequestWire> {
    let data = req.data.ok_or_else(|| missing("data"))?;
    let committee_signature_pb = req
        .committee_signature
        .ok_or_else(|| missing("committee_signature"))?;
    let (epoch, signature, bitmap) = pb_to_committee_signature(committee_signature_pb)?;

    let wid = data.wid.ok_or_else(|| missing("wid"))?;
    let utxos_pb = data.utxos.ok_or_else(|| missing("utxos"))?;
    let utxos_wire = pb_to_tx_utxos_wire(utxos_pb)?;
    let timestamp_secs = data
        .timestamp_secs
        .ok_or_else(|| missing("timestamp_secs"))?;
    let seq = data.seq.ok_or_else(|| missing("seq"))?;

    Ok(SignedStandardWithdrawalRequestWire {
        data: StandardWithdrawalRequestWire {
            wid,
            utxos: utxos_wire,
            timestamp_secs,
            seq,
        },
        signature: CommitteeSignatureWire {
            epoch,
            signature,
            bitmap,
        },
    })
}

impl TryFrom<pb::SignedStandardWithdrawalResponse> for GuardianSigned<StandardWithdrawalResponse> {
    type Error = GuardianError;

    fn try_from(resp: pb::SignedStandardWithdrawalResponse) -> Result<Self, Self::Error> {
        let data = resp.data.ok_or_else(|| missing("data"))?;
        let timestamp_ms = resp.timestamp_ms.ok_or_else(|| missing("timestamp_ms"))?;
        let signature_bytes = resp.signature.ok_or_else(|| missing("signature"))?;

        let signature = GuardianSignature::try_from(signature_bytes.as_ref())
            .map_err(|e| InvalidInputs(format!("invalid signature: {e}")))?;

        let enclave_signatures: Vec<BitcoinSignature> = data
            .enclave_signatures
            .iter()
            .map(|sig_bytes| {
                BitcoinSignature::from_slice(sig_bytes.as_ref())
                    .map_err(|e| InvalidInputs(format!("invalid bitcoin signature: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(GuardianSigned {
            data: StandardWithdrawalResponse { enclave_signatures },
            timestamp_ms,
            signature,
        })
    }
}

// ----------------------------------------------------------
//              Domain -> Proto (serialization)
// ----------------------------------------------------------

pub fn setup_new_key_response_signed_to_pb(
    s: GuardianSigned<SetupNewKeyResponse>,
) -> pb::SignedSetupNewKeyResponse {
    let signature = s.signature.to_bytes().to_vec();

    pb::SignedSetupNewKeyResponse {
        data: Some(setup_new_key_response_to_pb(s.data)),
        timestamp_ms: Some(s.timestamp_ms),
        signature: Some(signature.into()),
    }
}

pub fn setup_new_key_request_to_pb(s: SetupNewKeyRequest) -> pb::SetupNewKeyRequest {
    pb::SetupNewKeyRequest {
        key_provisioner_public_keys: s
            .public_keys()
            .iter()
            .map(|pk| pk.to_bytes().to_vec().into())
            .collect(),
    }
}

// Throws an error if network is invalid
pub fn operator_init_request_to_pb(
    r: OperatorInitRequest,
) -> GuardianResult<pb::OperatorInitRequest> {
    let (s3_config, share_commitments, network) = r.into_parts();
    Ok(pb::OperatorInitRequest {
        s3_config: Some(s3_config_to_pb(s3_config)),
        share_commitments: share_commitments
            .into_iter()
            .map(share_commitment_to_pb)
            .collect(),
        network: Some(network_to_pb(network)?),
    })
}

pub fn provisioner_init_request_to_pb(
    r: ProvisionerInitRequest,
) -> GuardianResult<pb::ProvisionerInitRequest> {
    Ok(pb::ProvisionerInitRequest {
        encrypted_share: Some(encrypted_share_to_pb(r.encrypted_share)),
        state: Some(provisioner_init_state_to_pb(r.state)),
    })
}

pub fn provisioner_init_state_to_pb(s: ProvisionerInitState) -> pb::ProvisionerInitState {
    let (committee, withdrawal_config, limiter_state, hashi_btc_master_pubkey) = s.into_parts();

    pb::ProvisionerInitState {
        committee: Some(hashi_committee_to_pb(committee)),
        withdrawal_config: Some(withdrawal_config_to_pb(withdrawal_config)),
        hashi_btc_master_pubkey: Some(hashi_btc_master_pubkey.serialize().to_vec().into()),
        limiter_state: Some(limiter_state_to_pb(limiter_state)),
    }
}

pub fn get_guardian_info_response_to_pb(r: GetGuardianInfoResponse) -> pb::GetGuardianInfoResponse {
    pb::GetGuardianInfoResponse {
        attestation: Some(r.attestation.into()),
        signing_pub_key: Some(r.signing_pub_key.to_bytes().to_vec().into()),
        signed_info: Some(signed_guardian_info_to_pb(r.signed_info)),
        limiter_state: r.limiter_state.map(limiter_state_to_pb),
    }
}

pub fn signed_standard_withdrawal_request_to_pb(
    req: &HashiSigned<StandardWithdrawalRequest>,
) -> pb::SignedStandardWithdrawalRequest {
    let data: StandardWithdrawalRequestWire = req.message().clone().into();

    pb::SignedStandardWithdrawalRequest {
        data: Some(standard_withdrawal_request_wire_to_pb(data)),
        committee_signature: Some(pb::CommitteeSignature {
            epoch: Some(req.epoch()),
            signature: Some(req.signature_bytes().to_vec().into()),
            bitmap: Some(req.signers_bitmap_bytes().to_vec().into()),
        }),
    }
}

pub fn standard_withdrawal_response_signed_to_pb(
    s: GuardianSigned<StandardWithdrawalResponse>,
) -> pb::SignedStandardWithdrawalResponse {
    let signature = s.signature.to_bytes().to_vec();

    pb::SignedStandardWithdrawalResponse {
        data: Some(pb::StandardWithdrawalResponseData {
            enclave_signatures: s
                .data
                .enclave_signatures
                .iter()
                .map(|sig| sig.to_vec().into())
                .collect(),
        }),
        timestamp_ms: Some(s.timestamp_ms),
        signature: Some(signature.into()),
    }
}

// ----------------------------------
//              Helpers
// ----------------------------------

fn missing(field: &str) -> GuardianError {
    InvalidInputs(format!("missing {field}"))
}

fn pb_to_committee_signature(s: pb::CommitteeSignature) -> GuardianResult<(u64, Vec<u8>, Vec<u8>)> {
    let epoch = s.epoch.ok_or_else(|| missing("epoch"))?;
    let signature_bytes = s.signature.ok_or_else(|| missing("signature"))?;
    let signer_bitmap_bytes = s.bitmap.ok_or_else(|| missing("signer_bitmap"))?;

    Ok((
        epoch,
        signature_bytes.to_vec(),
        signer_bitmap_bytes.to_vec(),
    ))
}

pub fn pb_share_commitments_to_domain(
    commitments: &[pb::GuardianShareCommitment],
) -> GuardianResult<ShareCommitments> {
    let commitments = commitments
        .iter()
        .map(|c| {
            let digest_hex = c.digest_hex.clone().ok_or_else(|| missing("digest_hex"))?;
            let digest = hex::decode(&digest_hex)
                .map_err(|e| InvalidInputs(format!("invalid digest_hex: {e}")))?;
            Ok(ShareCommitment {
                id: pb_to_share_id(c.id)?,
                digest,
            })
        })
        .collect::<GuardianResult<Vec<_>>>()?;

    ShareCommitments::new(commitments)
}

fn pb_to_s3_bucket_info(info: pb::S3BucketInfo) -> GuardianResult<super::S3BucketInfo> {
    let bucket = info.bucket.ok_or_else(|| missing("bucket"))?;
    let region = info.region.ok_or_else(|| missing("region"))?;
    Ok(super::S3BucketInfo { bucket, region })
}

fn s3_bucket_info_to_pb(info: super::S3BucketInfo) -> pb::S3BucketInfo {
    pb::S3BucketInfo {
        bucket: Some(info.bucket),
        region: Some(info.region),
    }
}

fn pb_to_guardian_info_data(data: pb::GuardianInfoData) -> GuardianResult<GuardianInfo> {
    let share_commitments = match data.share_commitments {
        None => None,
        Some(wrapper) => Some(pb_share_commitments_to_domain(&wrapper.share_commitments)?),
    };

    let bucket_info = data.bucket_info.map(pb_to_s3_bucket_info).transpose()?;

    let encryption_pubkey = data
        .encryption_pubkey
        .ok_or_else(|| missing("encryption_pubkey"))?
        .to_vec();

    let server_version = data
        .server_version
        .ok_or_else(|| missing("server_version"))?;

    Ok(GuardianInfo {
        share_commitments,
        bucket_info,
        encryption_pubkey,
        server_version,
    })
}

fn guardian_info_data_to_pb(info: GuardianInfo) -> pb::GuardianInfoData {
    pb::GuardianInfoData {
        share_commitments: info
            .share_commitments
            .map(|v| pb::GuardianShareCommitments {
                share_commitments: v.into_iter().map(share_commitment_to_pb).collect(),
            }),
        bucket_info: info.bucket_info.map(s3_bucket_info_to_pb),
        encryption_pubkey: Some(info.encryption_pubkey.into()),
        server_version: Some(info.server_version),
    }
}

fn pb_to_signed_guardian_info(
    s: pb::SignedGuardianInfo,
) -> GuardianResult<GuardianSigned<GuardianInfo>> {
    let data_pb = s.data.ok_or_else(|| missing("signed_info.data"))?;
    let timestamp_ms = s
        .timestamp_ms
        .ok_or_else(|| missing("signed_info.timestamp_ms"))?;
    let signature_bytes = s
        .signature
        .ok_or_else(|| missing("signed_info.signature"))?;

    let signature = GuardianSignature::try_from(signature_bytes.as_ref())
        .map_err(|e| InvalidInputs(format!("invalid signed_info.signature: {e}")))?;

    Ok(GuardianSigned {
        data: pb_to_guardian_info_data(data_pb)?,
        timestamp_ms,
        signature,
    })
}

fn signed_guardian_info_to_pb(s: GuardianSigned<GuardianInfo>) -> pb::SignedGuardianInfo {
    pb::SignedGuardianInfo {
        data: Some(guardian_info_data_to_pb(s.data)),
        timestamp_ms: Some(s.timestamp_ms),
        signature: Some(s.signature.to_bytes().to_vec().into()),
    }
}

fn pb_to_share_id(id_pb_opt: Option<pb::GuardianShareId>) -> GuardianResult<ShareID> {
    let id = id_pb_opt
        .ok_or_else(|| missing("id"))?
        .id
        .ok_or_else(|| missing("id"))?;

    // Cast down to u16
    let id = u16::try_from(id)
        .map_err(|_| InvalidInputs("invalid id: out of range for u16".to_string()))?;

    // Cast to NonZeroU16
    NonZeroU16::try_from(id).map_err(|e| InvalidInputs(format!("invalid id: {}", e)))
}

fn share_id_to_pb(id: ShareID) -> pb::GuardianShareId {
    pb::GuardianShareId {
        id: Some(id.get() as u32),
    }
}

fn pb_to_s3_config(cfg: pb::S3Config) -> GuardianResult<super::S3Config> {
    let access_key = cfg.access_key.ok_or_else(|| missing("access_key"))?;
    let secret_key = cfg.secret_key.ok_or_else(|| missing("secret_key"))?;
    let bucket_name = cfg.bucket_name.ok_or_else(|| missing("bucket_name"))?;
    let region = cfg.region.ok_or_else(|| missing("region"))?;

    Ok(super::S3Config {
        access_key: access_key.to_string(),
        secret_key: secret_key.to_string(),
        bucket_info: super::S3BucketInfo {
            bucket: bucket_name.to_string(),
            region: region.to_string(),
        },
    })
}

fn s3_config_to_pb(cfg: super::S3Config) -> pb::S3Config {
    pb::S3Config {
        access_key: Some(cfg.access_key),
        secret_key: Some(cfg.secret_key),
        bucket_name: Some(cfg.bucket_info.bucket),
        region: Some(cfg.bucket_info.region),
    }
}

fn pb_to_network(n: i32) -> GuardianResult<super::Network> {
    match pb::Network::try_from(n) {
        Ok(pb::Network::Mainnet) => Ok(super::Network::Bitcoin),
        Ok(pb::Network::Testnet) => Ok(super::Network::Testnet),
        Ok(pb::Network::Regtest) => Ok(super::Network::Regtest),
        Ok(pb::Network::Signet) => Ok(super::Network::Signet),
        Err(_) => Err(InvalidInputs(format!("invalid network: enum value {n}"))),
    }
}

fn network_to_pb(n: super::Network) -> GuardianResult<i32> {
    match n {
        super::Network::Bitcoin => Ok(pb::Network::Mainnet as i32),
        super::Network::Testnet => Ok(pb::Network::Testnet as i32),
        super::Network::Regtest => Ok(pb::Network::Regtest as i32),
        super::Network::Signet => Ok(pb::Network::Signet as i32),
        _ => Err(InvalidInputs(format!("invalid network: enum value {n}"))),
    }
}

fn pb_to_ciphertext(ciphertext_pb_opt: Option<pb::HpkeCiphertext>) -> GuardianResult<Ciphertext> {
    let ciphertext_pb = ciphertext_pb_opt.ok_or_else(|| missing("ciphertext"))?;

    let encapsulated_key = ciphertext_pb
        .encapsulated_key
        .ok_or_else(|| missing("encapsulated_key"))?;

    let aes_ciphertext = ciphertext_pb
        .aes_ciphertext
        .ok_or_else(|| missing("aes_ciphertext"))?;

    Ok(Ciphertext {
        encapsulated_key: encapsulated_key.to_vec(),
        aes_ciphertext: aes_ciphertext.to_vec(),
    })
}

fn ciphertext_to_pb(c: Ciphertext) -> pb::HpkeCiphertext {
    pb::HpkeCiphertext {
        encapsulated_key: Some(c.encapsulated_key.to_vec().into()),
        aes_ciphertext: Some(c.aes_ciphertext.to_vec().into()),
    }
}

pub fn encrypted_share_to_pb(s: EncryptedShare) -> pb::GuardianShareEncrypted {
    pb::GuardianShareEncrypted {
        id: Some(share_id_to_pb(s.id)),
        ciphertext: Some(ciphertext_to_pb(s.ciphertext)),
    }
}

pub fn share_commitment_to_pb(c: ShareCommitment) -> pb::GuardianShareCommitment {
    pb::GuardianShareCommitment {
        id: Some(share_id_to_pb(c.id)),
        digest_hex: Some(hex::encode(c.digest)),
    }
}

pub fn setup_new_key_response_to_pb(r: SetupNewKeyResponse) -> pb::SetupNewKeyResponseData {
    pb::SetupNewKeyResponseData {
        encrypted_shares: r
            .encrypted_shares
            .into_iter()
            .map(encrypted_share_to_pb)
            .collect(),
        share_commitments: r
            .share_commitments
            .into_iter()
            .map(share_commitment_to_pb)
            .collect(),
    }
}

fn pb_to_withdrawal_config(cfg: pb::WithdrawalConfig) -> GuardianResult<WithdrawalConfig> {
    let committee_threshold = cfg
        .committee_threshold
        .ok_or_else(|| missing("committee_threshold"))?;
    let refill_rate_sats_per_sec = cfg
        .refill_rate_sats_per_sec
        .ok_or_else(|| missing("refill_rate_sats_per_sec"))?;
    let max_bucket_capacity_sats = cfg
        .max_bucket_capacity_sats
        .ok_or_else(|| missing("max_bucket_capacity_sats"))?;

    Ok(WithdrawalConfig {
        committee_threshold,
        refill_rate_sats_per_sec,
        max_bucket_capacity_sats,
    })
}

fn withdrawal_config_to_pb(cfg: WithdrawalConfig) -> pb::WithdrawalConfig {
    pb::WithdrawalConfig {
        committee_threshold: Some(cfg.committee_threshold),
        refill_rate_sats_per_sec: Some(cfg.refill_rate_sats_per_sec),
        max_bucket_capacity_sats: Some(cfg.max_bucket_capacity_sats),
    }
}

fn pb_to_limiter_state(limiter: pb::LimiterState) -> GuardianResult<LimiterState> {
    let num_tokens_available = limiter
        .num_tokens_available_sats
        .ok_or_else(|| missing("num_tokens_available_sats"))?;
    let last_updated_at = limiter
        .last_updated_at_secs
        .ok_or_else(|| missing("last_updated_at_secs"))?;
    let next_seq = limiter.next_seq.ok_or_else(|| missing("next_seq"))?;

    Ok(LimiterState {
        num_tokens_available,
        last_updated_at,
        next_seq,
    })
}

fn limiter_state_to_pb(state: LimiterState) -> pb::LimiterState {
    pb::LimiterState {
        num_tokens_available_sats: Some(state.num_tokens_available),
        last_updated_at_secs: Some(state.last_updated_at),
        next_seq: Some(state.next_seq),
    }
}

fn pb_to_hashi_committee(c: pb::Committee) -> GuardianResult<HashiCommittee> {
    let epoch = c.epoch.ok_or_else(|| missing("epoch"))?;

    let members: Vec<HashiCommitteeMember> = c
        .members
        .into_iter()
        .map(pb_to_hashi_committee_member)
        .collect::<GuardianResult<Vec<_>>>()?;

    let total_weight = c.total_weight.ok_or_else(|| missing("total_weight"))?;

    let mpc_threshold_in_basis_points = c
        .mpc_threshold_in_basis_points
        .map(|v| v as u16)
        .unwrap_or(DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS);
    let mpc_weight_reduction_allowed_delta = c
        .mpc_weight_reduction_allowed_delta
        .map(|v| v as u16)
        .unwrap_or(DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA);
    let mpc_max_faulty_in_basis_points = c
        .mpc_max_faulty_in_basis_points
        .map(|v| v as u16)
        .unwrap_or(DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS);
    let committee = HashiCommittee::new(
        members,
        epoch,
        mpc_threshold_in_basis_points,
        mpc_weight_reduction_allowed_delta,
        mpc_max_faulty_in_basis_points,
    );

    if committee.total_weight() != total_weight {
        return Err(InvalidInputs(format!(
            "invalid total_weight: expected {total_weight}, computed {}",
            committee.total_weight()
        )));
    }

    Ok(committee)
}

fn hashi_committee_to_pb(c: HashiCommittee) -> pb::Committee {
    pb::Committee {
        epoch: Some(c.epoch()),
        members: c
            .members()
            .iter()
            .map(|m| hashi_committee_member_to_pb(m.clone()))
            .collect(),
        total_weight: Some(c.total_weight()),
        mpc_threshold_in_basis_points: Some(c.mpc_threshold_in_basis_points() as u64),
        mpc_weight_reduction_allowed_delta: Some(c.mpc_weight_reduction_allowed_delta() as u64),
        mpc_max_faulty_in_basis_points: Some(c.mpc_max_faulty_in_basis_points() as u64),
    }
}

fn pb_to_hashi_committee_member(m: pb::CommitteeMember) -> GuardianResult<HashiCommitteeMember> {
    let address = m.address.ok_or_else(|| missing("address"))?;
    let validator_address = sui_sdk_types::Address::from_str(&address)
        .map_err(|e| InvalidInputs(format!("invalid address: {e}")))?;

    let public_key = m.public_key.ok_or_else(|| missing("public_key"))?;
    let encryption_public_key = m
        .encryption_public_key
        .ok_or_else(|| missing("encryption_public_key"))?;

    let weight = m.weight.ok_or_else(|| missing("weight"))?;

    let x = crate::move_types::CommitteeMember {
        validator_address,
        public_key: public_key.to_vec(),
        encryption_public_key: encryption_public_key.to_vec(),
        weight,
    };

    HashiCommitteeMember::try_from(x)
        .map_err(|e| InvalidInputs(format!("invalid committee member: {e}")))
}

fn hashi_committee_member_to_pb(m: HashiCommitteeMember) -> pb::CommitteeMember {
    let x = crate::move_types::CommitteeMember::from(&m);
    pb::CommitteeMember {
        address: Some(x.validator_address.to_string()),
        public_key: Some(x.public_key.into()),
        encryption_public_key: Some(x.encryption_public_key.into()),
        weight: Some(x.weight),
    }
}

// -----------------------------------------
//    Standard Withdrawal Helper Functions
// -----------------------------------------

fn pb_to_tx_utxos_wire(utxos_pb: pb::TxUtxos) -> GuardianResult<TxUTXOsWire> {
    let inputs = utxos_pb
        .inputs
        .into_iter()
        .map(pb_to_input_utxo_wire)
        .collect::<GuardianResult<Vec<_>>>()?;

    let outputs = utxos_pb
        .outputs
        .into_iter()
        .map(pb_to_output_utxo_wire)
        .collect::<GuardianResult<Vec<_>>>()?;

    Ok(TxUTXOsWire { inputs, outputs })
}

fn pb_to_input_utxo_wire(input_pb: pb::InputUtxo) -> GuardianResult<InputUTXOWire> {
    let outpoint_pb = input_pb.outpoint.ok_or_else(|| missing("outpoint"))?;
    let txid_bytes = outpoint_pb.txid.ok_or_else(|| missing("txid"))?;
    let vout = outpoint_pb.vout.ok_or_else(|| missing("vout"))?;

    let txid = Txid::from_slice(txid_bytes.as_ref())
        .map_err(|e| InvalidInputs(format!("invalid txid: {e}")))?;
    let outpoint = OutPoint { txid, vout };

    let amount = input_pb.amount.ok_or_else(|| missing("amount"))?;
    let address_str = input_pb.address.ok_or_else(|| missing("address"))?;
    let address = BitcoinAddress::<NetworkUnchecked>::from_str(&address_str)
        .map_err(|e| InvalidInputs(format!("invalid address: {e}")))?;

    let leaf_hash_bytes = input_pb.leaf_hash.ok_or_else(|| missing("leaf_hash"))?;
    let leaf_hash = TapLeafHash::from_slice(leaf_hash_bytes.as_ref())
        .map_err(|e| InvalidInputs(format!("invalid leaf_hash: {e}")))?;

    Ok(InputUTXOWire {
        outpoint,
        amount: Amount::from_sat(amount),
        address,
        leaf_hash,
    })
}

fn pb_to_output_utxo_wire(output_pb: pb::OutputUtxo) -> GuardianResult<OutputUTXOWire> {
    let output = output_pb.output.ok_or_else(|| missing("output"))?;

    match output {
        pb::output_utxo::Output::External(ext) => {
            let address_str = ext.address.ok_or_else(|| missing("address"))?;
            let address = BitcoinAddress::<NetworkUnchecked>::from_str(&address_str)
                .map_err(|e| InvalidInputs(format!("invalid address: {e}")))?;
            let amount = ext.amount.ok_or_else(|| missing("amount"))?;

            Ok(OutputUTXOWire::External(ExternalOutputUTXOWire {
                address,
                amount: Amount::from_sat(amount),
            }))
        }
        pb::output_utxo::Output::Internal(int) => {
            let derivation_path_bytes = int
                .derivation_path
                .ok_or_else(|| missing("derivation_path"))?;
            let derivation_path: [u8; 32] = derivation_path_bytes
                .as_ref()
                .try_into()
                .map_err(|_| InvalidInputs("invalid derivation_path: expected 32 bytes".into()))?;
            let amount = int.amount.ok_or_else(|| missing("amount"))?;

            Ok(OutputUTXOWire::Internal(InternalOutputUTXO::new(
                derivation_path,
                Amount::from_sat(amount),
            )))
        }
    }
}

pub fn standard_withdrawal_request_wire_to_pb(
    req: StandardWithdrawalRequestWire,
) -> pb::StandardWithdrawalRequestData {
    pb::StandardWithdrawalRequestData {
        wid: Some(req.wid),
        utxos: Some(tx_utxos_wire_to_pb(req.utxos)),
        timestamp_secs: Some(req.timestamp_secs),
        seq: Some(req.seq),
    }
}

fn tx_utxos_wire_to_pb(utxos: TxUTXOsWire) -> pb::TxUtxos {
    pb::TxUtxos {
        inputs: utxos
            .inputs
            .into_iter()
            .map(input_utxo_wire_to_pb)
            .collect(),
        outputs: utxos
            .outputs
            .into_iter()
            .map(output_utxo_wire_to_pb)
            .collect(),
    }
}

fn input_utxo_wire_to_pb(input: InputUTXOWire) -> pb::InputUtxo {
    pb::InputUtxo {
        outpoint: Some(pb::UtxoId {
            txid: Some(input.outpoint.txid.as_byte_array().to_vec().into()),
            vout: Some(input.outpoint.vout),
        }),
        amount: Some(input.amount.to_sat()),
        address: Some(input.address.assume_checked_ref().to_string()),
        leaf_hash: Some(input.leaf_hash.as_byte_array().to_vec().into()),
    }
}

fn output_utxo_wire_to_pb(output: OutputUTXOWire) -> pb::OutputUtxo {
    let output_enum = match output {
        OutputUTXOWire::External(ext) => {
            pb::output_utxo::Output::External(pb::ExternalOutputUtxo {
                address: Some(ext.address.assume_checked_ref().to_string()),
                amount: Some(ext.amount.to_sat()),
            })
        }
        OutputUTXOWire::Internal(int) => {
            pb::output_utxo::Output::Internal(pb::InternalOutputUtxo {
                derivation_path: Some(int.derivation_path_bytes().to_vec().into()),
                amount: Some(int.amount().to_sat()),
            })
        }
    };

    pb::OutputUtxo {
        output: Some(output_enum),
    }
}

#[cfg(test)]
mod tests {
    use super::super::AddressValidation;
    use super::super::StandardWithdrawalRequest;
    use super::*;
    use bitcoin::Network;

    #[test]
    fn get_guardian_info_response_round_trip() {
        let resp = GetGuardianInfoResponse::mock_for_testing();
        let pb = get_guardian_info_response_to_pb(resp.clone());
        let back = GetGuardianInfoResponse::try_from(pb).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn setup_new_key_request_round_trip() {
        let req = SetupNewKeyRequest::mock_for_testing();
        let pb = setup_new_key_request_to_pb(req.clone());
        let back = SetupNewKeyRequest::try_from(pb).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn setup_new_key_response_round_trip() {
        let resp = GuardianSigned::<SetupNewKeyResponse>::mock_for_testing();
        let pb = setup_new_key_response_signed_to_pb(resp.clone());
        let back = GuardianSigned::<SetupNewKeyResponse>::try_from(pb).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn operator_init_request_round_trip() {
        let req = OperatorInitRequest::mock_for_testing();
        let pb = operator_init_request_to_pb(req.clone()).unwrap();
        let back = OperatorInitRequest::try_from(pb).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn provisioner_init_request_round_trip() {
        let req = ProvisionerInitRequest::mock_for_testing();
        let pb = provisioner_init_request_to_pb(req.clone()).unwrap();
        let back = ProvisionerInitRequest::try_from(pb).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn standard_withdrawal_request_round_trip() {
        // 1) Create mock *domain* request and sign it.
        let signed_domain = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);

        // 2) Convert to pb.
        let signed_pb = signed_standard_withdrawal_request_to_pb(&signed_domain);

        // 3) Convert back from pb -> wire.
        let signed_wire = pb_to_signed_standard_withdrawal_request_wire(signed_pb).unwrap();

        // 4) Convert wire -> HashiSigned<StandardWithdrawalRequest> using AddressValidation.
        let signed_back =
            HashiSigned::<StandardWithdrawalRequest>::validate_addr(signed_wire, Network::Regtest)
                .unwrap();

        // 5) Compare the signed messages by their canonical bytes.
        assert_eq!(signed_domain.epoch(), signed_back.epoch());
        assert_eq!(
            signed_domain.signature_bytes(),
            signed_back.signature_bytes()
        );
        assert_eq!(
            signed_domain.signers_bitmap_bytes(),
            signed_back.signers_bitmap_bytes()
        );
        assert_eq!(signed_domain.message(), signed_back.message());
    }

    #[test]
    fn standard_withdrawal_response_round_trip() {
        let resp = GuardianSigned::<StandardWithdrawalResponse>::mock_for_testing();
        let pb = standard_withdrawal_response_signed_to_pb(resp.clone());
        let back = GuardianSigned::<StandardWithdrawalResponse>::try_from(pb).unwrap();
        assert_eq!(resp, back);
    }
}
