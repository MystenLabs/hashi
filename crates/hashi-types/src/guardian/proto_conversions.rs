// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// ---------------------------------
//    Protobuf RPC conversions
// ---------------------------------

use super::BuildPcrs;
use super::Ciphertext;
use super::CommitteeTransitionRequest;
use super::GetGuardianInfoResponse;
use super::GuardianEncryptedShare;
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
use super::InitConfig;
use super::KPEncryptedShare;
use super::KPEncryptedShares;
use super::KpSigned;
use super::LimiterConfig;
use super::LimiterState;
use super::NitroAttestation;
use super::OperatorActivateRequest;
use super::OperatorInitRequest;
use super::OperatorWriteGenesisRequest;
use super::PcrAllowlist;
use super::ProvisionerInitRequest;
use super::RotateKpsRequest;
use super::RotateKpsResponse;
use super::RotateKpsState;
use super::SecretSharingInstance;
use super::SetupNewKeyRequest;
use super::SetupNewKeyResponse;
use super::ShareCommitment;
use super::ShareCommitments;
use super::ShareID;
use super::SignedStandardWithdrawalRequestWire;
use super::SingleProvisionerInitRequest;
use super::StandardWithdrawalRequest;
use super::StandardWithdrawalRequestWire;
use super::StandardWithdrawalResponse;
use crate::bitcoin::BitcoinAddress;
use crate::bitcoin::BitcoinPubkey;
use crate::bitcoin::BitcoinSignature;
use crate::bitcoin::DerivationPath;
use crate::bitcoin::ExternalOutputUTXOWire;
use crate::bitcoin::HashiMasterG;
use crate::bitcoin::InputUTXO;
use crate::bitcoin::InternalOutputUTXO;
use crate::bitcoin::OutputUTXOWire;
use crate::bitcoin::TxUTXOsWire;
use crate::move_types::CommitteeSignature;
use crate::pgp::PgpPublicCert;
use crate::proto as pb;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Txid;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash as _;
use fastcrypto::serde_helpers::ToFromByteArray;
use std::num::NonZeroU16;
use std::str::FromStr;

use crate::move_types::Config;

// --------------------------------------------
//      Proto -> Domain (deserialization)
// --------------------------------------------

fn pb_to_kp_encrypted_share(pb: pb::KpEncryptedShare) -> GuardianResult<KPEncryptedShare> {
    Ok(KPEncryptedShare {
        id: pb_to_share_id(pb.id)?,
        recipient_fingerprint: pb
            .recipient_fingerprint
            .ok_or_else(|| missing("recipient_fingerprint"))?,
        armored_ciphertext: pb
            .armored_ciphertext
            .ok_or_else(|| missing("armored_ciphertext"))?,
    })
}

pub fn pb_to_guardian_encrypted_share(
    pb: pb::GuardianEncryptedShare,
) -> GuardianResult<GuardianEncryptedShare> {
    Ok(GuardianEncryptedShare {
        id: pb_to_share_id(pb.id)?,
        ciphertext: pb_to_ciphertext(pb.ciphertext)?,
    })
}

impl TryFrom<pb::SetupNewKeyRequest> for SetupNewKeyRequest {
    type Error = GuardianError;

    fn try_from(req: pb::SetupNewKeyRequest) -> Result<Self, Self::Error> {
        let certs = req
            .key_provisioner_pgp_certs
            .iter()
            .cloned()
            .map(|cert| PgpPublicCert::new(cert).map_err(|e| InvalidInputs(e.to_string())))
            .collect::<GuardianResult<Vec<_>>>()?;

        let num_shares = req.num_shares.ok_or_else(|| missing("num_shares"))? as usize;
        let threshold = req.threshold.ok_or_else(|| missing("threshold"))? as usize;

        SetupNewKeyRequest::new(certs, num_shares, threshold)
    }
}

impl TryFrom<pb::SignedSetupNewKeyResponse> for GuardianSigned<SetupNewKeyResponse> {
    type Error = GuardianError;

    fn try_from(resp: pb::SignedSetupNewKeyResponse) -> Result<Self, Self::Error> {
        let signature_bytes = resp.signature.ok_or_else(|| missing("signature"))?;

        let signature = GuardianSignature::try_from(signature_bytes.as_ref())
            .map_err(|e| InvalidInputs(format!("invalid signature: {e}")))?;

        let data = resp.data.ok_or_else(|| missing("data"))?;

        let encrypted_shares = data
            .encrypted_shares
            .into_iter()
            .map(pb_to_kp_encrypted_share)
            .collect::<GuardianResult<Vec<_>>>()?;
        let encrypted_shares = KPEncryptedShares::new(encrypted_shares)?;

        let secret_sharing_instance = pb_to_secret_sharing_instance(
            data.secret_sharing_instance
                .ok_or_else(|| missing("secret_sharing_instance"))?,
        )?;

        let btc_master_pubkey = BitcoinPubkey::from_slice(data.btc_master_pubkey.as_ref())
            .map_err(|e| InvalidInputs(format!("invalid btc_master_pubkey: {e}")))?;

        let timestamp_ms = resp.timestamp_ms.ok_or_else(|| missing("timestamp_ms"))?;

        Ok(GuardianSigned {
            data: SetupNewKeyResponse {
                encrypted_shares,
                secret_sharing_instance,
                btc_master_pubkey,
            },
            timestamp_ms,
            signature,
        })
    }
}

impl TryFrom<pb::OperatorInitRequest> for OperatorInitRequest {
    type Error = GuardianError;

    fn try_from(req: pb::OperatorInitRequest) -> Result<Self, Self::Error> {
        let s3_config = pb_to_s3_config(req.s3_config.ok_or_else(|| missing("s3_config"))?)?;
        // `init_config` present ⇔ withdraw mode; absent ⇔ ceremony (S3 only).
        match req.init_config.map(InitConfig::try_from).transpose()? {
            Some(init_config) => Ok(OperatorInitRequest::new_withdraw_mode(
                s3_config,
                init_config,
            )),
            None => Ok(OperatorInitRequest::new_ceremony_mode(s3_config)),
        }
    }
}

impl TryFrom<pb::OperatorActivateRequest> for OperatorActivateRequest {
    type Error = GuardianError;

    fn try_from(req: pb::OperatorActivateRequest) -> Result<Self, Self::Error> {
        let expected_state_hash = req
            .expected_state_hash
            .ok_or_else(|| missing("expected_state_hash"))?;
        let expected_state_hash = <[u8; 32]>::try_from(expected_state_hash.as_ref())
            .map_err(|_| InvalidInputs("expected_state_hash must be 32 bytes".into()))?;
        Ok(OperatorActivateRequest::new(expected_state_hash))
    }
}

impl TryFrom<pb::OperatorWriteGenesisRequest> for OperatorWriteGenesisRequest {
    type Error = GuardianError;

    fn try_from(req: pb::OperatorWriteGenesisRequest) -> Result<Self, Self::Error> {
        let committee_pb = req.committee.ok_or_else(|| missing("committee"))?;
        Ok(OperatorWriteGenesisRequest::from_move_committee(
            pb_to_move_committee(committee_pb)?,
        ))
    }
}

pub fn pb_to_secret_sharing_instance(
    pb: pb::SecretSharingInstance,
) -> GuardianResult<SecretSharingInstance> {
    let commitments = pb_share_commitments_to_domain(&pb.commitments)?;
    let num_shares = pb.num_shares.ok_or_else(|| missing("num_shares"))? as usize;
    let threshold = pb.threshold.ok_or_else(|| missing("threshold"))? as usize;
    let sharing_seq = pb.sharing_seq.ok_or_else(|| missing("sharing_seq"))?;
    SecretSharingInstance::new(commitments, num_shares, threshold, sharing_seq)
}

pub fn secret_sharing_instance_to_pb(
    instance: &SecretSharingInstance,
) -> pb::SecretSharingInstance {
    pb::SecretSharingInstance {
        commitments: instance
            .commitments()
            .iter()
            .map(share_commitment_to_pb)
            .collect(),
        num_shares: Some(instance.num_shares() as u32),
        threshold: Some(instance.threshold() as u32),
        sharing_seq: Some(instance.sharing_seq()),
    }
}

impl TryFrom<pb::ProvisionerInitRequest> for ProvisionerInitRequest {
    type Error = GuardianError;

    fn try_from(req: pb::ProvisionerInitRequest) -> Result<Self, Self::Error> {
        let encrypted_shares = req
            .encrypted_shares
            .into_iter()
            .map(pb_to_guardian_encrypted_share)
            .collect::<GuardianResult<Vec<_>>>()?;

        Ok(ProvisionerInitRequest::new(encrypted_shares))
    }
}

impl TryFrom<pb::SignedSingleProvisionerInitRequest> for KpSigned<SingleProvisionerInitRequest> {
    type Error = GuardianError;

    fn try_from(req: pb::SignedSingleProvisionerInitRequest) -> Result<Self, Self::Error> {
        if req.expected_session_id.is_empty() {
            return Err(missing("expected_session_id"));
        }
        if req.signer_cert.is_empty() {
            return Err(missing("signer_cert"));
        }
        if req.kp_signature.is_empty() {
            return Err(missing("kp_signature"));
        }
        let encrypted_share = pb_to_guardian_encrypted_share(
            req.encrypted_share
                .ok_or_else(|| missing("encrypted_share"))?,
        )?;
        let signer_cert =
            PgpPublicCert::new(req.signer_cert).map_err(|e| InvalidInputs(e.to_string()))?;
        let request = SingleProvisionerInitRequest::new(req.expected_session_id, encrypted_share);
        Ok(KpSigned {
            data: request,
            signer_cert,
            signature: req.kp_signature,
        })
    }
}

impl TryFrom<pb::RotateKpsRequest> for RotateKpsRequest {
    type Error = GuardianError;

    fn try_from(req: pb::RotateKpsRequest) -> Result<Self, Self::Error> {
        let encrypted_old_shares = req
            .encrypted_old_shares
            .into_iter()
            .map(pb_to_guardian_encrypted_share)
            .collect::<GuardianResult<Vec<_>>>()?;

        let new_num_shares = req
            .new_num_shares
            .ok_or_else(|| missing("new_num_shares"))? as usize;
        let new_threshold = req.new_threshold.ok_or_else(|| missing("new_threshold"))? as usize;

        let new_kp_pgp_certs = req
            .new_kp_pgp_certs
            .into_iter()
            .map(|cert| PgpPublicCert::new(cert).map_err(|e| InvalidInputs(e.to_string())))
            .collect::<GuardianResult<Vec<_>>>()?;
        let state = RotateKpsState::new(new_kp_pgp_certs, new_num_shares, new_threshold)?;

        let old_instance = pb_to_secret_sharing_instance(
            req.old_instance.ok_or_else(|| missing("old_instance"))?,
        )?;

        Ok(RotateKpsRequest::new(
            encrypted_old_shares,
            old_instance,
            state,
        ))
    }
}

impl TryFrom<pb::SignedRotateKpsResponse> for GuardianSigned<RotateKpsResponse> {
    type Error = GuardianError;

    fn try_from(resp: pb::SignedRotateKpsResponse) -> Result<Self, Self::Error> {
        let signature_bytes = resp.signature.ok_or_else(|| missing("signature"))?;
        let signature = GuardianSignature::try_from(signature_bytes.as_ref())
            .map_err(|e| InvalidInputs(format!("invalid signature: {e}")))?;

        let data = resp.data.ok_or_else(|| missing("data"))?;
        let encrypted_shares = data
            .encrypted_shares
            .into_iter()
            .map(pb_to_kp_encrypted_share)
            .collect::<GuardianResult<Vec<_>>>()?;
        let encrypted_shares = KPEncryptedShares::new(encrypted_shares)?;

        let timestamp_ms = resp.timestamp_ms.ok_or_else(|| missing("timestamp_ms"))?;

        Ok(GuardianSigned {
            data: RotateKpsResponse { encrypted_shares },
            timestamp_ms,
            signature,
        })
    }
}

impl TryFrom<pb::BuildPcrs> for BuildPcrs {
    type Error = GuardianError;

    fn try_from(build_pb: pb::BuildPcrs) -> Result<Self, Self::Error> {
        let git_revision = build_pb
            .git_revision
            .ok_or_else(|| missing("git_revision"))?;
        let pcr0 = build_pb.pcr0.ok_or_else(|| missing("pcr0"))?.to_vec();
        Ok(BuildPcrs::new(&git_revision, pcr0))
    }
}

impl TryFrom<pb::PcrAllowlist> for PcrAllowlist {
    type Error = GuardianError;

    fn try_from(allowlist_pb: pb::PcrAllowlist) -> Result<Self, Self::Error> {
        let current_build = BuildPcrs::try_from(
            allowlist_pb
                .current_build
                .ok_or_else(|| missing("current_build"))?,
        )?;
        let prev_builds = allowlist_pb
            .prev_builds
            .into_iter()
            .map(BuildPcrs::try_from)
            .collect::<GuardianResult<Vec<_>>>()?;
        PcrAllowlist::new(current_build, prev_builds)
    }
}

impl TryFrom<pb::InitConfig> for InitConfig {
    type Error = GuardianError;

    fn try_from(config_pb: pb::InitConfig) -> Result<Self, Self::Error> {
        let limiter_config_pb = config_pb
            .limiter_config
            .ok_or_else(|| missing("limiter_config"))?;
        let limiter_config = pb_to_limiter_config(limiter_config_pb)?;

        let master_pk_bytes = config_pb
            .hashi_btc_master_pubkey
            .ok_or_else(|| missing("hashi_btc_master_pubkey"))?;

        let master_pk_bytes_arr: [u8; 33] = master_pk_bytes.as_ref().try_into().map_err(|_| {
            InvalidInputs(format!(
                "hashi_btc_master_pubkey must be 33 bytes (compressed), got {}",
                master_pk_bytes.len()
            ))
        })?;
        let hashi_btc_master_pubkey = HashiMasterG::from_byte_array(&master_pk_bytes_arr)
            .map_err(|e| InvalidInputs(format!("invalid hashi_btc_master_pubkey: {e:?}")))?;

        let pcr_allowlist = PcrAllowlist::try_from(
            config_pb
                .pcr_allowlist
                .ok_or_else(|| missing("pcr_allowlist"))?,
        )?;

        let network = pb_to_network(config_pb.network.ok_or_else(|| missing("network"))?)?;

        InitConfig::new(
            limiter_config,
            hashi_btc_master_pubkey,
            pcr_allowlist,
            network,
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

        let encrypted_shares = resp
            .encrypted_shares
            .into_iter()
            .map(pb_to_kp_encrypted_share)
            .collect::<GuardianResult<Vec<_>>>()?;
        let encrypted_shares = KPEncryptedShares::new(encrypted_shares)?;

        Ok(GetGuardianInfoResponse::new(
            NitroAttestation::new(attestation.to_vec()),
            signing_pub_key,
            signed_info,
            encrypted_shares,
        ))
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

    let wid_bytes = data.wid.ok_or_else(|| missing("wid"))?;
    let wid = super::WithdrawalID::from_bytes(wid_bytes.as_ref())
        .map_err(|_| InvalidInputs(format!("wid must be 32 bytes, got {}", wid_bytes.len())))?;
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
        signature: CommitteeSignature {
            epoch,
            signature,
            signers_bitmap: bitmap,
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

pub fn rotate_kps_response_signed_to_pb(
    s: GuardianSigned<RotateKpsResponse>,
) -> pb::SignedRotateKpsResponse {
    let signature = s.signature.to_bytes().to_vec();

    pb::SignedRotateKpsResponse {
        data: Some(pb::RotateKpsResponseData {
            encrypted_shares: s
                .data
                .encrypted_shares
                .into_vec()
                .into_iter()
                .map(kp_encrypted_share_to_pb)
                .collect(),
        }),
        timestamp_ms: Some(s.timestamp_ms),
        signature: Some(signature.into()),
    }
}

pub fn setup_new_key_request_to_pb(s: SetupNewKeyRequest) -> pb::SetupNewKeyRequest {
    pb::SetupNewKeyRequest {
        key_provisioner_pgp_certs: s
            .pgp_certs()
            .iter()
            .map(|cert| cert.armored().to_string())
            .collect(),
        num_shares: Some(s.num_shares() as u32),
        threshold: Some(s.threshold() as u32),
    }
}

// Throws an error if network is invalid
pub fn operator_init_request_to_pb(
    r: OperatorInitRequest,
) -> GuardianResult<pb::OperatorInitRequest> {
    let (s3_config, init_config) = r.into_parts();
    Ok(pb::OperatorInitRequest {
        s3_config: Some(s3_config_to_pb(s3_config)),
        init_config: init_config.map(init_config_to_pb).transpose()?,
    })
}

pub fn operator_activate_request_to_pb(r: OperatorActivateRequest) -> pb::OperatorActivateRequest {
    pb::OperatorActivateRequest {
        expected_state_hash: Some(r.expected_state_hash().to_vec().into()),
    }
}

pub fn operator_write_genesis_request_to_pb(
    r: OperatorWriteGenesisRequest,
) -> pb::OperatorWriteGenesisRequest {
    pb::OperatorWriteGenesisRequest {
        committee: Some(move_committee_to_pb(&r.into_committee())),
    }
}

pub fn provisioner_init_request_to_pb(
    r: ProvisionerInitRequest,
) -> GuardianResult<pb::ProvisionerInitRequest> {
    Ok(pb::ProvisionerInitRequest {
        encrypted_shares: r
            .into_parts()
            .into_iter()
            .map(guardian_encrypted_share_to_pb)
            .collect(),
    })
}

impl From<KpSigned<SingleProvisionerInitRequest>> for pb::SignedSingleProvisionerInitRequest {
    fn from(r: KpSigned<SingleProvisionerInitRequest>) -> Self {
        let KpSigned {
            data: request,
            signer_cert,
            signature,
        } = r;
        let (expected_session_id, encrypted_share) = request.into_parts();
        Self {
            encrypted_share: Some(guardian_encrypted_share_to_pb(encrypted_share)),
            expected_session_id,
            signer_cert: signer_cert.armored().to_string(),
            kp_signature: signature,
        }
    }
}

// Throws an error if network is invalid.
pub fn init_config_to_pb(s: InitConfig) -> GuardianResult<pb::InitConfig> {
    let (limiter_config, hashi_btc_master_pubkey, pcr_allowlist, network) = s.into_parts();

    Ok(pb::InitConfig {
        limiter_config: Some(limiter_config_to_pb(limiter_config)),
        hashi_btc_master_pubkey: Some(hashi_btc_master_pubkey.to_byte_array().to_vec().into()),
        pcr_allowlist: Some(pcr_allowlist_to_pb(pcr_allowlist)),
        network: Some(network_to_pb(network)?),
    })
}

fn build_pcrs_to_pb(build: BuildPcrs) -> pb::BuildPcrs {
    pb::BuildPcrs {
        git_revision: Some(build.git_revision().to_string()),
        pcr0: Some(build.pcr0().to_vec().into()),
    }
}

fn pcr_allowlist_to_pb(allowlist: PcrAllowlist) -> pb::PcrAllowlist {
    let current_build = allowlist.current_build().clone();
    let prev_builds = allowlist.prev_builds().to_vec();
    pb::PcrAllowlist {
        current_build: Some(build_pcrs_to_pb(current_build)),
        prev_builds: prev_builds.into_iter().map(build_pcrs_to_pb).collect(),
    }
}

pub fn rotate_kps_request_to_pb(r: RotateKpsRequest) -> pb::RotateKpsRequest {
    let (encrypted_old_shares, old_instance, state) = r.into_parts();
    let (new_kp_pgp_certs, new_params) = state.into_parts();
    pb::RotateKpsRequest {
        encrypted_old_shares: encrypted_old_shares
            .into_iter()
            .map(guardian_encrypted_share_to_pb)
            .collect(),
        new_kp_pgp_certs: new_kp_pgp_certs
            .into_iter()
            .map(|cert| cert.armored().to_string())
            .collect(),
        new_num_shares: Some(new_params.num_shares() as u32),
        new_threshold: Some(new_params.threshold() as u32),
        old_instance: Some(secret_sharing_instance_to_pb(&old_instance)),
    }
}

pub fn get_guardian_info_response_to_pb(r: GetGuardianInfoResponse) -> pb::GetGuardianInfoResponse {
    pb::GetGuardianInfoResponse {
        attestation: Some(r.attestation.into_bytes().into()),
        signing_pub_key: Some(r.signing_pub_key.to_bytes().to_vec().into()),
        signed_info: Some(signed_guardian_info_to_pb(r.signed_info)),
        encrypted_shares: r
            .encrypted_shares
            .into_vec()
            .into_iter()
            .map(kp_encrypted_share_to_pb)
            .collect(),
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
    let secret_sharing_instance = data
        .secret_sharing_instance
        .map(pb_to_secret_sharing_instance)
        .transpose()?;

    let bucket_info = data.bucket_info.map(pb_to_s3_bucket_info).transpose()?;

    let encryption_pubkey = data
        .encryption_pubkey
        .ok_or_else(|| missing("encryption_pubkey"))?
        .to_vec();

    let untrusted_git_revision = data
        .untrusted_git_revision
        .ok_or_else(|| missing("untrusted_git_revision"))?;

    let config_hash = data
        .config_hash
        .map(|b| {
            <[u8; 32]>::try_from(b.as_ref())
                .map_err(|_| InvalidInputs("config_hash must be 32 bytes".into()))
        })
        .transpose()?;

    let enclave_btc_pubkey = data
        .enclave_btc_pubkey
        .map(|bytes| {
            BitcoinPubkey::from_slice(bytes.as_ref())
                .map_err(|e| InvalidInputs(format!("invalid enclave_btc_pubkey: {e}")))
        })
        .transpose()?;

    let limiter_state = data.limiter_state.map(pb_to_limiter_state).transpose()?;
    let limiter_config = data.limiter_config.map(pb_to_limiter_config).transpose()?;

    let mpc_master_g = data
        .mpc_master_g
        .map(|b| {
            bcs::from_bytes(b.as_ref())
                .map_err(|e| InvalidInputs(format!("invalid mpc_master_g: {e}")))
        })
        .transpose()?;

    Ok(GuardianInfo {
        secret_sharing_instance,
        bucket_info,
        encryption_pubkey,
        config_hash,
        untrusted_git_revision,
        enclave_btc_pubkey,
        limiter_state,
        limiter_config,
        current_committee_epoch: data.current_committee_epoch,
        mpc_master_g,
    })
}

fn guardian_info_data_to_pb(info: GuardianInfo) -> pb::GuardianInfoData {
    pb::GuardianInfoData {
        secret_sharing_instance: info
            .secret_sharing_instance
            .as_ref()
            .map(secret_sharing_instance_to_pb),
        bucket_info: info.bucket_info.map(s3_bucket_info_to_pb),
        encryption_pubkey: Some(info.encryption_pubkey.into()),
        config_hash: info.config_hash.map(|h| h.to_vec().into()),
        untrusted_git_revision: Some(info.untrusted_git_revision),
        enclave_btc_pubkey: info
            .enclave_btc_pubkey
            .map(|pk| pk.serialize().to_vec().into()),
        limiter_state: info.limiter_state.map(limiter_state_to_pb),
        limiter_config: info.limiter_config.map(limiter_config_to_pb),
        current_committee_epoch: info.current_committee_epoch,
        mpc_master_g: info
            .mpc_master_g
            .map(|g| bcs::to_bytes(&g).expect("serialize MPC master G").into()),
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

pub fn kp_encrypted_share_to_pb(s: KPEncryptedShare) -> pb::KpEncryptedShare {
    pb::KpEncryptedShare {
        id: Some(share_id_to_pb(s.id)),
        armored_ciphertext: Some(s.armored_ciphertext),
        recipient_fingerprint: Some(s.recipient_fingerprint),
    }
}

pub fn guardian_encrypted_share_to_pb(s: GuardianEncryptedShare) -> pb::GuardianEncryptedShare {
    pb::GuardianEncryptedShare {
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
            .into_vec()
            .into_iter()
            .map(kp_encrypted_share_to_pb)
            .collect(),
        secret_sharing_instance: Some(secret_sharing_instance_to_pb(&r.secret_sharing_instance)),
        btc_master_pubkey: r.btc_master_pubkey.serialize().to_vec().into(),
    }
}

fn pb_to_limiter_config(cfg: pb::LimiterConfig) -> GuardianResult<LimiterConfig> {
    let refill_rate = cfg
        .refill_rate_sats_per_sec
        .ok_or_else(|| missing("refill_rate_sats_per_sec"))?;
    let max_bucket_capacity = cfg
        .max_bucket_capacity_sats
        .ok_or_else(|| missing("max_bucket_capacity_sats"))?;

    Ok(LimiterConfig {
        refill_rate,
        max_bucket_capacity,
    })
}

fn limiter_config_to_pb(cfg: LimiterConfig) -> pb::LimiterConfig {
    pb::LimiterConfig {
        refill_rate_sats_per_sec: Some(cfg.refill_rate),
        max_bucket_capacity_sats: Some(cfg.max_bucket_capacity),
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

    // The pinned config is carried verbatim as BCS bytes so the committee's
    // signed bytes survive the wire without reconstruction.
    let config_bytes = c.config.ok_or_else(|| missing("config"))?;
    let config: Config = bcs::from_bytes(&config_bytes)
        .map_err(|e| InvalidInputs(format!("invalid config: {e}")))?;
    let committee = HashiCommittee::with_config(members, epoch, config);

    if committee.total_weight() != total_weight {
        return Err(InvalidInputs(format!(
            "invalid total_weight: expected {total_weight}, computed {}",
            committee.total_weight()
        )));
    }

    Ok(committee)
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

// -----------------------------------------
//    Standard Withdrawal Helper Functions
// -----------------------------------------

fn pb_to_tx_utxos_wire(utxos_pb: pb::TxUtxos) -> GuardianResult<TxUTXOsWire> {
    let inputs = utxos_pb
        .inputs
        .into_iter()
        .map(pb_to_input_utxo)
        .collect::<GuardianResult<Vec<_>>>()?;

    let outputs = utxos_pb
        .outputs
        .into_iter()
        .map(pb_to_output_utxo_wire)
        .collect::<GuardianResult<Vec<_>>>()?;

    Ok(TxUTXOsWire { inputs, outputs })
}

fn pb_to_input_utxo(input_pb: pb::InputUtxo) -> GuardianResult<InputUTXO> {
    let outpoint_pb = input_pb.outpoint.ok_or_else(|| missing("outpoint"))?;
    let txid_bytes = outpoint_pb.txid.ok_or_else(|| missing("txid"))?;
    let vout = outpoint_pb.vout.ok_or_else(|| missing("vout"))?;

    let txid = Txid::from_slice(txid_bytes.as_ref())
        .map_err(|e| InvalidInputs(format!("invalid txid: {e}")))?;
    let outpoint = OutPoint { txid, vout };

    let amount = input_pb.amount.ok_or_else(|| missing("amount"))?;

    let path_bytes = input_pb
        .derivation_path
        .ok_or_else(|| missing("derivation_path"))?;
    let derivation_path = DerivationPath::from_bytes(path_bytes.as_ref())
        .map_err(|_| InvalidInputs("invalid derivation_path: expected 32 bytes".into()))?;

    Ok(InputUTXO::new(
        outpoint,
        Amount::from_sat(amount),
        derivation_path,
    ))
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
            let path_bytes = int
                .derivation_path
                .ok_or_else(|| missing("derivation_path"))?;
            let derivation_path = DerivationPath::from_bytes(path_bytes.as_ref())
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
        wid: Some(Vec::from(req.wid).into()),
        utxos: Some(tx_utxos_wire_to_pb(req.utxos)),
        timestamp_secs: Some(req.timestamp_secs),
        seq: Some(req.seq),
    }
}

fn tx_utxos_wire_to_pb(utxos: TxUTXOsWire) -> pb::TxUtxos {
    pb::TxUtxos {
        inputs: utxos.inputs.into_iter().map(input_utxo_to_pb).collect(),
        outputs: utxos
            .outputs
            .into_iter()
            .map(output_utxo_wire_to_pb)
            .collect(),
    }
}

fn input_utxo_to_pb(input: InputUTXO) -> pb::InputUtxo {
    pb::InputUtxo {
        outpoint: Some(pb::UtxoId {
            txid: Some(input.outpoint.txid.as_byte_array().to_vec().into()),
            vout: Some(input.outpoint.vout),
        }),
        amount: Some(input.amount.to_sat()),
        derivation_path: Some(input.derivation_path.into_inner().to_vec().into()),
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
                derivation_path: Some(int.derivation_path.into_inner().to_vec().into()),
                amount: Some(int.amount.to_sat()),
            })
        }
    };

    pb::OutputUtxo {
        output: Some(output_enum),
    }
}

// ----------------------------------
//   Committee Transition
// ----------------------------------

/// Decode the wire `Committee` into the BCS-stable `move_types::Committee`,
/// going through `HashiCommittee` so member keys and `total_weight` are
/// validated before we project back.
fn pb_to_move_committee(c: pb::Committee) -> GuardianResult<crate::move_types::Committee> {
    let hashi_committee = pb_to_hashi_committee(c)?;
    Ok(crate::move_types::Committee::from(&hashi_committee))
}

fn move_committee_to_pb(c: &crate::move_types::Committee) -> pb::Committee {
    pb::Committee {
        epoch: Some(c.epoch),
        members: c
            .members
            .iter()
            .map(|m| pb::CommitteeMember {
                address: Some(m.validator_address.to_string()),
                public_key: Some(m.public_key.clone().into()),
                encryption_public_key: Some(m.encryption_public_key.clone().into()),
                weight: Some(m.weight),
            })
            .collect(),
        total_weight: Some(c.total_weight),
        config: Some(bcs::to_bytes(&c.config).expect("Config serializes").into()),
    }
}

pub fn committee_transition_to_pb(t: &CommitteeTransitionRequest) -> pb::CommitteeTransition {
    pb::CommitteeTransition {
        new_committee: Some(move_committee_to_pb(&t.new_committee)),
    }
}

pub fn pb_to_committee_transition(
    t: pb::CommitteeTransition,
) -> GuardianResult<CommitteeTransitionRequest> {
    let new_committee_pb = t.new_committee.ok_or_else(|| missing("new_committee"))?;
    let new_committee = pb_to_move_committee(new_committee_pb)?;
    Ok(CommitteeTransitionRequest { new_committee })
}

pub fn signed_committee_transition_to_pb(
    signed: &HashiSigned<CommitteeTransitionRequest>,
) -> pb::SignedCommitteeTransition {
    pb::SignedCommitteeTransition {
        data: Some(committee_transition_to_pb(signed.message())),
        committee_signature: Some(pb::CommitteeSignature {
            epoch: Some(signed.epoch()),
            signature: Some(signed.signature_bytes().to_vec().into()),
            bitmap: Some(signed.signers_bitmap_bytes().to_vec().into()),
        }),
    }
}

pub fn pb_to_signed_committee_transition(
    req: pb::SignedCommitteeTransition,
) -> GuardianResult<HashiSigned<CommitteeTransitionRequest>> {
    let data_pb = req.data.ok_or_else(|| missing("data"))?;
    let transition = pb_to_committee_transition(data_pb)?;

    let committee_signature_pb = req
        .committee_signature
        .ok_or_else(|| missing("committee_signature"))?;
    let (epoch, signature, bitmap) = pb_to_committee_signature(committee_signature_pb)?;

    HashiSigned::<CommitteeTransitionRequest>::new(epoch, transition, &signature, &bitmap)
        .map_err(|e| InvalidInputs(format!("invalid signed committee transition: {e}")))
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
    fn guardian_info_data_with_enclave_btc_pubkey_round_trip() {
        use crate::bitcoin::create_btc_keypair_for_test;
        let kp = create_btc_keypair_for_test(&[7u8; 32]);
        let pk = kp.x_only_public_key().0;

        let info = GuardianInfo {
            secret_sharing_instance: None,
            bucket_info: None,
            encryption_pubkey: vec![0u8; 32],
            config_hash: None,
            untrusted_git_revision: "unknown".to_string(),
            enclave_btc_pubkey: Some(pk),
            limiter_state: None,
            limiter_config: None,
            current_committee_epoch: None,
            mpc_master_g: None,
        };
        let pb = guardian_info_data_to_pb(info.clone());
        let back = pb_to_guardian_info_data(pb).unwrap();
        assert_eq!(info, back);
        assert_eq!(back.enclave_btc_pubkey, Some(pk));
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
    fn signed_rotate_kps_response_round_trip() {
        let resp = GuardianSigned::<RotateKpsResponse>::mock_for_testing();
        let pb = rotate_kps_response_signed_to_pb(resp.clone());
        let back = GuardianSigned::<RotateKpsResponse>::try_from(pb).unwrap();
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
    fn signed_single_provisioner_init_request_round_trip_and_verifies() {
        use crate::pgp::test_utils::mock_pgp_keypair;
        use crate::pgp::test_utils::sign_detached_in_process;

        let (cert_armored, secret_armored) = mock_pgp_keypair();
        let cert = PgpPublicCert::new(cert_armored).unwrap();
        let encrypted_share = ProvisionerInitRequest::mock_for_testing()
            .into_parts()
            .pop()
            .unwrap();
        let request =
            SingleProvisionerInitRequest::new("session-a".to_string(), encrypted_share.clone());
        let signature =
            sign_detached_in_process(&secret_armored, &KpSigned::signed_bytes(&request));
        let signed = KpSigned {
            data: request,
            signer_cert: cert.clone(),
            signature,
        };

        let pb = pb::SignedSingleProvisionerInitRequest::from(signed);
        let back = KpSigned::<SingleProvisionerInitRequest>::try_from(pb.clone()).unwrap();
        assert_eq!(back.data.expected_session_id(), "session-a");
        assert_eq!(back.data.encrypted_share(), &encrypted_share);
        assert_eq!(back.signer_cert.fingerprint(), cert.fingerprint());
        back.verify().unwrap();

        let mut tampered = pb;
        tampered.expected_session_id = "other-session".to_string();
        let tampered = KpSigned::<SingleProvisionerInitRequest>::try_from(tampered).unwrap();
        assert!(
            tampered.verify().is_err(),
            "signature must bind the expected guardian session"
        );
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

    #[test]
    fn signed_committee_transition_round_trip() {
        use crate::committee::Bls12381PrivateKey;
        use crate::committee::BlsSignatureAggregator;
        use crate::committee::DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS;
        use crate::committee::DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS;
        use crate::committee::DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA;
        use crate::committee::EncryptionPublicKey;
        use crate::committee::VANILLA_MPC_NONCE_GENERATION_PROTOCOL;
        use rand::SeedableRng;

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xCAFE);
        let sk = Bls12381PrivateKey::generate(&mut rng);
        let enc_sk = crate::committee::EncryptionPrivateKey::new(&mut rng);
        let enc_pk = EncryptionPublicKey::from_private_key(&enc_sk);
        let addr = sui_sdk_types::Address::new([7u8; 32]);
        let member = HashiCommitteeMember::new(addr, sk.public_key(), enc_pk, 10);
        let outgoing = HashiCommittee::new(
            vec![member.clone()],
            5,
            DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS,
            DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA,
            DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS,
            VANILLA_MPC_NONCE_GENERATION_PROTOCOL,
        );
        let new_committee = HashiCommittee::new(
            vec![member],
            6,
            DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS,
            DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA,
            DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS,
            VANILLA_MPC_NONCE_GENERATION_PROTOCOL,
        );
        let transition = CommitteeTransitionRequest {
            new_committee: crate::move_types::Committee::from(&new_committee),
        };
        let sig = sk.sign(5, addr, &transition);
        let mut agg = BlsSignatureAggregator::new(&outgoing, transition.clone());
        agg.add_signature(sig).expect("member sig should verify");
        let signed = agg.finish().expect("threshold met");

        let pb = signed_committee_transition_to_pb(&signed);
        let back = pb_to_signed_committee_transition(pb).expect("round-trip");
        assert_eq!(signed.epoch(), back.epoch());
        assert_eq!(signed.signature_bytes(), back.signature_bytes());
        assert_eq!(signed.signers_bitmap_bytes(), back.signers_bitmap_bytes());
        assert_eq!(signed.message().new_committee, back.message().new_committee);
    }
}
