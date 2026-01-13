// ---------------------------------
//    Protobuf RPC conversions
// ---------------------------------

use crate::Ciphertext;
use crate::EncPubKey;
use crate::EncryptedShare;
use crate::GetGuardianInfoResponse;
use crate::GuardianError;
use crate::GuardianError::InvalidInputs;
use crate::GuardianResult;
use crate::GuardianSignature;
use crate::GuardianSigned;
use crate::HashiCommittee;
use crate::HashiCommitteeMember;
use crate::OperatorInitRequest;
use crate::ProvisionerInitRequest;
use crate::ProvisionerInitRequestState;
use crate::SetupNewKeyRequest;
use crate::SetupNewKeyResponse;
use crate::ShareCommitment;
use crate::ShareID;
use crate::WithdrawalConfig;
use crate::WithdrawalState;
use bitcoin::XOnlyPublicKey;
use fastcrypto::traits::ToFromBytes;
use hashi_types::committee::BLS12381PublicKey;
use hashi_types::committee::EncryptionPublicKey;
use hashi_types::proto as pb;
use hpke::Deserializable;
use hpke::Serializable;
use std::num::NonZeroU16;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use sui_sdk_types::bcs::FromBcs;
use sui_sdk_types::bcs::ToBcs;
use sui_sdk_types::Address as SuiAddress;

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

        let timestamp = UNIX_EPOCH
            .checked_add(Duration::from_millis(timestamp_ms))
            .ok_or_else(|| InvalidInputs("invalid timestamp".to_string()))?;

        Ok(GuardianSigned {
            data: SetupNewKeyResponse {
                encrypted_shares,
                share_commitments,
            },
            timestamp,
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

        let committee_pb = state_pb
            .hashi_committee
            .ok_or_else(|| missing("hashi_committee"))?;
        let hashi_committee = pb_to_hashi_committee(committee_pb)?;

        let withdrawal_config_pb = state_pb
            .withdrawal_config
            .ok_or_else(|| missing("withdrawal_config"))?;
        let withdrawal_config = pb_to_withdrawal_config(withdrawal_config_pb)?;

        let withdrawal_state_pb = state_pb
            .withdrawal_state
            .ok_or_else(|| missing("withdrawal_state"))?;
        let withdrawal_state = pb_to_withdrawal_state(withdrawal_state_pb)?;

        let master_pk_bytes = state_pb
            .hashi_btc_master_pubkey
            .ok_or_else(|| missing("hashi_btc_master_pubkey"))?;

        let hashi_btc_master_pubkey = XOnlyPublicKey::from_slice(master_pk_bytes.as_ref())
            .map_err(|e| InvalidInputs(format!("invalid hashi_btc_master_pubkey: {e}")))?;

        Ok(ProvisionerInitRequest::new(
            encrypted_share,
            ProvisionerInitRequestState::new(
                hashi_committee,
                withdrawal_config,
                withdrawal_state,
                hashi_btc_master_pubkey,
            ),
        ))
    }
}

impl TryFrom<pb::GetGuardianInfoResponse> for GetGuardianInfoResponse {
    type Error = GuardianError;
    fn try_from(resp: pb::GetGuardianInfoResponse) -> Result<Self, Self::Error> {
        let attestation = resp.attestation.ok_or_else(|| missing("attestation"))?;
        let server_version = resp.server.ok_or_else(|| missing("server"))?;

        Ok(GetGuardianInfoResponse {
            attestation: attestation.to_vec(),
            server_version,
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
        timestamp_ms: Some(system_time_to_ms(s.timestamp)),
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
    Ok(pb::OperatorInitRequest {
        s3_config: Some(s3_config_to_pb(r.s3_config)),
        share_commitments: r
            .share_commitments
            .into_iter()
            .map(share_commitment_to_pb)
            .collect(),
        network: Some(network_to_pb(r.network)?),
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

pub fn provisioner_init_state_to_pb(s: ProvisionerInitRequestState) -> pb::ProvisionerInitState {
    pb::ProvisionerInitState {
        hashi_committee: Some(hashi_committee_to_pb(s.hashi_committee)),
        withdrawal_config: Some(withdrawal_config_to_pb(s.withdrawal_config)),
        withdrawal_state: Some(withdrawal_state_to_pb(s.withdrawal_state)),
        hashi_btc_master_pubkey: Some(s.hashi_btc_master_pubkey.serialize().to_vec().into()),
    }
}

pub fn get_guardian_info_response_to_pb(r: GetGuardianInfoResponse) -> pb::GetGuardianInfoResponse {
    pb::GetGuardianInfoResponse {
        attestation: Some(r.attestation.into()),
        server: Some(r.server_version),
    }
}

// ----------------------------------
//              Helpers
// ----------------------------------

fn missing(field: &str) -> GuardianError {
    InvalidInputs(format!("missing {field}"))
}

fn pb_share_commitments_to_domain(
    commitments: &[pb::GuardianShareCommitment],
) -> GuardianResult<Vec<ShareCommitment>> {
    commitments
        .iter()
        .map(|c| {
            let digest = c.digest.clone().ok_or_else(|| missing("digest"))?;
            Ok(ShareCommitment {
                id: pb_to_share_id(c.id)?,
                digest: digest.to_vec(),
            })
        })
        .collect::<GuardianResult<Vec<_>>>()
}

fn system_time_to_ms(time: SystemTime) -> u64 {
    // For signing, timestamps older than UNIX_EPOCH should not be possible.
    time.duration_since(UNIX_EPOCH)
        .expect("system_time cannot be before Unix epoch")
        .as_millis() as u64
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

fn pb_to_s3_config(cfg: pb::S3Config) -> GuardianResult<crate::S3Config> {
    let access_key = cfg.access_key.ok_or_else(|| missing("access_key"))?;
    let secret_key = cfg.secret_key.ok_or_else(|| missing("secret_key"))?;
    let bucket_name = cfg.bucket_name.ok_or_else(|| missing("bucket_name"))?;

    Ok(crate::S3Config {
        access_key: access_key.to_string(),
        secret_key: secret_key.to_string(),
        bucket_name: bucket_name.to_string(),
    })
}

fn s3_config_to_pb(cfg: crate::S3Config) -> pb::S3Config {
    pb::S3Config {
        access_key: Some(cfg.access_key),
        secret_key: Some(cfg.secret_key),
        bucket_name: Some(cfg.bucket_name),
    }
}

fn pb_to_network(n: i32) -> GuardianResult<crate::Network> {
    match pb::Network::try_from(n) {
        Ok(pb::Network::Mainnet) => Ok(crate::Network::Bitcoin),
        Ok(pb::Network::Testnet) => Ok(crate::Network::Testnet),
        Ok(pb::Network::Regtest) => Ok(crate::Network::Regtest),
        Err(_) => Err(InvalidInputs(format!("invalid network: enum value {n}"))),
    }
}

fn network_to_pb(n: crate::Network) -> GuardianResult<i32> {
    match n {
        crate::Network::Bitcoin => Ok(pb::Network::Mainnet as i32),
        crate::Network::Testnet => Ok(pb::Network::Testnet as i32),
        crate::Network::Regtest => Ok(pb::Network::Regtest as i32),
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
        digest: Some(c.digest.into()),
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
    let min_delay_secs = cfg
        .delayed_withdrawals_min_delay
        .ok_or_else(|| missing("delayed_withdrawals_min_delay"))?;
    let timeout_secs = cfg
        .delayed_withdrawals_timeout
        .ok_or_else(|| missing("delayed_withdrawals_timeout"))?;

    Ok(WithdrawalConfig {
        committee_threshold,
        delayed_withdrawals_min_delay: Duration::from_secs(min_delay_secs),
        delayed_withdrawals_timeout: Duration::from_secs(timeout_secs),
    })
}

fn withdrawal_config_to_pb(cfg: WithdrawalConfig) -> pb::WithdrawalConfig {
    pb::WithdrawalConfig {
        committee_threshold: Some(cfg.committee_threshold),
        delayed_withdrawals_min_delay: Some(cfg.delayed_withdrawals_min_delay.as_secs()),
        delayed_withdrawals_timeout: Some(cfg.delayed_withdrawals_timeout.as_secs()),
    }
}

fn pb_to_withdrawal_state(st: pb::WithdrawalState) -> GuardianResult<WithdrawalState> {
    let num_withdrawals = st
        .num_withdrawals
        .ok_or_else(|| missing("num_withdrawals"))?;

    Ok(WithdrawalState { num_withdrawals })
}

fn withdrawal_state_to_pb(st: WithdrawalState) -> pb::WithdrawalState {
    pb::WithdrawalState {
        num_withdrawals: Some(st.num_withdrawals),
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

    let committee = HashiCommittee::new(members, epoch);

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
    }
}

fn pb_to_hashi_committee_member(m: pb::CommitteeMember) -> GuardianResult<HashiCommitteeMember> {
    let address = m.address.ok_or_else(|| missing("address"))?;
    let sui_address = SuiAddress::from_str(&address.to_string())
        .map_err(|e| InvalidInputs(format!("invalid address: {e}")))?;

    let public_key = m.public_key.ok_or_else(|| missing("public_key"))?;
    let public_key = BLS12381PublicKey::from_bytes(public_key.as_ref())
        .map_err(|e| InvalidInputs(format!("invalid public_key: {e}")))?;

    let encryption_public_key = m
        .encryption_public_key
        .ok_or_else(|| missing("encryption_public_key"))?;
    let encryption_public_key = EncryptionPublicKey::from_bcs(&encryption_public_key)
        .map_err(|e| InvalidInputs(format!("invalid encryption_public_key: {e}")))?;

    let weight = m.weight.ok_or_else(|| missing("weight"))?;

    Ok(HashiCommitteeMember::new(
        sui_address,
        public_key,
        encryption_public_key,
        weight,
    ))
}

fn hashi_committee_member_to_pb(m: HashiCommitteeMember) -> pb::CommitteeMember {
    let pk = BLS12381PublicKey::as_bytes(m.public_key()).to_vec();
    let enc_pk = EncryptionPublicKey::to_bcs(m.encryption_public_key())
        .expect("serialization should not fail");
    pb::CommitteeMember {
        address: Some(m.validator_address().to_string()),
        public_key: Some(pk.into()),
        encryption_public_key: Some(enc_pk.into()),
        weight: Some(m.weight()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ToBytes;

    #[test]
    fn get_guardian_info_response_round_trip() {
        let resp = GetGuardianInfoResponse {
            attestation: "abcd".to_bytes(),
            server_version: "v1".into(),
        };
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
}
