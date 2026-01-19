// ---------------------------------
//    Protobuf RPC conversions
// ---------------------------------

use crate::bitcoin_utils::ExternalOutputUTXOWire;
use crate::bitcoin_utils::InputUTXOWire;
use crate::bitcoin_utils::InternalOutputUTXO;
use crate::bitcoin_utils::OutputUTXOWire;
use crate::bitcoin_utils::TxUTXOsWire;
use crate::epoch_store::EpochWindow;
use crate::BitcoinSignature;
use crate::Ciphertext;
use crate::CommitteeSignatureWire;
use crate::CommitteeStore;
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
use crate::HashiSigned;
use crate::OperatorInitRequest;
use crate::ProvisionerInitRequest;
use crate::ProvisionerInitState;
use crate::RateLimiter;
use crate::SetupNewKeyRequest;
use crate::SetupNewKeyResponse;
use crate::ShareCommitment;
use crate::ShareID;
use crate::SignedStandardWithdrawalRequestWire;
use crate::StandardWithdrawalRequest;
use crate::StandardWithdrawalRequestWire;
use crate::StandardWithdrawalResponse;
use crate::WithdrawalConfig;
use crate::WithdrawalState;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash as _;
use bitcoin::Address as BitcoinAddress;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::TapLeafHash;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;
use hashi_types::proto as pb;
use hpke::Deserializable;
use hpke::Serializable;
use std::num::NonZeroU16;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
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

        let epoch_window_pb = state_pb
            .epoch_window
            .ok_or_else(|| missing("epoch_window"))?;
        let epoch_window = pb_to_epoch_window(epoch_window_pb)?;

        let committees_pb = state_pb
            .hashi_committees
            .ok_or_else(|| missing("committees"))?;
        let hashi_committees = pb_to_hashi_committee_store(committees_pb, epoch_window)?;

        let withdrawal_config_pb = state_pb
            .withdrawal_config
            .ok_or_else(|| missing("withdrawal_config"))?;
        let withdrawal_config = pb_to_withdrawal_config(withdrawal_config_pb)?;

        let withdrawal_state_pb = state_pb
            .withdrawal_state
            .ok_or_else(|| missing("withdrawal_state"))?;
        let withdrawal_state = pb_to_withdrawal_state(withdrawal_state_pb, epoch_window)?;

        let master_pk_bytes = state_pb
            .hashi_btc_master_pubkey
            .ok_or_else(|| missing("hashi_btc_master_pubkey"))?;

        let hashi_btc_master_pubkey = XOnlyPublicKey::from_slice(master_pk_bytes.as_ref())
            .map_err(|e| InvalidInputs(format!("invalid hashi_btc_master_pubkey: {e}")))?;

        Ok(ProvisionerInitRequest::new(
            encrypted_share,
            ProvisionerInitState::new(
                hashi_committees,
                withdrawal_config,
                withdrawal_state,
                hashi_btc_master_pubkey,
            )?,
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

    Ok(SignedStandardWithdrawalRequestWire {
        data: StandardWithdrawalRequestWire {
            wid,
            utxos: utxos_wire,
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

        let timestamp = UNIX_EPOCH
            .checked_add(Duration::from_millis(timestamp_ms))
            .ok_or_else(|| InvalidInputs("invalid timestamp".to_string()))?;

        Ok(GuardianSigned {
            data: StandardWithdrawalResponse { enclave_signatures },
            timestamp,
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

pub fn provisioner_init_state_to_pb(s: ProvisionerInitState) -> pb::ProvisionerInitState {
    // Shared window metadata.
    let window = s.hashi_committees.epoch_window();
    debug_assert_eq!(
        window,
        s.withdrawal_state.rate_limiter().epoch_window(),
        "committee store and rate limiter must use the same EpochWindow"
    );

    pb::ProvisionerInitState {
        hashi_committees: Some(hashi_committee_store_to_pb(s.hashi_committees)),
        withdrawal_config: Some(withdrawal_config_to_pb(s.withdrawal_config)),
        withdrawal_state: Some(withdrawal_state_to_pb(s.withdrawal_state)),
        hashi_btc_master_pubkey: Some(s.hashi_btc_master_pubkey.serialize().to_vec().into()),
        epoch_window: Some(epoch_window_to_pb(window)),
    }
}

pub fn get_guardian_info_response_to_pb(r: GetGuardianInfoResponse) -> pb::GetGuardianInfoResponse {
    pb::GetGuardianInfoResponse {
        attestation: Some(r.attestation.into()),
        server: Some(r.server_version),
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
        timestamp_ms: Some(system_time_to_ms(s.timestamp)),
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

fn pb_to_epoch_window(w: pb::EpochWindow) -> GuardianResult<EpochWindow> {
    let base_epoch = w
        .base_epoch
        .ok_or_else(|| missing("epoch_window.base_epoch"))?;
    let num_epochs = w
        .num_epochs
        .ok_or_else(|| missing("epoch_window.num_epochs"))?;

    let num_epochs = u16::try_from(num_epochs)
        .map_err(|_| InvalidInputs("num_epochs: out of range for u16".into()))?;
    let num_epochs = NonZeroU16::new(num_epochs)
        .ok_or_else(|| InvalidInputs("num_epochs must be >= 1".into()))?;

    Ok(EpochWindow::new(base_epoch, num_epochs))
}

fn epoch_window_to_pb(w: EpochWindow) -> pb::EpochWindow {
    pb::EpochWindow {
        base_epoch: Some(w.first_epoch),
        num_epochs: Some(w.num_epochs.get() as u32),
    }
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

// TODO: Do we need to handle the case of an empty rate limiter? Yes: below might need change. No: insert_strict in epoch_store might be better.
fn pb_to_withdrawal_state(
    st: pb::WithdrawalState,
    epoch_window: EpochWindow,
) -> GuardianResult<WithdrawalState> {
    let rl = st
        .rate_limiter_state
        .ok_or_else(|| missing("rate_limiter_state"))?;

    let withdrawn: Vec<Amount> = rl
        .withdrawn_sats
        .into_iter()
        .map(Amount::from_sat)
        .collect();

    let max_withdrawable_per_epoch_sats = rl
        .max_withdrawable_per_epoch_sats
        .ok_or_else(|| missing("rate_limiter_state.max_withdrawable_per_epoch_sats"))?;

    Ok(WithdrawalState::new(RateLimiter::new(
        epoch_window,
        withdrawn,
        Amount::from_sat(max_withdrawable_per_epoch_sats),
    )?))
}

fn withdrawal_state_to_pb(st: WithdrawalState) -> pb::WithdrawalState {
    let limiter = st.rate_limiter();

    pb::WithdrawalState {
        rate_limiter_state: Some(pb::RateLimiter {
            withdrawn_sats: limiter
                .state
                .iter()
                .map(|(_, x)| Amount::to_sat(*x))
                .collect(),
            max_withdrawable_per_epoch_sats: Some(limiter.max_withdrawable_per_epoch.to_sat()),
        }),
    }
}

fn pb_to_hashi_committee_store(
    c: pb::CommitteeStore,
    epoch_window: EpochWindow,
) -> GuardianResult<CommitteeStore> {
    CommitteeStore::new(
        epoch_window,
        c.committees
            .into_iter()
            .map(pb_to_hashi_committee)
            .collect::<GuardianResult<Vec<_>>>()?,
    )
}

fn hashi_committee_store_to_pb(c: CommitteeStore) -> pb::CommitteeStore {
    pb::CommitteeStore {
        committees: c
            .0
            .into_owned_iter()
            .map(|(_, x)| hashi_committee_to_pb(x))
            .collect(),
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
    let validator_address = sui_sdk_types::Address::from_str(&address)
        .map_err(|e| InvalidInputs(format!("invalid address: {e}")))?;

    let public_key = m.public_key.ok_or_else(|| missing("public_key"))?;
    let encryption_public_key = m
        .encryption_public_key
        .ok_or_else(|| missing("encryption_public_key"))?;

    let weight = m.weight.ok_or_else(|| missing("weight"))?;

    let x = hashi_types::move_types::CommitteeMember {
        validator_address,
        public_key: public_key.to_vec(),
        encryption_public_key: encryption_public_key.to_vec(),
        weight,
    };

    HashiCommitteeMember::try_from(x)
        .map_err(|e| InvalidInputs(format!("invalid committee member: {e}")))
}

fn hashi_committee_member_to_pb(m: HashiCommitteeMember) -> pb::CommitteeMember {
    let x = hashi_types::move_types::CommitteeMember::from(&m);
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
    use super::*;
    use crate::AddressValidation;
    use crate::StandardWithdrawalRequest;
    use bitcoin::Network;

    #[test]
    fn get_guardian_info_response_round_trip() {
        let resp = GetGuardianInfoResponse {
            attestation: "abcd".as_bytes().to_vec(),
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
