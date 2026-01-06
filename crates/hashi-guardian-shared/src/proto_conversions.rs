// ---------------------------------
//    Protobuf RPC conversions
// ---------------------------------

use crate::Ciphertext;
use crate::EncPubKey;
use crate::EncryptedShare;
use crate::GuardianError;
use crate::GuardianError::InvalidInputs;
use crate::GuardianResult;
use crate::GuardianSignature;
use crate::GuardianSigned;
use crate::SetupNewKeyRequest;
use crate::SetupNewKeyResponse;
use crate::ShareCommitment;
use crate::ShareID;
use hashi::proto as pb;
use hpke::Deserializable;
use hpke::Serializable;
use std::num::NonZeroU16;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

// ----------------------------------------------------------
//      Proto -> Domain (deserialization & validation)
// ----------------------------------------------------------

impl TryFrom<pb::SetupNewKeyRequest> for SetupNewKeyRequest {
    type Error = GuardianError;

    fn try_from(req: pb::SetupNewKeyRequest) -> Result<Self, Self::Error> {
        let pks = req
            .key_provisioner_public_keys
            .iter()
            .map(|b| EncPubKey::from_bytes(b))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| InvalidInputs(format!("Failed to deserialize public key: {}", e)))?;

        SetupNewKeyRequest::new(pks)
    }
}

impl TryFrom<pb::SignedSetupNewKeyResponse> for GuardianSigned<SetupNewKeyResponse> {
    type Error = GuardianError;

    fn try_from(resp: pb::SignedSetupNewKeyResponse) -> Result<Self, Self::Error> {
        let s = resp
            .signature
            .ok_or_else(|| InvalidInputs("missing signature".to_string()))?;

        let signature = GuardianSignature::try_from(s.as_ref())
            .map_err(|e| InvalidInputs(format!("signature deserialization error: {}", e)))?;

        let d = resp
            .data
            .ok_or_else(|| InvalidInputs("missing data".to_string()))?;

        let encrypted_shares: Vec<EncryptedShare> = d
            .encrypted_shares
            .iter()
            .map(|b| {
                Ok(EncryptedShare {
                    id: pb_to_share_id(b.id)?,
                    ciphertext: pb_to_ciphertext(b.ciphertext.clone())?,
                })
            })
            .collect::<GuardianResult<Vec<_>>>()?;

        let share_commitments: Vec<ShareCommitment> = d
            .share_commitments
            .iter()
            .map(|c| {
                let digest = c
                    .digest
                    .clone()
                    .ok_or_else(|| InvalidInputs("Missing digest".to_string()))?;

                Ok(ShareCommitment {
                    id: pb_to_share_id(c.id)?,
                    digest: digest.to_vec(),
                })
            })
            .collect::<GuardianResult<Vec<_>>>()?;

        let t = resp
            .timestamp_ms
            .ok_or_else(|| InvalidInputs("missing timestamp_ms".to_string()))?;

        let timestamp = UNIX_EPOCH
            .checked_add(Duration::from_millis(t))
            .ok_or_else(|| InvalidInputs("invalid timestamp_ms".to_string()))?;

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

// ----------------------------------
//              Helpers
// ----------------------------------

fn system_time_to_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .expect("should not be older than unix epoch")
        .as_millis() as u64
}

fn pb_to_share_id(id_ser: Option<pb::GuardianShareId>) -> GuardianResult<ShareID> {
    let id = id_ser.ok_or_else(|| InvalidInputs("Missing id".to_string()))?;

    let id = id
        .id
        .ok_or_else(|| InvalidInputs("Missing id".to_string()))?;

    // Cast down to u16
    let id = u16::try_from(id).map_err(|_| InvalidInputs("Invalid id".to_string()))?;

    // Cast to NonZeroU16
    NonZeroU16::try_from(id).map_err(|e| InvalidInputs(format!("invalid id: {}", e)))
}

fn share_id_to_pb(id: ShareID) -> pb::GuardianShareId {
    // ShareID is a NonZeroU16 in this codebase.
    pb::GuardianShareId {
        id: Some(id.get() as u32),
    }
}

fn pb_to_ciphertext(c_ser: Option<pb::HpkeCiphertext>) -> GuardianResult<Ciphertext> {
    let c = c_ser.ok_or_else(|| InvalidInputs("Missing ciphertext".to_string()))?;

    let e = c
        .encapsulated_key
        .ok_or_else(|| InvalidInputs("Missing encapsulated key".to_string()))?;

    let a = c
        .aes_ciphertext
        .ok_or_else(|| InvalidInputs("Missing aes ciphertext".to_string()))?;

    Ok(Ciphertext {
        encapsulated_key: e.to_vec(),
        aes_ciphertext: a.to_vec(),
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
