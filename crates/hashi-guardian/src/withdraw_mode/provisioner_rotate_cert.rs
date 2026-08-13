// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Replace one certificate in a KP roster entry. The live guardian verifies
//! that the caller submitted the currently committed share, then appends a new
//! `kp-shares/` snapshot with that share encrypted to the replacement cert.

use std::sync::Arc;

use crate::Enclave;
use hashi_types::guardian::crypto::decrypt_share;
use hashi_types::guardian::crypto::encrypt_share_for_provisioner;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianError::Unauthenticated;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::GuardianSignedResponse;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::ProvisionerRotateCertRequest;
use hashi_types::guardian::ProvisionerRotateCertResponse;
use hashi_types::guardian::SessionBoundRequest;
use tracing::info;

pub async fn provisioner_rotate_cert(
    enclave: Arc<Enclave>,
    signed_request: KpSigned<ProvisionerRotateCertRequest>,
) -> GuardianResult<GuardianSignedResponse<ProvisionerRotateCertResponse>> {
    info!("/provisioner_rotate_cert - Received request.");

    enclave.require_fully_initialized()?;

    let signer_fingerprint = signed_request.signer_fingerprint().to_hex();
    let request = signed_request
        .verify_into_data()
        .map_err(|error| Unauthenticated(error.to_string()))?;

    let live_session_id = enclave.s3_session_id();
    request.validate_session(&live_session_id)?;

    let share_id = request.share_id();
    let target_fingerprint = request.target_kp_pgp_fingerprint().to_owned();
    let new_recipient_fingerprint = request.new_recipient_fingerprint();
    let encrypted_share = request.encrypted_share().clone();

    let mut reader = enclave.new_guardian_reader()?;

    let latest_state = reader.read_latest_ceremony_state().await?;
    let enclave_btc_pubkey = enclave.config.enclave_btc_pubkey()?;
    if latest_state.btc_master_pubkey != enclave_btc_pubkey {
        return Err(InvalidInputs(format!(
            "latest ceremony BTC pubkey differs from initialized enclave BTC pubkey: latest \
             {:?}, initialized {enclave_btc_pubkey:?}",
            latest_state.btc_master_pubkey
        )));
    }
    let sharing_seq = latest_state.secret_sharing_instance.sharing_seq();

    if latest_state.cert_seq != request.expected_cert_seq() {
        return Err(InvalidInputs(format!(
            "provisioner_rotate_cert request expected cert_seq {}, latest cert_seq is {}",
            request.expected_cert_seq(),
            latest_state.cert_seq
        )));
    }

    let latest_instance = latest_state.secret_sharing_instance;
    let encrypted_shares = latest_state.encrypted_shares;
    let signer_share_id = encrypted_shares
        .find_by_fingerprint(&signer_fingerprint)
        .map(|(share, _)| share.id)
        .ok_or_else(|| {
            InvalidInputs(format!(
                "signer fingerprint {signer_fingerprint} is not present in the latest KP share \
                 state"
            ))
        })?;
    let target_share_id = encrypted_shares
        .find_by_fingerprint(&target_fingerprint)
        .map(|(share, _)| share.id)
        .ok_or_else(|| {
            InvalidInputs(format!(
                "target fingerprint {target_fingerprint} is not present in the latest KP share \
                 state"
            ))
        })?;
    if signer_share_id != target_share_id {
        return Err(InvalidInputs(format!(
            "signer fingerprint {signer_fingerprint} is assigned share id {}, but target \
             fingerprint {target_fingerprint} is assigned share id {}",
            signer_share_id.get(),
            target_share_id.get()
        )));
    }
    if signer_share_id != share_id {
        return Err(InvalidInputs(format!(
            "signer fingerprint {signer_fingerprint} is assigned share id {}, not submitted share \
             id {}",
            signer_share_id.get(),
            share_id.get()
        )));
    }

    // The KP signature binds the ciphertext and the rest of this request to the
    // current session and cert sequence, so no additional HPKE AAD is needed.
    let share = decrypt_share(&encrypted_share, enclave.encryption_secret_key(), None)?;
    if share.id != share_id {
        return Err(InvalidInputs(format!(
            "decrypted share id {} does not match requested share id {}",
            share.id.get(),
            share_id.get()
        )));
    }
    latest_instance.commitments().verify_share(&share)?;

    let replacement_ciphertext = encrypt_share_for_provisioner(&share, request.new_kp_pgp_cert());
    let (encrypted_shares, changed_entry) = encrypted_shares.replace_recipient(
        &target_fingerprint,
        new_recipient_fingerprint.clone(),
        replacement_ciphertext,
    )?;
    let next_cert_seq = latest_state
        .cert_seq
        .checked_add(1)
        .ok_or_else(|| InvalidInputs("cert_seq overflow".into()))?;

    enclave
        .log_kp_share_state(sharing_seq, next_cert_seq, encrypted_shares)
        .await?;

    info!(
        sharing_seq,
        cert_seq = next_cert_seq,
        share_id = share_id.get(),
        signer_fingerprint = %signer_fingerprint,
        target_fingerprint = %target_fingerprint,
        new_fingerprint = %new_recipient_fingerprint,
        "KP certificate rotation complete",
    );

    Ok(enclave.sign(ProvisionerRotateCertResponse {
        cert_seq: next_cert_seq,
        encrypted_shares: changed_entry,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::Ciphertext;
    use hashi_types::guardian::GuardianEncryptedShare;
    use hashi_types::guardian::GuardianError::LifecycleMismatch;
    use hashi_types::pgp::test_utils::mock_pgp_cert;
    use std::num::NonZeroU16;

    #[tokio::test]
    async fn rejects_wrong_lifecycle_before_verifying_signature() {
        let enclave = Enclave::create_with_random_keys();
        let signer_cert = mock_pgp_cert();
        let request = ProvisionerRotateCertRequest::from_encrypted_share_for_testing(
            "mock-session".into(),
            0,
            signer_cert.fingerprint().to_hex(),
            mock_pgp_cert(),
            GuardianEncryptedShare {
                id: NonZeroU16::new(1).unwrap(),
                ciphertext: Ciphertext {
                    encapsulated_key: vec![],
                    aes_ciphertext: vec![],
                },
            },
        );
        let signed_request = KpSigned::from_parts(request, signer_cert, "invalid signature".into());

        let err = provisioner_rotate_cert(enclave, signed_request)
            .await
            .expect_err("wrong lifecycle should be rejected first");

        assert!(matches!(err, LifecycleMismatch { .. }));
    }
}
