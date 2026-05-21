// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use hashi_types::guardian::crypto::split_and_encrypt_for_kps;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::*;
use k256::SecretKey;
use std::env;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tracing::info;

/// Set up a new BTC key. Flow:
///     1. KPs send their age recipients to the operator
///     2. Operator calls setup_new_key (and optionally returns its response to all KPs)
///     3. KPs fetch the setup_new_key response from `secret_sharing/` in S3
pub async fn setup_new_key(
    enclave: Arc<Enclave>,
    request: SetupNewKeyRequest,
) -> GuardianResult<GuardianSigned<SetupNewKeyResponse>> {
    info!("/setup_new_key - Received request.");
    if !enclave.is_operator_init_complete() {
        return Err(InvalidInputs("call operator_init first".into()));
    }

    let n = request.num_shares();
    let t = request.threshold();
    let key_provisioner_recipients = request.recipients();
    info!(
        "Received {} age recipients.",
        key_provisioner_recipients.len()
    );

    info!("Generating new Bitcoin private key.");
    // Confine the !Send `ThreadRng` to a sync scope so the surrounding async
    // future stays Send.
    let (encrypted_shares, share_commitments, fingerprint_hex) = {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::random(&mut rng);
        let fp = format!("{:x}", fingerprint(&sk));
        info!("Splitting secret into {n} shares (threshold: {t}).");
        let (encrypted, commitments) =
            split_and_encrypt_for_kps(&sk, key_provisioner_recipients, t, &mut rng)?;
        (encrypted, commitments, fp)
    };
    info!(
        "Bitcoin key generated with fingerprint {}; all {} shares encrypted.",
        fingerprint_hex, n
    );

    let secret_sharing_config = SecretSharingConfig::new(share_commitments.clone(), n, t, 0)?;

    enclave
        .log_secret_sharing(SecretSharingLogMessage {
            encrypted_shares: encrypted_shares.clone(),
            secret_sharing_config,
        })
        .await?;

    let response = enclave.sign(SetupNewKeyResponse {
        encrypted_shares,
        share_commitments,
    });

    Ok(response)
}

pub fn check_yubikey_age_plugin() -> GuardianResult<()> {
    let Some(path) = env::var_os("PATH") else {
        return Err(InvalidInputs(
            "`age-plugin-yubikey` must be on PATH so setup_new_key can encrypt shares to YubiKey age recipients".into(),
        ));
    };

    let plugin_found = env::split_paths(&path).any(|dir| {
        let path = dir.join("age-plugin-yubikey");
        path.is_file()
            && path
                .metadata()
                .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
    });

    plugin_found.then_some(()).ok_or_else(|| {
        InvalidInputs(
            "`age-plugin-yubikey` must be on PATH so setup_new_key can encrypt shares to YubiKey age recipients".into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::commit_share;
    use hashi_types::guardian::decrypt_age_share;
    use std::str::FromStr;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    fn mock_setup_new_key_request() -> (SetupNewKeyRequest, Vec<age::x25519::Identity>) {
        let mut identities = vec![];
        let mut recipients = vec![];
        for _i in 0..TEST_N {
            let identity = age::x25519::Identity::generate();
            recipients.push(AgeRecipient::from_str(&identity.to_public().to_string()).unwrap());
            identities.push(identity);
        }

        (
            SetupNewKeyRequest::new(recipients, TEST_N, TEST_T).unwrap(),
            identities,
        )
    }

    #[tokio::test]
    async fn test_setup_new_key() {
        let enclave = Enclave::create_operator_initialized().await;
        let verification_key = &enclave.signing_pubkey();
        let (request, kp_identities) = mock_setup_new_key_request();
        let resp = setup_new_key(enclave.clone(), request).await.unwrap();
        let validated_resp = resp.verify(verification_key).unwrap();
        assert_eq!(validated_resp.encrypted_shares.len(), TEST_N);

        for (enc_share, sk) in validated_resp
            .encrypted_shares
            .iter()
            .zip(kp_identities.iter())
            .take(TEST_N)
        {
            assert!(enc_share
                .armored_ciphertext
                .starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
            let share = decrypt_age_share(enc_share, sk).unwrap();
            let commitment = commit_share(&share);
            assert!(validated_resp.share_commitments.contains(&commitment));
            println!("Received share: (id) {:?}", enc_share.id);
        }
    }
}
