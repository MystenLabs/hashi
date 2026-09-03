// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A current KP's signed KP-set rotation submission, carried to the operator
//! as a file: the wire message, prost-encoded, so the operator decodes it with
//! the conversion the enclave applies. It holds nothing secret: the old share
//! is encrypted to one enclave session and everything else is public.

use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::ProvisionerRotateKpSetRequest;
use hashi_types::proto as pb;
use prost::Message;

pub fn write(path: &Path, signed: KpSigned<ProvisionerRotateKpSetRequest>) -> Result<()> {
    let bytes = pb::SignedProvisionerRotateKpSetRequest::from(signed).encode_to_vec();
    std::fs::write(path, bytes)
        .with_context(|| format!("write rotation submission to {}", path.display()))
}

pub fn read(path: &Path) -> Result<KpSigned<ProvisionerRotateKpSetRequest>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("read rotation submission at {}", path.display()))?;
    let message = pb::SignedProvisionerRotateKpSetRequest::decode(bytes.as_slice())
        .with_context(|| format!("decode rotation submission at {}", path.display()))?;
    KpSigned::try_from(message)
        .map_err(|e| anyhow!("invalid rotation submission at {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::BuildPcrs;
    use hashi_types::guardian::Ciphertext;
    use hashi_types::guardian::GuardianEncryptedShare;
    use hashi_types::guardian::PcrAllowlist;
    use hashi_types::guardian::ShareID;
    use hashi_types::guardian::test_utils::mock_kp_certs_roster;
    use hashi_types::pgp::PgpPublicCert;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use hashi_types::pgp::test_utils::sign_detached_in_process;

    #[test]
    fn round_trips_a_signed_submission() {
        let (cert_armored, secret_armored) = mock_pgp_keypair();
        let cert = PgpPublicCert::new(cert_armored).unwrap();
        let request = ProvisionerRotateKpSetRequest::new(
            "session".into(),
            PcrAllowlist::new(BuildPcrs::new("test", vec![0]), []).unwrap(),
            GuardianEncryptedShare {
                id: ShareID::new(2).unwrap(),
                ciphertext: Ciphertext {
                    encapsulated_key: vec![1, 2, 3],
                    aes_ciphertext: vec![4, 5, 6],
                },
            },
            mock_kp_certs_roster(3),
            3,
            2,
        )
        .unwrap();
        let signature =
            sign_detached_in_process(&secret_armored, &KpSigned::signed_bytes(&request));
        let signed = KpSigned::from_parts(request.clone(), cert.clone(), signature);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kp2.rotation");
        write(&path, signed).unwrap();
        let decoded = read(&path).unwrap();

        assert_eq!(decoded.signer_fingerprint(), cert.fingerprint());
        assert_eq!(decoded.verify_signature().unwrap(), &request);
    }

    #[test]
    fn rejects_a_file_that_is_not_a_submission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage");
        std::fs::write(&path, b"not a submission").unwrap();
        assert!(read(&path).is_err());
        assert!(read(&dir.path().join("missing")).is_err());
    }
}
