// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use hashi_types::guardian::AttestedKpCert;
use hashi_types::pgp::PgpPublicCert;
use std::path::Path;
use std::path::PathBuf;

/// Load and verify a KP certificate and its sibling YubiKey attestation files.
///
/// The certificate must have an `.asc` extension. For `jdoe-kp-pubkey.asc`, the siblings
/// are `jdoe-kp-pubkey.attestation-device.pem`, `jdoe-kp-pubkey.attestation-sig.pem`, and
/// `jdoe-kp-pubkey.attestation-dec.pem`, as emitted by the provisioning script.
/// All three artifacts are required and checked against the pinned Yubico issuers.
pub fn load_attested_kp_cert(path: &Path) -> Result<AttestedKpCert> {
    let cert = read_kp_cert(path)?;
    let [device_path, sig_path, dec_path] = attestation_paths(path);
    let device_pem = std::fs::read(&device_path)
        .with_context(|| format!("failed to read attestation at {}", device_path.display()))?;
    let sig_pem = std::fs::read(&sig_path)
        .with_context(|| format!("failed to read attestation at {}", sig_path.display()))?;
    let dec_pem = std::fs::read(&dec_path)
        .with_context(|| format!("failed to read attestation at {}", dec_path.display()))?;

    AttestedKpCert::new(cert, device_pem, sig_pem, dec_pem).with_context(|| {
        format!(
            "invalid attestations for PGP cert at {} (device: {}, signing: {}, decryption: {})",
            path.display(),
            device_path.display(),
            sig_path.display(),
            dec_path.display()
        )
    })
}

/// Write the attestation files [`load_attested_kp_cert`] reads for the dev KP
/// certificate at `path`, from a software device in place of a YubiKey.
#[cfg(feature = "non-enclave-dev")]
pub fn write_dev_attestations(path: &Path) -> Result<()> {
    let cert = read_kp_cert(path)?;
    let pems = hashi_types::guardian::test_utils::dev_kp_attestations(&cert)
        .with_context(|| format!("failed to attest PGP cert at {}", path.display()))?;
    for (attestation_path, pem) in attestation_paths(path).iter().zip(pems) {
        std::fs::write(attestation_path, pem).with_context(|| {
            format!(
                "failed to write attestation at {}",
                attestation_path.display()
            )
        })?;
    }
    load_attested_kp_cert(path).map(|_| ())
}

fn read_kp_cert(path: &Path) -> Result<PgpPublicCert> {
    ensure!(
        path.extension().is_some_and(|extension| extension == "asc"),
        "KP cert path must have an .asc extension: {}",
        path.display()
    );
    PgpPublicCert::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to read PGP cert at {}", path.display()))?,
    )
    .with_context(|| format!("invalid PGP cert at {}", path.display()))
}

fn attestation_paths(path: &Path) -> [PathBuf; 3] {
    [
        "attestation-device.pem",
        "attestation-sig.pem",
        "attestation-dec.pem",
    ]
    .map(|extension| path.with_extension(extension))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::GuardianError;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use std::io::ErrorKind;

    #[cfg(feature = "non-enclave-dev")]
    #[test]
    fn dev_attestations_load_beside_their_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kp1.asc");
        std::fs::write(&path, mock_pgp_keypair().0).unwrap();
        write_dev_attestations(&path).unwrap();
        load_attested_kp_cert(&path).unwrap();
    }

    #[test]
    fn missing_certificate_reports_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.asc");
        let error = load_attested_kp_cert(&path).unwrap_err();
        assert!(error.to_string().contains(&path.display().to_string()));
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn malformed_certificate_reports_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("malformed.asc");
        std::fs::write(&path, "not a PGP certificate").unwrap();
        let error = load_attested_kp_cert(&path).unwrap_err();
        assert!(error.to_string().contains(&path.display().to_string()));
    }

    #[test]
    fn rejects_paths_without_exact_asc_extension_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        for filename in ["alice", "alice.ASC", "alice.asc.pem"] {
            let path = dir.path().join(filename);
            let error = load_attested_kp_cert(&path).unwrap_err();
            assert!(error.to_string().contains(&path.display().to_string()));
            assert!(error.downcast_ref::<std::io::Error>().is_none());
        }
    }

    #[test]
    fn requires_each_sibling_and_rejects_present_invalid_proofs() {
        let dir = tempfile::Builder::new()
            .prefix("kp loader ")
            .tempdir()
            .unwrap();
        let path = dir.path().join("jdoe.backup-kp-pubkey.asc");
        let (public, _) = mock_pgp_keypair();
        std::fs::write(&path, public).unwrap();
        for filename in [
            "jdoe.backup-kp-pubkey.attestation-device.pem",
            "jdoe.backup-kp-pubkey.attestation-sig.pem",
            "jdoe.backup-kp-pubkey.attestation-dec.pem",
        ] {
            let sidecar = dir.path().join(filename);
            let error = load_attested_kp_cert(&path).unwrap_err();
            assert!(error.to_string().contains(&sidecar.display().to_string()));
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                ErrorKind::NotFound
            );
            std::fs::write(sidecar, b"not an attestation").unwrap();
        }
        let error = load_attested_kp_cert(&path).unwrap_err();
        assert!(error.to_string().contains(&path.display().to_string()));
        assert!(matches!(
            error.downcast_ref::<GuardianError>(),
            Some(GuardianError::InvalidInputs(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_filenames_when_loading_siblings() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join(OsString::from_vec(b"alice\xff.asc".to_vec()));
        let (public, _) = mock_pgp_keypair();
        std::fs::write(&path, public).unwrap();
        for filename in [
            b"alice\xff.attestation-device.pem".as_slice(),
            b"alice\xff.attestation-sig.pem".as_slice(),
            b"alice\xff.attestation-dec.pem".as_slice(),
        ] {
            std::fs::write(
                dir.path().join(OsString::from_vec(filename.to_vec())),
                b"not an attestation",
            )
            .unwrap();
        }
        let error = load_attested_kp_cert(&path).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<GuardianError>(),
            Some(GuardianError::InvalidInputs(_))
        ));
    }
}
