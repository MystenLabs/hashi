// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ephemeral keypair load/persist. In `non-enclave-dev` builds the guardian
//! persists its keypair to `GUARDIAN_EPH_KEY_PATH` (when set) so a redeploy keeps
//! the same signing pubkey; the enclave build always generates fresh keys.

use anyhow::Result;
use hashi_types::guardian::GuardianEncKeyPair;
use hashi_types::guardian::GuardianSignKeyPair;
use rand::CryptoRng;
use rand::RngCore;

/// Path the guardian persists its ephemeral keypair to (non-enclave-dev only).
pub const EPH_KEY_PATH_ENV: &str = "GUARDIAN_EPH_KEY_PATH";

fn generate(rng: &mut (impl CryptoRng + RngCore)) -> (GuardianSignKeyPair, GuardianEncKeyPair) {
    let signing = GuardianSignKeyPair::new(&mut *rng);
    let encryption = GuardianEncKeyPair::random(&mut *rng);
    (signing, encryption)
}

#[cfg(not(feature = "non-enclave-dev"))]
pub fn load_or_create(
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(GuardianSignKeyPair, GuardianEncKeyPair)> {
    Ok(generate(rng))
}

#[cfg(feature = "non-enclave-dev")]
pub fn load_or_create(
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(GuardianSignKeyPair, GuardianEncKeyPair)> {
    match std::env::var(EPH_KEY_PATH_ENV) {
        Ok(path) if !path.is_empty() => {
            persist::load_or_create_at(std::path::Path::new(&path), rng)
        }
        _ => Ok(generate(rng)),
    }
}

#[cfg(feature = "non-enclave-dev")]
mod persist {
    use super::*;
    use anyhow::Context;
    use serde::Deserialize;
    use serde::Serialize;
    use std::path::Path;
    use tracing::info;

    // hex-encoded raw key bytes. The encryption pubkey is stored alongside the
    // secret because hpke exposes no sk -> pk derivation.
    #[derive(Serialize, Deserialize)]
    struct PersistedEphKeys {
        signing_sk: String,
        enc_sk: String,
        enc_pk: String,
    }

    pub(super) fn load_or_create_at(
        path: &Path,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(GuardianSignKeyPair, GuardianEncKeyPair)> {
        if path.exists() {
            let keys = load(path)?;
            info!("Loaded guardian ephemeral keypair from {}.", path.display());
            Ok(keys)
        } else {
            let (signing, encryption) = generate(rng);
            store(path, &signing, &encryption)?;
            info!(
                "Persisted guardian ephemeral keypair to {}.",
                path.display()
            );
            Ok((signing, encryption))
        }
    }

    fn load(path: &Path) -> Result<(GuardianSignKeyPair, GuardianEncKeyPair)> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let keys: PersistedEphKeys = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing {}", path.display()))?;

        let signing = GuardianSignKeyPair::try_from(hex::decode(&keys.signing_sk)?.as_slice())
            .map_err(|e| anyhow::anyhow!("invalid signing key: {e}"))?;
        let encryption = GuardianEncKeyPair::from_bytes(
            &hex::decode(&keys.enc_sk)?,
            &hex::decode(&keys.enc_pk)?,
        )
        .map_err(|e| anyhow::anyhow!("invalid encryption key: {e}"))?;
        Ok((signing, encryption))
    }

    fn store(
        path: &Path,
        signing: &GuardianSignKeyPair,
        encryption: &GuardianEncKeyPair,
    ) -> Result<()> {
        let keys = PersistedEphKeys {
            signing_sk: hex::encode(signing.to_bytes()),
            enc_sk: hex::encode(encryption.to_secret_bytes()),
            enc_pk: hex::encode(encryption.public_key_bytes()),
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        write_private(path, &serde_json::to_vec_pretty(&keys)?)
            .with_context(|| format!("writing {}", path.display()))
    }

    // Owner-only, written via temp file + rename so a crash can't leave a
    // half-written keyfile.
    fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        let tmp = path.with_extension("tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn persist_then_reload_returns_same_keys() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("eph_keys.json");
            let mut rng = rand::thread_rng();

            let (s1, e1) = load_or_create_at(&path, &mut rng).unwrap();
            assert!(path.exists());

            let (s2, e2) = load_or_create_at(&path, &mut rng).unwrap();
            assert_eq!(s1.to_bytes(), s2.to_bytes());
            assert_eq!(e1.to_secret_bytes(), e2.to_secret_bytes());
            assert_eq!(e1.public_key_bytes(), e2.public_key_bytes());
        }

        #[cfg(unix)]
        #[test]
        fn keyfile_is_owner_only() {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("eph_keys.json");
            load_or_create_at(&path, &mut rand::thread_rng()).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
