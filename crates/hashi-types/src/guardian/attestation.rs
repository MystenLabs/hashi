// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

use super::GuardianInfo;
use super::GuardianPubKey;
use super::GuardianResult;
use super::errors::GuardianError::InvalidInputs;
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use super::time_utils::now_timestamp_ms;

/// Git commit revision reported by the enclave build.
pub type GitRevision = String;

/// Raw AWS Nitro attestation document bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NitroAttestation(Vec<u8>);

impl NitroAttestation {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Off-enclave (dev/test) stand-in for a real Nitro document. There is no
    /// NSM to produce one, so encode just the fields `verify` checks — the
    /// signing key it commits to and the build's PCR0. Used by the guardian's
    /// `non-enclave-dev` attestation path; never produced on a real enclave.
    pub fn mock(signing_pubkey: &GuardianPubKey, pcr0: &[u8]) -> Self {
        let doc = MockAttestationDoc {
            public_key: signing_pubkey.to_bytes(),
            pcr0: pcr0.to_vec(),
        };
        Self(bcs::to_bytes(&doc).expect("serialize mock attestation document"))
    }

    /// Verify this Nitro attestation document (COSE signature + AWS cert chain
    /// to the Nitro root + freshness), that it commits to `signing_pubkey`, and
    /// that its PCR0 matches `build_pcrs`.
    ///
    /// Off-enclave there is no NSM: the `non-enclave-dev` build checks the mock
    /// document's key + PCR0 binding (`verify_mock_attestation`); `cfg(test)` is a
    /// no-op. Real COSE/cert-chain verification runs only in enclave builds.
    pub fn verify(
        &self,
        signing_pubkey: &GuardianPubKey,
        build_pcrs: &BuildPcrs,
    ) -> GuardianResult<()> {
        #[cfg(test)]
        {
            // Unit tests build placeholder documents; the strict off-enclave
            // path is covered by `verify_mock_attestation`'s own tests.
            let _ = (signing_pubkey, build_pcrs);
            Ok(())
        }
        #[cfg(all(feature = "non-enclave-dev", not(test)))]
        {
            // No NSM off-enclave, so the COSE signature / cert chain can't be
            // checked — but the guardian still emits a mock document binding its
            // signing key + PCR0 (`NitroAttestation::mock`), so verify those.
            verify_mock_attestation(&self.0, signing_pubkey, build_pcrs)
        }
        #[cfg(not(any(test, feature = "non-enclave-dev")))]
        {
            use fastcrypto::nitro_attestation::parse_nitro_attestation;
            use fastcrypto::nitro_attestation::verify_nitro_attestation;

            // Bools: (is_upgraded_parsing, include_all_nonzero_pcrs,
            // always_include_required_pcrs). The last keeps PCR0 in `pcr_map` even if
            // zero, so the pin below can't be bypassed by a missing entry.
            let (signature, signed_message, doc) =
                parse_nitro_attestation(&self.0, true, true, true)
                    .map_err(|e| InvalidInputs(format!("attestation parse failed: {e}")))?;
            verify_nitro_attestation(&signature, &signed_message, &doc, now_timestamp_ms())
                .map_err(|e| InvalidInputs(format!("attestation verification failed: {e}")))?;

            let attested = doc
                .public_key
                .ok_or_else(|| InvalidInputs("attestation has no public_key".into()))?;
            if attested != signing_pubkey.to_bytes() {
                return Err(InvalidInputs(
                    "attestation public_key does not match the session signing pubkey".into(),
                ));
            }

            // Pin PCR0 (the whole EIF image hash).
            if doc.pcr_map.get(&0).map(Vec::as_slice) != Some(build_pcrs.pcr0()) {
                return Err(InvalidInputs(
                    "attestation PCR0 does not match the expected enclave image".into(),
                ));
            }
            Ok(())
        }
    }
}

/// A session's verified guardian info: the attestation-anchored signing pubkey,
/// the signed `GuardianInfo`, and the build PCRs proven by attestation.
#[derive(Debug, Clone)]
pub struct VerifiedSessionInfo {
    pub signing_pubkey: GuardianPubKey,
    pub info: GuardianInfo,
    pub build_pcrs: BuildPcrs,
}

/// Payload of a [`NitroAttestation::mock`] document — the subset of a real
/// Nitro document the off-enclave `verify` path can still check.
#[derive(Serialize, Deserialize)]
struct MockAttestationDoc {
    public_key: [u8; 32],
    pcr0: Vec<u8>,
}

/// Off-enclave counterpart to the real `verify`: skips the COSE signature / cert
/// chain (no NSM to produce them) but still checks the signing-key binding and
/// PCR0, so dev/e2e exercises the same policy a real node enforces.
#[cfg(any(test, feature = "non-enclave-dev"))]
fn verify_mock_attestation(
    bytes: &[u8],
    signing_pubkey: &GuardianPubKey,
    build_pcrs: &BuildPcrs,
) -> GuardianResult<()> {
    let doc: MockAttestationDoc = bcs::from_bytes(bytes)
        .map_err(|e| InvalidInputs(format!("mock attestation parse failed: {e}")))?;
    if doc.public_key != signing_pubkey.to_bytes() {
        return Err(InvalidInputs(
            "mock attestation public_key does not match the session signing pubkey".into(),
        ));
    }
    if doc.pcr0.as_slice() != build_pcrs.pcr0() {
        return Err(InvalidInputs(
            "mock attestation PCR0 does not match the expected enclave image".into(),
        ));
    }
    Ok(())
}

/// One enclave build: its git revision and known-good Nitro measurement. A build is
/// identified by its revision and pinned by PCR0 - the hash of the whole enclave
/// image (EIF), which uniquely identifies the build.
///
/// We record only PCR0: in a StageX (reproducible, single-binary) build it is
/// the only measurement that carries signal - the others (kernel, bootloader, IAM
/// role) are constant or irrelevant for our pinning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildPcrs {
    git_revision: GitRevision,
    pcr0: Vec<u8>,
}

impl BuildPcrs {
    pub fn new(git_revision: &str, pcr0: Vec<u8>) -> Self {
        Self {
            git_revision: git_revision.to_string(),
            pcr0,
        }
    }

    pub fn git_revision(&self) -> &str {
        &self.git_revision
    }

    pub fn pcr0(&self) -> &[u8] {
        &self.pcr0
    }
}

/// PCR pins for enclave builds that may appear in guardian attestations.
/// Used by GuardianReader in s3_reader.rs.
///
/// `current_build` is the current/live build. `prev_builds` contains older
/// builds that may still appear in persisted logs during an upgrade or replay.
/// Verification matches the signature-verified `untrusted_git_revision` to one
/// entry, then checks PCR0 against that entry. Callers use the resolved
/// `BuildPcrs` to enforce the policy for their context.
#[derive(Debug, Clone)]
pub struct PcrAllowlist {
    current_build: BuildPcrs,
    prev_builds: Vec<BuildPcrs>,
}

impl PcrAllowlist {
    pub fn new(
        current_build: BuildPcrs,
        prev_builds: impl IntoIterator<Item = BuildPcrs>,
    ) -> GuardianResult<Self> {
        let prev_builds = prev_builds.into_iter().collect::<Vec<_>>();
        let mut seen = BTreeSet::new();
        for build in std::iter::once(&current_build).chain(prev_builds.iter()) {
            if !seen.insert(build.git_revision.clone()) {
                return Err(InvalidInputs(format!(
                    "duplicate PCR allowlist entry for build '{}'",
                    build.git_revision
                )));
            }
        }

        Ok(Self {
            current_build,
            prev_builds,
        })
    }

    pub fn current_build(&self) -> &BuildPcrs {
        &self.current_build
    }

    pub fn prev_builds(&self) -> &[BuildPcrs] {
        &self.prev_builds
    }

    /// The `BuildPcrs` whose revision is `git_revision`.
    pub fn resolve(&self, git_revision: &str) -> GuardianResult<&BuildPcrs> {
        if self.current_build.git_revision == git_revision {
            return Ok(&self.current_build);
        }
        if let Some(prev_build) = self
            .prev_builds
            .iter()
            .find(|build| build.git_revision == git_revision)
        {
            return Ok(prev_build);
        }
        Err(InvalidInputs(format!(
            "enclave reports build '{git_revision}' not present in PCR allowlist"
        )))
    }

    pub fn is_current_build(&self, build_pcrs: &BuildPcrs) -> bool {
        self.current_build == *build_pcrs
    }

    pub fn require_current_build(&self, build_pcrs: &BuildPcrs) -> GuardianResult<()> {
        if self.is_current_build(build_pcrs) {
            Ok(())
        } else {
            Err(InvalidInputs(
                "guardian attestation matched a non-current build, but current build is required"
                    .into(),
            ))
        }
    }
}

impl<'de> Deserialize<'de> for BuildPcrs {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct BuildPcrsWire {
            git_revision: GitRevision,
            pcr0: String,
        }

        let wire = BuildPcrsWire::deserialize(deserializer)?;
        let pcr0 = hex::decode(wire.pcr0.trim_start_matches("0x")).map_err(|e| {
            serde::de::Error::custom(format!(
                "build '{}' pcr0 is not valid hex: {e}",
                wire.git_revision
            ))
        })?;
        Ok(BuildPcrs::new(&wire.git_revision, pcr0))
    }
}

impl<'de> Deserialize<'de> for PcrAllowlist {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct PcrAllowlistWire {
            current_build: BuildPcrs,
            #[serde(default)]
            prev_builds: Vec<BuildPcrs>,
        }

        let wire = PcrAllowlistWire::deserialize(deserializer)?;
        PcrAllowlist::new(wire.current_build, wire.prev_builds).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::super::GuardianSignKeyPair;
    use super::*;

    fn keypair() -> GuardianSignKeyPair {
        GuardianSignKeyPair::new(rand::thread_rng())
    }

    #[test]
    fn mock_attestation_accepts_matching_build_and_key() {
        let pubkey = keypair().verification_key();
        let att = NitroAttestation::mock(&pubkey, &[7u8; 48]);
        verify_mock_attestation(
            &att.into_bytes(),
            &pubkey,
            &BuildPcrs::new("test-build", vec![7u8; 48]),
        )
        .expect("matching mock attestation should verify");
    }

    #[test]
    fn mock_attestation_rejects_pcr0_mismatch() {
        let pubkey = keypair().verification_key();
        let att = NitroAttestation::mock(&pubkey, &[7u8; 48]);
        assert!(
            verify_mock_attestation(
                &att.into_bytes(),
                &pubkey,
                &BuildPcrs::new("test-build", vec![8u8; 48])
            )
            .is_err()
        );
    }

    #[test]
    fn mock_attestation_rejects_pubkey_mismatch() {
        let att = NitroAttestation::mock(&keypair().verification_key(), &[7u8; 48]);
        let other = keypair().verification_key();
        assert!(
            verify_mock_attestation(
                &att.into_bytes(),
                &other,
                &BuildPcrs::new("test-build", vec![7u8; 48])
            )
            .is_err()
        );
    }
}
