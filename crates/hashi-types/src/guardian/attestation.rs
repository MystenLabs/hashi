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
pub struct NitroAttestation(#[serde(with = "crate::guardian::serde_utils::base64_bytes")] Vec<u8>);

impl NitroAttestation {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Verify this Nitro attestation document (COSE signature + AWS cert chain to the
    /// Nitro root + freshness), that it commits to `signing_pubkey`, and that its
    /// PCR0 matches `build_pcrs`.
    ///
    /// In non-enclave dev/test builds the enclave emits a mock document, so the
    /// attestation check is a no-op, mirroring `get_attestation` `non-enclave-dev`
    /// stub behavior. Real verification runs only in enclave builds.
    pub fn verify(
        &self,
        signing_pubkey: &GuardianPubKey,
        build_pcrs: &BuildPcrs,
    ) -> GuardianResult<()> {
        #[cfg(any(test, feature = "non-enclave-dev"))]
        {
            let _ = (signing_pubkey, build_pcrs);
            // Real attestation is stubbed here — announce it loudly (once) so a
            // `non-enclave-dev` binary can't be mistaken for a real enclave.
            // Gated off `test` so unit tests stay quiet.
            #[cfg(all(feature = "non-enclave-dev", not(test)))]
            {
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    tracing::warn!(
                        "Nitro attestation verification DISABLED (non-enclave-dev build)"
                    );
                });
            }
            Ok(())
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

/// One enclave build: its git revision and known-good Nitro measurement. A build is
/// identified by its revision and pinned by PCR0 - the hash of the whole enclave
/// image (EIF), which uniquely identifies the build.
///
/// We record only PCR0: in a StageX (reproducible, single-binary) build it is
/// the only measurement that carries signal - the others (kernel, bootloader, IAM
/// role) are constant or irrelevant for our pinning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
