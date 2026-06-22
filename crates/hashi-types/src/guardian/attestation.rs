// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;

use super::GuardianPubKey;
use super::GuardianResult;
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use super::errors::GuardianError::InvalidInputs;
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use super::time_utils::now_timestamp_ms;

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

    /// Verify this Nitro attestation document (COSE signature + AWS cert chain
    /// to the Nitro root + freshness), that it commits to `signing_pubkey`, and
    /// that its PCR0 matches `build_pcrs`.
    pub fn verify(
        &self,
        signing_pubkey: &GuardianPubKey,
        build_pcrs: &BuildPcrs,
    ) -> GuardianResult<()> {
        #[cfg(any(test, feature = "non-enclave-dev"))]
        {
            let _ = (signing_pubkey, build_pcrs);
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

/// Known-good Nitro measurement an attestation is pinned to. Construction
/// mandates PCR0 - the hash of the whole enclave image (EIF), which uniquely
/// identifies the build - so a pinning policy can never omit it.
///
/// We record only PCR0: in a StageX (reproducible, single-binary) build it is
/// the only measurement that carries signal - the others (kernel, bootloader,
/// IAM role) are constant or irrelevant for our pinning.
///
/// TODO: holds only a single PCR0, so it can't accept the two valid measurements
/// that briefly coexist during a software upgrade (old + new image), nor pin
/// additional PCRs. A `commit -> PCRs` allowlist keyed on `untrusted_git_revision`
/// is the follow-up.
#[derive(Debug, Clone)]
pub struct BuildPcrs {
    pcr0: Vec<u8>,
}

impl BuildPcrs {
    pub fn new(pcr0: Vec<u8>) -> Self {
        Self { pcr0 }
    }

    pub fn pcr0(&self) -> &[u8] {
        &self.pcr0
    }
}

/// Deserialize from a hex string (optional `0x` prefix) - the form config files
/// pin PCR0 in.
impl<'de> Deserialize<'de> for BuildPcrs {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(deserializer)?;
        let pcr0 =
            hex::decode(hex_str.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
        Ok(Self { pcr0 })
    }
}
