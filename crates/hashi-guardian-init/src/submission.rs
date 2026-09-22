// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A current KP's signed rotation submission, carried to the operator as a
//! file: the prost-encoded wire message, decoded with the conversion the
//! enclave applies. It holds nothing secret.

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

    #[test]
    fn rejects_a_file_that_is_not_a_submission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage");
        std::fs::write(&path, b"not a submission").unwrap();
        assert!(read(&path).is_err());
        assert!(read(&dir.path().join("missing")).is_err());
    }
}
