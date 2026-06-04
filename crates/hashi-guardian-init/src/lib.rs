// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Off-enclave tooling that initializes a guardian.
//!
//! Houses the key-provisioner and (later) operator init flows, which read the
//! guardian's S3 logs via `hashi_guardian::s3_reader`, verify the attested
//! enclave, and emit the artifacts that drive `ProvisionerInit` / boot.

/// Key-provisioner init flow (IOP-225 checks A-E).
pub mod provisioner_init;
