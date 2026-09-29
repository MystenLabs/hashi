// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Self-describing decode of dynamic-field values.
//!
//! A dynamic-field slot holds whatever type the package wrote into it, and a
//! package upgrade can start writing a different type into the same slot. A
//! reader therefore never assumes the layout of the bytes it is handed, and it
//! never infers the layout from a global version flag, which can lag the
//! actual on-chain state mid-upgrade and mis-decode a straggler field written
//! before the flip. It reads the field's own on-chain `value_type`
//! (`DynamicField.value_type`) and decodes only a type it implements.
//!
//! Every TOB certificate bucket is a `tob::EpochCertsV1`, so that is the one
//! type [`ensure_tob_cert_bucket`] accepts. Any other type fails cleanly (a
//! clear error) instead of silently misparsing: a bucket layout introduced by
//! a later package version fails loudly on a binary that predates it. This
//! complements the [`super::version`] active-version gate: that halts *writes*
//! when the chain is ahead; this makes *reads* fail loud rather than wrong.
//!
//! Identification is [`MoveType::matches`] against the Rust mirrors: the full
//! tag, defining package address included, so the mirrors stay the single
//! source of truth for type identity and a same-name type from a foreign
//! package is rejected rather than trusted. The defining address is resolved
//! through the version that introduced the type ([`MoveType::PACKAGE_VERSION`]),
//! which never moves across upgrades. A tag whose introducing version this
//! node has not yet observed in the package history fails the match and
//! surfaces as a clean unknown-type error: loud and retryable, never a
//! misdecode.

use anyhow::Context;
use anyhow::Result;
use hashi_types::move_types::EpochCertsV1;
use hashi_types::move_types::MoveType;
use hashi_types::move_types::PackageVersions;
use sui_rpc::proto::sui::rpc::v2::DynamicField;
use sui_sdk_types::StructTag;

/// The concrete Move type a dynamic field's value carries on chain. Requires
/// `value_type` in the `list_dynamic_fields` read mask.
pub fn field_value_type(field: &DynamicField) -> Result<StructTag> {
    let raw = field
        .value_type_opt()
        .context("dynamic field is missing value_type (add it to the read mask)")?;
    raw.parse::<StructTag>()
        .with_context(|| format!("parsing dynamic field value_type {raw:?}"))
}

/// Check that a TOB certificate bucket's on-chain value type is
/// `tob::EpochCertsV1`, whose `LinkedTable` nodes are `DealerSubmissionV1`.
/// The tag must fully match the mirror via [`MoveType::matches`]; any other
/// type is an error.
pub fn ensure_tob_cert_bucket(packages: &PackageVersions, tag: &StructTag) -> Result<()> {
    anyhow::ensure!(
        EpochCertsV1::matches(packages, tag),
        "unknown TOB cert bucket type: {}::{}::{}",
        tag.address(),
        tag.module(),
        tag.name()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use sui_sdk_types::Address;

    /// v1 published at 0x7, v2 at 0x9.
    fn packages() -> PackageVersions {
        PackageVersions::new(BTreeMap::from([
            (1, Address::from_bytes([0x7; 32]).unwrap()),
            (2, Address::from_bytes([0x9; 32]).unwrap()),
        ]))
    }

    fn tag(s: &str) -> StructTag {
        s.parse().unwrap()
    }

    fn addr_tag(byte: u8, rest: &str) -> StructTag {
        format!("{}::{rest}", Address::from_bytes([byte; 32]).unwrap())
            .parse()
            .unwrap()
    }

    #[test]
    fn identifies_the_bucket_at_its_defining_address() {
        ensure_tob_cert_bucket(&packages(), &addr_tag(0x7, "tob::EpochCertsV1")).unwrap();
    }

    #[test]
    fn rejects_unknown_name_and_wrong_module() {
        assert!(ensure_tob_cert_bucket(&packages(), &addr_tag(0x7, "tob::SomethingElse")).is_err());
        // A bucket type a later package version could introduce.
        assert!(ensure_tob_cert_bucket(&packages(), &addr_tag(0x9, "tob::EpochCertsV2")).is_err());
        assert!(
            ensure_tob_cert_bucket(&packages(), &addr_tag(0x7, "other::EpochCertsV1")).is_err()
        );
    }

    #[test]
    fn rejects_a_known_name_at_a_foreign_address() {
        // Right module::name, wrong defining package: a same-name type from a
        // package outside the history must not be trusted.
        assert!(ensure_tob_cert_bucket(&packages(), &tag("0x42::tob::EpochCertsV1")).is_err());
        // A known name at the *other* version's address is also rejected: the
        // defining address of a type never moves.
        assert!(ensure_tob_cert_bucket(&packages(), &addr_tag(0x9, "tob::EpochCertsV1")).is_err());
    }

    #[test]
    fn field_value_type_requires_the_mask_field() {
        let missing = DynamicField::default();
        assert!(field_value_type(&missing).is_err());

        let bucket = format!(
            "{}::tob::EpochCertsV1",
            Address::from_bytes([0x7; 32]).unwrap()
        );
        let present = DynamicField::default().with_value_type(bucket);
        let parsed = field_value_type(&present).unwrap();
        ensure_tob_cert_bucket(&packages(), &parsed).unwrap();
    }
}
