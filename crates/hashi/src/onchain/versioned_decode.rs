// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Self-describing decode of version-divergent dynamic-field values.
//!
//! When a package upgrade changes the *type* stored in a dynamic-field slot — a
//! v2 replaces type A with type B in the same bucket, e.g. the TOB nonce-cert
//! buckets gaining stamped variants — a reader must decide which layout to
//! BCS-decode the bytes as. Rather than infer that from a global version flag
//! (which can lag the actual on-chain state mid-upgrade and mis-decode a
//! straggler field written before the flip), we read the field's own on-chain
//! `value_type` (`DynamicField.value_type`) and decode exactly what the chain
//! reports.
//!
//! This is transition-safe: during an upgrade a mix of old- and new-layout
//! fields is each decoded correctly, and a layout this binary does not implement
//! fails cleanly (a clear error) instead of silently misparsing. It complements
//! the [`super::version`] active-version gate: that halts *writes* when the
//! chain is ahead; this makes *reads* fail loud rather than wrong.
//!
//! Identification is [`MoveType::matches`] against the Rust mirrors — the full
//! tag, defining package address included, so the mirrors stay the single
//! source of truth for type identity and a same-name type from a foreign
//! package is rejected rather than trusted. The defining address is resolved
//! through the version that introduced the type ([`MoveType::PACKAGE_VERSION`]),
//! which never moves across upgrades. A tag whose introducing version this
//! node has not yet observed in the package history fails the match and
//! surfaces as a clean unknown-type error — loud and retryable, never a
//! misdecode.

use anyhow::Context;
use anyhow::Result;
use hashi_types::move_types::EpochCertsV1;
use hashi_types::move_types::MoveType;
use hashi_types::move_types::PackageVersions;
use hashi_types::move_types::StampedEpochCertsV1;
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

/// The layout family of a TOB certificate bucket, identified by its on-chain
/// value type.
///
/// The bucket structs (`EpochCertsV1` / `StampedEpochCertsV1`) are BCS-identical
/// — the divergence is in the `LinkedTable` node values they hold
/// (`DealerSubmissionV1` vs the stamped variant). So the bucket's type is
/// what tells a reader which node layout to expect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TobCertLayout {
    /// `tob::EpochCertsV1` — nodes are `DealerSubmissionV1`.
    Bare,
    /// `tob::StampedEpochCertsV1` — nodes carry a timestamp. Decoding it
    /// requires binary support for the stamped types (the nonce dealer-cert
    /// window work); a build without them identifies the layout but must not
    /// attempt to decode its nodes.
    Stamped,
}

impl TobCertLayout {
    /// Identify the bucket layout from its on-chain value type: the tag must
    /// fully match one of the known mirrors via [`MoveType::matches`].
    pub fn from_struct_tag(packages: &PackageVersions, tag: &StructTag) -> Result<Self> {
        if EpochCertsV1::matches(packages, tag) {
            Ok(Self::Bare)
        } else if StampedEpochCertsV1::matches(packages, tag) {
            Ok(Self::Stamped)
        } else {
            anyhow::bail!(
                "unknown TOB cert bucket type: {}::{}::{}",
                tag.address(),
                tag.module(),
                tag.name()
            )
        }
    }
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
    fn identifies_bare_and_stamped_at_their_defining_addresses() {
        assert_eq!(
            TobCertLayout::from_struct_tag(&packages(), &addr_tag(0x7, "tob::EpochCertsV1"))
                .unwrap(),
            TobCertLayout::Bare
        );
        // Introduced by v2, so its defining address is the v2 package.
        assert_eq!(
            TobCertLayout::from_struct_tag(&packages(), &addr_tag(0x9, "tob::StampedEpochCertsV1"))
                .unwrap(),
            TobCertLayout::Stamped
        );
    }

    #[test]
    fn rejects_unknown_name_and_wrong_module() {
        assert!(
            TobCertLayout::from_struct_tag(&packages(), &addr_tag(0x7, "tob::SomethingElse"))
                .is_err()
        );
        assert!(
            TobCertLayout::from_struct_tag(&packages(), &addr_tag(0x7, "other::EpochCertsV1"))
                .is_err()
        );
    }

    #[test]
    fn rejects_a_known_name_at_a_foreign_address() {
        // Right module::name, wrong defining package: a same-name type from a
        // package outside the history must not be trusted.
        assert!(
            TobCertLayout::from_struct_tag(&packages(), &tag("0x42::tob::EpochCertsV1")).is_err()
        );
        // A known name at the *other* version's address is also rejected: the
        // defining address of a type never moves.
        assert!(
            TobCertLayout::from_struct_tag(&packages(), &addr_tag(0x9, "tob::EpochCertsV1"))
                .is_err()
        );
    }

    #[test]
    fn field_value_type_requires_the_mask_field() {
        let missing = DynamicField::default();
        assert!(field_value_type(&missing).is_err());

        let bare = format!(
            "{}::tob::EpochCertsV1",
            Address::from_bytes([0x7; 32]).unwrap()
        );
        let present = DynamicField::default().with_value_type(bare);
        let parsed = field_value_type(&present).unwrap();
        assert_eq!(
            TobCertLayout::from_struct_tag(&packages(), &parsed).unwrap(),
            TobCertLayout::Bare
        );
    }
}
