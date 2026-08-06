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
//! Identification keys on `(module, name)` only — [`MoveType::MODULE_NAME`],
//! so the Rust mirrors stay the single source of truth for type identity. A
//! Move type keeps its module and name across upgrades, and a divergent layout
//! must be a *new* type with a new name (an upgrade cannot change an existing
//! struct's layout — the compat gate enforces this), so the name is an
//! authoritative layout discriminator. Deliberately not the address-checking
//! [`MoveType::matches`]: the field's `value_type` is already authoritative
//! here, and address-keyed dispatch would reintroduce the mid-upgrade lag this
//! module exists to avoid.

use anyhow::Context;
use anyhow::Result;
use hashi_types::move_types::EpochCertsV1;
use hashi_types::move_types::MoveType;
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
/// (`DealerSubmissionV1` vs the stamped variant). So the bucket's type name is
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
    /// Identify the bucket layout from its on-chain value type.
    pub fn from_struct_tag(tag: &StructTag) -> Result<Self> {
        let key = (tag.module().as_str(), tag.name().as_str());
        if key == EpochCertsV1::MODULE_NAME {
            Ok(Self::Bare)
        } else if key == StampedEpochCertsV1::MODULE_NAME {
            Ok(Self::Stamped)
        } else {
            anyhow::bail!(
                "unknown TOB cert bucket type: {}::{}",
                tag.module(),
                tag.name()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(s: &str) -> StructTag {
        s.parse().unwrap()
    }

    #[test]
    fn identifies_bare_and_stamped_by_name() {
        assert_eq!(
            TobCertLayout::from_struct_tag(&tag("0x7::tob::EpochCertsV1")).unwrap(),
            TobCertLayout::Bare
        );
        // Distinct package address (a v2 upgrade) — dispatch is by name, so the
        // address is irrelevant to which layout it is.
        assert_eq!(
            TobCertLayout::from_struct_tag(&tag("0x9::tob::StampedEpochCertsV1")).unwrap(),
            TobCertLayout::Stamped
        );
    }

    #[test]
    fn rejects_unknown_name_and_wrong_module() {
        assert!(TobCertLayout::from_struct_tag(&tag("0x7::tob::SomethingElse")).is_err());
        assert!(TobCertLayout::from_struct_tag(&tag("0x7::other::EpochCertsV1")).is_err());
    }

    #[test]
    fn field_value_type_requires_the_mask_field() {
        let missing = DynamicField::default();
        assert!(field_value_type(&missing).is_err());

        let present = DynamicField::default().with_value_type("0x7::tob::EpochCertsV1");
        let parsed = field_value_type(&present).unwrap();
        assert_eq!(
            TobCertLayout::from_struct_tag(&parsed).unwrap(),
            TobCertLayout::Bare
        );
    }
}
