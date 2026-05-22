// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Derived components mirroring on-chain Move types.
//!
//! Each entry here is a Rust newtype wrapping one of the
//! `hashi_types::move_types` mirrors plus a [`sui_ecs::Derived`] impl
//! that parses the raw `sui_sdk_types::Object`'s BCS contents into the
//! mirror when the on-chain `StructTag` matches.
//!
//! Type matching is by `module` + `name` (and, for dynamic fields, by
//! the value-side type parameter), not by full struct tag. This keeps
//! parsing stable across package upgrades — the `Address` of the
//! package changes but `hashi::hashi::Hashi` is still the same Move
//! struct.

use std::any::TypeId;

use sui_ecs::{Component, Derived, Index, OneToOne, World};
use sui_sdk_types::{Address, Object, StructTag, TypeTag};

use hashi_types::move_types;

use crate::onchain::{convert_move_uncompressed_g1_pubkey, parse_encryption_public_key, types};

// ---- top-level objects --------------------------------------------------

/// Parsed contents of the singleton `hashi::hashi::Hashi` Move object.
#[derive(Debug)]
pub struct HashiRoot(pub move_types::Hashi);

impl Component for HashiRoot {}

impl Derived for HashiRoot {
    fn dependencies() -> Vec<TypeId> {
        vec![TypeId::of::<Object>()]
    }

    fn compute(world: &World, entity: Address) -> Option<Self> {
        parse_struct::<move_types::Hashi>(world, entity, "hashi", "Hashi").map(HashiRoot)
    }
}

/// Parsed contents of the `BitcoinState` dynamic field that hangs off
/// the Hashi root. Contains the deposit queue, withdrawal queue, and
/// UTXO pool bag ids — the entry points for the Bitcoin-side state
/// graph.
#[derive(Debug)]
pub struct BitcoinStateField(pub move_types::Field<move_types::BitcoinStateKey, move_types::BitcoinState>);

impl Component for BitcoinStateField {}

impl Derived for BitcoinStateField {
    fn dependencies() -> Vec<TypeId> {
        vec![TypeId::of::<Object>()]
    }

    fn compute(world: &World, entity: Address) -> Option<Self> {
        let obj = world.get::<Object>(entity)?;
        let ms = obj.as_struct()?;
        let tag = ms.object_type();
        if !is_dynamic_field(tag) {
            return None;
        }
        // value-side type param must be hashi::bitcoin_state::BitcoinState.
        let TypeTag::Struct(v) = tag.type_params().get(1)? else {
            return None;
        };
        if v.module().as_str() != "bitcoin_state" || v.name().as_str() != "BitcoinState" {
            return None;
        }
        bcs::from_bytes(ms.contents()).ok().map(BitcoinStateField)
    }
}

// ---- per-entry dynamic fields (one entity per bag entry) ---------------

/// One validator's `MemberInfo` — the raw move-type as it sits in the
/// `Field<Address, MemberInfo>` dynamic field. Kept separate from the
/// "rich" parsed version (see [`RichMemberInfo`]) so consumers that
/// only need the wire shape don't pay for BLS validation, and so the
/// TLS reverse index can be populated even when BLS parsing of the
/// same entry would have failed.
#[derive(Debug)]
pub struct MemberInfoEntry(pub move_types::MemberInfo);

impl Component for MemberInfoEntry {}

impl Derived for MemberInfoEntry {
    fn dependencies() -> Vec<TypeId> {
        vec![TypeId::of::<Object>()]
    }

    fn compute(world: &World, entity: Address) -> Option<Self> {
        let obj = world.get::<Object>(entity)?;
        let ms = obj.as_struct()?;
        let tag = ms.object_type();
        if !is_field_with_value(tag, "committee_set", "MemberInfo") {
            return None;
        }
        bcs::from_bytes::<move_types::Field<Address, move_types::MemberInfo>>(ms.contents())
            .ok()
            .map(|f| MemberInfoEntry(f.value))
    }
}

/// Validated `MemberInfo` — same `types::MemberInfo` shape the legacy
/// container produces. Derived from [`MemberInfoEntry`], so the
/// scheduler re-runs the parse automatically whenever the underlying
/// chain object changes. Entries whose BLS bytes don't decode silently
/// produce `None` and the component is dropped for that entity — the
/// legacy path's behavior is to panic, which is wrong for a derivation
/// (it would tear down the entire world).
#[derive(Debug, Clone)]
pub struct RichMemberInfo(pub types::MemberInfo);

impl Component for RichMemberInfo {}

impl Derived for RichMemberInfo {
    fn dependencies() -> Vec<TypeId> {
        vec![TypeId::of::<MemberInfoEntry>()]
    }

    fn compute(world: &World, entity: Address) -> Option<Self> {
        let raw = world.get::<MemberInfoEntry>(entity)?;
        let move_types::MemberInfo {
            validator_address,
            operator_address,
            next_epoch_public_key,
            endpoint_url,
            tls_public_key,
            next_epoch_encryption_public_key,
        } = &raw.0;

        // blst panics on malformed G1 bytes; treat that as "this
        // entry isn't representable as a rich MemberInfo" rather than
        // letting the panic escape the derivation.
        let bls = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            convert_move_uncompressed_g1_pubkey(next_epoch_public_key)
        }))
        .ok()?;

        Some(RichMemberInfo(types::MemberInfo {
            validator_address: *validator_address,
            operator_address: *operator_address,
            next_epoch_public_key: bls,
            endpoint_url: endpoint_url.clone().try_into().ok(),
            tls_public_key: tls_public_key.as_slice().try_into().ok(),
            next_epoch_encryption_public_key: parse_encryption_public_key(
                next_epoch_encryption_public_key.as_slice(),
            )
            .map(Into::into),
        }))
    }
}

/// Reverse index: validator TLS public key bytes -> validator address.
///
/// Driven by `MemberInfoEntry` (the *raw* shape) rather than
/// `RichMemberInfo`, so the index is populated regardless of whether
/// BLS validation succeeds for an entry. The TLS check only needs 32
/// well-formed bytes; we don't care about the BLS key here.
pub struct TlsKeyToAddress;

impl Index for TlsKeyToAddress {
    type Storage = OneToOne<[u8; 32], Address>;
}

/// One per-epoch `Committee` sitting in a `Field<u64, Committee>` on
/// the committees.committees bag.
#[derive(Debug)]
pub struct CommitteeEntry(pub move_types::Committee);

impl Component for CommitteeEntry {}

impl Derived for CommitteeEntry {
    fn dependencies() -> Vec<TypeId> {
        vec![TypeId::of::<Object>()]
    }

    fn compute(world: &World, entity: Address) -> Option<Self> {
        let obj = world.get::<Object>(entity)?;
        let ms = obj.as_struct()?;
        let tag = ms.object_type();
        if !is_field_with_value(tag, "committee", "Committee") {
            return None;
        }
        bcs::from_bytes::<move_types::Field<u64, move_types::Committee>>(ms.contents())
            .ok()
            .map(|f| CommitteeEntry(f.value))
    }
}

/// One pending deposit request, in a `Field<Address, DepositRequest>`
/// dynamic field on `BitcoinState.deposit_queue.requests`.
#[derive(Debug)]
pub struct DepositRequestEntry(pub move_types::DepositRequest);

impl Component for DepositRequestEntry {}

impl Derived for DepositRequestEntry {
    fn dependencies() -> Vec<TypeId> {
        vec![TypeId::of::<Object>()]
    }

    fn compute(world: &World, entity: Address) -> Option<Self> {
        let obj = world.get::<Object>(entity)?;
        let ms = obj.as_struct()?;
        let tag = ms.object_type();
        if !is_field_with_value(tag, "deposit_queue", "DepositRequest") {
            return None;
        }
        bcs::from_bytes::<move_types::Field<Address, move_types::DepositRequest>>(ms.contents())
            .ok()
            .map(|f| DepositRequestEntry(f.value))
    }
}

/// One on-chain proposal. Proposals are dynamic-object-fields (each
/// proposal is its own top-level Move object stored under a key in the
/// active/executed bag), so the inner Move struct is `Proposal<T>` for
/// some `T`. We discriminate `T` via the outer struct tag's type param
/// and dispatch to the right BCS layout.
///
/// Stored as the lightweight `{id, timestamp_ms, proposal_type}` shape
/// the existing system uses — that's what consumers actually need.
#[derive(Debug, Clone)]
pub struct ProposalEntry {
    pub id: Address,
    pub timestamp_ms: u64,
    pub proposal_type: ProposalType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalType {
    UpdateConfig,
    EnableVersion,
    DisableVersion,
    Upgrade,
    EmergencyPause,
    AbortReconfig,
    UpdateGuardian,
    Unknown(String),
}

impl Component for ProposalEntry {}

impl Derived for ProposalEntry {
    fn dependencies() -> Vec<TypeId> {
        vec![TypeId::of::<Object>()]
    }

    fn compute(world: &World, entity: Address) -> Option<Self> {
        let obj = world.get::<Object>(entity)?;
        let ms = obj.as_struct()?;
        let tag = ms.object_type();
        if tag.module().as_str() != "proposal" || tag.name().as_str() != "Proposal" {
            return None;
        }
        let proposal_type = classify_proposal(tag.type_params().first()?);
        let contents = ms.contents();
        let (id, timestamp_ms) = match &proposal_type {
            ProposalType::UpdateConfig => parse_proposal::<move_types::UpdateConfig>(contents)?,
            ProposalType::EnableVersion => parse_proposal::<move_types::EnableVersion>(contents)?,
            ProposalType::DisableVersion => parse_proposal::<move_types::DisableVersion>(contents)?,
            ProposalType::Upgrade => parse_proposal::<move_types::Upgrade>(contents)?,
            ProposalType::EmergencyPause => parse_proposal::<move_types::EmergencyPause>(contents)?,
            ProposalType::AbortReconfig => parse_proposal::<move_types::AbortReconfig>(contents)?,
            ProposalType::UpdateGuardian => parse_proposal::<move_types::UpdateGuardian>(contents)?,
            ProposalType::Unknown(_) => return None,
        };
        Some(ProposalEntry {
            id,
            timestamp_ms,
            proposal_type,
        })
    }
}

// ---- helpers -----------------------------------------------------------

fn parse_struct<T: serde::de::DeserializeOwned>(
    world: &World,
    entity: Address,
    module: &str,
    name: &str,
) -> Option<T> {
    let obj = world.get::<Object>(entity)?;
    let ms = obj.as_struct()?;
    let tag = ms.object_type();
    if tag.module().as_str() != module || tag.name().as_str() != name {
        return None;
    }
    bcs::from_bytes(ms.contents()).ok()
}

fn parse_proposal<T: serde::de::DeserializeOwned>(contents: &[u8]) -> Option<(Address, u64)> {
    bcs::from_bytes::<move_types::Proposal<T>>(contents)
        .ok()
        .map(|p| (p.id, p.timestamp_ms))
}

/// True when the struct tag is `0x2::dynamic_field::Field` (regardless
/// of type params). Used as a first-pass filter before checking the
/// value-side type parameter.
fn is_dynamic_field(tag: &StructTag) -> bool {
    tag.module().as_str() == "dynamic_field" && tag.name().as_str() == "Field"
}

/// True when the struct tag is a `Field<_, V>` whose `V` is the struct
/// `<package>::<module>::<name>`. Package is ignored so upgrades don't
/// invalidate the match.
fn is_field_with_value(tag: &StructTag, module: &str, name: &str) -> bool {
    if !is_dynamic_field(tag) {
        return false;
    }
    let Some(TypeTag::Struct(v)) = tag.type_params().get(1) else {
        return false;
    };
    v.module().as_str() == module && v.name().as_str() == name
}

fn classify_proposal(type_param: &TypeTag) -> ProposalType {
    let TypeTag::Struct(s) = type_param else {
        return ProposalType::Unknown(format!("{type_param:?}"));
    };
    match (s.module().as_str(), s.name().as_str()) {
        ("update_config", "UpdateConfig") => ProposalType::UpdateConfig,
        ("enable_version", "EnableVersion") => ProposalType::EnableVersion,
        ("disable_version", "DisableVersion") => ProposalType::DisableVersion,
        ("upgrade", "Upgrade") => ProposalType::Upgrade,
        ("emergency_pause", "EmergencyPause") => ProposalType::EmergencyPause,
        ("abort_reconfig", "AbortReconfig") => ProposalType::AbortReconfig,
        ("update_guardian", "UpdateGuardian") => ProposalType::UpdateGuardian,
        (m, n) => ProposalType::Unknown(format!("{m}::{n}")),
    }
}

/// Register every component this module defines on `world` so the
/// scheduler will keep parsed values in sync with their underlying
/// `Object`s. Also wires up framework-maintained indexes such as
/// [`TlsKeyToAddress`].
pub fn install(world: &mut World) {
    world.register_derived::<HashiRoot>();
    world.register_derived::<BitcoinStateField>();
    world.register_derived::<MemberInfoEntry>();
    world.register_derived::<RichMemberInfo>();
    world.register_derived::<CommitteeEntry>();
    world.register_derived::<DepositRequestEntry>();
    world.register_derived::<ProposalEntry>();

    world
        .register_index::<TlsKeyToAddress>()
        .driven_by::<MemberInfoEntry>()
        .on_insert(|idx, _entity, info| {
            // The on-chain field is `vector<u8>` so anything other than
            // 32 bytes is invalid; skip those rather than truncating.
            if let Ok(bytes) = <[u8; 32]>::try_from(info.0.tls_public_key.as_slice()) {
                idx.insert(bytes, info.0.validator_address);
            }
        })
        .on_remove(|idx, _entity, info| {
            if let Ok(bytes) = <[u8; 32]>::try_from(info.0.tls_public_key.as_slice()) {
                idx.remove(&bytes);
            }
        })
        .register();
}

