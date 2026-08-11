// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Registry of Hashi committee state: registered member metadata
/// (`MemberInfo`), per-epoch `Committee`s, the current epoch, the MPC
/// threshold public key, and the pending epoch change while a reconfiguration
/// is in flight. Members register (and rotate keys/metadata) here between
/// epochs; `start_reconfig` builds the next committee from Sui's active
/// validator set, and `end_reconfig` activates it — storing the outgoing
/// committee's handoff certificate for non-initial reconfigs.
#[allow(unused_function, unused_field)]
module hashi::committee_set;

use hashi::{committee::{Self, Committee}, config::{Self, Config}, config_value};
use std::string::String;
use sui::{
    bag::Bag,
    bcs,
    bls12381::{UncompressedG1, bls12381_min_pk_verify, g1_from_bytes, g1_to_uncompressed_g1},
    group_ops::Element
};

// ~~~~~~~ Constants ~~~~~~~

/// `MemberInfo.extra_fields` key holding the governance "ignored" flag as a
/// `Bool` value. An absent key means not ignored, so members registered
/// before this key existed need no migration.
///
/// The flag lives in `extra_fields` only because `MemberInfo`'s layout is
/// frozen on the deployed network.
///
/// TODO(pre-mainnet-wipe): when testnet is wiped and the Move versions are
/// squashed before mainnet, promote this to a root-level `ignored: bool`
/// field on `MemberInfo` and delete this key (and its Rust mirror
/// `MEMBER_IGNORED_KEY` / the `extra_fields` decode in
/// `convert_move_member_info`).
const MEMBER_IGNORED_KEY: vector<u8> = b"ignored";

/// `MemberInfo.extra_fields` key holding the voluntary "resigned" flag as a
/// `Bool` value. Set by `request_resignation`, cleared by
/// `clear_resignation`, honored by committee formation (skip); the
/// registration itself is deleted by the permissionless
/// `remove_inactive_member` once the member holds no epoch duties.
///
/// TODO(pre-mainnet-wipe): promote to a root-level `resigned: bool` field on
/// `MemberInfo` together with `MEMBER_IGNORED_KEY` above.
const MEMBER_RESIGNED_KEY: vector<u8> = b"resigned";

// ~~~~~~~ Errors ~~~~~~~

#[error(code = 0)]
const EMemberNotRegistered: vector<u8> = b"No member is registered under this validator address";
#[error(code = 1)]
const EAlreadyResigned: vector<u8> = b"Member has already requested resignation";
#[error(code = 2)]
const ENotResigned: vector<u8> = b"Member has no pending resignation to withdraw";
#[error(code = 4)]
const EMemberStillActive: vector<u8> = b"Member is in the current or pending committee";
#[error(code = 5)]
const ECannotRemoveIgnoredMember: vector<u8> =
    b"Governance-ignored members stay registered until un-ignored";
#[error(code = 6)]
const EMemberNotRemovable: vector<u8> =
    b"Member is neither resigned nor gone from the Sui validator set";
#[error(code = 3)]
const ELastActiveMember: vector<u8> =
    b"Cannot resign as the last active committee member; the committee would be unable to form";

// ~~~~~~~ Structs ~~~~~~~

public struct CommitteeSet has store {
    members: Bag,
    /// The current epoch.
    epoch: u64,
    committees: Bag,
    pending_epoch_change: Option<PendingEpochChange>,
    /// The MPC committee's threshold public key.
    mpc_public_key: vector<u8>,
}

/// Reconfiguration state while a new committee is pending activation.
///
/// `epoch` is the next epoch that will become current when reconfig ends.
/// For non-initial reconfigs, `committee_handoff_cert` is filled by the
/// current committee before `end_reconfig` activates the pending committee.
public struct PendingEpochChange has copy, drop, store {
    epoch: u64,
    committee_handoff_cert: Option<committee::CommitteeSignature>,
}

/// Key for a completed committee handoff certificate.
///
/// `epoch` is the source epoch of the handoff, i.e. the current epoch at the
/// time the old committee signs the transition to the pending committee.
public struct CommitteeHandoffKey has copy, drop, store {
    epoch: u64,
}

/// Certificate showing that an old committee approved the next committee.
///
/// Stored after `end_reconfig` for non-initial reconfigs so the new committee
/// epoch can be associated with the old committee's transition signature.
public struct CommitteeHandoff has store {
    next_epoch: u64,
    cert: committee::CommitteeSignature,
}

public struct MemberInfo has store {
    /// Sui Validator Address of this node
    validator_address: address,
    /// Sui Address of an operations account
    operator_address: address,
    /// bls12381 public key to be used in the next epoch.
    ///
    /// The public key for this node which is active in the current epoch can
    /// be found in the `Committee` struct.
    ///
    /// This public key can be rotated but will only take effect at the
    /// beginning of the next epoch.
    next_epoch_public_key: Element<UncompressedG1>,
    /// The HTTPS network address where the instance of the `hashi` service for
    /// this validator can be reached.
    ///
    /// This HTTPS address can be rotated and any such updates will take effect
    /// immediately.
    endpoint_url: String,
    /// ed25519 public key used to verify TLS self-signed x509 certs
    ///
    /// This public key can be rotated and any such updates will take effect
    /// immediately.
    tls_public_key: vector<u8>,
    /// A 32-byte ristretto255 Ristretto encryption public key (ristretto255
    /// RistrettoPoint) for MPC ECIES, to be used in the next epoch.
    ///
    /// This public key can be rotated but will only take effect at the
    /// beginning of the next epoch.
    next_epoch_encryption_public_key: vector<u8>,
    /// Open-ended per-member extension slot; lets future upgrades attach new
    /// member data (e.g. per-protocol keys) without a MemberInfoV2 migration.
    ///
    /// Carries the governance flags (`MEMBER_IGNORED_KEY`) as typed values
    /// because MemberInfo's layout is frozen on the deployed network. When
    /// testnet is wiped before mainnet, promote them to real `bool` fields
    /// on MemberInfo and delete the keys.
    extra_fields: Config,
}

// ~~~~~~~ Package Functions ~~~~~~~

public(package) fun create(ctx: &mut TxContext): CommitteeSet {
    CommitteeSet {
        members: sui::bag::new(ctx),
        epoch: 0,
        committees: sui::bag::new(ctx),
        pending_epoch_change: option::none(),
        mpc_public_key: std::vector::empty(),
    }
}

/// Register as a member of Hashi.
///
/// Only BLS key is required at registration time, other info can be set in
/// other PTB commands or at some point in the future.
public(package) fun new_member(
    committee_set: &mut CommitteeSet,
    sui_system: &sui_system::sui_system::SuiSystemState,
    ctx: &TxContext,
) {
    let validator_address = ctx.sender();

    // Only allow Sui Validators to register as Hashi members
    assert!(sui_system.active_validator_addresses_ref().contains(&validator_address));

    let member = MemberInfo {
        validator_address: validator_address,
        operator_address: validator_address,
        next_epoch_public_key: g1_to_uncompressed_g1(&sui::bls12381::g1_identity()),
        endpoint_url: std::vector::empty().to_string(),
        tls_public_key: std::vector::empty(),
        next_epoch_encryption_public_key: std::vector::empty(),
        extra_fields: config::empty(),
    };

    committee_set.insert_member(member);
}

/// Returns true if the transaction sender is authorized to act on behalf of the
/// member registered under `validator_address` — that is, the sender is either
/// the validator's own Sui address or the operator address it has delegated to.
/// Returns false if no such member exists.
///
/// The validator's own key always retains authority, so it can serve as a
/// backup if the operator key is lost.
public(package) fun member_authorized(
    self: &CommitteeSet,
    validator_address: address,
    ctx: &TxContext,
): bool {
    self.has_member(validator_address) && self.member(validator_address).is_authorized(ctx)
}

public(package) fun has_member(self: &CommitteeSet, validator_address: address): bool {
    self.members.contains_with_type<_, MemberInfo>(validator_address)
}

/// Set the public key of the member.
public(package) fun set_next_epoch_public_key(
    self: &mut CommitteeSet,
    validator_address: address,
    next_epoch_public_key: vector<u8>,
    proof_of_possession_signature: vector<u8>,
    ctx: &TxContext,
) {
    let next_epoch_public_key = verify_bls_public_key(
        ctx.epoch(),
        validator_address,
        next_epoch_public_key,
        proof_of_possession_signature,
    );

    let member = self.member_mut(validator_address);
    member.assert_authorized(ctx);

    member.next_epoch_public_key = next_epoch_public_key;
}

/// Set the endpoint_url of the member.
public(package) fun set_endpoint_url(
    self: &mut CommitteeSet,
    validator_address: address,
    endpoint_url: String,
    ctx: &TxContext,
) {
    let member = self.member_mut(validator_address);
    member.assert_authorized(ctx);

    member.endpoint_url = endpoint_url;
}

/// Set the tls_public_key of the member.
public(package) fun set_tls_public_key(
    self: &mut CommitteeSet,
    validator_address: address,
    tls_public_key: vector<u8>,
    ctx: &TxContext,
) {
    assert!(tls_public_key.length() == 32);

    let member = self.member_mut(validator_address);
    member.assert_authorized(ctx);
    member.tls_public_key = tls_public_key;
}

/// Set the next_epoch_encryption_public_key of the member.
public(package) fun set_next_epoch_encryption_public_key(
    self: &mut CommitteeSet,
    validator_address: address,
    next_epoch_encryption_public_key: vector<u8>,
    ctx: &TxContext,
) {
    assert!(next_epoch_encryption_public_key.length() == 32);

    let member = self.member_mut(validator_address);
    member.assert_authorized(ctx);
    member.next_epoch_encryption_public_key = next_epoch_encryption_public_key;
}

/// Set the operator_address of the member (delegate operations to an operator
/// key, or rotate it).
///
/// Authorized for the validator's own key or its current operator key. The
/// validator key always retains authority, so it can recover the delegation even
/// if the operator key is lost.
public(package) fun set_operator_address(
    self: &mut CommitteeSet,
    validator_address: address,
    operator_address: address,
    ctx: &TxContext,
) {
    let member = self.member_mut(validator_address);
    member.assert_authorized(ctx);
    member.operator_address = operator_address;
}

/// Set or clear the governance "ignored" flag on a registered member.
///
/// Unlike the operator-gated `set_*` functions above, this deliberately has
/// no `assert_authorized`: it is a governance write reachable only through
/// the quorum-gated `ignore_member::execute` — `public(package)` visibility
/// is the gate.
///
/// The flag is only read at committee formation (`start_reconfig`), so it
/// takes effect at the next formation; the current epoch's committee is
/// never altered.
public(package) fun set_member_ignored(
    self: &mut CommitteeSet,
    validator_address: address,
    ignored: bool,
) {
    assert!(self.has_member(validator_address), EMemberNotRegistered);
    self
        .member_mut(validator_address)
        .extra_fields
        .upsert(MEMBER_IGNORED_KEY, config_value::new_bool(ignored));
}

/// Whether the registered member is currently flagged as ignored by
/// governance. Aborts if no member is registered under this address.
public(package) fun is_member_ignored(self: &CommitteeSet, validator_address: address): bool {
    assert!(self.has_member(validator_address), EMemberNotRegistered);
    self.member(validator_address).is_ignored()
}

/// Whether the registered member has a pending resignation. Aborts if no
/// member is registered under this address.
public(package) fun is_member_resigned(self: &CommitteeSet, validator_address: address): bool {
    assert!(self.has_member(validator_address), EMemberNotRegistered);
    self.member(validator_address).is_resigned()
}

/// Request resignation from the committee, authorized for the validator's
/// own key or its delegated operator key.
///
/// Only sets a flag: the member keeps their registration and any epoch
/// duties, the next committee formation skips them, and the registration is
/// deleted by the separate permissionless `remove_inactive_member` once
/// they hold no duties. The reconfiguration flow itself never touches the
/// registry. Revocable via `clear_resignation` until the registration is
/// removed.
public(package) fun request_resignation(
    self: &mut CommitteeSet,
    validator_address: address,
    ctx: &TxContext,
) {
    assert!(self.has_member(validator_address), EMemberNotRegistered);
    let member = self.member(validator_address);
    member.assert_authorized(ctx);
    assert!(!member.is_resigned(), EAlreadyResigned);

    if (self.in_current_or_pending_committee(validator_address)) {
        self.assert_not_last_active_member(validator_address);
    };
    self
        .member_mut(validator_address)
        .extra_fields
        .upsert(MEMBER_RESIGNED_KEY, config_value::new_bool(true));
}

/// Permissionless registry cleanup: delete the registration of a member who
/// holds no epoch duties (not in the current committee, nor in a pending
/// one mid-reconfiguration) and either voluntarily resigned or is no longer
/// in Sui's active validator set.
///
/// A governance-ignored member is deliberately NOT removable: deleting the
/// registration would delete the flag with it, letting the member shed the
/// exclusion by simply re-registering. Their registration stays until
/// governance lifts the ignore.
public(package) fun remove_inactive_member(
    self: &mut CommitteeSet,
    validator_address: address,
    is_active_sui_validator: bool,
) {
    assert!(self.has_member(validator_address), EMemberNotRegistered);
    assert!(!self.in_current_or_pending_committee(validator_address), EMemberStillActive);
    let member = self.member(validator_address);
    assert!(!member.is_ignored(), ECannotRemoveIgnoredMember);
    assert!(member.is_resigned() || !is_active_sui_validator, EMemberNotRemovable);
    self.remove_member(validator_address);
}

/// Withdraw a pending resignation. If the next committee has already been
/// formed without the member, they keep their registration but sit out that
/// one epoch.
public(package) fun clear_resignation(
    self: &mut CommitteeSet,
    validator_address: address,
    ctx: &TxContext,
) {
    assert!(self.has_member(validator_address), EMemberNotRegistered);
    let member = self.member(validator_address);
    member.assert_authorized(ctx);
    assert!(member.is_resigned(), ENotResigned);
    self
        .member_mut(validator_address)
        .extra_fields
        .upsert(MEMBER_RESIGNED_KEY, config_value::new_bool(false));
}

public(package) fun start_reconfig(
    self: &mut CommitteeSet,
    sui_system: &sui_system::sui_system::SuiSystemState,
    config: Config,
    ctx: &TxContext,
): u64 {
    // We can't trigger reconfig if we are already reconfiguring
    assert!(!self.is_reconfiguring());
    // Don't start a reconfig for an epoch where we already have a committee
    // determined.
    assert!(!self.has_committee(ctx.epoch()));
    // We can only trigger reconfig if the current epoch is 0 (for genesis) or
    // our current epoch is not the same as Sui's epoch
    assert!(self.epoch == 0 || self.epoch != ctx.epoch());

    let committee = self.new_committee_from_validator_set(
        sui_system,
        config,
        ctx,
    );

    let epoch = committee.epoch();
    self.pending_epoch_change =
        option::some(PendingEpochChange {
            epoch,
            committee_handoff_cert: option::none(),
        });
    self.insert_committee(committee);
    epoch
}

public(package) fun set_pending_committee_handoff_cert(
    self: &mut CommitteeSet,
    cert: committee::CommitteeSignature,
) {
    let mut pending = self.pending_epoch_change.extract();
    assert!(pending.committee_handoff_cert.is_none());
    pending.committee_handoff_cert = option::some(cert);
    self.pending_epoch_change = option::some(pending);
}

public(package) fun end_reconfig(
    self: &mut CommitteeSet,
    mpc_public_key: vector<u8>,
    _ctx: &TxContext,
): (u64, Option<committee::CommitteeSignature>) {
    assert!(self.is_reconfiguring());
    let PendingEpochChange { epoch: next_epoch, committee_handoff_cert } = self
        .pending_epoch_change
        .extract();
    assert!(self.has_committee(next_epoch));

    // If the mpc_public_key is empty, then this is the initial reconfig where
    // DKG is run and we need to set the produced pubkey.
    if (self.mpc_public_key.is_empty()) {
        self.mpc_public_key = mpc_public_key;
    } else {
        assert!(committee_handoff_cert.is_some());
    };

    // On subsequent reconfigs where key resharing is performing instead of
    // DKG, we need to ensure that the pubkey remains constant
    assert!(self.mpc_public_key == mpc_public_key);

    self.epoch = next_epoch;
    (next_epoch, committee_handoff_cert)
}

public(package) fun abort_reconfig(self: &mut CommitteeSet, _ctx: &TxContext): u64 {
    assert!(self.is_reconfiguring());
    let PendingEpochChange { epoch: next_epoch, committee_handoff_cert } = self
        .pending_epoch_change
        .extract();
    if (committee_handoff_cert.is_some()) {
        committee_handoff_cert.destroy_some();
    } else {
        committee_handoff_cert.destroy_none();
    };

    self.remove_committee(next_epoch);
    next_epoch
}

public(package) fun insert_committee_handoff(
    self: &mut CommitteeSet,
    from_epoch: u64,
    next_epoch: u64,
    cert: committee::CommitteeSignature,
) {
    let key = CommitteeHandoffKey { epoch: from_epoch };
    assert!(!self.committees.contains_with_type<CommitteeHandoffKey, CommitteeHandoff>(key));
    self.committees.add(key, CommitteeHandoff { next_epoch, cert })
}

/// Return the current epoch.
public(package) fun epoch(self: &CommitteeSet): u64 {
    self.epoch
}

public(package) fun current_committee(self: &CommitteeSet): &Committee {
    &self.committees[self.epoch()]
}

public(package) fun get_committee(self: &CommitteeSet, epoch: u64): &Committee {
    &self.committees[epoch]
}

public(package) fun has_committee(self: &CommitteeSet, epoch: u64): bool {
    self.committees.contains_with_type<u64, Committee>(epoch)
}

/// True iff at least one committee epoch lies strictly between `epoch` and
/// the current epoch — i.e. `epoch` is strictly older than the previous
/// committee's epoch. Committee epochs are Sui epochs and can gap (a reconfig
/// may not run every Sui epoch), so this walks down from `current - 1` rather
/// than assuming `current - 1` is the previous committee. The walk is bounded
/// by the current↔previous committee gap in every case: it returns at the
/// first committee found descending, and in the not-found case the range
/// (epoch, current) contains no committee at all. A pending committee's epoch
/// is `> current` and is never visited.
public(package) fun is_before_previous_committee(self: &CommitteeSet, epoch: u64): bool {
    let mut e = self.epoch;
    while (e > epoch + 1) {
        e = e - 1;
        if (self.has_committee(e)) return true
    };
    false
}

public(package) fun pending_epoch_change(self: &CommitteeSet): Option<u64> {
    if (self.pending_epoch_change.is_some()) {
        option::some(self.pending_epoch_change.borrow().epoch)
    } else {
        option::none()
    }
}

public(package) fun mpc_public_key(self: &CommitteeSet): &vector<u8> {
    &self.mpc_public_key
}

public(package) fun is_reconfiguring(self: &CommitteeSet): bool {
    self.pending_epoch_change.is_some()
}

// ~~~~~~~ Private Functions ~~~~~~~

fun member(self: &CommitteeSet, validator_address: address): &MemberInfo {
    &self.members[validator_address]
}

fun member_mut(self: &mut CommitteeSet, validator_address: address): &mut MemberInfo {
    &mut self.members[validator_address]
}

fun insert_member(self: &mut CommitteeSet, member: MemberInfo) {
    self.members.add(member.validator_address, member)
}

fun committee(self: &CommitteeSet, epoch: u64): &Committee {
    &self.committees[epoch]
}

fun insert_committee(self: &mut CommitteeSet, committee: Committee) {
    self.committees.add(committee.epoch(), committee)
}

fun remove_committee(self: &mut CommitteeSet, epoch: u64): Committee {
    self.committees.remove(epoch)
}

/// Thin wrapper extracting the epoch and voting powers from the system
/// object. Split from `new_committee_from_voting_powers` because unit tests
/// cannot construct a `SuiSystemState`: the pure inner function is what lets
/// formation (including the ignore filtering) be unit-tested at all.
fun new_committee_from_validator_set(
    self: &CommitteeSet,
    sui_system: &sui_system::sui_system::SuiSystemState,
    config: Config,
    ctx: &TxContext,
): Committee {
    self.new_committee_from_voting_powers(
        ctx.epoch(),
        sui_system.active_validator_voting_powers(),
        config,
    )
}

/// Build a committee for `epoch` from a validator -> voting-power map,
/// keeping only validators that are registered members with usable keys and
/// that governance has not flagged as ignored.
///
/// The iteration order of `validator_set` determines member order, which is
/// load-bearing: it is the BLS signers-bitmap index and the MPC party id.
fun new_committee_from_voting_powers(
    self: &CommitteeSet,
    epoch: u64,
    mut validator_set: sui::vec_map::VecMap<address, u64>,
    config: Config,
): Committee {
    let g1_identity = g1_to_uncompressed_g1(&sui::bls12381::g1_identity());

    let mut committee_members = vector[];

    while (!validator_set.is_empty()) {
        let (validator_address, weight) = validator_set.pop();

        // If there is no registered info for this validator, skip them
        if (!self.has_member(validator_address)) {
            continue
        };

        let member = self.member(validator_address);

        // If governance has flagged the member as ignored, skip them: they
        // are treated as not part of the committee, and total weight re-sums
        // without them.
        if (member.is_ignored()) {
            continue
        };

        // If the member has requested resignation, skip them; once they hold
        // no epoch duties, the permissionless `remove_inactive_member`
        // deletes the registration.
        if (member.is_resigned()) {
            continue
        };

        // If the member has not registered a valid bls public key, skip them
        if (sui::group_ops::equal(&member.next_epoch_public_key, &g1_identity)) {
            continue
        };

        // If the member has not registered a valid encryption key, skip them
        if (member.next_epoch_encryption_public_key.is_empty()) {
            continue
        };

        let committee_member = committee::new_committee_member(
            validator_address,
            member.next_epoch_public_key,
            member.next_epoch_encryption_public_key,
            weight,
        );

        committee_members.push_back(committee_member);
    };

    // XXX do we sort by address or weight?

    committee::new_committee(
        epoch,
        committee_members,
        config,
    )
}

/// True if the tx sender is authorized to act for this member — its validator
/// key or its delegated operator key. The validator key always retains authority.
fun is_authorized(self: &MemberInfo, ctx: &TxContext): bool {
    let sender = ctx.sender();
    sender == self.validator_address || sender == self.operator_address
}

/// Whether governance has flagged this member as ignored. An absent key
/// means not ignored.
fun is_ignored(self: &MemberInfo): bool {
    self.extra_fields.try_get(MEMBER_IGNORED_KEY).map!(|value| value.as_bool()).destroy_or!(false)
}

/// Whether this member has a pending resignation. An absent key means not
/// resigned.
fun is_resigned(self: &MemberInfo): bool {
    self.extra_fields.try_get(MEMBER_RESIGNED_KEY).map!(|value| value.as_bool()).destroy_or!(false)
}

/// Whether the member currently serves an epoch: in the current committee,
/// or in the pending committee of an in-flight reconfiguration. Safe
/// pre-genesis, where no committee exists yet for the current epoch.
fun in_current_or_pending_committee(self: &CommitteeSet, validator_address: address): bool {
    let in_current =
        self.has_committee(self.epoch()) && self.current_committee().has_member(&validator_address);
    if (in_current) return true;
    if (self.pending_epoch_change.is_none()) return false;
    let pending_epoch = self.pending_epoch_change.borrow().epoch;
    self.has_committee(pending_epoch) &&
    self.get_committee(pending_epoch).has_member(&validator_address)
}

/// Best-effort guard against the last active member resigning: when the
/// caller is in the current committee, at least one OTHER current-committee
/// member must be registered, not resigned, and not ignored — otherwise the
/// next formation would produce an empty committee and reconfiguration
/// would abort. The hard backstop remains `committee::new_committee`'s
/// non-empty assert (the current committee keeps operating, and the state
/// is healable by withdrawing a resignation or a new registration).
fun assert_not_last_active_member(self: &CommitteeSet, validator_address: address) {
    if (!self.has_committee(self.epoch())) return;
    let committee = self.current_committee();
    if (!committee.has_member(&validator_address)) return;
    let n = committee.n_members();
    let mut has_other_active = false;
    let mut i = 0;
    while (i < n) {
        let addr = committee.get_idx(i).validator_address();
        if (
            addr != validator_address &&
            self.has_member(addr) &&
            !self.member(addr).is_resigned() &&
            !self.member(addr).is_ignored()
        ) {
            has_other_active = true;
            break
        };
        i = i + 1;
    };
    assert!(has_other_active, ELastActiveMember);
}

/// Delete a member's registration. The first (and only) removal path from
/// the members bag; MemberInfo has only `store`, so it is destructured.
fun remove_member(self: &mut CommitteeSet, validator_address: address) {
    let MemberInfo {
        validator_address: _,
        operator_address: _,
        next_epoch_public_key: _,
        endpoint_url: _,
        tls_public_key: _,
        next_epoch_encryption_public_key: _,
        extra_fields: _,
    } = self.members.remove(validator_address);
}

fun assert_authorized(self: &MemberInfo, ctx: &TxContext) {
    assert!(self.is_authorized(ctx));
}

// === Accessors ===

/// Return the address of the node.
fun validator_address(self: &MemberInfo): &address {
    &self.validator_address
}

/// Return the next epoch public key of the node.
fun next_epoch_public_key(self: &MemberInfo): &Element<UncompressedG1> {
    &self.next_epoch_public_key
}

/// Return the endpoint_url of the node.
fun endpoint_url(self: &MemberInfo): &String {
    &self.endpoint_url
}

/// Return the tls_public_key of the node.
fun tls_public_key(self: &MemberInfo): &vector<u8> {
    &self.tls_public_key
}

/// Return the next epoch encryption public key of the node.
fun next_epoch_encryption_public_key(self: &MemberInfo): &vector<u8> {
    &self.next_epoch_encryption_public_key
}

// Verifies that the provided bls public key is valid and there is a valid
// proof of possession.
fun verify_bls_public_key(
    epoch: u64,
    validator_address: address,
    bls_public_key: vector<u8>,
    proof_of_possession_signature: vector<u8>,
): Element<UncompressedG1> {
    // Verify the proof of possession of the private key
    assert!(
        verify_proof_of_possession(
            epoch,
            &validator_address,
            &bls_public_key,
            &proof_of_possession_signature,
        ),
    );

    // Convert the public key to its Uncompressed form
    g1_to_uncompressed_g1(&g1_from_bytes(&bls_public_key))
}

fun verify_proof_of_possession(
    epoch: u64,
    validator_address: &address,
    bls_public_key: &vector<u8>,
    proof_of_possession_signature: &vector<u8>,
): bool {
    let mut message = vector[];
    message.append(bcs::to_bytes(&hashi::intent::proof_of_possession()));
    message.append(bcs::to_bytes(&epoch));
    message.append(bcs::to_bytes(validator_address));
    bls_public_key.do_ref!(|key_byte| message.append(bcs::to_bytes(key_byte)));

    bls12381_min_pk_verify(
        proof_of_possession_signature,
        bls_public_key,
        &message,
    )
}

// ~~~~~~~ Test Helpers ~~~~~~~

#[test_only]
public fun has_committee_handoff_for_testing(self: &CommitteeSet, from_epoch: u64): bool {
    self
        .committees
        .contains_with_type<CommitteeHandoffKey, CommitteeHandoff>(CommitteeHandoffKey {
            epoch: from_epoch,
        })
}

#[test_only]
public fun set_pending_reconfig_for_testing(self: &mut CommitteeSet, committee: Committee) {
    let epoch = committee.epoch();
    assert!(!self.is_reconfiguring());
    assert!(!self.has_committee(epoch));
    self.pending_epoch_change =
        option::some(PendingEpochChange {
            epoch,
            committee_handoff_cert: option::none(),
        });
    self.insert_committee(committee);
}

#[test_only]
public fun set_mpc_public_key_for_testing(self: &mut CommitteeSet, mpc_public_key: vector<u8>) {
    self.mpc_public_key = mpc_public_key;
}

#[test_only]
/// Exercise committee formation (including the registration/key/ignored skip
/// branches) without a SuiSystemState by supplying the voting-power map
/// directly.
public fun new_committee_from_voting_powers_for_testing(
    self: &CommitteeSet,
    epoch: u64,
    validator_set: sui::vec_map::VecMap<address, u64>,
    config: Config,
): Committee {
    self.new_committee_from_voting_powers(epoch, validator_set, config)
}

#[test_only]
/// Creates a pre-genesis CommitteeSet for testing: members registered, but
/// no committee exists yet for the current epoch (the state before the
/// initial reconfiguration completes).
public fun create_pre_genesis_for_testing(
    member_addresses: vector<address>,
    bls_pubkey_bytes: vector<u8>,
    encryption_key: vector<u8>,
    ctx: &mut TxContext,
): CommitteeSet {
    let mut committee_set = create(ctx);
    member_addresses.do!(|addr| {
        let member_info = create_member_info_for_testing(
            addr,
            bls_pubkey_bytes,
            encryption_key,
        );
        committee_set.members.add(addr, member_info);
    });
    committee_set
}

#[test_only]
/// Drop a test CommitteeSet (Bag fields prevent plain drop).
public fun destroy_for_testing(self: CommitteeSet) {
    std::unit_test::destroy(self)
}

#[test_only]
public fun insert_committee_for_testing(self: &mut CommitteeSet, committee: Committee) {
    self.insert_committee(committee)
}

#[test_only]
/// Creates a CommitteeSet for testing with a pre-built committee
public fun create_for_testing(
    committee: Committee,
    member_addresses: vector<address>,
    bls_pubkey_bytes: vector<u8>,
    encryption_key: vector<u8>,
    ctx: &mut TxContext,
): CommitteeSet {
    let mut committee_set = create(ctx);
    committee_set.epoch = committee.epoch();

    // Add member info for each address so has_member checks pass
    member_addresses.do!(|addr| {
        let member_info = create_member_info_for_testing(
            addr,
            bls_pubkey_bytes,
            encryption_key,
        );
        committee_set.members.add(addr, member_info);
    });

    // Insert the committee
    committee_set.committees.add(committee.epoch(), committee);

    committee_set
}

#[test_only]
/// Creates member info for testing with provided keys
fun create_member_info_for_testing(
    validator_address: address,
    bls_pubkey_bytes: vector<u8>,
    encryption_key: vector<u8>,
): MemberInfo {
    use sui::bls12381;

    let public_key = bls12381::g1_to_uncompressed_g1(
        &bls12381::g1_from_bytes(&bls_pubkey_bytes),
    );

    MemberInfo {
        validator_address,
        operator_address: validator_address,
        next_epoch_public_key: public_key,
        endpoint_url: std::vector::empty().to_string(),
        tls_public_key: std::vector::empty(),
        next_epoch_encryption_public_key: encryption_key,
        extra_fields: config::empty(),
    }
}
