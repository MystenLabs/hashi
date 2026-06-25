// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Package version gating and upgrade authority.
///
/// Holds the set of package versions allowed to run and custodies the package
/// `UpgradeCap`. The two live together because they are one lifecycle:
/// committing an upgrade through the cap auto-enables the new version. Every
/// entry function gates on `assert_version_enabled` so a disabled version
/// cannot be executed.
module hashi::versioning;

use sui::{package::{Self, UpgradeCap, UpgradeTicket, UpgradeReceipt}, vec_set::{Self, VecSet}};

const PACKAGE_VERSION: u64 = 1;

#[error(code = 0)]
const EVersionDisabled: vector<u8> = b"Version disabled";
#[error(code = 1)]
const EDisableCurrentVersion: vector<u8> = b"Cannot disable current version";

public struct Versioning has store {
    /// Package versions allowed to run; gated on every entry.
    enabled_versions: VecSet<u64>,
    /// The package's UpgradeCap. Custodied here because committing an upgrade
    /// auto-enables the new version.
    upgrade_cap: Option<UpgradeCap>,
}

// ======== Constructor ========

public(package) fun create(): Versioning {
    Versioning {
        enabled_versions: vec_set::from_keys(vector[PACKAGE_VERSION]),
        upgrade_cap: option::none(),
    }
}

// ======== Version Management ========

/// Assert that the package version is currently enabled.
#[allow(implicit_const_copy)]
public(package) fun assert_version_enabled(self: &Versioning) {
    assert!(self.enabled_versions.contains(&PACKAGE_VERSION), EVersionDisabled);
}

public(package) fun disable_version(self: &mut Versioning, version: u64) {
    assert!(version != PACKAGE_VERSION, EDisableCurrentVersion);
    self.enabled_versions.remove(&version);
}

public(package) fun enable_version(self: &mut Versioning, version: u64) {
    self.enabled_versions.insert(version);
}

// ======== Upgrade Management ========

public(package) fun authorize_upgrade(self: &mut Versioning, digest: vector<u8>): UpgradeTicket {
    let policy = sui::package::upgrade_policy(self.upgrade_cap.borrow());
    sui::package::authorize_upgrade(
        self.upgrade_cap.borrow_mut(),
        policy,
        digest,
    )
}

public(package) fun commit_upgrade(self: &mut Versioning, receipt: UpgradeReceipt) {
    package::commit_upgrade(self.upgrade_cap.borrow_mut(), receipt);
    let version = self.upgrade_cap.borrow().version();
    self.enabled_versions.insert(version);
}

public(package) fun set_upgrade_cap(self: &mut Versioning, upgrade_cap: UpgradeCap) {
    self.upgrade_cap.fill(upgrade_cap);
}

public(package) fun upgrade_cap(self: &Versioning): &UpgradeCap {
    self.upgrade_cap.borrow()
}
