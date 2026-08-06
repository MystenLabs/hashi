// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guardian S3 Object Lock retention policies.

use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;

use super::LogType;

const ONE_WEEK: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const THIRTY_DAYS: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const NINETY_DAYS: Duration = Duration::from_secs(90 * 24 * 60 * 60);
const TEN_YEARS: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

/// Object-lock retention policy for Guardian S3 logs.
///
/// Long-lived records include initialization, withdrawals, ceremonies,
/// committee updates, and genesis. They remain usable only while both the
/// record and its initialization chain are protected from replacement.
///
/// Object Lock expiry permits deletion; it does not trigger it. Heartbeats may
/// be removed by a separate lifecycle policy. Encrypted KP shares use the same
/// short-lived lock so stale shares can be explicitly deleted after their
/// recovery window, for example when a KP encryption key is retired or lost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct S3ObjectLockPolicy {
    pub long_lived: Duration,
    pub short_lived: Duration,
}

// TODO: Retire this enum once the repository has a canonical
// Hashi network enum from which the retention policy can be derived.
/// Hashi deployment class used to select an S3 object-lock policy.
///
/// This is intentionally independent of `bitcoin::Network`: a Hashi
/// deployment comprises both a Sui chain and a Bitcoin chain, and neither one
/// alone is the deployment identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum S3RetentionEnvironment {
    Devnet,
    Mainnet,
    Testnet,
}

/// Devnet records balance useful debugging history with rapid iteration.
pub const DEVNET_S3_OBJECT_LOCK_POLICY: S3ObjectLockPolicy = S3ObjectLockPolicy {
    long_lived: NINETY_DAYS,
    short_lived: ONE_WEEK,
};

/// Mainnet records are durable audit and recovery inputs.
pub const MAINNET_S3_OBJECT_LOCK_POLICY: S3ObjectLockPolicy = S3ObjectLockPolicy {
    long_lived: TEN_YEARS,
    short_lived: THIRTY_DAYS,
};

/// Testnet is a durable deployment and uses the mainnet retention policy.
pub const TESTNET_S3_OBJECT_LOCK_POLICY: S3ObjectLockPolicy = S3ObjectLockPolicy {
    long_lived: TEN_YEARS,
    short_lived: THIRTY_DAYS,
};

impl S3ObjectLockPolicy {
    pub const fn for_environment(environment: S3RetentionEnvironment) -> Self {
        match environment {
            S3RetentionEnvironment::Devnet => DEVNET_S3_OBJECT_LOCK_POLICY,
            S3RetentionEnvironment::Mainnet => MAINNET_S3_OBJECT_LOCK_POLICY,
            S3RetentionEnvironment::Testnet => TESTNET_S3_OBJECT_LOCK_POLICY,
        }
    }

    pub(super) const fn duration_for(self, log_type: LogType) -> Duration {
        match log_type {
            LogType::Heartbeat | LogType::KpShareState => self.short_lived,
            LogType::Init
            | LogType::Withdrawal
            | LogType::Ceremony
            | LogType::CommitteeUpdate
            | LogType::Genesis => self.long_lived,
        }
    }
}
