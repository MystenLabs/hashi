// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;

/// Which flows an enclave serves, fixed at boot. A `Ceremony` enclave runs
/// `setup_new_key`/`rotate_kps`; a `Withdraw` enclave runs `provisioner_init` +
/// `standard_withdrawal`. `operator_init` and `get_guardian_info` are enabled
/// in both modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnclaveMode {
    Ceremony,
    Withdraw,
}

/// Signed mode and lifecycle stage of an enclave session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnclaveLifecycle {
    Ceremony(CeremonyStage),
    Withdraw(WithdrawStage),
}

impl EnclaveLifecycle {
    pub fn mode(self) -> EnclaveMode {
        match self {
            Self::Ceremony(_) => EnclaveMode::Ceremony,
            Self::Withdraw(_) => EnclaveMode::Withdraw,
        }
    }

    pub fn predecessor(self) -> Option<Self> {
        match self {
            Self::Ceremony(stage) => stage.predecessor().map(Self::Ceremony),
            Self::Withdraw(stage) => stage.predecessor().map(Self::Withdraw),
        }
    }
}

impl From<CeremonyStage> for EnclaveLifecycle {
    fn from(stage: CeremonyStage) -> Self {
        Self::Ceremony(stage)
    }
}

impl From<WithdrawStage> for EnclaveLifecycle {
    fn from(stage: WithdrawStage) -> Self {
        Self::Withdraw(stage)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyStage {
    Uninitialized,
    OperatorInitialized,
    Completed,
}

impl CeremonyStage {
    pub fn predecessor(self) -> Option<Self> {
        match self {
            Self::Uninitialized => None,
            Self::OperatorInitialized => Some(Self::Uninitialized),
            Self::Completed => Some(Self::OperatorInitialized),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawStage {
    Uninitialized,
    OperatorInitialized,
    ProvisionerInitialized,
    Activated,
}

impl WithdrawStage {
    pub fn predecessor(self) -> Option<Self> {
        match self {
            Self::Uninitialized => None,
            Self::OperatorInitialized => Some(Self::Uninitialized),
            Self::ProvisionerInitialized => Some(Self::OperatorInitialized),
            Self::Activated => Some(Self::ProvisionerInitialized),
        }
    }
}
