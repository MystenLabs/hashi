// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;

use crate::MpcManager;
use crate::SigningManager;

#[derive(Default)]
pub struct MpcServiceState {
    mpc_manager: OnceLock<Arc<RwLock<MpcManager>>>,
    signing_manager: RwLock<Option<Arc<SigningManager>>>,
    reconfig_signatures: RwLock<HashMap<u64, Vec<u8>>>,
}

impl MpcServiceState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mpc_manager(&self) -> Option<Arc<RwLock<MpcManager>>> {
        self.mpc_manager.get().cloned()
    }

    pub fn set_mpc_manager(&self, manager: MpcManager) {
        match self.mpc_manager.get() {
            Some(lock) => {
                *lock.write().unwrap() = manager;
            }
            None => {
                let _ = self.mpc_manager.set(Arc::new(RwLock::new(manager)));
            }
        }
    }

    pub fn signing_manager_for(&self, epoch: u64) -> Option<Arc<SigningManager>> {
        let stored = self.signing_manager.read().unwrap();
        stored
            .as_ref()
            .filter(|manager| manager.epoch() == epoch)
            .cloned()
    }

    pub fn signing_verifying_key(&self) -> Option<fastcrypto_tbls::threshold_schnorr::G> {
        self.signing_manager
            .read()
            .unwrap()
            .as_ref()
            .map(|manager| manager.verifying_key())
    }

    pub fn store_signing_manager(&self, manager: SigningManager) {
        *self.signing_manager.write().unwrap() = Some(Arc::new(manager));
    }

    /// Test-only.
    pub fn clear_signing_manager_for_test(&self) {
        *self.signing_manager.write().unwrap() = None;
    }

    pub fn store_reconfig_signature(&self, epoch: u64, signature: Vec<u8>) {
        self.reconfig_signatures
            .write()
            .unwrap()
            .insert(epoch, signature);
    }

    pub fn get_reconfig_signature(&self, epoch: u64) -> Option<Vec<u8>> {
        self.reconfig_signatures
            .read()
            .unwrap()
            .get(&epoch)
            .cloned()
    }
}
