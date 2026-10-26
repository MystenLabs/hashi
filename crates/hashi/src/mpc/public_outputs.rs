// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::RwLock;

use hashi_types::proto;

use crate::mpc::types::GetPublicMpcOutputResponse;
use crate::mpc::types::MpcError;
use crate::mpc::types::MpcOutput;
use crate::mpc::types::MpcResult;
use crate::mpc::types::PublicMpcOutput;

#[derive(Default)]
pub(crate) struct PublicOutputs(RwLock<BTreeMap<u64, Arc<proto::GetPublicMpcOutputResponse>>>);

impl PublicOutputs {
    pub(crate) fn lookup(
        &self,
        epoch: u64,
        current_epoch: u64,
        previous_epoch: u64,
    ) -> MpcResult<Arc<proto::GetPublicMpcOutputResponse>> {
        if epoch != current_epoch && epoch != previous_epoch {
            return Err(MpcError::NotFound(format!(
                "no DKG output for epoch {epoch} (current epoch is {current_epoch})"
            )));
        }
        self.0.read().unwrap().get(&epoch).cloned().ok_or_else(|| {
            MpcError::NotFound(format!("DKG output for epoch {epoch} not yet available"))
        })
    }

    #[cfg(test)]
    pub(crate) fn epochs(&self) -> Vec<u64> {
        self.0.read().unwrap().keys().copied().collect()
    }

    fn publish(&self, epoch: u64, output: &MpcOutput) {
        let response = Arc::new(proto::GetPublicMpcOutputResponse::from(
            &GetPublicMpcOutputResponse {
                output: PublicMpcOutput::from_mpc_output(output),
            },
        ));
        let replaced = self.0.write().unwrap().insert(epoch, Arc::clone(&response));
        if replaced.is_some_and(|replaced| replaced != response) {
            tracing::warn!("Public MPC output for epoch {epoch} replaced by a different one");
        }
    }

    fn retain(&self, epoch: u64, previous_epoch: Option<u64>) {
        let _dropped = {
            let mut published = self.0.write().unwrap();
            let kept = [Some(epoch), previous_epoch]
                .into_iter()
                .flatten()
                .filter_map(|wanted| published.remove_entry(&wanted))
                .collect();
            std::mem::replace(&mut *published, kept)
        };
    }
}

#[derive(Default)]
pub(crate) struct MpcOutputs {
    current: Option<MpcOutput>,
    previous: Option<MpcOutput>,
    public: Arc<PublicOutputs>,
}

impl MpcOutputs {
    pub(crate) fn current(&self) -> Option<&MpcOutput> {
        self.current.as_ref()
    }

    pub(crate) fn previous(&self) -> Option<&MpcOutput> {
        self.previous.as_ref()
    }

    pub(crate) fn public(&self) -> &PublicOutputs {
        &self.public
    }

    pub(crate) fn set_current(&mut self, epoch: u64, output: MpcOutput) {
        self.public.publish(epoch, &output);
        self.current = Some(output);
    }

    pub(crate) fn set_previous(&mut self, epoch: Option<u64>, output: MpcOutput) {
        if let Some(epoch) = epoch {
            self.public.publish(epoch, &output);
        }
        self.previous = Some(output);
    }

    pub(crate) fn adopt(
        &mut self,
        public: &Arc<PublicOutputs>,
        epoch: u64,
        previous_epoch: Option<u64>,
    ) {
        public.retain(epoch, previous_epoch);
        self.public = Arc::clone(public);
        if let Some(output) = &self.current {
            self.public.publish(epoch, output);
        }
        if let Some((previous_epoch, output)) = previous_epoch.zip(self.previous.as_ref()) {
            self.public.publish(previous_epoch, output);
        }
    }
}
