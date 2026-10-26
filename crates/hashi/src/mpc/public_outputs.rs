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

    fn publish(&self, epoch: u64, output: &MpcOutput) {
        let response = proto::GetPublicMpcOutputResponse::from(&GetPublicMpcOutputResponse {
            output: PublicMpcOutput::from_mpc_output(output),
        });
        let _replaced = self.0.write().unwrap().insert(epoch, Arc::new(response));
    }
}

#[derive(Default)]
pub(crate) struct MpcOutputs {
    current: Option<MpcOutput>,
    previous: Option<MpcOutput>,
    public: PublicOutputs,
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

    pub(crate) fn set_previous(
        &mut self,
        previous_epoch: u64,
        current_epoch: u64,
        output: MpcOutput,
    ) {
        if previous_epoch != current_epoch {
            self.public.publish(previous_epoch, &output);
        }
        self.previous = Some(output);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use fastcrypto::groups::GroupElement;
    use fastcrypto_tbls::threshold_schnorr::G;
    use fastcrypto_tbls::threshold_schnorr::avss;

    use super::MpcOutputs;
    use crate::mpc::types::GetPublicMpcOutputResponse;
    use crate::mpc::types::MpcOutput;

    fn output(public_key: G) -> MpcOutput {
        MpcOutput {
            public_key,
            key_shares: avss::SharesForNode { shares: vec![] },
            commitments: BTreeMap::new(),
            threshold: 1,
        }
    }

    #[test]
    fn the_current_output_is_served_when_both_epochs_are_equal() {
        let current = G::generator();
        let mut outputs = MpcOutputs::default();
        outputs.set_current(5, output(current));
        outputs.set_previous(5, 5, output(current + current));
        let served = outputs.public().lookup(5, 5, 5).unwrap();
        let served = GetPublicMpcOutputResponse::try_from(&*served).unwrap();
        assert_eq!(served.output.public_key, current);
    }
}
