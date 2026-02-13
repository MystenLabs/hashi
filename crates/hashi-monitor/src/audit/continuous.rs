use std::collections::HashMap;

use hashi_guardian_shared::WithdrawalID;

use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::UnixSeconds;
use crate::state_machine::WithdrawalStateMachine;

/// A continuous auditor that runs indefinitely processing events as they arrive.
/// Constructors accept a start time as input that acts as a starting point for the auditor.
pub struct ContinuousAuditor {
    pub cfg: Config,
    pub cursors: Cursors,
    pub pending: HashMap<WithdrawalID, WithdrawalStateMachine>,
}

impl ContinuousAuditor {
    pub fn new(_cfg: Config, _start_time: UnixSeconds) -> Self {
        todo!("set cursor appropriately given the start time")
    }

    pub async fn run(&mut self) {
        todo!("implement me")
    }
}
