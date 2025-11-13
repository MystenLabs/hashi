use super::DkgResult;
use super::types::{SessionContext, SessionId};
use crate::types::ValidatorAddress;
use fastcrypto_tbls::threshold_schnorr::avss;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DealerMessageKey {
    pub session_id: SessionId,
    pub dealer: ValidatorAddress,
}

impl DealerMessageKey {
    pub fn new(session: &SessionContext, dealer: &ValidatorAddress) -> Self {
        Self {
            session_id: session.session_id,
            dealer: dealer.clone(),
        }
    }
}

pub trait DealerMessageStore: Send + Sync {
    /// Store a dealer's message for a specific session
    /// If message already exists for this (session, dealer), it will be overwritten
    fn store_dealer_message(
        &mut self,
        session: &SessionContext,
        dealer: &ValidatorAddress,
        message: &avss::Message,
    ) -> DkgResult<()>;

    /// Retrieve a dealer's message for a specific session
    /// Returns None if no message exists for this (session, dealer)
    fn get_dealer_message(
        &self,
        session: &SessionContext,
        dealer: &ValidatorAddress,
    ) -> DkgResult<Option<avss::Message>>;

    /// Delete all messages for a completed session
    fn delete_session(&mut self, session: &SessionContext) -> DkgResult<()>;
}
