use super::DkgResult;
use super::types::SessionId;
use crate::types::ValidatorAddress;
use fastcrypto_tbls::threshold_schnorr::avss;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DealerMessageKey {
    pub session_id: SessionId,
    pub dealer: ValidatorAddress,
}

pub trait DealerMessageStore: Send + Sync {
    /// Store a dealer's message for a specific `DealerMessageKey`
    /// If message already exists for this key, it will be overwritten
    fn store_dealer_message(
        &mut self,
        key: &DealerMessageKey,
        message: &avss::Message,
    ) -> DkgResult<()>;

    /// Retrieve a dealer's message for a specific `DealerMessageKey`
    /// Returns None if no message exists for this key
    fn get_dealer_message(&self, key: &DealerMessageKey) -> DkgResult<Option<avss::Message>>;

    /// Delete all messages for a completed session
    fn delete_session(&mut self, session_id: SessionId) -> DkgResult<()>;
}
