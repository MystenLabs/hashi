use super::DkgResult;
use super::types::SessionId;
use fastcrypto_tbls::threshold_schnorr::avss;

/// Storage for secret shares produced by DKG
pub trait SecretSharesStore {
    /// Store the secret shares from a completed DKG session
    /// If shares already exist for this session, they will be overwritten
    fn store_shares(
        &mut self,
        session_id: SessionId,
        shares: &avss::SharesForNode,
    ) -> DkgResult<()>;

    /// Retrieve the secret shares for a session
    /// Returns None if no shares exist for this session
    fn get_shares(&self, session_id: SessionId) -> DkgResult<Option<avss::SharesForNode>>;

    /// Delete the secret shares for a session
    fn delete_shares(&mut self, session_id: SessionId) -> DkgResult<()>;
}
