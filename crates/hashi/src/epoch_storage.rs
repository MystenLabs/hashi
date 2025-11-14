use crate::types::ValidatorAddress;
use anyhow::Result;
use fastcrypto_tbls::threshold_schnorr::avss;

pub trait EpochStorage {
    /// Store a dealer's DKG message
    ///
    /// If a message already exists for this dealer, it will be overwritten.
    fn store_dealer_message(
        &mut self,
        dealer: &ValidatorAddress,
        message: &avss::Message,
    ) -> Result<()>;

    /// Retrieve a dealer's DKG message
    ///
    /// Returns None if no message exists for this dealer.
    fn get_dealer_message(&self, dealer: &ValidatorAddress) -> Result<Option<avss::Message>>;

    /// Clear all stored data
    ///
    /// Called during epoch transitions to remove old epoch data.
    fn clear(&mut self) -> Result<()>;
}
