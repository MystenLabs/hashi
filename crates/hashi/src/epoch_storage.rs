use crate::dkg::EncryptionGroupElement;
use crate::types::ValidatorAddress;
use anyhow::Result;
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::threshold_schnorr::avss;

pub trait PublicMessageStore {
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

    /// Clear all stored messages (called at epoch transitions)
    fn clear(&mut self) -> Result<()>;
}

pub trait SecretStore {
    /// Store DKG secret shares
    ///
    /// Fails if called more than once.
    fn store_shares(&mut self, shares: &avss::SharesForNode) -> Result<()>;

    /// Retrieve DKG secret shares
    fn get_shares(&self) -> Result<Option<avss::SharesForNode>>;

    /// Store encryption private key
    ///
    /// Fails if called more than once.
    fn store_encryption_key(&mut self, key: &PrivateKey<EncryptionGroupElement>) -> Result<()>;

    /// Retrieve encryption private key
    fn get_encryption_key(&self) -> Result<Option<PrivateKey<EncryptionGroupElement>>>;

    /// Clear all secrets (called at epoch transitions)
    fn clear(&mut self) -> Result<()>;
}
