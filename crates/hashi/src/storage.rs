use crate::committee::EncryptionPrivateKey;
use crate::dkg::types::DkgOutput;
use anyhow::Result;
use fastcrypto_tbls::threshold_schnorr::avss;
use sui_sdk_types::Address;

pub trait PublicMessagesStore: Send + Sync {
    /// Store a dealer's DKG message
    ///
    /// If a message already exists for this dealer, it will be overwritten.
    fn store_dealer_message(&mut self, dealer: &Address, message: &avss::Message) -> Result<()>;

    /// Retrieve a dealer's DKG message
    ///
    /// Returns None if no message exists for this dealer.
    fn get_dealer_message(&self, dealer: &Address) -> Result<Option<avss::Message>>;

    /// Clear all stored messages (called at epoch transitions)
    fn clear(&mut self) -> Result<()>;
}

pub trait SecretsStore: Send + Sync {
    /// Store encryption private key
    ///
    /// Fails if called more than once.
    // TODO: Apply at node initialization
    fn store_encryption_key(&mut self, key: &EncryptionPrivateKey) -> Result<()>;

    /// Retrieve encryption private key
    fn get_encryption_key(&self) -> Result<Option<EncryptionPrivateKey>>;

    /// Clear all secrets (called at epoch transitions)
    fn clear(&mut self) -> Result<()>;
}

pub trait DkgOutputStore: Send + Sync {
    fn store_dkg_output(&mut self, epoch: u64, output: &DkgOutput) -> Result<()>;

    fn get_dkg_output(&self, epoch: u64) -> Result<Option<DkgOutput>>;
}
