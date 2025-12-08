mod file;

use crate::dkg::EncryptionGroupElement;
use anyhow::Result;
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::threshold_schnorr::avss;
use sui_sdk_types::Address;

pub use file::FilePublicMessagesStore;
pub use file::FileSecretsStore;

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
    fn store_encryption_key(&mut self, key: &PrivateKey<EncryptionGroupElement>) -> Result<()>;

    /// Retrieve encryption private key
    fn get_encryption_key(&self) -> Result<Option<PrivateKey<EncryptionGroupElement>>>;

    /// Clear all secrets (called at epoch transitions)
    fn clear(&mut self) -> Result<()>;
}
