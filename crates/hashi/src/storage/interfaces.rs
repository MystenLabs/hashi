use anyhow::Result;
use fastcrypto_tbls::threshold_schnorr::avss;
use sui_sdk_types::Address;

pub use crate::mpc::types::Messages;
pub use crate::mpc::types::RotationMessages;

pub trait PublicMessagesStore: Send + Sync {
    /// Store a dealer's DKG message.
    ///
    /// If a message already exists for this dealer, it will be overwritten.
    /// Old messages (for epochs < current_epoch - 1) are automatically cleaned up.
    fn store_dealer_message(&mut self, dealer: &Address, message: &avss::Message) -> Result<()>;

    /// Retrieve a dealer's DKG message.
    ///
    /// Returns None if no message exists for this dealer.
    fn get_dealer_message(&self, dealer: &Address) -> Result<Option<avss::Message>>;

    /// List all stored dealer messages for the current epoch.
    fn list_all_dealer_messages(&self) -> Result<Vec<(Address, Messages)>>;

    /// Store a dealer's rotation messages.
    ///
    /// If messages already exist for this dealer, they will be overwritten.
    /// Old messages (for epochs < current_epoch - 1) are automatically cleaned up.
    fn store_rotation_messages(
        &mut self,
        dealer: &Address,
        messages: &RotationMessages,
    ) -> Result<()>;

    /// Retrieve a dealer's rotation messages.
    ///
    /// Returns None if no messages exist for this dealer.
    fn get_rotation_messages(&self, dealer: &Address) -> Result<Option<RotationMessages>>;

    /// List all stored rotation messages for the current epoch.
    fn list_all_rotation_messages(&self) -> Result<Vec<(Address, Messages)>>;
}
