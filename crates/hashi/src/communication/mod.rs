//! Generic communication primitives for distributed protocols
//!
//! This module provides protocol-agnostic communication channels:
//! - P2P channels for direct validator-to-validator messaging
//! - Ordered broadcast channels for consensus-critical messages

#[cfg(test)]
pub mod in_memory;
pub mod interfaces;
pub mod sui_tob;
pub mod timeout_and_retry;

#[cfg(test)]
pub use in_memory::InMemoryOrderedBroadcastChannel;
pub use interfaces::ChannelError;
pub use interfaces::ChannelResult;
pub use interfaces::OrderedBroadcastChannel;
pub use interfaces::P2PChannel;
pub use sui_tob::SuiTobChannel;
pub use sui_tob::fetch_certificates;
pub use timeout_and_retry::with_timeout_and_retry;
