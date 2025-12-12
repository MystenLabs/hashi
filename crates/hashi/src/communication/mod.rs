//! Generic communication primitives for distributed protocols
//!
//! This module provides protocol-agnostic communication channels:
//! - P2P channels for direct validator-to-validator messaging
//! - Ordered broadcast channels for consensus-critical messages

#[cfg(test)]
pub mod in_memory;
pub mod interfaces;
pub mod timeout_and_retry;

#[cfg(test)]
pub use in_memory::InMemoryOrderedBroadcastChannel;
pub use interfaces::{ChannelError, ChannelResult, OrderedBroadcastChannel, P2PChannel};
pub use timeout_and_retry::with_timeout_and_retry;
