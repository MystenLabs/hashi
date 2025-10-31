//! Generic communication primitives for distributed protocols
//!
//! This module provides protocol-agnostic communication channels:
//! - P2P channels for direct validator-to-validator messaging
//! - Ordered broadcast channels for consensus-critical messages

pub mod in_memory;
pub mod interfaces;

pub use in_memory::InMemoryOrderedBroadcastChannel;
pub use interfaces::{ChannelError, ChannelResult, OrderedBroadcastChannel, P2PChannel};
