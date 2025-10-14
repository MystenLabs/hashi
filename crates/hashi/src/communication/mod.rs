//! Generic communication primitives for distributed protocols
//!
//! This module provides protocol-agnostic communication channels:
//! - P2P channels for direct validator-to-validator messaging
//! - Ordered broadcast channels for consensus-critical messages

pub mod error;
pub mod in_memory;
pub mod interfaces;

pub use error::{ChannelError, ChannelResult};
pub use in_memory::{InMemoryOrderedBroadcastChannel, InMemoryP2PChannel};
pub use interfaces::{OrderedBroadcastChannel, P2PChannel};
