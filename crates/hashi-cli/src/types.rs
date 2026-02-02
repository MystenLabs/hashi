//! Type re-exports and display helpers for the CLI
//!
//! This module re-exports types from `hashi::onchain::types` and provides
//! display formatting utilities for CLI output.

// Re-export onchain types used by the CLI
pub use hashi::onchain::types::Proposal;

use hashi::onchain::types::ProposalType;
use sui_sdk_types::Address;

/// Display formatting helpers
pub mod display {
    use super::*;

    /// Format an address for display (truncated)
    pub fn format_address(addr: &Address) -> String {
        let hex = addr.to_hex();
        if hex.len() > 16 {
            format!("{}...{}", &hex[..10], &hex[hex.len() - 6..])
        } else {
            hex
        }
    }

    /// Format a full address
    pub fn format_address_full(addr: &Address) -> String {
        addr.to_hex()
    }

    /// Format a timestamp in human-readable form
    pub fn format_timestamp(timestamp_ms: u64) -> String {
        use std::time::Duration;
        use std::time::UNIX_EPOCH;
        let datetime = UNIX_EPOCH + Duration::from_millis(timestamp_ms);
        format!("{:?}", datetime)
    }

    /// Format proposal type for display (from on-chain type)
    pub fn format_proposal_type(proposal_type: &ProposalType) -> String {
        match proposal_type {
            ProposalType::Upgrade => "Upgrade".to_string(),
            ProposalType::UpdateDepositFee => "UpdateDepositFee".to_string(),
            ProposalType::EnableVersion => "EnableVersion".to_string(),
            ProposalType::DisableVersion => "DisableVersion".to_string(),
            ProposalType::Unknown(s) => format!("Unknown({})", s),
        }
    }
}
