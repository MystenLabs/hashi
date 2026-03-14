//! Type re-exports and display helpers for the CLI
//!
//! This module re-exports types from `crate::onchain::types` and provides
//! display formatting utilities for CLI output.

// Re-export onchain types used by the CLI
pub use crate::onchain::types::Proposal;

use crate::onchain::types::ProposalType;
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
        let ts = jiff::Timestamp::from_millisecond(timestamp_ms as i64)
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH);
        let dt = ts.to_zoned(jiff::tz::TimeZone::UTC).datetime();
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02} UTC",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute()
        )
    }

    /// Format proposal type for display (from on-chain type)
    pub fn format_proposal_type(proposal_type: &ProposalType) -> String {
        match proposal_type {
            ProposalType::Upgrade => "Upgrade".to_string(),
            ProposalType::UpdateConfig => "UpdateConfig".to_string(),
            ProposalType::EnableVersion => "EnableVersion".to_string(),
            ProposalType::DisableVersion => "DisableVersion".to_string(),
            ProposalType::Unknown(s) => format!("Unknown({})", s),
        }
    }
}
