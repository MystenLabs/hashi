// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Domain model for the monitor.
//!
//! We model the cross-system withdrawal flow as a sequence of events:
//! - E1 or E_hashi: Hashi approval event on sui (corresponds to WithdrawalPickedForProcessing)
//! - E2 or E_guardian: Guardian approval event on S3 (corresponds to NormalWithdrawalSuccess)
//! - E3 or E_btc: BTC transaction confirmed
//!
//! Predecessor checks: every E_{i+1} has a corresponding E_i, and E_i does not
//! occur more than `clock_skew` after E_{i+1}.
//! Successor checks: for every E_i, there exists a corresponding E_{i+1} within time `t`.
//!
//! Note: IOP-203 matches the withdrawal destination & amount that a user inputs with that in E_hashi.
//! The monitor is insecure without this check as a malicious hashi committee can include an arbitrary destination address.

use std::fmt;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use bitcoin::Txid;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time_utils::UnixSeconds;
use serde::Deserialize;

// TODO: duplicate of `hashi_types::guardian::time_utils::now_timestamp_secs`;
// remove and migrate the remaining monitor callers.
pub fn now_unix_seconds() -> UnixSeconds {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Unix seconds rendered in the monitor's canonical UTC timestamp format.
pub struct UtcTimestamp(UnixSeconds);

pub fn utc_timestamp(timestamp: UnixSeconds) -> UtcTimestamp {
    UtcTimestamp(timestamp)
}

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(timestamp) = i64::try_from(self.0)
            && let Ok(datetime) = time::OffsetDateTime::from_unix_timestamp(timestamp)
        {
            return write!(
                formatter,
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                datetime.year(),
                u8::from(datetime.month()),
                datetime.day(),
                datetime.hour(),
                datetime.minute(),
                datetime.second(),
            );
        }

        formatter.write_str("<invalid UTC timestamp>")
    }
}

/// Seconds rendered as a compact human-readable duration.
pub struct HumanDuration(UnixSeconds);

pub fn human_duration(seconds: UnixSeconds) -> HumanDuration {
    HumanDuration(seconds)
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hours = self.0 / 3_600;
        let minutes = (self.0 % 3_600) / 60;
        let seconds = self.0 % 60;

        if hours > 0 {
            write!(formatter, "{hours}h")?;
        }
        if minutes > 0 || hours > 0 {
            write!(formatter, "{minutes}m")?;
        }
        write!(formatter, "{seconds}s")
    }
}

/// Signed difference between two Unix timestamps, rendered compactly.
pub struct HumanTimestampDelta(i128);

pub fn human_timestamp_delta(later: UnixSeconds, earlier: UnixSeconds) -> HumanTimestampDelta {
    HumanTimestampDelta(i128::from(later) - i128::from(earlier))
}

impl fmt::Display for HumanTimestampDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 < 0 {
            formatter.write_str("-")?;
        }

        let total_seconds = self.0.unsigned_abs();
        let hours = total_seconds / 3_600;
        let minutes = (total_seconds % 3_600) / 60;
        let seconds = total_seconds % 60;

        if hours > 0 {
            write!(formatter, "{hours}h")?;
        }
        if minutes > 0 || hours > 0 {
            write!(formatter, "{minutes}m")?;
        }
        write!(formatter, "{seconds}s")
    }
}

/// Parse the monitor's sole public timestamp format: whole-second UTC RFC 3339.
pub fn parse_utc_timestamp(value: &str) -> Result<UnixSeconds, String> {
    if !value.ends_with('Z') {
        return Err(
            "timestamp must be UTC and end in `Z` (for example, 2026-08-04T19:00:00Z)".to_string(),
        );
    }

    let datetime =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            .map_err(|error| format!("invalid UTC timestamp `{value}`: {error}"))?;
    let timestamp = UnixSeconds::try_from(datetime.unix_timestamp())
        .map_err(|_| "timestamp must not precede 1970-01-01T00:00:00Z".to_string())?;
    if utc_timestamp(timestamp).to_string() != value {
        return Err(
            "timestamp must use exactly `YYYY-MM-DDTHH:MM:SSZ` with no fractional seconds"
                .to_string(),
        );
    }

    Ok(timestamp)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MonitorEvent {
    Withdrawal(MonitorWithdrawalEvent),
    Deposit(MonitorDepositEvent),
}

impl fmt::Display for MonitorEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Withdrawal(event) => write!(
                formatter,
                "Withdrawal(type={:?}, wid={}, timestamp={}, btc_txid={})",
                event.event_type,
                event.wid,
                utc_timestamp(event.timestamp_secs),
                event.btc_txid,
            ),
            Self::Deposit(event) => write!(
                formatter,
                "Deposit(type={:?}, timestamp={}, btc_txid={}, btc_vout={})",
                event.event_type,
                utc_timestamp(event.timestamp_secs),
                event.btc_txid,
                event.btc_vout,
            ),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
pub enum MonitorEventType {
    Withdrawal(WithdrawalEventType),
    Deposit(DepositEventType),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitorWithdrawalEvent {
    /// Who produced the event?
    pub event_type: WithdrawalEventType,

    /// Stable withdrawal identifier.
    pub wid: WithdrawalID,

    /// Unix timestamp embedded in the Sui event / S3 log / BTC block.
    pub timestamp_secs: UnixSeconds,

    /// btc txid
    pub btc_txid: Txid,
}

/// Event source or type.
/// Note: Make sure WithdrawalEventType::NON_TERMINAL_EVENTS and TERMINAL_EVENT are up-to-date.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
pub enum WithdrawalEventType {
    /// E_hashi (WithdrawalPickedForProcessing on sui)
    E1HashiApproved,
    /// E_guardian (NormalWithdrawalSuccess on s3)
    E2GuardianApproved,
    /// E_btc
    E3BtcConfirmed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitorDepositEvent {
    pub event_type: DepositEventType,
    pub timestamp_secs: UnixSeconds,
    pub btc_txid: Txid,
    pub btc_vout: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
pub enum DepositEventType {
    /// deposit confirmed event on btc
    E1BtcConfirmed,
    /// `DepositApproved` on Sui.
    ///
    /// This event carries its approval timestamp and lets the monitor detect a
    /// Bitcoin mismatch before hBTC is minted. `DepositConfirmed` is also a
    /// natural monitoring point because it is unique per deposit and directly
    /// represents hBTC minting, but it does not carry a timestamp of its own.
    E2HashiApproved,
}

impl WithdrawalEventType {
    pub const NON_TERMINAL_EVENTS: [WithdrawalEventType; 2] =
        [Self::E1HashiApproved, Self::E2GuardianApproved];
    pub const TERMINAL_EVENT: Self = Self::E3BtcConfirmed;

    pub fn successor(&self) -> Option<Self> {
        match self {
            WithdrawalEventType::E1HashiApproved => Some(WithdrawalEventType::E2GuardianApproved),
            WithdrawalEventType::E2GuardianApproved => Some(WithdrawalEventType::E3BtcConfirmed),
            WithdrawalEventType::E3BtcConfirmed => None,
        }
    }

    pub fn has_successor(&self) -> bool {
        self.successor().is_some()
    }

    pub fn predecessor(&self) -> Option<Self> {
        match self {
            WithdrawalEventType::E1HashiApproved => None,
            WithdrawalEventType::E2GuardianApproved => Some(WithdrawalEventType::E1HashiApproved),
            WithdrawalEventType::E3BtcConfirmed => Some(WithdrawalEventType::E2GuardianApproved),
        }
    }
}

/// Per-source cursors tracking how far we've read from each data source.
#[derive(Clone, Copy, Debug)]
pub struct Cursors {
    pub sui: UnixSeconds,
    pub guardian: UnixSeconds,
}

impl Cursors {
    pub fn for_event_type(&self, et: WithdrawalEventType) -> UnixSeconds {
        match et {
            WithdrawalEventType::E1HashiApproved => self.sui,
            WithdrawalEventType::E2GuardianApproved => self.guardian,
            WithdrawalEventType::E3BtcConfirmed => {
                unreachable!("E3 cursor is tracked per-withdrawal via btc_checked_at")
            }
        }
    }

    pub fn min(&self) -> UnixSeconds {
        self.sui.min(self.guardian)
    }
}

/// Outcome of a Guardian or Sui poll
pub enum PollOutcome {
    CursorAdvanced(Vec<MonitorEvent>),
    CursorUnmoved,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_timestamp_round_trip() {
        let input = "2026-08-04T19:45:38Z";
        let timestamp = parse_utc_timestamp(input).unwrap();
        assert_eq!(utc_timestamp(timestamp).to_string(), input);
    }

    #[test]
    fn timestamp_parser_requires_canonical_utc_format() {
        assert!(parse_utc_timestamp("1785872738").is_err());
        assert!(parse_utc_timestamp("2026-08-04T19:45:38+00:00").is_err());
        assert!(parse_utc_timestamp("2026-08-04T19:45:38.000Z").is_err());
    }

    #[test]
    fn duration_uses_compact_human_readable_format() {
        assert_eq!(human_duration(0).to_string(), "0s");
        assert_eq!(human_duration(191).to_string(), "3m11s");
        assert_eq!(human_duration(4_028).to_string(), "1h7m8s");
        assert_eq!(human_timestamp_delta(100, 120).to_string(), "-20s");
    }
}
