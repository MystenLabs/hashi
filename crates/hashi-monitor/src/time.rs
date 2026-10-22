// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Timestamps and durations as the monitor prints and parses them.
//!
//! Why it exists: every log line, finding and CLI argument uses one
//! timestamp format, whole-second UTC RFC 3339, and one compact duration
//! format. Keeping them here keeps the domain types free of formatting.

use std::fmt;

use hashi_types::guardian::time::UnixSeconds;

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
        write_hms(formatter, self.0.into())
    }
}

/// Write `total_seconds` as `{h}h{m}m{s}s`, without the leading zero units.
fn write_hms(formatter: &mut fmt::Formatter<'_>, total_seconds: u128) -> fmt::Result {
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
        write_hms(formatter, self.0.unsigned_abs())
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
