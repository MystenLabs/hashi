// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::guardian::time::UnixSeconds;
use anyhow::Context;
use std::convert::TryFrom;
use std::fmt;
use std::time::Duration;
use time::Date;
use time::OffsetDateTime;
use time::PrimitiveDateTime;
use time::Time;

/// S3 sub-prefixes used for guardian log streams.
/// See `crates/hashi-guardian/README.md` for canonical key layout.
pub const S3_DIR_INIT: &str = "init";
pub const S3_DIR_WITHDRAW: &str = "withdraw";
pub const S3_DIR_HEARTBEAT: &str = "heartbeat";
pub const S3_DIR_CEREMONY: &str = "ceremony";
pub const S3_DIR_KP_SHARES: &str = "kp-shares";
pub const S3_DIR_COMMITTEE_UPDATE: &str = "committee-update";
pub const S3_DIR_GENESIS: &str = "genesis";

pub const SECONDS_PER_HOUR: UnixSeconds = 60 * 60;
const DIR_WRITES_COMPLETION_DELAY: Duration = Duration::from_mins(10);

/// How far a reader's cursor can trail wall clock: the hour it is still waiting
/// on, plus the delay before that directory counts as complete.
pub const MAX_DIR_COMPLETION_LAG: UnixSeconds =
    SECONDS_PER_HOUR + DIR_WRITES_COMPLETION_DELAY.as_secs();

type Year = i32;
type Month = u8;
type Day = u8;
type Hour = u8;

/// An S3 prefix followed by numeric directory components.
/// For example, `withdraw/2026/09/` represents prefix `withdraw` with components
/// `[2026, 9]`, while `kp-shares/00000000000000000003/` represents prefix
/// `kp-shares` with components `[3]`. Date paths may stop at any level or include
/// the full year/month/day/hour, e.g. `withdraw/2026/09/28/18/`.
///
/// This type ensures directories are sorted by numeric value rather than raw
/// text: hour `9` sorts before hour `18`, regardless of zero-padding.
///
/// Ordering compares the prefix, then numeric components, then the original
/// path to break ties. Formatting preserves the exact input path; padding and
/// calendar rules belong to the specific directory layout.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct S3NumericDirectory {
    prefix: String,
    components: Vec<u64>,
    path: String,
}

impl S3NumericDirectory {
    pub fn components(&self) -> &[u64] {
        &self.components
    }

    /// Parse `{prefix}/{number}/...`, with one optional trailing slash.
    pub fn from_path(path: &str) -> anyhow::Result<Self> {
        let mut parts = path.strip_suffix('/').unwrap_or(path).split('/');
        let prefix = parts.next().context("missing directory prefix")?;
        anyhow::ensure!(!prefix.is_empty(), "empty directory prefix in {path}");
        let components = parts
            .map(|part| {
                part.parse::<u64>()
                    .with_context(|| format!("invalid numeric directory component in {path}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            prefix: prefix.to_string(),
            components,
            path: path.to_string(),
        })
    }
}

impl fmt::Display for S3NumericDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.path)
    }
}

/// An S3 directory: prefix/YYYY/MM/DD/HH.
/// All logs emitted within an hour are stored in the same directory, e.g., logs emitted between 12-1 PM are in `<prefix>`/12 directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3HourDirectory {
    prefix: String,
    year: Year,
    month: Month,
    day: Day,
    hour: Hour,
}

impl S3HourDirectory {
    /// Return an error if `t` is outside the supported calendar range.
    pub fn new(prefix: &str, t: UnixSeconds) -> anyhow::Result<Self> {
        let unix_seconds = i64::try_from(t).context("timestamp exceeds i64 range")?;
        let datetime = OffsetDateTime::from_unix_timestamp(unix_seconds)
            .context("timestamp outside supported calendar range")?;
        Ok(Self {
            prefix: prefix.to_string(),
            year: datetime.year(),
            month: u8::from(datetime.month()),
            day: datetime.day(),
            hour: datetime.hour(),
        })
    }

    /// Construct the withdrawal-log directory containing `t`.
    pub fn withdraw(t: UnixSeconds) -> anyhow::Result<Self> {
        Self::new(S3_DIR_WITHDRAW, t)
    }

    /// Construct the heartbeat-log directory containing `t`.
    pub fn heartbeat(t: UnixSeconds) -> anyhow::Result<Self> {
        Self::new(S3_DIR_HEARTBEAT, t)
    }

    pub fn next_dir(&self) -> anyhow::Result<Self> {
        Self::new(
            &self.prefix,
            self.to_unix_seconds().saturating_add(SECONDS_PER_HOUR),
        )
    }

    /// Returns the directory for the previous hour. Saturates at the Unix epoch.
    pub fn prev_dir(&self) -> Self {
        Self::new(
            &self.prefix,
            self.to_unix_seconds().saturating_sub(SECONDS_PER_HOUR),
        )
        .expect("previous hour is within the validated calendar range")
    }

    /// The time at which writes to current S3 directory finish.
    /// DIR_WRITES_COMPLETION_DELAY accounts for any in-flight retries and clock skew.
    pub fn write_completion_time(&self) -> UnixSeconds {
        self.to_unix_seconds()
            .saturating_add(SECONDS_PER_HOUR)
            .saturating_add(DIR_WRITES_COMPLETION_DELAY.as_secs())
    }

    pub fn to_unix_seconds(&self) -> UnixSeconds {
        let (date, time) = parse_calendar(self.year, self.month, self.day, self.hour)
            .expect("invariants validated at construction");
        let ts = PrimitiveDateTime::new(date, time)
            .assume_utc()
            .unix_timestamp();
        UnixSeconds::try_from(ts).expect("timestamp should be non-negative")
    }

    /// Parses a directory path of the form `{prefix}/{yyyy}/{mm}/{dd}/{hh}/`
    /// (with or without the trailing slash) back into a directory value.
    /// Requires the canonical zero-padding emitted by `Display`, so formatting
    /// the parsed value cannot redirect a read to a different S3 prefix.
    pub fn from_path(path: &str) -> anyhow::Result<Self> {
        S3NumericDirectory::from_path(path)?.try_into()
    }
}

impl TryFrom<S3NumericDirectory> for S3HourDirectory {
    type Error = anyhow::Error;

    fn try_from(dir: S3NumericDirectory) -> anyhow::Result<Self> {
        let [year, month, day, hour] = dir.components.as_slice() else {
            anyhow::bail!("expected a complete YYYY/MM/DD/HH directory, got {dir}");
        };
        let year = Year::try_from(*year).context("year out of range")?;
        anyhow::ensure!(year >= 1970, "directory predates the Unix epoch: {dir}");
        let month = Month::try_from(*month).context("month out of range")?;
        let day = Day::try_from(*day).context("day out of range")?;
        let hour = Hour::try_from(*hour).context("hour out of range")?;
        parse_calendar(year, month, day, hour).with_context(|| format!("invalid path {dir}"))?;
        let complete = Self {
            prefix: dir.prefix,
            year,
            month,
            day,
            hour,
        };
        let canonical = complete.to_string();
        let path = dir.path.strip_suffix('/').unwrap_or(&dir.path);
        anyhow::ensure!(
            canonical.strip_suffix('/') == Some(path),
            "noncanonical directory path {path}; expected {canonical}"
        );
        Ok(complete)
    }
}

/// Validates the (year, month, day, hour) tuple and returns the corresponding
/// `(Date, Time)` if every component is in range. Shared by [`S3HourDirectory::from_path`]
/// (which uses it to validate before construction) and
/// [`S3HourDirectory::to_unix_seconds`] (which is infallible because the
/// struct invariant guarantees validity).
fn parse_calendar(year: Year, month: Month, day: Day, hour: Hour) -> anyhow::Result<(Date, Time)> {
    let month_enum =
        time::Month::try_from(month).map_err(|e| anyhow::anyhow!("invalid month {month}: {e}"))?;
    let date = Date::from_calendar_date(year, month_enum, day)
        .map_err(|e| anyhow::anyhow!("invalid date {year}-{month:02}-{day:02}: {e}"))?;
    let time =
        Time::from_hms(hour, 0, 0).map_err(|e| anyhow::anyhow!("invalid hour {hour}: {e}"))?;
    Ok((date, time))
}

impl fmt::Display for S3HourDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{:04}/{:02}/{:02}/{:02}/",
            self.prefix, self.year, self.month, self.day, self.hour
        )
    }
}

#[cfg(test)]
mod tests {
    use super::DIR_WRITES_COMPLETION_DELAY;
    use super::S3HourDirectory;
    use super::S3NumericDirectory;

    #[test]
    fn numeric_directory_sort_preserves_original_paths() {
        let paths = [
            "withdraw/2026/09/28/09/",
            "withdraw/2026/09/28/18/",
            "withdraw/2026/09/28/9/",
            "withdraw/2026/09/28/02/",
        ];
        let mut dirs = paths
            .iter()
            .map(|path| S3NumericDirectory::from_path(path).unwrap())
            .collect::<Vec<_>>();
        dirs.sort();
        dirs.reverse();
        let sorted = dirs.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(sorted, [paths[1], paths[2], paths[0], paths[3]]);
    }

    #[test]
    fn numeric_directory_preserves_paths_at_every_depth() {
        for path in [
            "withdraw/",
            "withdraw/2026/",
            "withdraw/2026/9/",
            "withdraw/2026/09/28/",
            "withdraw/2026/09/28/9/",
            "kp-shares/00000000004294967296/",
        ] {
            let dir = S3NumericDirectory::from_path(path).unwrap();
            assert_eq!(dir.to_string(), path);
            let without_slash = path.strip_suffix('/').unwrap();
            let dir = S3NumericDirectory::from_path(without_slash).unwrap();
            assert_eq!(dir.to_string(), without_slash);
        }
    }

    #[test]
    fn numeric_directory_order_compares_all_components() {
        for (older, newer) in [
            ("withdraw/999/", "withdraw/2026/"),
            ("withdraw/2026/9/", "withdraw/2026/10/"),
            ("withdraw/2026/09/9/", "withdraw/2026/09/18/"),
            ("withdraw/2026/09/28/9/", "withdraw/2026/09/28/18/"),
            ("withdraw/2025/12/31/23/", "withdraw/2026/01/01/00/"),
            ("kp-shares/9/", "kp-shares/4294967296/"),
        ] {
            assert!(
                S3NumericDirectory::from_path(older).unwrap()
                    < S3NumericDirectory::from_path(newer).unwrap(),
                "{older} must sort before {newer}"
            );
        }
    }

    #[test]
    fn numeric_directory_rejects_invalid_components() {
        for path in [
            "",
            "/2026/",
            "withdraw//",
            "withdraw/not-a-number/",
            "withdraw/-1/",
            "withdraw/18446744073709551616/",
        ] {
            assert!(S3NumericDirectory::from_path(path).is_err(), "{path}");
        }
    }

    #[test]
    fn numeric_directory_conversion_requires_a_canonical_complete_date() {
        for path in [
            "withdraw/",
            "withdraw/2026/09/28/",
            "withdraw/2026/09/28/9/",
            "withdraw/2026/02/30/09/",
        ] {
            let dir = S3NumericDirectory::from_path(path).unwrap();
            assert!(S3HourDirectory::try_from(dir).is_err(), "{path}");
        }
        let path = "withdraw/2026/09/28/09/";
        let dir = S3HourDirectory::try_from(S3NumericDirectory::from_path(path).unwrap()).unwrap();
        assert_eq!(dir.to_string(), path);
    }

    #[test]
    fn test_epoch_directory_format() {
        let dir = S3HourDirectory::new("heartbeat", 0).unwrap();
        assert_eq!(dir.to_string(), "heartbeat/1970/01/01/00/");
    }

    #[test]
    fn rejects_out_of_range_timestamps() {
        for timestamp in [i64::MAX as u64, u64::MAX] {
            assert!(S3HourDirectory::new("heartbeat", timestamp).is_err());
        }
        let max_timestamp = time::Date::MAX
            .with_hms(23, 59, 59)
            .unwrap()
            .assume_utc()
            .unix_timestamp() as u64;
        let last_hour = S3HourDirectory::withdraw(max_timestamp).unwrap();
        assert!(S3HourDirectory::withdraw(max_timestamp + 1).is_err());
        assert!(last_hour.next_dir().is_err());
        assert_eq!(
            last_hour.write_completion_time(),
            max_timestamp + 1 + DIR_WRITES_COMPLETION_DELAY.as_secs()
        );
    }

    #[test]
    fn test_hour_and_day_rollover_format() {
        let before_hour_boundary = S3HourDirectory::new("withdraw", 3_599).unwrap();
        assert_eq!(before_hour_boundary.to_string(), "withdraw/1970/01/01/00/");

        let next_hour = S3HourDirectory::new("withdraw", 3_600).unwrap();
        assert_eq!(next_hour.to_string(), "withdraw/1970/01/01/01/");

        let next_day = S3HourDirectory::new("withdraw", 86_400).unwrap();
        assert_eq!(next_day.to_string(), "withdraw/1970/01/02/00/");
    }

    #[test]
    fn test_prev_dir_walks_back_and_saturates_at_epoch() {
        let mut dir = S3HourDirectory::new("withdraw", 86_400 + 3_600).unwrap();
        assert_eq!(dir.to_string(), "withdraw/1970/01/02/01/");
        dir = dir.prev_dir();
        assert_eq!(dir.to_string(), "withdraw/1970/01/02/00/");
        dir = dir.prev_dir();
        assert_eq!(dir.to_string(), "withdraw/1970/01/01/23/");

        // Saturates at epoch.
        let epoch = S3HourDirectory::new("withdraw", 0).unwrap();
        assert_eq!(epoch.prev_dir(), epoch);
    }

    #[test]
    fn test_from_path_roundtrips_with_display() {
        let dir = S3HourDirectory::new("withdraw", 1_700_000_000).unwrap();
        let displayed = dir.to_string();
        let parsed = S3HourDirectory::from_path(&displayed).expect("roundtrip");
        assert_eq!(parsed, dir);
        // Also accept the trailing-slash-stripped form.
        let parsed_nopfx = S3HourDirectory::from_path(displayed.trim_end_matches('/'))
            .expect("roundtrip without trailing slash");
        assert_eq!(parsed_nopfx, dir);
    }

    #[test]
    fn test_from_path_rejects_wrong_shape() {
        assert!(S3HourDirectory::from_path("withdraw/1969/12/31/23/").is_err());
        assert!(S3HourDirectory::from_path("withdraw/2024/03/15/").is_err()); // missing hour
        assert!(S3HourDirectory::from_path("withdraw/2024/03/15/14/extra/").is_err()); // too many parts
        assert!(S3HourDirectory::from_path("withdraw/2024/13/15/14/").is_err()); // invalid month
        assert!(S3HourDirectory::from_path("withdraw/2024/02/30/14/").is_err()); // invalid day
        assert!(S3HourDirectory::from_path("withdraw/2024/02/15/24/").is_err()); // invalid hour
        assert!(S3HourDirectory::from_path("withdraw/notayear/03/15/14/").is_err()); // non-numeric
    }

    #[test]
    fn test_from_path_rejects_noncanonical_names() {
        for path in [
            "withdraw/026/09/28/09/",
            "withdraw/2026/9/28/09/",
            "withdraw/2026/09/8/09/",
            "withdraw/2026/09/28/9/",
            "withdraw/02026/09/28/09/",
            "withdraw/2026/009/28/09/",
            "withdraw/2026/09/028/09/",
            "withdraw/2026/09/28/009/",
            "withdraw/2026/09/28/+9/",
        ] {
            assert!(S3HourDirectory::from_path(path).is_err(), "{path}");
            assert!(
                S3HourDirectory::from_path(path.strip_suffix('/').unwrap()).is_err(),
                "{path} without its trailing slash"
            );
        }
        assert!(S3HourDirectory::from_path("withdraw/2026/09/28/09//").is_err());
    }

    #[test]
    fn test_next_dir_and_completion_time() {
        let mut dir = S3HourDirectory::new("withdraw", 3_599).unwrap();
        assert_eq!(dir.to_string(), "withdraw/1970/01/01/00/");
        assert_eq!(dir.to_unix_seconds(), 0);
        assert_eq!(
            dir.write_completion_time(),
            3_600 + DIR_WRITES_COMPLETION_DELAY.as_secs()
        );

        for i in 0..24 {
            assert_eq!(dir.to_string(), format!("withdraw/1970/01/01/{:02}/", i));
            dir = dir.next_dir().unwrap();
        }
        assert_eq!(dir.to_string(), "withdraw/1970/01/02/00/");
    }
}
