// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::guardian::time_utils::UnixSeconds;
use anyhow::Context;
use std::convert::TryFrom;
use std::fmt;
use std::time::Duration;
use time::Date;
use time::OffsetDateTime;
use time::PrimitiveDateTime;
use time::Time;

pub const SECONDS_PER_HOUR: UnixSeconds = 60 * 60;
const DIR_WRITES_COMPLETION_DELAY: Duration = Duration::from_mins(10);

type Year = i32;
type Month = u8;
type Day = u8;
type Hour = u8;

/// An S3 directory: prefix/YYYY/MM/DD/HH.
/// All logs emitted within an hour are stored in the same directory, e.g., logs emitted between 12-1 PM are in `<prefix>`/12 directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3HourScopedDirectory {
    prefix: String,
    year: Year,
    month: Month,
    day: Day,
    hour: Hour,
}

impl S3HourScopedDirectory {
    pub fn new(prefix: &str, t: UnixSeconds) -> Self {
        let unix_seconds = i64::try_from(t).expect("timestamp should fit i64");
        let datetime =
            OffsetDateTime::from_unix_timestamp(unix_seconds).expect("timestamp should be valid");
        Self {
            prefix: prefix.to_string(),
            year: datetime.year(),
            month: u8::from(datetime.month()),
            day: datetime.day(),
            hour: datetime.hour(),
        }
    }

    pub fn next_dir(&self) -> Self {
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
    }

    /// The time at which writes to current S3 directory finish.
    /// DIR_WRITES_COMPLETION_DELAY accounts for any in-flight retries and clock skew.
    pub fn write_completion_time(&self) -> UnixSeconds {
        self.next_dir()
            .to_unix_seconds()
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
    /// Inverse of the `Display` impl.
    pub fn from_path(path: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = path.trim_end_matches('/').split('/').collect();
        anyhow::ensure!(
            parts.len() == 5,
            "expected `{{prefix}}/YYYY/MM/DD/HH/` in {path}"
        );
        let prefix = parts[0];
        let year: Year = parts[1]
            .parse()
            .with_context(|| format!("invalid year in {path}"))?;
        let month: Month = parts[2]
            .parse()
            .with_context(|| format!("invalid month in {path}"))?;
        let day: Day = parts[3]
            .parse()
            .with_context(|| format!("invalid day in {path}"))?;
        let hour: Hour = parts[4]
            .parse()
            .with_context(|| format!("invalid hour in {path}"))?;
        parse_calendar(year, month, day, hour).with_context(|| format!("invalid path {path}"))?;
        Ok(Self {
            prefix: prefix.to_string(),
            year,
            month,
            day,
            hour,
        })
    }
}

/// Validates the (year, month, day, hour) tuple and returns the corresponding
/// `(Date, Time)` if every component is in range. Shared by [`S3HourScopedDirectory::from_path`]
/// (which uses it to validate before construction) and
/// [`S3HourScopedDirectory::to_unix_seconds`] (which is infallible because the
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

impl fmt::Display for S3HourScopedDirectory {
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
    use super::S3HourScopedDirectory;

    #[test]
    fn test_epoch_directory_format() {
        let dir = S3HourScopedDirectory::new("heartbeat", 0);
        assert_eq!(dir.to_string(), "heartbeat/1970/01/01/00/");
    }

    #[test]
    fn test_hour_and_day_rollover_format() {
        let before_hour_boundary = S3HourScopedDirectory::new("withdraw", 3_599);
        assert_eq!(before_hour_boundary.to_string(), "withdraw/1970/01/01/00/");

        let next_hour = S3HourScopedDirectory::new("withdraw", 3_600);
        assert_eq!(next_hour.to_string(), "withdraw/1970/01/01/01/");

        let next_day = S3HourScopedDirectory::new("withdraw", 86_400);
        assert_eq!(next_day.to_string(), "withdraw/1970/01/02/00/");
    }

    #[test]
    fn test_prev_dir_walks_back_and_saturates_at_epoch() {
        let mut dir = S3HourScopedDirectory::new("withdraw", 86_400 + 3_600);
        assert_eq!(dir.to_string(), "withdraw/1970/01/02/01/");
        dir = dir.prev_dir();
        assert_eq!(dir.to_string(), "withdraw/1970/01/02/00/");
        dir = dir.prev_dir();
        assert_eq!(dir.to_string(), "withdraw/1970/01/01/23/");

        // Saturates at epoch.
        let epoch = S3HourScopedDirectory::new("withdraw", 0);
        assert_eq!(epoch.prev_dir(), epoch);
    }

    #[test]
    fn test_from_path_roundtrips_with_display() {
        let dir = S3HourScopedDirectory::new("withdraw", 1_700_000_000);
        let displayed = dir.to_string();
        let parsed = S3HourScopedDirectory::from_path(&displayed).expect("roundtrip");
        assert_eq!(parsed, dir);
        // Also accept the trailing-slash-stripped form.
        let parsed_nopfx = S3HourScopedDirectory::from_path(displayed.trim_end_matches('/'))
            .expect("roundtrip without trailing slash");
        assert_eq!(parsed_nopfx, dir);
    }

    #[test]
    fn test_from_path_rejects_wrong_shape() {
        assert!(S3HourScopedDirectory::from_path("withdraw/2024/03/15/").is_err()); // missing hour
        assert!(S3HourScopedDirectory::from_path("withdraw/2024/03/15/14/extra/").is_err()); // too many parts
        assert!(S3HourScopedDirectory::from_path("withdraw/2024/13/15/14/").is_err()); // invalid month
        assert!(S3HourScopedDirectory::from_path("withdraw/2024/02/30/14/").is_err()); // invalid day
        assert!(S3HourScopedDirectory::from_path("withdraw/2024/02/15/24/").is_err()); // invalid hour
        assert!(S3HourScopedDirectory::from_path("withdraw/notayear/03/15/14/").is_err()); // non-numeric
    }

    #[test]
    fn test_next_dir_and_completion_time() {
        let mut dir = S3HourScopedDirectory::new("withdraw", 3_599);
        assert_eq!(dir.to_string(), "withdraw/1970/01/01/00/");
        assert_eq!(dir.to_unix_seconds(), 0);
        assert_eq!(
            dir.write_completion_time(),
            3_600 + DIR_WRITES_COMPLETION_DELAY.as_secs()
        );

        for i in 0..24 {
            assert_eq!(dir.to_string(), format!("withdraw/1970/01/01/{:02}/", i));
            dir = dir.next_dir();
        }
        assert_eq!(dir.to_string(), "withdraw/1970/01/02/00/");
    }
}
