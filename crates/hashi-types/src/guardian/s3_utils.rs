use crate::guardian::time_utils::UnixSeconds;
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

    /// The time at which writes to current S3 directory finish.
    /// DIR_WRITES_COMPLETION_DELAY accounts for any in-flight retries and clock skew.
    pub fn write_completion_time(&self) -> UnixSeconds {
        self.next_dir()
            .to_unix_seconds()
            .saturating_add(DIR_WRITES_COMPLETION_DELAY.as_secs())
    }

    pub fn to_unix_seconds(&self) -> UnixSeconds {
        let month = time::Month::try_from(self.month).expect("month should be valid");
        let date =
            Date::from_calendar_date(self.year, month, self.day).expect("date should be valid");
        let time = Time::from_hms(self.hour, 0, 0).expect("hour should be valid");
        let ts = PrimitiveDateTime::new(date, time)
            .assume_utc()
            .unix_timestamp();
        UnixSeconds::try_from(ts).expect("timestamp should be non-negative")
    }
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
