use crate::guardian::time_utils::UnixMillis;
use crate::guardian::time_utils::unix_millis_to_seconds;
use std::fmt;
use time::OffsetDateTime;

type Year = i32;
type Month = u8;
type Day = u8;
type Hour = u8;

/// An S3 directory: prefix/YYYY/MM/DD/HH.
/// All logs emitted within an hour are stored in the same directory, e.g., logs emitted between 12-1 PM are in the `<prefix>`/12 directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3Directory {
    prefix: String,
    year: Year,
    month: Month,
    day: Day,
    hour: Hour,
}

impl S3Directory {
    pub fn new(prefix: &str, t: UnixMillis) -> Self {
        let unix_seconds =
            i64::try_from(unix_millis_to_seconds(t)).expect("timestamp should fit i64");
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
}

impl fmt::Display for S3Directory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{:04}/{:02}/{:02}/{:02}",
            self.prefix, self.year, self.month, self.day, self.hour
        )
    }
}

#[cfg(test)]
mod tests {
    use super::S3Directory;

    #[test]
    fn test_epoch_directory_format() {
        let dir = S3Directory::new("heartbeat", 0);
        assert_eq!(dir.to_string(), "heartbeat/1970/01/01/00");
    }

    #[test]
    fn test_hour_and_day_rollover_format() {
        let before_hour_boundary = S3Directory::new("withdraw", 3_599_999);
        assert_eq!(before_hour_boundary.to_string(), "withdraw/1970/01/01/00");

        let next_hour = S3Directory::new("withdraw", 3_600_000);
        assert_eq!(next_hour.to_string(), "withdraw/1970/01/01/01");

        let next_day = S3Directory::new("withdraw", 86_400_000);
        assert_eq!(next_day.to_string(), "withdraw/1970/01/02/00");
    }
}
