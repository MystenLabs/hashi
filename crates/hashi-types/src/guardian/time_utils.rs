use std::time::SystemTime;
use std::time::UNIX_EPOCH;

pub type UnixMillis = u64;

pub const MILLIS_PER_SECOND: UnixMillis = 1000;

/// Milliseconds since Unix epoch.
/// Panics if the system clock is before `UNIX_EPOCH`.
pub fn now_timestamp_ms() -> UnixMillis {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system_time cannot be before Unix epoch")
        .as_millis() as UnixMillis
}

pub fn unix_millis_to_seconds(ms: UnixMillis) -> u64 {
    ms / MILLIS_PER_SECOND
}

#[cfg(test)]
mod tests {
    use super::unix_millis_to_seconds;

    #[test]
    fn test_unix_millis_to_seconds_floor_division() {
        assert_eq!(unix_millis_to_seconds(0), 0);
        assert_eq!(unix_millis_to_seconds(999), 0);
        assert_eq!(unix_millis_to_seconds(1_000), 1);
        assert_eq!(unix_millis_to_seconds(1_500), 1);
    }
}
