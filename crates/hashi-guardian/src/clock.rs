// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Wall time for Guardian's S3 logs, heartbeat checks, and withdrawal freshness.
//! Monotonic deadlines continue to use `Instant`.

use hashi_types::guardian::time::unix_millis_to_seconds;
use hashi_types::guardian::time::UnixMillis;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::GuardianError::Unavailable;
use hashi_types::guardian::GuardianResult;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

pub type SharedClock = Arc<dyn WallClock>;

pub trait WallClock: Send + Sync {
    fn now_ms(&self) -> GuardianResult<UnixMillis>;

    fn now_secs(&self) -> GuardianResult<UnixSeconds> {
        self.now_ms().map(unix_millis_to_seconds)
    }
}

/// Explicit system-clock backend for off-enclave tooling and development.
/// Production enclave startup always selects PTP; this is not a fallback.
pub struct SystemClock;

impl WallClock for SystemClock {
    fn now_ms(&self) -> GuardianResult<UnixMillis> {
        let elapsed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| Unavailable(format!("System clock is before Unix epoch: {e}")))?;
        duration_to_millis(elapsed)
    }
}

fn duration_to_millis(elapsed: Duration) -> GuardianResult<UnixMillis> {
    elapsed
        .as_millis()
        .try_into()
        .map_err(|_| Unavailable("Wall-clock timestamp does not fit in milliseconds".into()))
}

/// Open and read the production clock before creating keys or serving requests.
pub fn initialize_clock() -> GuardianResult<SharedClock> {
    #[cfg(feature = "non-enclave-dev")]
    let clock: SharedClock = Arc::new(SystemClock);
    #[cfg(all(not(feature = "non-enclave-dev"), target_os = "linux"))]
    let clock: SharedClock = Arc::new(PtpClock::open()?);
    #[cfg(all(not(feature = "non-enclave-dev"), not(target_os = "linux")))]
    {
        Err(Unavailable(
            "Guardian requires Linux PTP; use non-enclave-dev for development".into(),
        ))
    }
    #[cfg(any(feature = "non-enclave-dev", target_os = "linux"))]
    {
        clock.now_ms()?;
        Ok(clock)
    }
}

#[cfg(all(target_os = "linux", not(feature = "non-enclave-dev")))]
struct PtpClock(std::fs::File);

#[cfg(all(target_os = "linux", not(feature = "non-enclave-dev")))]
impl PtpClock {
    fn open() -> GuardianResult<Self> {
        std::fs::File::open("/dev/ptp0")
            .map(Self)
            .map_err(|e| Unavailable(format!("Failed to open /dev/ptp0: {e}")))
    }
}

#[cfg(all(target_os = "linux", not(feature = "non-enclave-dev")))]
impl WallClock for PtpClock {
    fn now_ms(&self) -> GuardianResult<UnixMillis> {
        use nix::time::clock_gettime;
        use nix::time::ClockId;
        use std::os::fd::AsRawFd;

        // Linux FD_TO_CLOCKID. The owned File stays open for every read.
        // https://man7.org/linux/man-pages/man2/clock_gettime.2.html#DESCRIPTION
        let id = ClockId::from_raw((!self.0.as_raw_fd() << 3) | 3);
        let time =
            clock_gettime(id).map_err(|e| Unavailable(format!("Failed to read /dev/ptp0: {e}")))?;
        let seconds = u64::try_from(time.tv_sec())
            .map_err(|_| Unavailable("PTP clock is before Unix epoch".into()))?;
        let nanos = u32::try_from(time.tv_nsec())
            .map_err(|_| Unavailable("PTP clock returned invalid nanoseconds".into()))?;
        duration_to_millis(Duration::new(seconds, nanos))
    }
}

#[cfg(test)]
pub(crate) struct FixedClock(pub UnixMillis);

#[cfg(test)]
impl WallClock for FixedClock {
    fn now_ms(&self) -> GuardianResult<UnixMillis> {
        Ok(self.0)
    }
}

#[cfg(test)]
pub(crate) struct FailedClock;

#[cfg(test)]
impl WallClock for FailedClock {
    fn now_ms(&self) -> GuardianResult<UnixMillis> {
        Err(Unavailable("Injected clock read failure".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn milliseconds_and_seconds_truncate_subunits() {
        assert_eq!(
            duration_to_millis(Duration::new(123, 456_789_123)).unwrap(),
            123_456
        );
        assert_eq!(FixedClock(123_999).now_secs().unwrap(), 123);
    }

    #[cfg(all(target_os = "linux", not(feature = "non-enclave-dev")))]
    #[test]
    fn open_file_is_not_necessarily_a_readable_clock() {
        let clock = PtpClock(std::fs::File::open("/dev/null").unwrap());
        assert!(matches!(clock.now_ms(), Err(Unavailable(_))));
    }
}
