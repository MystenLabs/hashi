use std::time::Duration;

// TODO: Leave as consts or make them configurable?
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_mins(1);
pub const MAX_HEARTBEAT_FAILURES: u32 = 5;

/// If we do not see any heartbeats for this amount of time, then we can safely regard the enclave to have died.
/// MAX_HEARTBEAT_FAILURES * HEARTBEAT_INTERVAL + grace period. The grace period accounts for time spent retrying & clock skew.
pub const NO_HEARTBEAT_PERIOD: Duration = Duration::from_mins(10);

pub mod s3_logger; // used by the monitor
