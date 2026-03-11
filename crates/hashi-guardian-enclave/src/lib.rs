use std::time::Duration;

// TODO: Leave as consts or make them configurable?
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_mins(1);
pub const HEARTBEAT_RETRY_INTERVAL: Duration = Duration::from_secs(10);
pub const MAX_HEARTBEAT_FAILURES_INTERVAL: Duration = Duration::from_mins(5);

pub mod s3_logger; // used by the monitor
