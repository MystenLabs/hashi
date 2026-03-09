use std::time::Duration;

// TODO: Leave as consts or make them configurable?
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_mins(1);
pub const MAX_HEARTBEAT_FAILURES: u32 = 5;

pub mod s3_logger; // used by the monitor
