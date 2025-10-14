//! Error types for communication channels

use thiserror::Error;

pub type ChannelResult<T> = Result<T, ChannelError>;

#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Receive timeout")]
    Timeout,

    #[error("Channel closed")]
    Closed,

    #[error("Channel error: {0}")]
    Other(String),
}
