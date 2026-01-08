//! Retry and timeout utilities

use super::ChannelError;
use super::ChannelResult;
use backon::ExponentialBuilder;
use backon::Retryable;
use std::future::Future;
use std::time::Duration;

// Unit tests use low thresholds for quick feedback.
#[cfg(test)]
pub const RETRY_MIN_DELAY: Duration = Duration::from_millis(50);
#[cfg(test)]
pub const RETRY_MAX_DELAY: Duration = Duration::from_millis(100);
#[cfg(test)]
pub const MAX_RETRIES: usize = 1;
#[cfg(test)]
pub const CALL_TIMEOUT: Duration = Duration::from_millis(200);

#[cfg(not(test))]
pub const RETRY_MIN_DELAY: Duration = Duration::from_secs(2);
#[cfg(not(test))]
pub const RETRY_MAX_DELAY: Duration = Duration::from_secs(10);
#[cfg(not(test))]
pub const MAX_RETRIES: usize = 3;
#[cfg(not(test))]
pub const CALL_TIMEOUT: Duration = Duration::from_secs(90);

pub async fn with_timeout_and_retry<T, F, Fut>(mut f: F) -> ChannelResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ChannelResult<T>>,
{
    (move || with_timeout(f())).retry(retry_policy()).await
}

fn retry_policy() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(RETRY_MIN_DELAY)
        .with_max_delay(RETRY_MAX_DELAY)
        .with_max_times(MAX_RETRIES)
}

async fn with_timeout<T>(fut: impl Future<Output = ChannelResult<T>>) -> ChannelResult<T> {
    match tokio::time::timeout(CALL_TIMEOUT, fut).await {
        Ok(result) => result,
        Err(_) => Err(ChannelError::Timeout),
    }
}
