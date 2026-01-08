//! Retry and timeout utilities

use super::ChannelError;
use super::ChannelResult;
use backon::ExponentialBuilder;
use backon::Retryable;
use std::future::Future;
use std::time::Duration;

// TODO: Use lower thresholds for unit tests.
pub const RETRY_MIN_DELAY: Duration = Duration::from_millis(100);
pub const RETRY_MAX_DELAY: Duration = Duration::from_secs(2);
pub const MAX_RETRIES: usize = 10;
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

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
