// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Retry and timeout utilities

use super::ChannelError;
use super::ChannelResult;
use backon::ExponentialBuilder;
use backon::Retryable;
use futures::future::join_all;
use std::future::Future;
use std::time::Duration;
use sui_sdk_types::Address;

// TODO: Use lower thresholds for unit tests.
pub const RETRY_MIN_DELAY: Duration = Duration::from_millis(100);
pub const RETRY_MAX_DELAY: Duration = Duration::from_secs(2);
pub const MAX_RETRIES: usize = 10;
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn with_timeout_and_retry<T, F, Fut>(f: F) -> ChannelResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ChannelResult<T>>,
{
    with_timeout_and_retry_budget(f, CALL_TIMEOUT, MAX_RETRIES).await
}

/// Like [`with_timeout_and_retry`], but with a caller-chosen per-call timeout
/// and retry budget.
///
/// Use this on paths that already have their own outer retry loop (e.g. the
/// partial-signature collection rounds in `mpc::signing`), where the default
/// budget of 10 retries x 30 s lets a single unresponsive peer stall the
/// caller for minutes.
pub async fn with_timeout_and_retry_budget<T, F, Fut>(
    mut f: F,
    call_timeout: Duration,
    max_retries: usize,
) -> ChannelResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ChannelResult<T>>,
{
    (move || with_timeout(f(), call_timeout))
        .retry(retry_policy(max_retries))
        .await
}

fn retry_policy(max_retries: usize) -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(RETRY_MIN_DELAY)
        .with_max_delay(RETRY_MAX_DELAY)
        .with_max_times(max_retries)
        .with_jitter()
}

async fn with_timeout<T>(
    fut: impl Future<Output = ChannelResult<T>>,
    call_timeout: Duration,
) -> ChannelResult<T> {
    match tokio::time::timeout(call_timeout, fut).await {
        Ok(result) => result,
        Err(_) => Err(ChannelError::Timeout),
    }
}

pub async fn send_to_many<I, Req, Resp, F, Fut>(
    recipients: I,
    request: Req,
    send: F,
) -> Vec<(Address, ChannelResult<Resp>)>
where
    I: IntoIterator<Item = Address>,
    Req: Clone + Send + Sync,
    Resp: Send,
    F: Fn(Address, Req) -> Fut + Clone + Send + Sync,
    Fut: Future<Output = ChannelResult<Resp>> + Send,
{
    join_all(recipients.into_iter().map(|addr| {
        let req = request.clone();
        let send = send.clone();
        async move {
            let result = with_timeout_and_retry(|| send(addr, req.clone())).await;
            (addr, result)
        }
    }))
    .await
}
