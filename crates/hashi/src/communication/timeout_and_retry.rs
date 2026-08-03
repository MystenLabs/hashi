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

/// Wall clock a fan-out will spend before giving up on whoever has not
/// answered.
pub const FANOUT_DEADLINE: Duration = Duration::from_secs(60);

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
    let deadline = tokio::time::Instant::now() + FANOUT_DEADLINE;
    join_all(recipients.into_iter().map(|addr| {
        let req = request.clone();
        let send = send.clone();
        async move {
            let result =
                until_deadline(deadline, with_timeout_and_retry(|| send(addr, req.clone()))).await;
            (addr, result)
        }
    }))
    .await
}

async fn until_deadline<T>(
    deadline: tokio::time::Instant,
    fut: impl Future<Output = ChannelResult<T>>,
) -> ChannelResult<T> {
    tokio::time::timeout_at(deadline, fut)
        .await
        .unwrap_or(Err(ChannelError::Timeout))
}

pub async fn send_each<I, Req, Resp, F, Fut>(
    requests: I,
    send: F,
) -> Vec<(Address, ChannelResult<Resp>)>
where
    I: IntoIterator<Item = (Address, Req)>,
    Req: Clone + Send + Sync,
    Resp: Send,
    F: Fn(Address, Req) -> Fut + Clone + Send + Sync,
    Fut: Future<Output = ChannelResult<Resp>> + Send,
{
    let deadline = tokio::time::Instant::now() + FANOUT_DEADLINE;
    join_all(requests.into_iter().map(|(addr, req)| {
        let send = send.clone();
        async move {
            let result =
                until_deadline(deadline, with_timeout_and_retry(|| send(addr, req.clone()))).await;
            (addr, result)
        }
    }))
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    #[tokio::test(start_paused = true)]
    async fn no_peer_can_outlast_the_fan_out_deadline() {
        for (label, behaviour) in [
            ("refuses instantly", 0u8),
            ("swallows the connect", 1),
            ("connects then stalls", 2),
            ("answers slowly, just under CALL_TIMEOUT", 3),
        ] {
            let started = tokio::time::Instant::now();
            let results = send_to_many([Address::new([1u8; 32])], (), move |_, ()| async move {
                match behaviour {
                    0 => {}
                    1 => tokio::time::sleep(Duration::from_secs(5)).await,
                    2 => tokio::time::sleep(CALL_TIMEOUT).await,
                    _ => tokio::time::sleep(CALL_TIMEOUT - Duration::from_secs(1)).await,
                }
                Err::<(), _>(ChannelError::RequestFailed("no".into()))
            })
            .await;

            assert!(results[0].1.is_err(), "{label}");
            assert!(
                started.elapsed() <= Duration::from_secs(60),
                "{label}: took {:?}",
                started.elapsed()
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_that_answered_in_time_survives_a_slow_sibling() {
        let quick = Address::new([1u8; 32]);
        let never = Address::new([2u8; 32]);

        let results = send_to_many([quick, never], (), move |addr, ()| async move {
            if addr == never {
                tokio::time::sleep(Duration::from_secs(86_400)).await;
            }
            Ok::<_, ChannelError>(addr)
        })
        .await;

        let answered = results.iter().find(|(a, _)| *a == quick).unwrap();
        assert!(
            matches!(&answered.1, Ok(a) if *a == quick),
            "an answer that arrived before the deadline must be kept"
        );
        let cut = results.iter().find(|(a, _)| *a == never).unwrap();
        assert!(matches!(cut.1, Err(ChannelError::Timeout)));
    }

    #[tokio::test(start_paused = true)]
    async fn send_each_is_bounded_by_the_same_deadline() {
        let addr = Address::new([1u8; 32]);
        let started = tokio::time::Instant::now();

        let results = send_each([(addr, ())], move |_, ()| async move {
            tokio::time::sleep(Duration::from_secs(86_400)).await;
            Ok::<(), ChannelError>(())
        })
        .await;

        assert!(matches!(results[0].1, Err(ChannelError::Timeout)));
        assert!(
            started.elapsed() <= Duration::from_secs(60),
            "send_each took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_answering_slowly_but_in_time_is_accepted() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);

        let results = send_to_many([Address::new([1u8; 32])], (), move |_, ()| {
            let counter = Arc::clone(&counter);
            async move {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(15)).await;
                if n < 2 {
                    return Err(ChannelError::RequestFailed("slow".into()));
                }
                Ok(())
            }
        })
        .await;

        assert!(
            results[0].1.is_ok(),
            "an answer landing inside the deadline must be kept, not cut"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_is_still_retried_within_the_deadline() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        let _ = send_to_many([Address::new([1u8; 32])], (), move |_, ()| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(ChannelError::RequestFailed("busy".into()))
            }
        })
        .await;
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            MAX_RETRIES + 1,
            "a fast-failing peer still gets the full budget inside the deadline"
        );
    }
}
