// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianResult;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

/// Stateful heartbeat writer.
pub struct HeartbeatWriter {
    pub enclave: Arc<Enclave>,
    pub max_failures_interval: Duration,
    /// a local record to track how many heartbeat attempts failed
    pub consecutive_failures: u32,
    /// records the last success timestamp
    pub last_success_at: Option<Instant>,
    /// records the first failure timestamp
    pub failure_window_start_at: Option<Instant>,
    /// the next sequence number used in s3 logs
    pub next_seq: u64,
}

impl HeartbeatWriter {
    pub fn new(enclave: Arc<Enclave>, max_failures_interval: Duration) -> Self {
        Self {
            enclave,
            max_failures_interval,
            consecutive_failures: 0,
            last_success_at: None,
            failure_window_start_at: None,
            next_seq: 0,
        }
    }

    /// Attempt to send one heartbeat.
    ///
    /// - If operator init is not complete, this is a no-op.
    /// - On success, resets failure state.
    /// - On S3 error, retries are driven by `run`; errors after elapsed failure window.
    pub async fn tick(&mut self, now: Instant) -> GuardianResult<()> {
        if !self.enclave.is_operator_init_complete() {
            return Ok(());
        }

        match self.enclave.log_heartbeat(self.next_seq).await {
            Ok(()) => {
                self.consecutive_failures = 0;
                self.last_success_at = Some(now);
                self.failure_window_start_at = None;
                self.next_seq += 1;
            }
            Err(e) => {
                // other errors shouldn't occur due to checks in operator_init_complete
                debug_assert!(matches!(e, GuardianError::S3Error(_)));

                self.consecutive_failures += 1;
                if self.failure_window_start_at.is_none() {
                    self.failure_window_start_at = Some(now);
                }

                let reference = self
                    .last_success_at
                    .or(self.failure_window_start_at)
                    .unwrap_or(now);
                if now.duration_since(reference) > self.max_failures_interval {
                    return Err(GuardianError::InternalError(format!(
                        "Heartbeat has no successful write for {:?}; last success {:?}, failure window start {:?}, consecutive failures {}, latest error {:?}",
                        self.max_failures_interval,
                        self.last_success_at,
                        self.failure_window_start_at,
                        self.consecutive_failures,
                        e
                    )));
                }
            }
        }

        Ok(())
    }

    /// Run the periodic heartbeat loop.
    pub async fn run(mut self, interval: Duration, retry_interval: Duration) -> GuardianResult<()> {
        let mut delay = Duration::ZERO;
        loop {
            tokio::time::sleep(delay).await;
            self.tick(Instant::now()).await?;
            delay = if self.consecutive_failures > 0 {
                retry_interval
            } else {
                interval
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::s3_logger::S3Logger;
    use crate::OperatorInitTestArgs;
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::Client;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use aws_smithy_mocks::RuleMode;
    use hashi_types::guardian::S3Config;

    fn mk_s3_logger(client: Client) -> S3Logger {
        S3Logger::from_client_for_tests(S3Config::mock_for_testing(), client)
    }

    async fn mk_operator_initialized_enclave(s3_logger: S3Logger) -> Arc<Enclave> {
        Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_s3_logger(s3_logger),
        )
        .await
    }

    #[tokio::test]
    async fn test_heartbeat_fails_after_max_failure_interval() {
        // Mock S3 client that always fails put_object.
        let put_fail = mock!(Client::put_object)
            .match_requests(|req| req.bucket() == Some("test-bucket"))
            .sequence()
            .http_status(500, None)
            .times(10)
            .build();

        // Disable retries so each heartbeat attempt makes exactly one put_object call.
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_fail], |b| b
            .retry_config(
                aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(1)
            ));

        let enclave = mk_operator_initialized_enclave(mk_s3_logger(client)).await;

        let max_failure_interval = Duration::from_secs(20);
        let mut writer = HeartbeatWriter::new(enclave, max_failure_interval);
        let t0 = Instant::now();

        assert!(writer.tick(t0).await.is_ok());
        assert_eq!(writer.consecutive_failures, 1);
        assert_eq!(writer.last_success_at, None);
        assert_eq!(writer.failure_window_start_at, Some(t0));

        assert!(writer.tick(t0 + Duration::from_secs(10)).await.is_ok());
        assert_eq!(writer.consecutive_failures, 2);
        assert_eq!(writer.last_success_at, None);

        assert!(writer.tick(t0 + Duration::from_secs(21)).await.is_err());
        assert_eq!(put_fail.num_calls(), 3usize);
    }

    #[tokio::test]
    async fn test_heartbeat_resets_failure_state_on_success() {
        // fail twice, succeed, then fail again
        let put_flaky = mock!(Client::put_object)
            .match_requests(|req| req.bucket() == Some("test-bucket"))
            .sequence()
            .http_status(500, None)
            .times(2)
            .output(|| PutObjectOutput::builder().build())
            .http_status(500, None)
            .build();

        // Disable retries so each heartbeat attempt makes exactly one put_object call.
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_flaky], |b| b
            .retry_config(
                aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(1)
            ));

        let enclave = mk_operator_initialized_enclave(mk_s3_logger(client)).await;

        let max_failure_interval = Duration::from_secs(30);
        let mut writer = HeartbeatWriter::new(enclave, max_failure_interval);
        let t0 = Instant::now();

        assert!(writer.tick(t0).await.is_ok());
        assert_eq!(writer.consecutive_failures, 1);
        assert_eq!(writer.last_success_at, None);
        assert_eq!(writer.failure_window_start_at, Some(t0));

        assert!(writer.tick(t0 + Duration::from_secs(10)).await.is_ok());
        assert_eq!(writer.consecutive_failures, 2);
        assert_eq!(writer.last_success_at, None);

        assert!(writer.tick(t0 + Duration::from_secs(15)).await.is_ok());
        assert_eq!(writer.consecutive_failures, 0, "should reset");
        assert_eq!(writer.next_seq, 1, "success should advance sequence");
        assert_eq!(writer.last_success_at, Some(t0 + Duration::from_secs(15)));
        assert_eq!(writer.failure_window_start_at, None);

        assert!(writer.tick(t0 + Duration::from_secs(40)).await.is_ok());
        assert_eq!(writer.consecutive_failures, 1);
        assert_eq!(writer.last_success_at, Some(t0 + Duration::from_secs(15)));
        assert_eq!(
            writer.failure_window_start_at,
            Some(t0 + Duration::from_secs(40))
        );

        assert_eq!(put_flaky.num_calls(), 4usize);
    }
}
