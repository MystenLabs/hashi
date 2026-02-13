use crate::Enclave;
use hashi_guardian_shared::GuardianError;
use hashi_guardian_shared::GuardianResult;
use hashi_guardian_shared::LogMessage;
use std::sync::Arc;
use std::time::Duration;

/// Stateful heartbeat writer.
pub struct HeartbeatWriter {
    pub enclave: Arc<Enclave>,
    pub max_failures: u32,
    pub consecutive_failures: u32,
}

impl HeartbeatWriter {
    pub fn new(enclave: Arc<Enclave>, max_failures: u32) -> Self {
        Self {
            enclave,
            max_failures,
            consecutive_failures: 0,
        }
    }

    /// Attempt to send one heartbeat.
    ///
    /// - If operator init is not complete, this is a no-op.
    /// - On success, resets the failure counter.
    /// - On S3 error, increments failures; errors once `max_failures` is reached.
    pub async fn tick(&mut self) -> GuardianResult<()> {
        if !self.enclave.is_operator_init_complete() {
            return Ok(());
        }

        match self.enclave.sign_and_log(LogMessage::Heartbeat).await {
            Ok(()) => {
                self.consecutive_failures = 0;
            }
            Err(e) => {
                // other errors shouldn't occur due to checks in operator_init_complete
                debug_assert!(matches!(e, GuardianError::S3Error(_)));

                self.consecutive_failures += 1;
                if self.consecutive_failures >= self.max_failures {
                    return Err(GuardianError::InternalError(format!(
                        "Heartbeat failed for {} times: {:?}",
                        self.max_failures, e
                    )));
                }
            }
        }

        Ok(())
    }

    /// Run the periodic heartbeat loop.
    pub async fn run(mut self, interval: Duration) -> GuardianResult<()> {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            self.tick().await?;
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
    use hashi_guardian_shared::S3Config;

    fn mk_s3_logger(client: Client) -> S3Logger {
        S3Logger::from_client_for_tests(
            "test-session-id".to_string(),
            S3Config::mock_for_testing(),
            client,
        )
    }

    async fn mk_operator_initialized_enclave(s3_logger: S3Logger) -> Arc<Enclave> {
        Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_s3_logger(s3_logger),
        )
        .await
    }

    #[tokio::test]
    async fn test_heartbeat_fails_after_max_failures() {
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

        let max_failures = 3u32;
        let mut writer = HeartbeatWriter::new(enclave, max_failures);

        // First (max_failures - 1) failures should be tolerated.
        for i in 0..(max_failures - 1) {
            assert!(writer.tick().await.is_ok());
            assert_eq!(writer.consecutive_failures, i + 1);
        }

        // The next failure should exceed the threshold and return Err.
        assert!(writer.tick().await.is_err());
        assert_eq!(put_fail.num_calls(), max_failures as usize);
    }

    #[tokio::test]
    async fn test_heartbeat_resets_failures_on_success_before_threshold() {
        // Fail (max_failures - 1) times, then succeed once. This should reset the failure counter
        // and *not* return an error.
        let max_failures = 3u32;

        let put_flaky = mock!(Client::put_object)
            .match_requests(|req| req.bucket() == Some("test-bucket"))
            .sequence()
            .http_status(500, None)
            .times((max_failures - 1) as usize)
            .output(|| PutObjectOutput::builder().build())
            .build();

        // Disable retries so each heartbeat attempt makes exactly one put_object call.
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_flaky], |b| b
            .retry_config(
                aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(1)
            ));

        let enclave = mk_operator_initialized_enclave(mk_s3_logger(client)).await;

        let mut writer = HeartbeatWriter::new(enclave, max_failures);
        for i in 0..(max_failures - 1) {
            assert!(writer.tick().await.is_ok());
            assert_eq!(writer.consecutive_failures, i + 1);
        }

        assert!(writer.tick().await.is_ok());
        assert_eq!(writer.consecutive_failures, 0, "should reset");

        assert_eq!(put_flaky.num_calls(), max_failures as usize);
    }
}
