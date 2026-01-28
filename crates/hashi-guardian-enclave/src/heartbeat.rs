use crate::Enclave;
use hashi_guardian_shared::GuardianError::InternalError;
use hashi_guardian_shared::{GuardianResult, LogMessage};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// Send heartbeat messages to S3 once per interval, until max_failures failures happen
pub async fn run_heartbeat_writer_task(
    enclave: Arc<Enclave>,
    interval: Duration,
    max_failures: u32,
) -> GuardianResult<()> {
    let mut ticker = tokio::time::interval(interval);
    let mut failures = 0;
    let mut first_heart_beat = true;

    loop {
        ticker.tick().await;

        // TODO: When should we start heartbeats? post operator_init or post provisioner_init?
        if !enclave.is_operator_init_complete() {
            continue;
        } else if first_heart_beat {
            first_heart_beat = false;
            info!("Beginning to write heartbeats to S3");
        }

        if let Err(e) = enclave.sign_and_log(LogMessage::Heartbeat).await {
            failures += 1;
            if failures >= max_failures {
                return Err(InternalError(format!(
                    "Heartbeat failed for {} times: {:?}",
                    max_failures, e
                )));
            }
        } else {
            failures = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::Client;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use aws_smithy_mocks::RuleMode;
    use hashi_guardian_shared::s3_logger::S3Logger;
    use hashi_guardian_shared::S3Config;
    use crate::OperatorInitTestArgs;

    #[tokio::test(start_paused = true)]
    async fn test_heartbeat_fails_after_max_failures() {
        // Mock S3 client that always fails put_object, and disable retries so failures are immediate.
        let put_fail = mock!(Client::put_object)
            .match_requests(|req| req.bucket() == Some("test-bucket"))
            .sequence()
            .http_status(500, None)
            .times(10)
            .build();

        let max_attempts = 1;
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_fail], |b| b
            .retry_config(
                aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(max_attempts)
            ));

        let s3_logger = S3Logger::from_client_for_tests(
            "test-session-id".to_string(),
            S3Config::mock_for_testing(),
            client,
        );

        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_s3_logger(s3_logger),
        )
        .await;

        let max_failures = 3;
        let hb = tokio::spawn(run_heartbeat_writer_task(
            enclave,
            Duration::from_secs(1),
            max_failures as u32,
        ));

        // interval.tick() fires immediately once, then every second.
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;

        let res = hb.await.expect("heartbeat task should join");
        assert_eq!(put_fail.num_calls(), max_failures as usize);

        assert!(
            res.is_err(),
            "expected heartbeat to return Err after failures"
        );
    }

    #[tokio::test(start_paused = true)]
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
        let max_attempts = 1;
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_flaky], |b| b
            .retry_config(
                aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(max_attempts)
            ));

        let s3_logger = S3Logger::from_client_for_tests(
            "test-session-id".to_string(),
            S3Config::mock_for_testing(),
            client,
        );

        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_s3_logger(s3_logger),
        )
        .await;

        let hb = tokio::spawn(run_heartbeat_writer_task(
            enclave,
            Duration::from_secs(1),
            max_failures,
        ));

        // `interval.tick()` completes immediately the first time. Drive exactly 3 attempts:
        // 1) fail (immediate), 2) fail (after +1s), 3) succeed (after +1s).
        for expected_calls in 1..=3 {
            if expected_calls > 1 {
                tokio::time::advance(Duration::from_secs(1)).await;
            }

            // Give the spawned task a chance to run and consume the ready tick.
            for _ in 0..20 {
                tokio::task::yield_now().await;
                if put_flaky.num_calls() >= expected_calls {
                    break;
                }
            }
        }

        // If the failure counter wasn't reset by the success, the task would have returned Err.
        assert!(!hb.is_finished(), "heartbeat task unexpectedly finished");
        assert_eq!(put_flaky.num_calls(), 3);

        hb.abort();
        let _ = hb.await;
    }
}
