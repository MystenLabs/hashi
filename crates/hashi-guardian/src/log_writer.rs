// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::s3_client::GuardianS3Client;
use crate::ACTIVATING_READER_CLOCK_SKEW_BUDGET;
use crate::OTHER_SESSION_QUIET_PERIOD;
use crate::S3_WRITE_ATTEMPT_TIMEOUT;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianError::S3Error;
use hashi_types::guardian::GuardianSignKeyPair;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::LogType;
use hashi_types::guardian::SessionID;
use std::future::Future;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::warn;

const MAX_S3_WRITE_ATTEMPTS: usize = 5;
const S3_WRITE_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// Serializes every Guardian log write and owns the session-heartbeat fence.
pub(crate) struct LogWriter {
    state: Mutex<LatestHeartbeatTime>,
}

struct LatestHeartbeatTime(Option<Instant>);

enum DeadlineExceeded<T> {
    PerAttemptTimerElapsed,
    CompletionObservedLate(T),
}

impl LatestHeartbeatTime {
    fn new() -> Self {
        Self(None)
    }

    /// The local monotonic deadline before which the next S3 write must finish.
    /// The skew budget makes this deadline earlier than the reader's quiet
    /// period boundary for the heartbeat's signed wall-clock timestamp.
    fn next_write_deadline(&self) -> Option<Instant> {
        self.0.map(|heartbeat| {
            heartbeat
                .checked_add(OTHER_SESSION_QUIET_PERIOD)
                .and_then(|deadline| deadline.checked_sub(ACTIVATING_READER_CLOCK_SKEW_BUDGET))
                .expect("Guardian heartbeat deadline overflow")
        })
    }

    fn renew(&mut self, heartbeat: Instant) {
        self.0 = Some(heartbeat);
    }
}

impl LogWriter {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(LatestHeartbeatTime::new()),
        }
    }

    /// Construct and persist one serialized log record; see the README for fencing assumptions.
    pub(crate) async fn write(
        &self,
        s3: &GuardianS3Client,
        session_id: SessionID,
        message: LogMessage,
        signing_key: &GuardianSignKeyPair,
    ) {
        let mut state = self.state.lock().await;
        let write_started_at = Instant::now();
        let record = LogRecord::new(session_id, message, signing_key);
        let deadline = state.next_write_deadline();

        write_with_retries(s3, &record, deadline).await;
        if record.log_type() == LogType::Heartbeat {
            state.renew(write_started_at);
        }
    }
}

async fn write_with_retries(
    s3: &GuardianS3Client,
    record: &LogRecord,
    absolute_deadline: Option<Instant>,
) {
    let key = record.object_key();
    let mut last_error = None;

    for attempt in 1..=MAX_S3_WRITE_ATTEMPTS {
        let attempt_deadline = Instant::now()
            .checked_add(S3_WRITE_ATTEMPT_TIMEOUT)
            .expect("S3 write deadline overflow");
        if absolute_deadline.is_some_and(|deadline| attempt_deadline >= deadline) {
            panic_write_failure(
                key,
                "cannot complete another S3 attempt before the heartbeat fence",
                last_error,
            );
        }

        match complete_before_attempt_deadline(attempt_deadline, s3.write_log_record_once(record))
            .await
        {
            Ok(Ok(())) => return,
            Ok(Err(error)) => last_error = Some(error),
            Err(DeadlineExceeded::PerAttemptTimerElapsed) => {
                last_error = Some(S3Error(format!(
                    "S3 log {key} reached its attempt deadline before completion was accepted"
                )));
            }
            Err(DeadlineExceeded::CompletionObservedLate(Ok(()))) => {
                last_error = Some(S3Error(format!(
                    "S3 log {key} was confirmed after its attempt deadline"
                )));
            }
            Err(DeadlineExceeded::CompletionObservedLate(Err(error))) => {
                last_error = Some(S3Error(format!(
                    "S3 log {key} failed after its attempt deadline: {error}"
                )));
            }
        }

        if attempt < MAX_S3_WRITE_ATTEMPTS {
            warn!(
                %key,
                attempt,
                max_attempts = MAX_S3_WRITE_ATTEMPTS,
                error = ?last_error,
                "S3 log write attempt failed; retrying"
            );
            tokio::time::sleep(S3_WRITE_RETRY_INTERVAL).await;
        }
    }

    panic_write_failure(
        key,
        "failed after the maximum number of S3 attempts",
        last_error,
    )
}

fn panic_write_failure(key: &str, reason: &str, error: Option<GuardianError>) -> ! {
    if let Some(error) = error {
        panic!("S3 log {key} {reason}: {error}");
    }
    panic!("S3 log {key} {reason}");
}

/// Complete one S3 attempt before its deadline; see the README for fencing assumptions.
async fn complete_before_attempt_deadline<F>(
    deadline: Instant,
    future: F,
) -> Result<F::Output, DeadlineExceeded<F::Output>>
where
    F: Future,
{
    tokio::select! {
        // biased ensures that the deadline check is polled first
        biased;
        // Deadline check
        _ = tokio::time::sleep_until(deadline) => {
            Err(DeadlineExceeded::PerAttemptTimerElapsed)
        },
        // S3 write check
        result = future => {
            if Instant::now() < deadline {
                Ok(result)
            } else {
                Err(DeadlineExceeded::CompletionObservedLate(result))
            }
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
    use hashi_types::guardian::GuardianInfo;
    use hashi_types::guardian::HeartbeatLogMessage;
    use hashi_types::guardian::InitLogMessage;
    use hashi_types::guardian::NitroAttestation;
    use hashi_types::guardian::ResolvedS3Config;
    use std::future::pending;
    use std::future::ready;
    use std::sync::Arc;

    fn signing_key() -> GuardianSignKeyPair {
        GuardianSignKeyPair::from([7u8; 32])
    }

    fn session_id(signing_key: &GuardianSignKeyPair) -> SessionID {
        SessionID::from_signing_pubkey(&signing_key.verification_key())
    }

    fn mock_s3(client: Client) -> GuardianS3Client {
        GuardianS3Client::from_client_for_tests(ResolvedS3Config::mock_for_testing(), client)
    }

    fn heartbeat(seq: u64) -> LogMessage {
        LogMessage::Heartbeat(HeartbeatLogMessage::new(seq))
    }

    fn first_init(signing_key: &GuardianSignKeyPair) -> LogMessage {
        LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
            attestation: NitroAttestation::new(vec![]),
            signing_public_key: signing_key.verification_key(),
        }))
    }

    fn signed_init() -> LogMessage {
        LogMessage::Init(Box::new(InitLogMessage::OIGuardianInfo(Box::new(
            GuardianInfo::mock_for_testing(),
        ))))
    }

    #[tokio::test(start_paused = true)]
    async fn retries_four_failures_then_succeeds() {
        let put_flaky = mock!(Client::put_object)
            .match_requests(|req| {
                req.key()
                    .is_some_and(|key| key.ends_with("01-oi-attestation-unsigned.json"))
            })
            .sequence()
            .http_status(500, None)
            .times(4)
            .output(|| PutObjectOutput::builder().build())
            .build();
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_flaky]);
        let s3 = mock_s3(client);
        let writer = LogWriter::new();
        let signing_key = signing_key();

        writer
            .write(
                &s3,
                session_id(&signing_key),
                first_init(&signing_key),
                &signing_key,
            )
            .await;

        assert_eq!(put_flaky.num_calls(), 5);
    }

    #[tokio::test]
    async fn write_waits_for_serialization_lock_before_put() {
        let put_ok = mock!(Client::put_object).then_output(|| PutObjectOutput::builder().build());
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_ok]);
        let s3 = Arc::new(mock_s3(client));
        let writer = Arc::new(LogWriter::new());
        let signing_key = Arc::new(signing_key());
        let state_guard = writer.state.lock().await;

        let task = {
            let writer = writer.clone();
            let s3 = s3.clone();
            let signing_key = signing_key.clone();
            tokio::spawn(async move {
                writer
                    .write(
                        &s3,
                        session_id(&signing_key),
                        first_init(&signing_key),
                        &signing_key,
                    )
                    .await
            })
        };
        tokio::task::yield_now().await;

        assert_eq!(put_ok.num_calls(), 0);
        drop(state_guard);
        task.await.unwrap();
        assert_eq!(put_ok.num_calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn write_panics_after_five_failures() {
        let put_fail = mock!(Client::put_object)
            .sequence()
            .http_status(500, None)
            .times(5)
            .build();
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_fail]);
        let s3 = Arc::new(mock_s3(client));
        let writer = Arc::new(LogWriter::new());
        let signing_key = Arc::new(signing_key());

        let task = tokio::spawn(async move {
            writer
                .write(
                    &s3,
                    session_id(&signing_key),
                    first_init(&signing_key),
                    &signing_key,
                )
                .await
        });

        assert!(task.await.unwrap_err().is_panic());
        assert_eq!(put_fail.num_calls(), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn no_attempt_starts_when_its_full_budget_reaches_the_fence() {
        let put_ok = mock!(Client::put_object).then_output(|| PutObjectOutput::builder().build());
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_ok]);
        let s3 = Arc::new(mock_s3(client));
        let writer = Arc::new(LogWriter::new());
        let signing_key = Arc::new(signing_key());

        writer
            .write(&s3, session_id(&signing_key), heartbeat(1), &signing_key)
            .await;
        tokio::time::advance(
            OTHER_SESSION_QUIET_PERIOD
                - ACTIVATING_READER_CLOCK_SKEW_BUDGET
                - S3_WRITE_ATTEMPT_TIMEOUT,
        )
        .await;

        let task = {
            let writer = writer.clone();
            let s3 = s3.clone();
            let signing_key = signing_key.clone();
            tokio::spawn(async move {
                writer
                    .write(&s3, session_id(&signing_key), signed_init(), &signing_key)
                    .await
            })
        };

        assert!(task.await.unwrap_err().is_panic());
        assert_eq!(put_ok.num_calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn non_heartbeat_write_does_not_renew_the_heartbeat_fence() {
        let put_ok = mock!(Client::put_object).then_output(|| PutObjectOutput::builder().build());
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_ok]);
        let s3 = Arc::new(mock_s3(client));
        let writer = Arc::new(LogWriter::new());
        let signing_key = Arc::new(signing_key());

        writer
            .write(&s3, session_id(&signing_key), heartbeat(1), &signing_key)
            .await;
        tokio::time::advance(Duration::from_mins(3)).await;
        writer
            .write(&s3, session_id(&signing_key), signed_init(), &signing_key)
            .await;
        tokio::time::advance(Duration::from_mins(1)).await;

        let task = tokio::spawn(async move {
            writer
                .write(&s3, session_id(&signing_key), heartbeat(2), &signing_key)
                .await
        });

        assert!(task.await.unwrap_err().is_panic());
        assert_eq!(put_ok.num_calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn successful_heartbeat_renews_the_heartbeat_fence() {
        let put_ok = mock!(Client::put_object).then_output(|| PutObjectOutput::builder().build());
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_ok]);
        let s3 = mock_s3(client);
        let writer = LogWriter::new();
        let signing_key = signing_key();

        writer
            .write(&s3, session_id(&signing_key), heartbeat(1), &signing_key)
            .await;
        tokio::time::advance(Duration::from_mins(3)).await;
        writer
            .write(&s3, session_id(&signing_key), heartbeat(2), &signing_key)
            .await;
        tokio::time::advance(Duration::from_mins(3)).await;
        writer
            .write(&s3, session_id(&signing_key), signed_init(), &signing_key)
            .await;

        assert_eq!(put_ok.num_calls(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_wins_when_write_is_also_ready() {
        let deadline = Instant::now();

        let result = complete_before_attempt_deadline(deadline, ready(())).await;

        assert!(matches!(
            result,
            Err(DeadlineExceeded::PerAttemptTimerElapsed)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn pending_write_loses_when_attempt_deadline_elapses() {
        let deadline = Instant::now() + S3_WRITE_ATTEMPT_TIMEOUT;

        let result = complete_before_attempt_deadline(deadline, pending::<()>()).await;

        assert!(matches!(
            result,
            Err(DeadlineExceeded::PerAttemptTimerElapsed)
        ));
        assert_eq!(Instant::now(), deadline);
    }
}
