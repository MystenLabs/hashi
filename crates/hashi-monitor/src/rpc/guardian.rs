use crate::domain::PollOutcome;
use crate::domain::WithdrawalEvent;
use crate::domain::WithdrawalEventType;
use crate::domain::now_unix_seconds;
use hashi_guardian_enclave::s3_logger::S3Logger;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::S3_DIR_HEARTBEAT;
use hashi_types::guardian::S3_DIR_INIT;
use hashi_types::guardian::S3_DIR_WITHDRAW;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::guardian::s3_utils::S3Directory;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::guardian::time_utils::unix_millis_to_seconds;
use hashi_types::guardian::verify_enclave_attestation;
use std::collections::HashMap;
use tracing::info;

/// Idea: Since guardian can write out of order and S3 ListObjectVersions only supports lexicographic cursors, we
///       read from an S3 directory only after we are certain that all writes to it finish.
/// E.g., 12-1 PM bucket is read at 1 PM + DIR_WRITES_COMPLETION_DELAY, e.g., 1:10 PM.
pub struct GuardianWithdrawalsPoller {
    /// S3 logger
    s3_client: S3Logger,
    /// cursor
    cursor: S3Cursor,
    /// all the enclave pub keys it has seen: session id -> enclave pub key
    enclave_pub_keys: HashMap<String, GuardianPubKey>,
}

impl GuardianWithdrawalsPoller {
    // Note: Throws an error if there is a connectivity issue with S3
    pub async fn new(config: S3Config, start: UnixSeconds) -> anyhow::Result<Self> {
        let poller = Self {
            s3_client: S3Logger::new(config).await,
            cursor: S3Cursor::new(start, true),
            enclave_pub_keys: HashMap::new(),
        };

        poller
            .s3_client
            .test_s3_connectivity()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        info!("S3 connectivity check complete.");

        Ok(poller)
    }

    // Note: current design does not check if multiple concurrent sessions are running.
    //       one way to impl this: store the first & last observed session timestamp & ensure no overlap between time ranges.
    async fn read_cur_dir(&mut self) -> anyhow::Result<Vec<WithdrawalEvent>> {
        let all_guardian_logs = self
            .s3_client
            .list_all_objects_in_dir::<LogRecord>(&self.cursor.0)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        self.logs_to_events(all_guardian_logs).await
    }

    async fn logs_to_events(
        &mut self,
        all_guardian_logs: Vec<LogRecord>,
    ) -> anyhow::Result<Vec<WithdrawalEvent>> {
        let mut events = Vec::new();
        for log in all_guardian_logs {
            if !matches!(log.message, LogMessage::Withdrawal(..)) {
                return Err(anyhow::anyhow!("non-withdrawal logs found"));
            }

            self.ensure_session_loaded(&log.session_id).await?;

            let signing_pubkey = self
                .enclave_pub_keys
                .get(&log.session_id)
                .ok_or_else(|| anyhow::anyhow!("missing session signing pubkey"))?;

            let signed_timestamp = log.timestamp_ms;
            let message = log.verify(signing_pubkey).map_err(|e| anyhow::anyhow!(e))?;

            if let LogMessage::Withdrawal(withdrawal_message) = message
                && let WithdrawalLogMessage::Success {
                    txid, request_data, ..
                } = *withdrawal_message
            {
                events.push(WithdrawalEvent {
                    event_type: WithdrawalEventType::E2GuardianApproved,
                    wid: request_data.wid,
                    timestamp_secs: unix_millis_to_seconds(signed_timestamp),
                    btc_txid: txid,
                })
            }
        }

        Ok(events)
    }

    async fn ensure_session_loaded(&mut self, session_id: &str) -> anyhow::Result<()> {
        if self.enclave_pub_keys.contains_key(session_id) {
            return Ok(());
        }

        let init_key = format!(
            "{}/{}-{}.json",
            S3_DIR_INIT,
            session_id,
            InitLogMessage::OI_ATTEST_UNSIGNED
        );
        let log = self
            .s3_client
            .get_object::<LogRecord>(&init_key)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        let log = log
            .message
            .to_init_log()
            .ok_or_else(|| anyhow::anyhow!("non-init log found"))?;

        let (attestation, signing_pubkey) = log
            .to_attestation_log()
            .ok_or_else(|| anyhow::anyhow!("non-attestation log found"))?;

        verify_enclave_attestation(attestation)?;

        self.enclave_pub_keys
            .insert(session_id.to_string(), signing_pubkey);
        Ok(())
    }

    fn is_readable(&self) -> bool {
        now_unix_seconds() >= self.cursor.write_completion_time()
    }

    fn advance_cursor(&mut self) {
        self.cursor.advance();
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.cursor.to_seconds()
    }

    /// Polls the Guardian S3 bucket for one hour worth of events.
    /// A more aggressive fetch, e.g., one day at a time, can also be done if needed.
    pub async fn poll_one_hour(&mut self) -> anyhow::Result<PollOutcome> {
        if !self.is_readable() {
            return Ok(PollOutcome::CursorUnmoved);
        }

        let withdrawal_events = self.read_cur_dir().await?;
        self.advance_cursor();
        Ok(PollOutcome::CursorAdvanced(withdrawal_events))
    }
}

/// Cursor is simply an S3 directory. The next directory to read from.
struct S3Cursor(S3Directory);

impl S3Cursor {
    /// true => withdraw, false => heartbeat
    fn new(t: UnixSeconds, for_withdrawals: bool) -> Self {
        let prefix = if for_withdrawals {
            S3_DIR_WITHDRAW
        } else {
            S3_DIR_HEARTBEAT
        };
        Self(S3Directory::new(prefix, t))
    }

    fn advance(&mut self) {
        self.0 = self.0.next_dir();
    }

    /// The time at which writes to the current S3 directory finish
    fn write_completion_time(&self) -> UnixSeconds {
        self.0.completion_time()
    }

    fn to_seconds(&self) -> UnixSeconds {
        self.0.to_unix_seconds()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::Client;
    use aws_sdk_s3::operation::get_object::GetObjectOutput;
    use aws_sdk_s3::primitives::ByteStream;
    use aws_smithy_mocks::RuleMode;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use bitcoin::Network;
    use bitcoin::Txid;
    use bitcoin::hashes::Hash as _;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::GuardianSigned;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::StandardWithdrawalResponse;

    fn mk_success_log(
        session_id: &str,
        enclave_signing_key: &GuardianSignKeyPair,
        wid: u64,
        txid_fill: u8,
    ) -> LogRecord {
        let signed_req =
            StandardWithdrawalRequest::mock_signed_for_testing_with_wid(Network::Regtest, wid);
        let (request_sign, request_data) = signed_req.into_parts();
        let txid = Txid::from_slice(&[txid_fill; 32]).expect("valid txid");

        LogRecord::new(
            session_id.to_string(),
            LogMessage::Withdrawal(Box::new(WithdrawalLogMessage::Success {
                txid,
                request_data: request_data.into(),
                request_sign,
                response: GuardianSigned::<StandardWithdrawalResponse>::mock_for_testing().data,
            })),
            enclave_signing_key,
        )
    }

    fn mk_attestation_log(
        session_id: &str,
        enclave_signing_key: &GuardianSignKeyPair,
    ) -> LogRecord {
        LogRecord::new(
            session_id.to_string(),
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: vec![1, 2, 3],
                signing_public_key: enclave_signing_key.verification_key(),
            })),
            enclave_signing_key,
        )
    }

    #[tokio::test]
    async fn multi_session_same_hour_is_supported() {
        let session_a = "session-a";
        let session_b = "session-b";

        let sign_key_a = GuardianSignKeyPair::from([11u8; 32]);
        let sign_key_b = GuardianSignKeyPair::from([22u8; 32]);

        let init_key_a = format!(
            "{}/{}-{}.json",
            S3_DIR_INIT,
            session_a,
            InitLogMessage::OI_ATTEST_UNSIGNED
        );
        let init_key_b = format!(
            "{}/{}-{}.json",
            S3_DIR_INIT,
            session_b,
            InitLogMessage::OI_ATTEST_UNSIGNED
        );

        let init_log_a = mk_attestation_log(session_a, &sign_key_a);
        let init_log_b = mk_attestation_log(session_b, &sign_key_b);
        let init_body_a = serde_json::to_vec(&init_log_a).expect("serialize init log a");
        let init_body_b = serde_json::to_vec(&init_log_b).expect("serialize init log b");

        let get_init_a = mock!(Client::get_object)
            .match_requests(move |req| req.key() == Some(init_key_a.as_str()))
            .then_output(move || {
                GetObjectOutput::builder()
                    .body(ByteStream::from(init_body_a.clone()))
                    .build()
            });

        let get_init_b = mock!(Client::get_object)
            .match_requests(move |req| req.key() == Some(init_key_b.as_str()))
            .then_output(move || {
                GetObjectOutput::builder()
                    .body(ByteStream::from(init_body_b.clone()))
                    .build()
            });

        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&get_init_a, &get_init_b]);
        let s3_client = S3Logger::from_client_for_tests(S3Config::mock_for_testing(), client);

        let mut poller = GuardianWithdrawalsPoller {
            s3_client,
            cursor: S3Cursor::new(0, true),
            enclave_pub_keys: HashMap::new(),
        };

        let log_0 = mk_success_log(session_a, &sign_key_a, 1000, 30);
        let log_a = mk_success_log(session_a, &sign_key_a, 1001, 31);
        let log_b = mk_success_log(session_b, &sign_key_b, 1002, 32);
        let log_c = mk_success_log(session_b, &sign_key_b, 1003, 33);

        let events = poller
            .logs_to_events(vec![log_0, log_a, log_b, log_c])
            .await
            .expect("multi-session logs should parse");

        assert_eq!(events.len(), 4);
        assert!(events.iter().any(|e| {
            e.event_type == WithdrawalEventType::E2GuardianApproved
                && e.wid == 1000
                && e.btc_txid == Txid::from_slice(&[30u8; 32]).expect("valid txid")
        }));
        assert!(events.iter().any(|e| {
            e.event_type == WithdrawalEventType::E2GuardianApproved
                && e.wid == 1001
                && e.btc_txid == Txid::from_slice(&[31u8; 32]).expect("valid txid")
        }));
        assert!(events.iter().any(|e| {
            e.event_type == WithdrawalEventType::E2GuardianApproved
                && e.wid == 1002
                && e.btc_txid == Txid::from_slice(&[32u8; 32]).expect("valid txid")
        }));
        assert!(events.iter().any(|e| {
            e.event_type == WithdrawalEventType::E2GuardianApproved
                && e.wid == 1003
                && e.btc_txid == Txid::from_slice(&[33u8; 32]).expect("valid txid")
        }));

        assert_eq!(poller.enclave_pub_keys.len(), 2);
        assert_eq!(get_init_a.num_calls(), 1);
        assert_eq!(get_init_b.num_calls(), 1);
    }
}
