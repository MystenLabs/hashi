// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::HeartbeatLogMessage;
use std::sync::Arc;
use std::time::Duration;

/// Stateful heartbeat writer started only after durable withdraw operator initialization.
pub(crate) struct HeartbeatWriter {
    enclave: Arc<Enclave>,
    /// the next sequence number used in s3 logs
    next_seq: u64,
}

impl HeartbeatWriter {
    pub fn new(enclave: Arc<Enclave>) -> Self {
        Self {
            enclave,
            next_seq: 0,
        }
    }

    /// Attempt to send one heartbeat.
    ///
    /// The shared S3 writer retries failures and aborts the process on a
    /// terminal retry or heartbeat-fence failure.
    pub async fn tick(&mut self) -> GuardianResult<()> {
        self.enclave
            .log_heartbeat(HeartbeatLogMessage::new(self.next_seq))
            .await?;
        self.next_seq += 1;
        Ok(())
    }

    /// Run the periodic heartbeat loop.
    pub async fn run(mut self, interval: Duration) {
        let mut delay = Duration::ZERO;
        loop {
            tokio::time::sleep(delay).await;
            self.tick()
                .await
                .expect("heartbeat write failed unexpectedly");
            delay = interval;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperatorInitTestArgs;
    use hashi_types::guardian::LogMessageV1;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::VersionedLogMessage;

    #[tokio::test]
    async fn heartbeat_advances_after_durable_write() {
        let (logger, captures) = crate::test_utils::mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_s3_logger(logger),
        )
        .await;
        let mut writer = HeartbeatWriter::new(enclave);
        writer.tick().await.unwrap();
        assert_eq!(writer.next_seq, 1);

        let captured = captures.lock().unwrap();
        assert_eq!(captured.len(), 1, "heartbeat tick should write one record");
        let record: LogRecord = serde_json::from_slice(&captured[0].1).unwrap();
        assert_eq!(captured[0].0, record.object_key());
        let VersionedLogMessage::V1(LogMessageV1::Heartbeat(message)) = record.message() else {
            panic!("expected V1 heartbeat record");
        };
        assert_eq!(message.seq, 0);
    }

    #[tokio::test]
    async fn heartbeat_progresses_while_control_state_is_locked() {
        let (logger, captures) = crate::test_utils::mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_s3_logger(logger),
        )
        .await;
        let _state = enclave.state.lock().await;
        let mut writer = HeartbeatWriter::new(enclave.clone());

        // A long control operation must not prevent independent heartbeat logging.
        tokio::time::timeout(Duration::from_secs(1), writer.tick())
            .await
            .expect("heartbeat must not acquire control state")
            .unwrap();
        assert_eq!(writer.next_seq, 1);
        assert_eq!(captures.lock().unwrap().len(), 1);
    }
}
