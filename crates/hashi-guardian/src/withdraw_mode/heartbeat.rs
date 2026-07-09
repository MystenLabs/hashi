// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use hashi_types::guardian::GuardianResult;
use std::sync::Arc;
use std::time::Duration;

/// Stateful heartbeat writer.
pub struct HeartbeatWriter {
    pub enclave: Arc<Enclave>,
    /// the next sequence number used in s3 logs
    pub next_seq: u64,
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
    /// - If operator init is not complete, this is a no-op.
    /// The shared S3 writer retries failures and aborts the process if its grace
    /// period expires.
    pub async fn tick(&mut self) -> GuardianResult<()> {
        if !self.enclave.is_operator_init_complete() {
            return Ok(());
        }

        self.enclave.log_heartbeat(self.next_seq).await?;
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

    #[tokio::test]
    async fn heartbeat_is_a_noop_before_operator_init() {
        let mut writer = HeartbeatWriter::new(Enclave::create_with_random_keys());
        writer.tick().await.unwrap();
        assert_eq!(writer.next_seq, 0);
    }

    #[tokio::test]
    async fn heartbeat_advances_after_durable_write() {
        let enclave = Enclave::create_operator_initialized_with(Default::default()).await;
        let mut writer = HeartbeatWriter::new(enclave);
        writer.tick().await.unwrap();
        assert_eq!(writer.next_seq, 1);
    }
}
