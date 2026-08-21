// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::MAX_S3_WRITE_FAILURE_INTERVAL;
use crate::OTHER_SESSION_QUIET_PERIOD;
use hashi_types::guardian::GuardianResult;
use std::future::Future;
use std::sync::Mutex;
use tokio::time::Instant;

/// Serializes Guardian log writes and fences them against heartbeat expiry.
pub(crate) struct LogWriteCoordinator {
    write_lock: tokio::sync::Mutex<()>,
    heartbeat_health: Mutex<HeartbeatHealth>,
}

#[derive(Clone, Copy)]
enum HeartbeatHealth {
    Disabled,
    Armed { last_successful_heartbeat: Instant },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogWriteKind {
    Heartbeat,
    Other,
}

impl LogWriteCoordinator {
    pub(crate) fn new() -> Self {
        Self {
            write_lock: tokio::sync::Mutex::new(()),
            heartbeat_health: Mutex::new(HeartbeatHealth::Disabled),
        }
    }

    /// Begin heartbeat fencing after withdraw-mode operator initialization.
    ///
    /// The successful operator-init log provides the initial grace period. The
    /// heartbeat writer runs immediately thereafter and replaces this timestamp
    /// with the first successful heartbeat timestamp.
    pub(crate) fn arm_heartbeat_fencing(&self) {
        let mut health = self
            .heartbeat_health
            .lock()
            .expect("heartbeat-health lock poisoned");
        assert!(
            matches!(*health, HeartbeatHealth::Disabled),
            "heartbeat fencing already armed"
        );
        *health = HeartbeatHealth::Armed {
            last_successful_heartbeat: Instant::now(),
        };
    }

    /// Run one S3 log write while holding the enclave-wide write permit.
    ///
    /// When heartbeat fencing is armed, the callback receives the absolute
    /// deadline by which the write must finish. The pre-write check ensures that
    /// the complete S3 retry interval ends before another session may regard this
    /// one as quiet. A heartbeat advances the local lease only after its durable
    /// write.
    pub(crate) async fn write<Write, WriteFuture>(
        &self,
        kind: LogWriteKind,
        write: Write,
    ) -> GuardianResult<()>
    where
        Write: FnOnce(Option<Instant>) -> WriteFuture,
        WriteFuture: Future<Output = GuardianResult<()>>,
    {
        let _write_guard = self.write_lock.lock().await;
        let write_deadline = self.write_deadline_before_write();

        let result = write(write_deadline).await;
        if result.is_ok() {
            if let Some(deadline) = write_deadline {
                assert!(
                    Instant::now() < deadline,
                    "S3 log write completed after the heartbeat fencing deadline"
                );
            }
            if kind == LogWriteKind::Heartbeat {
                self.record_successful_heartbeat();
            }
        }
        result
    }

    fn write_deadline_before_write(&self) -> Option<Instant> {
        let HeartbeatHealth::Armed {
            last_successful_heartbeat,
        } = *self
            .heartbeat_health
            .lock()
            .expect("heartbeat-health lock poisoned")
        else {
            return None;
        };

        let fencing_deadline = last_successful_heartbeat
            .checked_add(OTHER_SESSION_QUIET_PERIOD)
            .expect("heartbeat fencing deadline overflow");
        let now = Instant::now();
        let write_deadline = now
            .checked_add(MAX_S3_WRITE_FAILURE_INTERVAL)
            .expect("S3 write deadline overflow");
        assert!(
            write_deadline < fencing_deadline,
            "last successful Guardian heartbeat is too old to safely start an S3 log write"
        );
        Some(write_deadline)
    }

    fn record_successful_heartbeat(&self) {
        let mut health = self
            .heartbeat_health
            .lock()
            .expect("heartbeat-health lock poisoned");
        let HeartbeatHealth::Armed { .. } = *health else {
            panic!("heartbeat succeeded before heartbeat fencing was armed");
        };
        *health = HeartbeatHealth::Armed {
            last_successful_heartbeat: Instant::now(),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;

    #[tokio::test]
    async fn serializes_log_writes() {
        let coordinator = Arc::new(LogWriteCoordinator::new());
        let first_entered = Arc::new(Notify::new());
        let release_first = Arc::new(Notify::new());
        let second_entered = Arc::new(AtomicBool::new(false));

        let first = {
            let coordinator = coordinator.clone();
            let first_entered = first_entered.clone();
            let release_first = release_first.clone();
            tokio::spawn(async move {
                coordinator
                    .write(LogWriteKind::Other, |_| async move {
                        first_entered.notify_one();
                        release_first.notified().await;
                        Ok(())
                    })
                    .await
            })
        };
        first_entered.notified().await;

        let second = {
            let coordinator = coordinator.clone();
            let second_entered = second_entered.clone();
            tokio::spawn(async move {
                coordinator
                    .write(LogWriteKind::Other, |_| async move {
                        second_entered.store(true, Ordering::SeqCst);
                        Ok(())
                    })
                    .await
            })
        };

        tokio::task::yield_now().await;
        assert!(!second_entered.load(Ordering::SeqCst));
        release_first.notify_one();
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
        assert!(second_entered.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn stale_heartbeat_panics_before_starting_write() {
        let coordinator = Arc::new(LogWriteCoordinator::new());
        coordinator.arm_heartbeat_fencing();
        tokio::time::advance(OTHER_SESSION_QUIET_PERIOD - MAX_S3_WRITE_FAILURE_INTERVAL).await;

        let write_started = Arc::new(AtomicBool::new(false));
        let task = {
            let coordinator = coordinator.clone();
            let write_started = write_started.clone();
            tokio::spawn(async move {
                coordinator
                    .write(LogWriteKind::Other, |_| async move {
                        write_started.store(true, Ordering::SeqCst);
                        Ok(())
                    })
                    .await
            })
        };

        assert!(task.await.unwrap_err().is_panic());
        assert!(!write_started.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn successful_heartbeat_refreshes_fencing_deadline() {
        let coordinator = LogWriteCoordinator::new();
        coordinator.arm_heartbeat_fencing();
        let nearly_stale =
            OTHER_SESSION_QUIET_PERIOD - MAX_S3_WRITE_FAILURE_INTERVAL - Duration::from_secs(1);
        tokio::time::advance(nearly_stale).await;

        coordinator
            .write(LogWriteKind::Heartbeat, |deadline| async move {
                assert!(deadline.is_some());
                Ok(())
            })
            .await
            .unwrap();
        tokio::time::advance(nearly_stale).await;

        coordinator
            .write(LogWriteKind::Other, |deadline| async move {
                assert!(deadline.is_some());
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn write_completing_at_its_deadline_panics() {
        let coordinator = Arc::new(LogWriteCoordinator::new());
        coordinator.arm_heartbeat_fencing();
        let task = tokio::spawn(async move {
            coordinator
                .write(LogWriteKind::Other, |_| async move {
                    tokio::time::advance(MAX_S3_WRITE_FAILURE_INTERVAL).await;
                    Ok(())
                })
                .await
        });

        assert!(task.await.unwrap_err().is_panic());
    }
}
