// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Local emulator of the guardian's token-bucket limiter. Bootstrapped
//! from the guardian at startup and advanced on every accepted consume.

use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;
use std::fmt;
use tokio::sync::Mutex;

pub struct LocalLimiter {
    config: LimiterConfig,
    state: Mutex<LimiterState>,
}

#[derive(Debug, thiserror::Error)]
pub enum LocalLimiterError {
    #[error("stale timestamp: local last_updated_at={local_last}, incoming={incoming}")]
    StaleTimestamp { local_last: u64, incoming: u64 },

    #[error("insufficient capacity: needed {needed}, available {available}")]
    InsufficientCapacity { needed: u64, available: u64 },

    #[error("seq mismatch: expected {expected}, applied {applied}")]
    SeqMismatch { expected: u64, applied: u64 },
}

impl fmt::Debug for LocalLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalLimiter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl LocalLimiter {
    pub fn new(config: LimiterConfig, state: LimiterState) -> Self {
        Self {
            config,
            state: Mutex::new(state),
        }
    }

    pub fn config(&self) -> &LimiterConfig {
        &self.config
    }

    pub async fn snapshot(&self) -> LimiterState {
        *self.state.lock().await
    }

    pub async fn capacity_at(&self, timestamp_secs: u64) -> u64 {
        let state = *self.state.lock().await;
        project_capacity(&self.config, &state, timestamp_secs)
    }

    pub async fn next_seq(&self) -> u64 {
        self.state.lock().await.next_seq
    }

    /// Returns the `seq` the caller should submit to the guardian. Does
    /// not mutate state — call `apply_consume` once the guardian accepts.
    pub async fn validate_consume(
        &self,
        timestamp_secs: u64,
        amount_sats: u64,
    ) -> Result<u64, LocalLimiterError> {
        let state = *self.state.lock().await;
        if timestamp_secs < state.last_updated_at {
            return Err(LocalLimiterError::StaleTimestamp {
                local_last: state.last_updated_at,
                incoming: timestamp_secs,
            });
        }
        let capacity = project_capacity(&self.config, &state, timestamp_secs);
        if capacity < amount_sats {
            return Err(LocalLimiterError::InsufficientCapacity {
                needed: amount_sats,
                available: capacity,
            });
        }
        Ok(state.next_seq)
    }

    /// Advance local state to match an accepted consume. State is left
    /// untouched on error.
    pub async fn apply_consume(
        &self,
        applied_seq: u64,
        timestamp_secs: u64,
        amount_sats: u64,
    ) -> Result<(), LocalLimiterError> {
        let mut guard = self.state.lock().await;
        if applied_seq != guard.next_seq {
            return Err(LocalLimiterError::SeqMismatch {
                expected: guard.next_seq,
                applied: applied_seq,
            });
        }
        if timestamp_secs < guard.last_updated_at {
            return Err(LocalLimiterError::StaleTimestamp {
                local_last: guard.last_updated_at,
                incoming: timestamp_secs,
            });
        }
        let capacity = project_capacity(&self.config, &guard, timestamp_secs);
        if capacity < amount_sats {
            return Err(LocalLimiterError::InsufficientCapacity {
                needed: amount_sats,
                available: capacity,
            });
        }
        guard.num_tokens_available = capacity - amount_sats;
        guard.last_updated_at = timestamp_secs;
        guard.next_seq += 1;
        Ok(())
    }
}

fn project_capacity(config: &LimiterConfig, state: &LimiterState, timestamp_secs: u64) -> u64 {
    let elapsed = timestamp_secs.saturating_sub(state.last_updated_at);
    let refilled = elapsed.saturating_mul(config.refill_rate);
    state
        .num_tokens_available
        .saturating_add(refilled)
        .min(config.max_bucket_capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_limiter(
        num_tokens_available: u64,
        last_updated_at: u64,
        next_seq: u64,
    ) -> LocalLimiter {
        let config = LimiterConfig {
            refill_rate: 1_000,
            max_bucket_capacity: 2_000_000,
        };
        let state = LimiterState {
            num_tokens_available,
            last_updated_at,
            next_seq,
        };
        LocalLimiter::new(config, state)
    }

    #[tokio::test]
    async fn test_validate_consume_happy_path() {
        let limiter = make_limiter(0, 0, 7);
        let seq = limiter.validate_consume(100, 80_000).await.unwrap();
        assert_eq!(seq, 7);
    }

    #[tokio::test]
    async fn test_validate_rejects_stale_timestamp() {
        let limiter = make_limiter(0, 100, 0);
        let err = limiter.validate_consume(50, 0).await.unwrap_err();
        assert!(matches!(err, LocalLimiterError::StaleTimestamp { .. }));
    }

    #[tokio::test]
    async fn test_validate_rejects_over_capacity() {
        let limiter = make_limiter(0, 0, 0);
        let err = limiter.validate_consume(10, 50_000).await.unwrap_err();
        match err {
            LocalLimiterError::InsufficientCapacity { needed, available } => {
                assert_eq!(needed, 50_000);
                assert_eq!(available, 10_000);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_apply_bumps_seq_and_updates_last_updated_at() {
        let limiter = make_limiter(0, 0, 42);
        let seq = limiter.validate_consume(100, 80_000).await.unwrap();
        limiter.apply_consume(seq, 100, 80_000).await.unwrap();
        let snap = limiter.snapshot().await;
        assert_eq!(snap.next_seq, 43);
        assert_eq!(snap.last_updated_at, 100);
        assert_eq!(snap.num_tokens_available, 20_000);
    }

    #[tokio::test]
    async fn test_apply_rejects_seq_mismatch() {
        let limiter = make_limiter(0, 0, 0);
        let err = limiter.apply_consume(5, 100, 1_000).await.unwrap_err();
        assert!(matches!(err, LocalLimiterError::SeqMismatch { .. }));
    }

    #[tokio::test]
    async fn test_capacity_at_refills_linearly_and_clamps_to_ceiling() {
        let limiter = make_limiter(100_000, 10, 0);
        assert_eq!(limiter.capacity_at(15).await, 105_000);
        assert_eq!(limiter.capacity_at(u64::MAX).await, 2_000_000);
    }

    #[tokio::test]
    async fn test_next_seq_matches_snapshot() {
        let limiter = make_limiter(0, 0, 11);
        assert_eq!(limiter.next_seq().await, 11);
    }
}
