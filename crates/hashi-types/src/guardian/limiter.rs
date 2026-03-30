// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::GuardianError::InvalidInputs;
use super::GuardianError::RateLimitExceeded;
use super::GuardianResult;
use serde::Serialize;

/// Immutable configuration for the token bucket rate limiter.
#[derive(Debug, Copy, Clone, PartialEq, Serialize)]
pub struct LimiterConfig {
    /// Refill rate in sats per second.
    pub refill_rate: u64,
    /// Maximum bucket capacity in sats.
    pub max_bucket_capacity: u64,
}

/// Serializable state for the token bucket rate limiter.
/// Provisioners provide this when initializing the enclave.
#[derive(Debug, Copy, Clone, PartialEq, Serialize)]
pub struct LimiterState {
    /// Available tokens in sats.
    pub num_tokens_available: u64,
    /// Last refill timestamp in unix seconds.
    pub last_updated_at: u64,
    /// Next expected withdrawal sequence number.
    pub next_seq: u64,
}

/// Token bucket rate limiter. Tokens refill linearly over time.
///
/// Pure data structure — concurrency is handled by the caller via a Mutex.
pub struct RateLimiter {
    config: LimiterConfig,
    state: LimiterState,
    /// Snapshot of state before the most recent `consume`, used for revert.
    prev_state: LimiterState,
}

impl RateLimiter {
    pub fn new(config: LimiterConfig, state: LimiterState) -> GuardianResult<Self> {
        if state.num_tokens_available > config.max_bucket_capacity {
            return Err(InvalidInputs(
                "num_tokens_available exceeds max_bucket_capacity".into(),
            ));
        }
        let prev_state = state;
        Ok(Self {
            config,
            state,
            prev_state,
        })
    }

    pub fn config(&self) -> &LimiterConfig {
        &self.config
    }

    pub fn state(&self) -> &LimiterState {
        &self.state
    }

    pub fn next_seq(&self) -> u64 {
        self.state.next_seq
    }

    /// Consume tokens from the bucket. Validates seq and timestamp ordering,
    /// refills based on elapsed time, then debits the requested amount.
    pub fn consume(&mut self, seq: u64, timestamp: u64, amount_sats: u64) -> GuardianResult<()> {
        if seq != self.state.next_seq {
            return Err(InvalidInputs(format!(
                "seq mismatch: expected {}, got {}",
                self.state.next_seq, seq
            )));
        }
        if timestamp < self.state.last_updated_at {
            return Err(InvalidInputs(format!(
                "timestamp {} < last_updated_at {}",
                timestamp, self.state.last_updated_at
            )));
        }

        // Refill tokens based on elapsed time.
        let elapsed = timestamp
            .checked_sub(self.state.last_updated_at)
            .expect("timestamp checked above");
        let refilled = elapsed.saturating_mul(self.config.refill_rate);
        let capacity = self
            .state
            .num_tokens_available
            .saturating_add(refilled)
            .min(self.config.max_bucket_capacity);

        if capacity < amount_sats {
            return Err(RateLimitExceeded);
        }

        // Snapshot for revert, then mutate.
        self.prev_state = self.state;
        self.state.last_updated_at = timestamp;
        self.state.num_tokens_available = capacity - amount_sats;
        self.state.next_seq += 1;
        Ok(())
    }

    /// Revert a previous `consume`. Restores state to pre-consume snapshot.
    pub fn revert(&mut self) {
        self.state = self.prev_state;
    }
}
