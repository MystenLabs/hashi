// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::GuardianError::InternalError;
use super::GuardianError::InvalidInputs;
use super::GuardianError::RateLimitExceeded;
use super::GuardianResult;
use bitcoin::Amount;
use serde::Serialize;

/// Single-epoch rate limiter. Tracks amount withdrawn in the current epoch.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RateLimiter {
    /// Current epoch.
    epoch: u64,
    /// Amount withdrawn so far in this epoch.
    withdrawn: Amount,
    /// Maximum amount withdrawable per epoch.
    max_withdrawable_per_epoch: Amount,
}

impl RateLimiter {
    pub fn new(
        epoch: u64,
        withdrawn: Amount,
        max_withdrawable_per_epoch: Amount,
    ) -> GuardianResult<Self> {
        if withdrawn > max_withdrawable_per_epoch {
            return Err(InvalidInputs("withdrawn exceeds max".into()));
        }
        Ok(Self {
            epoch,
            withdrawn,
            max_withdrawable_per_epoch,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn withdrawn(&self) -> Amount {
        self.withdrawn
    }

    pub fn max_withdrawable_per_epoch(&self) -> Amount {
        self.max_withdrawable_per_epoch
    }

    /// Consume amount from the current epoch's rate limit.
    pub fn consume(&mut self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        if epoch != self.epoch {
            return Err(InvalidInputs(format!(
                "epoch mismatch: expected {}, got {}",
                self.epoch, epoch
            )));
        }

        let new_sum = self
            .withdrawn
            .checked_add(amount)
            .ok_or(InvalidInputs("Overflow when computing sum".into()))?;

        if new_sum > self.max_withdrawable_per_epoch {
            return Err(RateLimitExceeded);
        }

        self.withdrawn = new_sum;
        Ok(())
    }

    /// Revert a previous consumption.
    pub fn revert(&mut self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        if epoch != self.epoch {
            return Err(InvalidInputs(format!(
                "epoch mismatch: expected {}, got {}",
                self.epoch, epoch
            )));
        }

        debug_assert!(self.withdrawn >= amount);
        self.withdrawn = self
            .withdrawn
            .checked_sub(amount)
            .ok_or(InternalError("Underflow when computing sub".into()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_consume_tests() {
        let mut limiter = RateLimiter::new(0, Amount::from_sat(0), Amount::from_sat(100)).unwrap();

        limiter.consume(0, Amount::from_sat(60)).unwrap();
        let err = limiter.consume(0, Amount::from_sat(50)).unwrap_err();
        assert_eq!(err, RateLimitExceeded);

        // Wrong epoch should fail.
        let err = limiter.consume(1, Amount::from_sat(1)).unwrap_err();
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[test]
    fn rate_limiter_revert_tests() {
        let mut limiter = RateLimiter::new(0, Amount::from_sat(0), Amount::from_sat(100)).unwrap();

        limiter.consume(0, Amount::from_sat(60)).unwrap();
        limiter.revert(0, Amount::from_sat(60)).unwrap();

        // If revert worked, we should be able to consume the full max again.
        limiter.consume(0, Amount::from_sat(100)).unwrap();
        let err = limiter.consume(0, Amount::from_sat(1)).unwrap_err();
        assert_eq!(err, RateLimitExceeded);
    }
}
