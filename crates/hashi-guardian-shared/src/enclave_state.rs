use crate::epoch_store::ConsecutiveEpochStore;
use crate::epoch_store::ConsecutiveEpochStoreRepr;
use crate::epoch_store::EpochWindow;
use crate::GuardianError::InternalError;
use crate::GuardianError::InvalidInputs;
use crate::GuardianError::RateLimitExceeded;
use crate::GuardianResult;
use crate::HashiCommittee;
use bitcoin::Amount;
use serde::Serialize;

/// Rate limiter state: Amount withdrawn in the last N epochs.
/// RateLimiterState and CommitteeStore have the same window & entries size. This is enforced in
/// ProvisionerInitState::new() and Enclave::register_new_epoch().
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RateLimiter {
    state: ConsecutiveEpochStore<Amount>,
    max_withdrawable_per_epoch: Amount,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WithdrawalState {
    limiter: RateLimiter,
}

/// A store for last N committees. Needs to be initialized with at least one committee.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitteeStore(ConsecutiveEpochStore<HashiCommittee>);

impl WithdrawalState {
    pub fn new(limiter: RateLimiter) -> Self {
        Self { limiter }
    }

    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    /// Consume amount units from the given epoch's rate limit
    pub fn consume_from_limiter(&mut self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        self.limiter.consume(epoch, amount)
    }

    /// Adds a new epoch and prunes an old epoch
    pub fn add_epoch_to_limiter(&mut self, epoch: u64) -> GuardianResult<()> {
        self.limiter.add_epoch(epoch)
    }

    /// Reverse of consume_from_limiter
    pub fn revert_limiter(&mut self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        self.limiter.revert(epoch, amount)
    }
}

impl RateLimiter {
    pub fn new(
        epoch_window: EpochWindow,
        amounts_withdrawn_per_epoch: Vec<Amount>,
        max_withdrawable_per_epoch: Amount,
    ) -> GuardianResult<Self> {
        // Note: instead of erring out, we could use zero as default
        if amounts_withdrawn_per_epoch.is_empty() {
            return Err(InvalidInputs("amounts empty".into()));
        }
        Ok(Self {
            state: ConsecutiveEpochStore::<Amount>::new(epoch_window, amounts_withdrawn_per_epoch)?,
            max_withdrawable_per_epoch,
        })
    }

    pub fn max_withdrawable_per_epoch(&self) -> Amount {
        self.max_withdrawable_per_epoch
    }

    pub fn state(&self) -> &ConsecutiveEpochStore<Amount> {
        &self.state
    }

    pub fn epoch_window(&self) -> EpochWindow {
        self.state.epoch_window()
    }

    pub fn num_entries(&self) -> usize {
        self.state.num_entries()
    }

    /// Consume amount units from the given epoch's rate limit.
    /// Stored values are the amount withdrawn so far in that epoch.
    pub fn consume(&mut self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        let cur_sum = *self.state.get_checked(epoch)?;

        let new_sum = cur_sum
            .checked_add(amount)
            .ok_or(InvalidInputs("Overflow when computing sum".into()))?;

        if new_sum > self.max_withdrawable_per_epoch {
            return Err(RateLimitExceeded);
        }

        *self.state.get_mut_checked(epoch)? = new_sum;
        Ok(())
    }

    /// Add back consumed units to the limiter
    pub fn revert(&mut self, epoch: u64, amount: Amount) -> GuardianResult<()> {
        let cur_sum = *self.state.get_checked(epoch)?;

        debug_assert!(cur_sum >= amount);
        let new_sum = cur_sum
            .checked_sub(amount)
            .ok_or(InternalError("Underflow when computing sub".into()))?; // this should be unreachable

        *self.state.get_mut_checked(epoch)? = new_sum;
        Ok(())
    }

    /// Adds a new epoch (must be the next consecutive epoch). Old epochs are pruned automatically.
    pub fn add_epoch(&mut self, epoch: u64) -> GuardianResult<()> {
        self.state.insert(epoch, Amount::from_sat(0))?;
        Ok(())
    }
}

impl CommitteeStore {
    pub fn new(epoch_window: EpochWindow, committees: Vec<HashiCommittee>) -> GuardianResult<Self> {
        // Err if input has no committees
        if committees.is_empty() {
            return Err(InvalidInputs("No committee set".into()));
        }

        // Match window.epoch() against committee.epoch()
        let mut base_epoch = epoch_window.first_epoch;
        for committee in &committees {
            if committee.epoch() != base_epoch {
                return Err(InvalidInputs("epoch doesn't match".into()));
            }
            base_epoch += 1;
        }

        Ok(Self(ConsecutiveEpochStore::<HashiCommittee>::new(
            epoch_window,
            committees,
        )?))
    }

    pub fn num_entries(&self) -> usize {
        self.0.num_entries()
    }

    pub fn epoch_window(&self) -> EpochWindow {
        self.0.epoch_window()
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &HashiCommittee)> {
        self.0.iter()
    }

    pub fn into_owned_iter(self) -> impl Iterator<Item = (u64, HashiCommittee)> {
        self.0.into_owned_iter()
    }
}

#[derive(Serialize)]
pub(crate) struct CommitteeStoreRepr(ConsecutiveEpochStoreRepr<hashi_types::move_types::Committee>);

impl From<CommitteeStore> for CommitteeStoreRepr {
    fn from(store: CommitteeStore) -> Self {
        CommitteeStoreRepr(
            ConsecutiveEpochStoreRepr::<hashi_types::move_types::Committee> {
                window: store.0.epoch_window(),
                entries: store.0.iter().map(|(_, c)| c.into()).collect(),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_store::EpochWindow;
    use std::num::NonZeroU16;

    fn nz(v: u16) -> NonZeroU16 {
        NonZeroU16::new(v).expect("non-zero")
    }

    #[test]
    fn rate_limiter_consume_tests() {
        let window = EpochWindow::new(0, nz(1));
        let mut limiter =
            RateLimiter::new(window, vec![Amount::from_sat(0)], Amount::from_sat(100)).unwrap();

        limiter.consume(0, Amount::from_sat(60)).unwrap();
        let err = limiter.consume(0, Amount::from_sat(50)).unwrap_err();
        assert_eq!(err, RateLimitExceeded);

        // Only epoch 0 is present.
        let err = limiter.consume(1, Amount::from_sat(1)).unwrap_err();
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[test]
    fn rate_limiter_revert_tests() {
        let window = EpochWindow::new(0, nz(1));
        let mut limiter =
            RateLimiter::new(window, vec![Amount::from_sat(0)], Amount::from_sat(100)).unwrap();

        limiter.consume(0, Amount::from_sat(60)).unwrap();
        limiter.revert(0, Amount::from_sat(60)).unwrap();

        // If revert worked, we should be able to consume the full max again.
        limiter.consume(0, Amount::from_sat(100)).unwrap();
        let err = limiter.consume(0, Amount::from_sat(1)).unwrap_err();
        assert_eq!(err, RateLimitExceeded);
    }

    #[test]
    fn rate_limiter_add_epoch_tests() {
        let window = EpochWindow::new(0, nz(2));
        let mut limiter = RateLimiter::new(
            window,
            vec![Amount::from_sat(0), Amount::from_sat(0)],
            Amount::from_sat(100),
        )
        .unwrap();

        assert_eq!(limiter.state.next_epoch_to_be_inserted(), 2);
        limiter.add_epoch(2).unwrap(); // prunes epoch 0
        assert_eq!(limiter.state.next_epoch_to_be_inserted(), 3);

        // Epoch 0 is now too old.
        let err = limiter.consume(0, Amount::from_sat(1)).unwrap_err();
        assert!(matches!(err, InvalidInputs(_)));

        // Epoch 1 and 2 are present.
        limiter.consume(1, Amount::from_sat(70)).unwrap();
        limiter.consume(2, Amount::from_sat(70)).unwrap();

        // Non-consecutive epoch insert should fail.
        let err = limiter.add_epoch(4).unwrap_err();
        assert!(matches!(err, InvalidInputs(_)));
    }
}
