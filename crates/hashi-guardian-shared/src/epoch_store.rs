use crate::GuardianError;
use crate::GuardianError::InvalidInputs;
use crate::GuardianResult;
use std::collections::VecDeque;
use std::num::NonZeroU16;
// TODO: Add tests

/// Shared epoch window metadata.
///
/// `base_epoch` is the epoch corresponding to index 0 of an epoch-indexed vector,
/// and `num_epochs` is the window capacity shared across components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochWindow {
    pub base_epoch: u64,
    pub num_epochs: NonZeroU16,
}

impl EpochWindow {
    pub fn new(base_epoch: u64, num_epochs: NonZeroU16) -> Self {
        Self {
            base_epoch,
            num_epochs,
        }
    }
}

/// A store of last X epoch's entries for some type T, e.g., committee, amount_withdrawn
#[derive(Debug, Clone, PartialEq)]
pub struct ConsecutiveEpochStore<V> {
    base_epoch: u64,
    entries: VecDeque<V>,
    capacity: NonZeroU16,
}

pub struct ConsecutiveEpochStoreRepr<V> {
    pub base_epoch: u64,
    pub entries: Vec<V>,
    pub capacity: NonZeroU16,
}

impl<V> TryFrom<ConsecutiveEpochStoreRepr<V>> for ConsecutiveEpochStore<V> {
    type Error = GuardianError;

    fn try_from(value: ConsecutiveEpochStoreRepr<V>) -> Result<Self, Self::Error> {
        ConsecutiveEpochStore::<V>::new(value.base_epoch, value.entries, value.capacity)
    }
}

impl<V> ConsecutiveEpochStore<V> {
    pub fn empty(capacity: NonZeroU16) -> Self {
        Self {
            base_epoch: 0,
            entries: VecDeque::new(),
            capacity,
        }
    }

    pub fn new(base_epoch: u64, entries: Vec<V>, capacity: NonZeroU16) -> GuardianResult<Self> {
        if entries.len() > capacity.get() as usize {
            return Err(InvalidInputs("too many entries".into()));
        }
        Ok(Self {
            base_epoch,
            entries: entries.into(),
            capacity,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn capacity(&self) -> NonZeroU16 {
        self.capacity
    }

    pub fn epoch_window(&self) -> EpochWindow {
        EpochWindow::new(self.base_epoch, self.capacity)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn is_initialized(&self) -> bool {
        !self.entries.is_empty()
    }

    /// Initialize the store
    pub fn start(&mut self, base_epoch: u64, value: V) -> GuardianResult<()> {
        if !self.entries.is_empty() {
            return Err(InvalidInputs("window already initialized".into()));
        }
        self.base_epoch = base_epoch;
        self.entries.push_back(value);
        Ok(())
    }

    pub fn base_epoch(&self) -> Option<u64> {
        if self.entries.is_empty() {
            None
        } else {
            Some(self.base_epoch)
        }
    }

    pub fn next_epoch(&self) -> Option<u64> {
        if self.entries.is_empty() {
            None
        } else {
            Some(self.base_epoch + self.entries.len() as u64)
        }
    }

    pub fn get(&self, epoch: u64) -> Option<&V> {
        if self.entries.is_empty() {
            return None;
        }
        if epoch < self.base_epoch {
            return None;
        }
        let idx = (epoch - self.base_epoch) as usize;
        self.entries.get(idx)
    }

    pub fn get_mut(&mut self, epoch: u64) -> Option<&mut V> {
        if self.entries.is_empty() {
            return None;
        }
        if epoch < self.base_epoch {
            return None;
        }
        let idx = (epoch - self.base_epoch) as usize;
        self.entries.get_mut(idx)
    }

    /// Checks that the epoch is in range and returns an Err if not
    fn assert_epoch_in_range(&self, epoch: u64) -> GuardianResult<()> {
        if self.entries.is_empty() {
            return Err(InvalidInputs("window not initialized".into()));
        }
        if epoch < self.base_epoch {
            return Err(InvalidInputs(format!(
                "epoch {} too old (base_epoch = {})",
                epoch, self.base_epoch
            )));
        }

        let next_epoch = self.base_epoch + self.entries.len() as u64;
        if epoch >= next_epoch {
            return Err(InvalidInputs(format!(
                "epoch {} not present (next_epoch = {})",
                epoch, next_epoch
            )));
        }
        Ok(())
    }

    /// Get a value for `epoch`, returns a structured error if not present.
    pub fn get_checked(&self, epoch: u64) -> GuardianResult<&V> {
        self.assert_epoch_in_range(epoch)?;
        let idx = (epoch - self.base_epoch) as usize;
        Ok(self.entries.get(idx).expect("checked above"))
    }

    /// Get a mutable value for `epoch`, returning a structured error instead of `None`.
    pub fn get_mut_checked(&mut self, epoch: u64) -> GuardianResult<&mut V> {
        self.assert_epoch_in_range(epoch)?;
        let idx = (epoch - self.base_epoch) as usize;
        Ok(self.entries.get_mut(idx).expect("checked above"))
    }

    /// Insert the next consecutive value into the store
    fn push_next(&mut self, value: V) -> GuardianResult<()> {
        if self.entries.is_empty() {
            return Err(InvalidInputs("window not initialized".into()));
        }
        self.entries.push_back(value);
        if self.entries.len() > self.capacity.get() as usize {
            self.entries.pop_front().expect("should not be empty");
            self.base_epoch += 1;
        }
        Ok(())
    }

    /// Push the next epoch. Throws an error if the store is uninitialized.
    pub fn insert_strict(&mut self, epoch: u64, value: V) -> GuardianResult<()> {
        let expected = self
            .next_epoch()
            .ok_or_else(|| InvalidInputs("window not initialized".into()))?;
        if epoch != expected {
            return Err(InvalidInputs(format!(
                "attempted to push non-consecutive epoch: expected {}, got {}",
                expected, epoch
            )));
        }
        self.push_next(value)
    }

    /// Push the next epoch or initialize the store.
    /// TODO: Investigate if callsites can use insert_strict instead
    pub fn insert_or_start(&mut self, epoch: u64, value: V) -> GuardianResult<()> {
        match self.next_epoch() {
            None => self.start(epoch, value),
            Some(expected) => {
                if expected != epoch {
                    return Err(InvalidInputs(format!(
                        "attempted to push non-consecutive epoch: expected {}, got {}",
                        expected, epoch,
                    )));
                }
                self.push_next(value)
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &V)> {
        let base = self.base_epoch;
        self.entries
            .iter()
            .enumerate()
            .map(move |(i, v)| (base + i as u64, v))
    }

    pub fn into_owned_iter(self) -> impl Iterator<Item = (u64, V)> {
        let base = self.base_epoch;
        self.entries
            .into_iter()
            .enumerate()
            .map(move |(i, v)| (base + i as u64, v))
    }
}
