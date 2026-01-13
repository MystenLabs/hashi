use crate::GuardianError;
use crate::GuardianError::InvalidInputs;
use crate::GuardianResult;
use crate::MAX_EPOCHS;
use std::collections::VecDeque;

// TODO: Add tests

/// A store of last X epoch's entries for some type T, e.g., committee, amount_withdrawn
#[derive(Debug, Clone, PartialEq)]
pub struct ConsecutiveEpochStore<V> {
    base_epoch: u64,
    entries: VecDeque<V>,
    capacity: usize,
}

pub struct ConsecutiveEpochStoreRepr<V> {
    pub base_epoch: u64,
    pub entries: Vec<V>,
}

impl<V> TryFrom<ConsecutiveEpochStoreRepr<V>> for ConsecutiveEpochStore<V> {
    type Error = GuardianError;

    fn try_from(value: ConsecutiveEpochStoreRepr<V>) -> Result<Self, Self::Error> {
        ConsecutiveEpochStore::<V>::new(value.base_epoch, value.entries, MAX_EPOCHS)
    }
}

impl<V> ConsecutiveEpochStore<V> {
    pub fn empty(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            base_epoch: 0,
            entries: VecDeque::new(),
            capacity,
        }
    }

    pub fn new(base_epoch: u64, entries: Vec<V>, capacity: usize) -> GuardianResult<Self> {
        assert!(capacity > 0);
        if entries.len() > capacity {
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

    /// Insert the next consecutive value into the store
    fn push_next(&mut self, value: V) -> GuardianResult<()> {
        if self.entries.is_empty() {
            return Err(InvalidInputs("window not initialized".into()));
        }
        self.entries.push_back(value);
        if self.entries.len() > self.capacity {
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
