use crate::GuardianError;
use crate::GuardianError::InvalidInputs;
use crate::GuardianResult;
use serde::Serialize;
use std::collections::VecDeque;
use std::num::NonZeroU16;

/// Shared epoch window metadata.
///
/// `first_epoch` is the epoch corresponding to index 0 of an epoch-indexed vector,
/// and `num_epochs` is the window capacity shared across components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EpochWindow {
    pub first_epoch: u64,
    pub num_epochs: NonZeroU16,
}

impl EpochWindow {
    pub fn new(first_epoch: u64, num_epochs: NonZeroU16) -> Self {
        Self {
            first_epoch,
            num_epochs,
        }
    }

    pub fn capacity(&self) -> u16 {
        self.num_epochs.get()
    }
}

/// A store of last X epoch's entries for some type T, e.g., committee, amount_withdrawn
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConsecutiveEpochStore<V> {
    window: EpochWindow,
    entries: VecDeque<V>,
}

#[derive(Serialize)]
pub struct ConsecutiveEpochStoreRepr<V> {
    pub window: EpochWindow,
    pub entries: Vec<V>,
}

impl<V> TryFrom<ConsecutiveEpochStoreRepr<V>> for ConsecutiveEpochStore<V> {
    type Error = GuardianError;

    fn try_from(value: ConsecutiveEpochStoreRepr<V>) -> Result<Self, Self::Error> {
        ConsecutiveEpochStore::<V>::new(value.window, value.entries)
    }
}

impl<V> ConsecutiveEpochStore<V> {
    /// Initialize the store.
    /// Note that `entries` is currently allowed to be empty.
    pub fn new(window: EpochWindow, entries: Vec<V>) -> GuardianResult<Self> {
        if entries.len() > window.capacity() as usize {
            return Err(InvalidInputs("too many entries".into()));
        }
        Ok(Self {
            window,
            entries: entries.into(),
        })
    }

    pub fn num_entries(&self) -> usize {
        self.entries.len()
    }

    pub fn capacity(&self) -> u16 {
        self.window.capacity()
    }

    pub fn epoch_window(&self) -> EpochWindow {
        self.window
    }

    /// First epoch for which we have an entry.
    pub fn first_epoch(&self) -> u64 {
        self.window.first_epoch
    }

    /// The epoch to insert next.
    pub fn next_epoch_to_be_inserted(&self) -> u64 {
        self.first_epoch() + self.entries.len() as u64
    }

    /// Last epoch for which we have an entry. Return None if no entries
    pub fn last_epoch(&self) -> Option<u64> {
        if self.entries.is_empty() {
            None
        } else {
            Some(self.next_epoch_to_be_inserted() - 1)
        }
    }

    /// Checks that the epoch is in range and returns an Err if not
    fn assert_epoch_has_entry(&self, epoch: u64) -> GuardianResult<()> {
        if epoch < self.first_epoch() {
            return Err(InvalidInputs(format!(
                "epoch {} too old (first_epoch = {})",
                epoch,
                self.first_epoch()
            )));
        }

        match self.last_epoch() {
            Some(last_epoch) => {
                if epoch > last_epoch {
                    return Err(InvalidInputs(format!(
                        "epoch {} not present (last_epoch = {})",
                        epoch, last_epoch
                    )));
                }
            }
            None => return Err(InvalidInputs("no entries".into())),
        }

        Ok(())
    }

    /// Get a value for `epoch`, returns an error if not present.
    pub fn get_checked(&self, epoch: u64) -> GuardianResult<&V> {
        self.assert_epoch_has_entry(epoch)?;
        let idx = (epoch - self.first_epoch()) as usize;
        Ok(self.entries.get(idx).expect("checked above"))
    }

    /// Get a mutable value for `epoch`, returns an error if not present.
    pub fn get_mut_checked(&mut self, epoch: u64) -> GuardianResult<&mut V> {
        self.assert_epoch_has_entry(epoch)?;
        let idx = (epoch - self.first_epoch()) as usize;
        Ok(self.entries.get_mut(idx).expect("checked above"))
    }

    /// Insert the next consecutive value into the store
    fn push_next(&mut self, value: V) -> GuardianResult<()> {
        self.entries.push_back(value);
        if self.entries.len() > self.capacity() as usize {
            self.entries.pop_front().expect("should not be empty");
            self.window.first_epoch += 1;
        }
        Ok(())
    }

    /// Push the next epoch.
    pub fn insert(&mut self, epoch: u64, value: V) -> GuardianResult<()> {
        let expected = self.next_epoch_to_be_inserted();
        if epoch != expected {
            return Err(InvalidInputs(format!(
                "attempted to push non-consecutive epoch: expected {}, got {}",
                expected, epoch
            )));
        }
        self.push_next(value)
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &V)> {
        let base = self.first_epoch();
        self.entries
            .iter()
            .enumerate()
            .map(move |(i, v)| (base + i as u64, v))
    }

    pub fn into_owned_iter(self) -> impl Iterator<Item = (u64, V)> {
        let base = self.first_epoch();
        self.entries
            .into_iter()
            .enumerate()
            .map(move |(i, v)| (base + i as u64, v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(v: u16) -> NonZeroU16 {
        NonZeroU16::new(v).expect("non-zero")
    }

    #[test]
    fn insert_bootstraps_from_empty() {
        let window = EpochWindow::new(10, nz(3));
        let mut store = ConsecutiveEpochStore::<&'static str>::new(window, vec![]).unwrap();

        assert_eq!(store.num_entries(), 0);
        assert_eq!(store.next_epoch_to_be_inserted(), 10);
        assert_eq!(store.last_epoch(), None);

        store.insert(10, "a").unwrap();

        assert_eq!(store.num_entries(), 1);
        assert_eq!(store.first_epoch(), 10);
        assert_eq!(store.last_epoch(), Some(10));
        assert_eq!(*store.get_checked(10).unwrap(), "a");
    }

    #[test]
    fn insert_rejects_non_consecutive_epoch() {
        let window = EpochWindow::new(10, nz(3));
        let mut store = ConsecutiveEpochStore::<u64>::new(window, vec![]).unwrap();

        let err = store.insert(11, 123).unwrap_err();
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[test]
    fn prune_advances_first_epoch_when_over_capacity() {
        let window = EpochWindow::new(5, nz(2));
        let mut store = ConsecutiveEpochStore::<u64>::new(window, vec![]).unwrap();

        store.insert(5, 50).unwrap();
        store.insert(6, 60).unwrap();
        store.insert(7, 70).unwrap(); // prunes epoch 5

        assert_eq!(store.num_entries(), 2);
        assert_eq!(store.first_epoch(), 6);
        assert_eq!(store.last_epoch(), Some(7));
        assert_eq!(*store.get_checked(6).unwrap(), 60);
        assert_eq!(*store.get_checked(7).unwrap(), 70);

        let err = store.get_checked(5).unwrap_err();
        assert!(matches!(err, InvalidInputs(_)));
    }

    #[test]
    fn get_checked_errors_on_empty_and_out_of_range() {
        let window = EpochWindow::new(100, nz(3));
        let mut store = ConsecutiveEpochStore::<u64>::new(window, vec![]).unwrap();

        // Empty store
        let err = store.get_checked(100).unwrap_err();
        assert!(matches!(err, InvalidInputs(_)));
        assert!(err.to_string().contains("no entries"));

        store.insert(100, 1).unwrap();
        store.insert(101, 2).unwrap();

        // Too old
        let err = store.get_checked(99).unwrap_err();
        assert!(matches!(err, InvalidInputs(_)));
        assert!(err.to_string().contains("too old"));

        // Too new
        let err = store.get_checked(102).unwrap_err();
        assert!(matches!(err, InvalidInputs(_)));
        assert!(err.to_string().contains("not present"));
    }
}
