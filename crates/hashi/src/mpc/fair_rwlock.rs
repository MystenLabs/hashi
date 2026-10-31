// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::LockResult;
use std::sync::RwLock;
use std::sync::RwLockReadGuard;
use std::sync::RwLockWriteGuard;
use std::sync::TryLockError;
use std::sync::TryLockResult;

use parking_lot::MutexGuard;

pub struct FairRwLock<T> {
    turnstile: parking_lot::Mutex<()>,
    lock: RwLock<T>,
}

impl<T> FairRwLock<T> {
    pub fn new(value: T) -> Self {
        Self {
            turnstile: parking_lot::Mutex::new(()),
            lock: RwLock::new(value),
        }
    }

    pub fn into_inner(self) -> LockResult<T> {
        self.lock.into_inner()
    }

    pub fn read(&self) -> LockResult<RwLockReadGuard<'_, T>> {
        let turn = self.turnstile.lock();
        let guard = self.lock.read();
        MutexGuard::unlock_fair(turn);
        guard
    }

    pub fn write(&self) -> LockResult<RwLockWriteGuard<'_, T>> {
        let turn = self.turnstile.lock();
        let guard = self.lock.write();
        MutexGuard::unlock_fair(turn);
        guard
    }

    pub fn try_write(&self) -> TryLockResult<RwLockWriteGuard<'_, T>> {
        let turn = self.turnstile.try_lock().ok_or(TryLockError::WouldBlock)?;
        let guard = self.lock.try_write();
        MutexGuard::unlock_fair(turn);
        guard
    }

    #[cfg(test)]
    pub(crate) fn turnstile_held(&self) -> bool {
        self.turnstile.is_locked()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;
    use std::time::Instant;

    use super::*;

    #[test]
    fn a_reader_queued_behind_a_writer_goes_before_a_later_writer() {
        let lock = Arc::new(FairRwLock::new(()));
        let order = Arc::new(Mutex::new(Vec::new()));
        let first = lock.write().unwrap();
        let reader = {
            let (lock, order) = (lock.clone(), order.clone());
            std::thread::spawn(move || {
                let _guard = lock.read().unwrap();
                order.lock().unwrap().push("reader");
            })
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !lock.turnstile_held() {
            assert!(Instant::now() < deadline, "the reader never queued");
            std::thread::sleep(Duration::from_millis(1));
        }
        let writer = {
            let (lock, order) = (lock.clone(), order.clone());
            std::thread::spawn(move || {
                let _guard = lock.write().unwrap();
                order.lock().unwrap().push("writer");
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        drop(first);
        reader.join().unwrap();
        writer.join().unwrap();

        assert_eq!(*order.lock().unwrap(), ["reader", "writer"]);
    }
}
