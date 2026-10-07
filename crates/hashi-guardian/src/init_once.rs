// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// A write-once container that requires exclusive mutable access to initialize.
#[derive(Debug, Clone)]
pub struct InitOnce<T>(Option<T>);

impl<T> InitOnce<T> {
    pub const fn new() -> Self {
        Self(None)
    }

    /// Returns the provided value if already initialized.
    pub fn set(&mut self, value: T) -> Result<(), T> {
        if self.0.is_some() {
            Err(value)
        } else {
            self.0 = Some(value);
            Ok(())
        }
    }

    /// Borrows the value if initialized.
    pub fn get(&self) -> Option<&T> {
        self.0.as_ref()
    }
}

impl<T> Default for InitOnce<T> {
    fn default() -> Self {
        Self::new()
    }
}
