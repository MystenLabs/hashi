// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub const MIN_SUPPORTED_PROTOCOL_VERSION: u64 = 1;
pub const MAX_SUPPORTED_PROTOCOL_VERSION: u64 = 1;

pub fn is_supported(version: u64) -> bool {
    (MIN_SUPPORTED_PROTOCOL_VERSION..=MAX_SUPPORTED_PROTOCOL_VERSION).contains(&version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_range_is_inclusive_and_bounded() {
        assert!(is_supported(MIN_SUPPORTED_PROTOCOL_VERSION));
        assert!(is_supported(MAX_SUPPORTED_PROTOCOL_VERSION));
        assert!(!is_supported(MAX_SUPPORTED_PROTOCOL_VERSION + 1));
        assert!(!is_supported(MIN_SUPPORTED_PROTOCOL_VERSION - 1) || MIN_SUPPORTED_PROTOCOL_VERSION == 0);
    }
}
