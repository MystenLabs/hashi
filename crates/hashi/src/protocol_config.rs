// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub const MIN_SUPPORTED_PROTOCOL_VERSION: u64 = 1;
pub const MAX_SUPPORTED_PROTOCOL_VERSION: u64 = 1;

pub fn supported_max(config: &crate::config::Config) -> u64 {
    match config.test_supported_protocol_version_max {
        Some(max) => {
            crate::assert_test_only_config(
                config.sui_chain_id(),
                config.bitcoin_chain_id(),
                "test_supported_protocol_version_max",
            );
            max
        }
        None => MAX_SUPPORTED_PROTOCOL_VERSION,
    }
}

pub fn is_supported(config: &crate::config::Config, version: u64) -> bool {
    (MIN_SUPPORTED_PROTOCOL_VERSION..=supported_max(config)).contains(&version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_range_is_inclusive_and_bounded() {
        let cfg = crate::config::Config::new_for_testing();
        assert!(is_supported(&cfg, MIN_SUPPORTED_PROTOCOL_VERSION));
        assert!(is_supported(&cfg, MAX_SUPPORTED_PROTOCOL_VERSION));
        assert!(!is_supported(&cfg, MAX_SUPPORTED_PROTOCOL_VERSION + 1));
    }

    #[test]
    fn test_override_widens_supported_range() {
        let mut cfg = crate::config::Config::new_for_testing();
        cfg.bitcoin_chain_id = Some(crate::constants::BITCOIN_REGTEST_CHAIN_ID.to_string());
        cfg.sui_chain_id = Some("localnet".to_string());
        assert!(!is_supported(&cfg, MAX_SUPPORTED_PROTOCOL_VERSION + 1));
        cfg.test_supported_protocol_version_max = Some(MAX_SUPPORTED_PROTOCOL_VERSION + 1);
        assert!(is_supported(&cfg, MAX_SUPPORTED_PROTOCOL_VERSION + 1));
        assert_eq!(supported_max(&cfg), MAX_SUPPORTED_PROTOCOL_VERSION + 1);
    }
}
