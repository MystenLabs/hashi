use serde::Deserialize;
use serde::Serialize;

/// Cursor used for Bitcoin ingestion.
///
/// Placeholder: height only. Add `block_hash` to detect chain reorgs?
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BtcCursor {
    /// Last fully-processed block height.
    pub height: u64,
}

/// Cursor used for Sui ingestion.
///
/// Placeholder: epoch-only. This will likely evolve into something more granular.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SuiCursor {
    /// Last fully-processed epoch.
    pub epoch: u64,
}

/// Cursor used for Guardian log ingestion.
///
/// Placeholder: epoch-only. This will likely evolve into something more granular.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardianCursor {
    /// Last fully-processed epoch.
    pub epoch: u64,
}
