use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GuardianError {
    InternalError(String),
    InvalidInputs(String),
}

pub type GuardianResult<T> = Result<T, GuardianError>;

impl std::fmt::Display for GuardianError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardianError::InternalError(e) => write!(f, "InternalError: {}", e),
            GuardianError::InvalidInputs(e) => write!(f, "InvalidInputs: {}", e),
        }
    }
}

impl std::error::Error for GuardianError {}
