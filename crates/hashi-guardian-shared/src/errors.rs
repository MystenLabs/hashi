use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use tracing::error;

#[derive(Debug, PartialEq)]
pub enum GuardianError {
    GenericError(String),
    Forbidden(String),
}

pub type GuardianResult<T> = Result<T, GuardianError>;

impl std::fmt::Display for GuardianError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardianError::GenericError(e) => write!(f, "Error: {}", e),
            GuardianError::Forbidden(e) => write!(f, "Forbidden: {}", e),
        }
    }
}

impl std::error::Error for GuardianError {}

/// Implement IntoResponse for EnclaveError.
impl IntoResponse for GuardianError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            GuardianError::GenericError(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
            GuardianError::Forbidden(e) => (StatusCode::FORBIDDEN, e),
        };
        error!("Status: {}, Message: {}", status, error_message);
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
