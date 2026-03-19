// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;
use tonic::Status;

#[derive(Error, Debug)]
pub enum HashiScreenerError {
    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl HashiScreenerError {
    pub fn to_grpc_status(&self) -> Status {
        match self {
            Self::ValidationError(message) => Status::invalid_argument(message.to_string()),
            Self::InternalError(message) => Status::internal(message.to_string()),
        }
    }
}
