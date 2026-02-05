use std::collections::HashMap;

use sui_sdk_types::Address;

use crate::mpc::types::GetPartialSignaturesRequest;
use crate::mpc::types::GetPartialSignaturesResponse;
use crate::mpc::types::PartialSigningOutput;
use crate::mpc::types::SendPartialSignaturesRequest;
use crate::mpc::types::SendPartialSignaturesResponse;
use crate::mpc::types::SigningError;
use crate::mpc::types::SigningResult;

pub struct SigningManager {
    /// Key: sui_request_id (hex-encoded Sui address identifying the request)
    pub partial_signing_outputs: HashMap<String, PartialSigningOutput>,
}

impl SigningManager {
    pub fn new() -> Self {
        Self {
            partial_signing_outputs: HashMap::new(),
        }
    }

    pub fn handle_send_partial_signatures_request(
        &mut self,
        sender: Address,
        request: &SendPartialSignaturesRequest,
    ) -> SigningResult<SendPartialSignaturesResponse> {
        if let Some(existing) = self.partial_signing_outputs.get(&request.sui_request_id) {
            if existing.presig != request.presig || existing.partial_sigs != request.partial_sigs {
                return Err(SigningError::InvalidMessage {
                    sender,
                    reason: "Sender sent different presig or partial signatures".to_string(),
                });
            }
            return Ok(SendPartialSignaturesResponse {});
        }
        self.partial_signing_outputs.insert(
            request.sui_request_id.clone(),
            PartialSigningOutput {
                presig: request.presig,
                partial_sigs: request.partial_sigs.clone(),
            },
        );
        Ok(SendPartialSignaturesResponse {})
    }

    pub fn handle_get_partial_signatures_request(
        &self,
        request: &GetPartialSignaturesRequest,
    ) -> SigningResult<GetPartialSignaturesResponse> {
        let output = self
            .partial_signing_outputs
            .get(&request.sui_request_id)
            .ok_or_else(|| {
                SigningError::NotFound(format!(
                    "Partial signing output for request {}",
                    request.sui_request_id
                ))
            })?;
        Ok(GetPartialSignaturesResponse {
            presig: output.presig,
            partial_sigs: output.partial_sigs.clone(),
        })
    }
}

impl Default for SigningManager {
    fn default() -> Self {
        Self::new()
    }
}
