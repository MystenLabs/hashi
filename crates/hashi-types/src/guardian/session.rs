// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::GuardianPubKey;
use super::errors::GuardianError::InvalidInputs;
use super::errors::GuardianResult;
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

/// Guardian session identifier. Canonical IDs are short prefixes of the
/// hex-encoded signing public key and tag per-session S3 objects.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct SessionID(String);

/// A KP-signed request bound to one guardian session.
pub trait SessionBoundRequest {
    const REQUEST_CONTEXT: &'static str;

    fn expected_session(&self) -> &SessionID;

    fn validate_session(&self, live_session: &SessionID) -> GuardianResult<()> {
        if self.expected_session() != live_session {
            return Err(InvalidInputs(format!(
                "{} expected guardian session {}, live session is {}",
                Self::REQUEST_CONTEXT,
                self.expected_session(),
                live_session,
            )));
        }
        Ok(())
    }
}

impl SessionID {
    /// Length of the signing-public-key prefix used for canonical session IDs.
    pub const HEX_LEN: usize = 16;

    pub fn from_signing_pubkey(signing_pub_key: &GuardianPubKey) -> Self {
        let mut session_id = ::hex::encode(signing_pub_key.as_bytes());
        session_id.truncate(Self::HEX_LEN);
        Self(session_id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for SessionID {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SessionID {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<SessionID> for String {
    fn from(value: SessionID) -> Self {
        value.0
    }
}

impl AsRef<str> for SessionID {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for SessionID {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Deref for SessionID {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for SessionID {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::ProvisionerInitRequest;

    #[test]
    fn session_bound_request_validates_live_session() {
        let request = ProvisionerInitRequest::mock_for_testing();
        request
            .validate_session(&SessionID::from("mock-session"))
            .unwrap();

        let err = request
            .validate_session(&SessionID::from("other-session"))
            .unwrap_err();
        assert!(matches!(
            err,
            InvalidInputs(message)
                if message == "PI submission expected guardian session mock-session, live session is other-session"
        ));
    }
}
