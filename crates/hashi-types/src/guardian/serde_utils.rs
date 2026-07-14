// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Canonical textual encodings for binary guardian fields.
//!
//! Both the S3 JSON and the BCS signing payload use these representations.

use crate::bitcoin::HashiMasterG;
use crate::guardian::GuardianPubKey;
use crate::guardian::GuardianSignature;
use base64ct::Base64;
use base64ct::Encoding;
use fastcrypto::serde_helpers::ToFromByteArray;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde::de::Error as _;
use serde::ser::SerializeMap;
use std::collections::BTreeMap;

fn decode_lower_hex<E: serde::de::Error>(encoded: &str) -> Result<Vec<u8>, E> {
    if !encoded
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(E::custom("expected lowercase hex without a 0x prefix"));
    }
    hex::decode(encoded).map_err(E::custom)
}

fn decode_lower_hex_array<const N: usize, E: serde::de::Error>(
    encoded: &str,
    field: &str,
) -> Result<[u8; N], E> {
    let bytes = decode_lower_hex::<E>(encoded)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        E::custom(format!("{field} must be {N} bytes, got {}", bytes.len()))
    })
}

pub(crate) mod option_hex_32 {
    use super::*;

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|encoded| decode_lower_hex_array(&encoded, "hex value"))
            .transpose()
    }
}

pub(crate) mod base64_bytes {
    use super::*;

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&Base64::encode_string(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        Base64::decode_vec(&encoded).map_err(D::Error::custom)
    }
}

pub(crate) mod guardian_pubkey {
    use super::*;

    pub fn serialize<S>(value: &GuardianPubKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(value.as_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<GuardianPubKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = decode_lower_hex_array::<32, D::Error>(&encoded, "guardian public key")?;
        GuardianPubKey::try_from(bytes.as_slice()).map_err(D::Error::custom)
    }
}

pub(crate) mod option_guardian_signature {
    use super::*;

    pub fn serialize<S>(value: &Option<GuardianSignature>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .as_ref()
            .map(|signature| hex::encode(signature.to_bytes()))
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<GuardianSignature>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|encoded| {
                decode_lower_hex_array::<64, D::Error>(&encoded, "guardian signature")
                    .map(GuardianSignature::from)
            })
            .transpose()
    }
}

pub(crate) mod option_mpc_master_g {
    use super::*;

    pub fn serialize<S>(value: &Option<HashiMasterG>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .as_ref()
            .map(|point| hex::encode(point.to_byte_array()))
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<HashiMasterG>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|encoded| {
                let bytes = decode_lower_hex_array::<33, D::Error>(&encoded, "MPC master G")?;
                HashiMasterG::from_byte_array(&bytes)
                    .map_err(|error| D::Error::custom(format!("invalid MPC master G: {error:?}")))
            })
            .transpose()
    }
}

pub(crate) mod hex_map_values {
    use super::*;

    pub fn serialize<S, K>(value: &BTreeMap<K, Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        K: Serialize + Ord,
    {
        let mut map = serializer.serialize_map(Some(value.len()))?;
        for (key, bytes) in value {
            map.serialize_entry(key, &hex::encode(bytes))?;
        }
        map.end()
    }

    pub fn deserialize<'de, D, K>(deserializer: D) -> Result<BTreeMap<K, Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
        K: Deserialize<'de> + Ord,
    {
        BTreeMap::<K, String>::deserialize(deserializer)?
            .into_iter()
            .map(|(key, encoded)| decode_lower_hex(&encoded).map(|bytes| (key, bytes)))
            .collect()
    }
}
