// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Typed value wrapper for config entries: the `Value` enum carries one of the
/// primitive types a configuration entry can hold, with a public constructor
/// per variant and package-level helpers for variant checks (`is_*`) and
/// extraction (`as_*`, aborting on a type mismatch). Storing typed values —
/// rather than raw bytes — lets `config::is_valid_config_update` reject
/// governance updates that would change an entry's type.
module hashi::config_value;

use std::string::String;

// ~~~~~~~ Errors ~~~~~~~

#[error]
const EInvalidConfigValue: vector<u8> = b"Config value has a different type than expected";

// ~~~~~~~ Structs ~~~~~~~

// Variant order is BCS-load-bearing: the Rust mirror (hashi-types) decodes
// by variant index, and once published to a persistent network the order is
// frozen — package upgrades reject enums whose existing variants change, so
// new variants may then only be appended at the end.
public enum Value has copy, drop, store {
    U64(u64),
    U128(u128),
    U256(u256),
    Address(address),
    String(String),
    Bool(bool),
    Bytes(vector<u8>),
}

// ~~~~~~~ Public Functions ~~~~~~~

public fun new_u64(value: u64): Value {
    Value::U64(value)
}

public fun new_address(value: address): Value {
    Value::Address(value)
}

public fun new_string(value: String): Value {
    Value::String(value)
}

public fun new_bool(value: bool): Value {
    Value::Bool(value)
}

public fun new_bytes(value: vector<u8>): Value {
    Value::Bytes(value)
}

public fun new_u128(value: u128): Value {
    Value::U128(value)
}

public fun new_u256(value: u256): Value {
    Value::U256(value)
}

// ~~~~~~~ Package Functions ~~~~~~~

public(package) fun same_variant(self: &Value, other: &Value): bool {
    match (self) {
        Value::U64(_) => other.is_u64(),
        Value::Address(_) => other.is_address(),
        Value::String(_) => other.is_string(),
        Value::Bool(_) => other.is_bool(),
        Value::Bytes(_) => other.is_bytes(),
        Value::U128(_) => other.is_u128(),
        Value::U256(_) => other.is_u256(),
    }
}

public(package) fun is_u64(value: &Value): bool {
    match (value) {
        Value::U64(_) => true,
        _ => false,
    }
}

public(package) fun is_u128(value: &Value): bool {
    match (value) {
        Value::U128(_) => true,
        _ => false,
    }
}

public(package) fun is_u256(value: &Value): bool {
    match (value) {
        Value::U256(_) => true,
        _ => false,
    }
}

public(package) fun is_address(value: &Value): bool {
    match (value) {
        Value::Address(_) => true,
        _ => false,
    }
}

public(package) fun is_string(value: &Value): bool {
    match (value) {
        Value::String(_) => true,
        _ => false,
    }
}

public(package) fun is_bool(value: &Value): bool {
    match (value) {
        Value::Bool(_) => true,
        _ => false,
    }
}

public(package) fun is_bytes(value: &Value): bool {
    match (value) {
        Value::Bytes(_) => true,
        _ => false,
    }
}

public(package) fun as_u64(value: Value): u64 {
    match (value) {
        Value::U64(num) => num,
        _ => abort EInvalidConfigValue,
    }
}

public(package) fun as_u128(value: Value): u128 {
    match (value) {
        Value::U128(num) => num,
        _ => abort EInvalidConfigValue,
    }
}

public(package) fun as_u256(value: Value): u256 {
    match (value) {
        Value::U256(num) => num,
        _ => abort EInvalidConfigValue,
    }
}

public(package) fun as_address(value: Value): address {
    match (value) {
        Value::Address(addr) => addr,
        _ => abort EInvalidConfigValue,
    }
}

public(package) fun as_string(value: Value): String {
    match (value) {
        Value::String(str) => str,
        _ => abort EInvalidConfigValue,
    }
}

public(package) fun as_bool(value: Value): bool {
    match (value) {
        Value::Bool(val) => val,
        _ => abort EInvalidConfigValue,
    }
}

public(package) fun as_bytes(value: Value): vector<u8> {
    match (value) {
        Value::Bytes(bytes) => bytes,
        _ => abort EInvalidConfigValue,
    }
}
