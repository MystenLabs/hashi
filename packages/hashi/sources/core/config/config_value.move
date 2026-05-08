// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::config_value;

use std::string::String;

const EInvalidConfigValue: u64 = 0;

public enum Value has copy, drop, store {
    U64(u64),
    Address(address),
    String(String),
    Bool(bool),
    Bytes(vector<u8>),
}

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

public(package) fun same_variant(self: &Value, other: &Value): bool {
    match (self) {
        Value::U64(_) => other.is_u64(),
        Value::Address(_) => other.is_address(),
        Value::String(_) => other.is_string(),
        Value::Bool(_) => other.is_bool(),
        Value::Bytes(_) => other.is_bytes(),
    }
}

public(package) fun is_u64(value: &Value): bool {
    match (value) {
        Value::U64(_) => true,
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
