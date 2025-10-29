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
    // Dynamic(TypeName, vector<u8>)
}

public(package) fun new_u64(value: u64): Value {
    Value::U64(value)
}

public(package) fun new_address(value: address): Value {
    Value::Address(value)
}

public(package) fun new_string(value: String): Value {
    Value::String(value)
}

public(package) fun new_bool(value: bool): Value {
    Value::Bool(value)
}

public(package) fun new_bytes(value: vector<u8>): Value {
    Value::Bytes(value)
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
