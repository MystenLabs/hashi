// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Progress output.
//!
//! A run is long and mostly spent waiting, so everything here goes to stderr
//! with a timestamp: stdout stays free for the report, and a scrollback is the
//! only forensics available when a run misbehaves overnight.

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

fn clock() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    format!("{h:02}:{m:02}:{s:02}")
}

pub fn header(title: &str) {
    eprintln!("\n== {title}");
}

pub fn ok(msg: &str) {
    eprintln!("{}  + {msg}", clock());
}

pub fn info(msg: &str) {
    eprintln!("{}    {msg}", clock());
}

pub fn step(msg: &str) {
    eprintln!("{}  . {msg}", clock());
}

pub fn warn(msg: &str) {
    eprintln!("{}  ! {msg}", clock());
}
