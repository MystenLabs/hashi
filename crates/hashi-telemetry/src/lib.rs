// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared `tracing` subscriber initialization for all hashi binaries.

use std::io::IsTerminal;
use std::io::stderr;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub struct TelemetryConfig {
    default_level: LevelFilter,
    json: Option<bool>,
    file_line: bool,
    target: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryConfig {
    pub fn new() -> Self {
        Self {
            default_level: LevelFilter::INFO,
            json: None,
            file_line: false,
            target: true,
        }
    }

    pub fn with_default_level(mut self, level: LevelFilter) -> Self {
        self.default_level = level;
        self
    }

    pub fn with_json(mut self, json: bool) -> Self {
        self.json = Some(json);
        self
    }

    pub fn with_file_line(mut self, enabled: bool) -> Self {
        self.file_line = enabled;
        self
    }

    pub fn with_target(mut self, enabled: bool) -> Self {
        self.target = enabled;
        self
    }

    /// `RUST_LOG_JSON=0`/`false`/`no` forces TTY; any other value forces JSON.
    pub fn with_env(mut self) -> Self {
        if let Ok(value) = std::env::var("RUST_LOG_JSON") {
            self.json = match value.trim().to_ascii_lowercase().as_str() {
                "0" | "false" | "no" => Some(false),
                _ => Some(true),
            };
        }
        self
    }

    pub fn init(self) -> TelemetryGuard {
        let use_json = match self.json {
            Some(true) => true,
            Some(false) => false,
            None => !stderr().is_terminal(),
        };

        let env_filter = EnvFilter::builder()
            .with_default_directive(self.default_level.into())
            .from_env_lossy();

        if use_json {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_target(self.target)
                .json()
                .with_filter(env_filter);

            tracing_subscriber::registry().with(fmt_layer).init();
        } else {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_file(self.file_line)
                .with_line_number(self.file_line)
                .with_target(self.target)
                .with_ansi(stderr().is_terminal())
                .with_filter(env_filter);

            tracing_subscriber::registry().with(fmt_layer).init();
        }

        TelemetryGuard { _private: () }
    }
}

#[must_use = "dropping the guard immediately will lose buffered log output"]
pub struct TelemetryGuard {
    _private: (),
}
