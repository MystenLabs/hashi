// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared telemetry configuration for all hashi binaries.
//!
//! Provides a [`TelemetryConfig`] builder that sets up a `tracing` subscriber with:
//! - **JSON output** for production (Kubernetes / Grafana / Loki)
//! - **Human-readable TTY output** for local development
//! - Automatic format detection based on whether stderr is a TTY
//! - `RUST_LOG` environment variable support via [`tracing_subscriber::EnvFilter`]

use std::io::stderr;

use crossterm::tty::IsTty;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Configuration for the tracing subscriber.
///
/// # Examples
///
/// ```no_run
/// use hashi_telemetry::TelemetryConfig;
///
/// // Production server: auto-detect JSON vs TTY, INFO default
/// let _guard = TelemetryConfig::new()
///     .with_file_line(true)
///     .with_service_name("hashi")
///     .with_env()
///     .init();
///
/// // CLI tool: WARN default, no target, verbose override
/// let _guard = TelemetryConfig::new()
///     .with_default_level(tracing::level_filters::LevelFilter::WARN)
///     .with_target(false)
///     .with_env()
///     .init();
/// ```
pub struct TelemetryConfig {
    /// Base log level when `RUST_LOG` is not set. Default: `INFO`.
    default_level: LevelFilter,
    /// Force JSON (`Some(true)`) or TTY (`Some(false)`) output.
    /// `None` means auto-detect: JSON if stderr is not a TTY, TTY otherwise.
    json: Option<bool>,
    /// Show `file:line` in log output. Default: `false`.
    file_line: bool,
    /// Show module target path in log output. Default: `true`.
    target: bool,
    /// Service name added as a field in JSON output.
    service_name: Option<String>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryConfig {
    /// Create a new config with sensible defaults (INFO level, auto-detect format).
    pub fn new() -> Self {
        Self {
            default_level: LevelFilter::INFO,
            json: None,
            file_line: false,
            target: true,
            service_name: None,
        }
    }

    /// Set the default log level (used when `RUST_LOG` is not set).
    pub fn with_default_level(mut self, level: LevelFilter) -> Self {
        self.default_level = level;
        self
    }

    /// Force JSON (`true`) or TTY (`false`) output, overriding auto-detection.
    pub fn with_json(mut self, json: bool) -> Self {
        self.json = Some(json);
        self
    }

    /// Show `file:line` in log output.
    pub fn with_file_line(mut self, enabled: bool) -> Self {
        self.file_line = enabled;
        self
    }

    /// Show module target path in log output.
    pub fn with_target(mut self, enabled: bool) -> Self {
        self.target = enabled;
        self
    }

    /// Set a service name (included as a field in JSON output).
    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = Some(name.into());
        self
    }

    /// Read configuration overrides from environment variables:
    /// - `RUST_LOG_JSON`: if set, forces JSON output
    pub fn with_env(mut self) -> Self {
        if std::env::var("RUST_LOG_JSON").is_ok() {
            self.json = Some(true);
        }
        self
    }

    /// Build and install the tracing subscriber.
    ///
    /// Returns a [`TelemetryGuard`] that must be held alive for the duration of the program.
    pub fn init(self) -> TelemetryGuard {
        let use_json = match self.json {
            Some(true) => true,
            Some(false) => false,
            // Auto-detect: use JSON when stderr is not a TTY (e.g. Kubernetes pods).
            None => !stderr().is_tty(),
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
                .with_ansi(stderr().is_tty())
                .with_filter(env_filter);

            tracing_subscriber::registry().with(fmt_layer).init();
        }

        TelemetryGuard { _private: () }
    }
}

/// Guard that must be held alive for the duration of the program.
///
/// Future additions (non-blocking writer flush, OpenTelemetry shutdown)
/// will be handled in its `Drop` implementation.
#[must_use = "dropping the guard immediately will lose buffered log output"]
pub struct TelemetryGuard {
    _private: (),
}
