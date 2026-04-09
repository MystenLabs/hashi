// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared telemetry configuration for all hashi binaries.
//!
//! Provides a [`TelemetryConfig`] builder that sets up a `tracing` subscriber with:
//! - **JSON output** for production (Kubernetes / Grafana / Loki)
//! - **Human-readable TTY output** for local development
//! - Automatic format detection based on [`std::io::IsTerminal`] for stderr:
//!   stderr is a terminal → human, stderr is a pipe/redirect → JSON.
//! - `RUST_LOG` environment variable support via [`tracing_subscriber::EnvFilter`]
//! - `RUST_LOG_JSON=1`/`0` hard override. CI workflows that want human-readable
//!   logs in pipe'd GitHub Actions output should set `RUST_LOG_JSON=0` in the
//!   workflow env block.
//!
//! Service-level identification (filtering Loki by `hashi` vs `hashi-screener`
//! etc.) is delegated to Kubernetes pod labels injected by Promtail/Alloy at
//! ingest time, not written into the log body. Use `{app="hashi"}` in LogQL.

use std::io::IsTerminal;
use std::io::stderr;

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
    /// `None` means auto-detect — see [`TelemetryConfig::init`].
    json: Option<bool>,
    /// Show `file:line` in log output. Default: `false`.
    file_line: bool,
    /// Show module target path in log output. Default: `true`.
    target: bool,
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

    /// Read configuration overrides from environment variables.
    ///
    /// `RUST_LOG_JSON`:
    /// - `0`, `false`, `no` (case-insensitive) → force JSON off, use the
    ///   human-readable format even inside a pipe or container.
    /// - any other non-empty value → force JSON on, overriding auto-detection.
    /// - unset → leave the auto-detected choice in place.
    pub fn with_env(mut self) -> Self {
        if let Ok(value) = std::env::var("RUST_LOG_JSON") {
            let normalized = value.trim().to_ascii_lowercase();
            self.json = match normalized.as_str() {
                "0" | "false" | "no" => Some(false),
                _ => Some(true),
            };
        }
        self
    }

    /// Build and install the tracing subscriber.
    ///
    /// Auto-detects the format when neither [`TelemetryConfig::with_json`] nor
    /// `RUST_LOG_JSON` is set: stderr is a terminal → human format; stderr is
    /// a pipe / redirect → JSON.
    ///
    /// Returns a [`TelemetryGuard`] that must be held alive for the duration of the program.
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
            // NOTE: JSON output always includes file/line regardless of the
            // `with_file_line` setting. In production (Kubernetes → Loki) we
            // always want the exact source location on every event for
            // debuggability, and the cost of the extra fields on structured
            // output is negligible. The `with_file_line` builder setting only
            // affects the TTY branch below, where it is off by default to
            // keep local dev output uncluttered.
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

/// Guard that must be held alive for the duration of the program.
///
/// Future additions (non-blocking writer flush, OpenTelemetry shutdown)
/// will be handled in its `Drop` implementation.
#[must_use = "dropping the guard immediately will lose buffered log output"]
pub struct TelemetryGuard {
    _private: (),
}
