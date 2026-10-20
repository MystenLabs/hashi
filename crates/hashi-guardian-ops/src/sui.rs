// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The Sui epoch, from Sui GraphQL. hashi's committee hands off to the guardian once per epoch, so a switchover must
//! sit well inside one.

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use serde::Deserialize;

use crate::Ctx;
use crate::exec::Cmd;
use crate::exec::read_json;

/// Minimum time since the epoch began, for the committee handoff to settle.
pub const SETTLE_SECS: i64 = 30 * 60;
/// Minimum time left in the epoch to point the proxy at the standby, for the switchover to finish in it.
pub const REMAINING_SECS: i64 = 60 * 60;
/// Minimum time left in the epoch to stop the old guardian: activation then waits ten minutes for it to fall quiet.
pub const STOP_REMAINING_SECS: i64 = 20 * 60;

/// Where now falls in the current epoch, taking it to last as long as the previous one did.
pub struct Window {
    pub epoch: u64,
    pub since: i64,
    pub remaining: i64,
    /// When the epoch ends, in seconds since the Unix epoch.
    pub end: i64,
}

impl Window {
    pub fn new(epoch: u64, start: i64, previous_start: i64, now: i64) -> Self {
        let end = 2 * start - previous_start;
        Self {
            epoch,
            since: now - start,
            remaining: end - now,
            end,
        }
    }

    /// Why a switchover can't start now, or `None` when it can.
    pub fn refusal(&self) -> Option<String> {
        let epoch = self.epoch;
        if self.since < SETTLE_SECS {
            Some(format!(
                "Sui epoch {epoch} began {} minutes ago; switch over once hashi's committee handoff has settled, 30 minutes after the epoch turns",
                self.since / 60
            ))
        } else if self.remaining < REMAINING_SECS {
            Some(format!(
                "Sui epoch {epoch} ends in about {} minutes; switch over after the next epoch has settled, so its committee handoff reaches the new guardian",
                self.remaining / 60
            ))
        } else {
            None
        }
    }
}

pub fn window(ctx: &Ctx, now: i64) -> Result<Window> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Epoch {
        epoch_id: Option<u64>,
        start_timestamp: String,
    }
    #[derive(Deserialize)]
    struct Data {
        epoch: Epoch,
    }
    #[derive(Deserialize)]
    struct Response {
        data: Data,
    }
    let url = ctx.env.require("SUI_GRAPHQL_URL")?;
    let query = |query: &str| -> Result<Epoch> {
        let response: Response = read_json(
            ctx.exec,
            &Cmd::new("curl")
                .args(["-fsS", "--max-time", "15"])
                .args(["-H", "Content-Type: application/json"])
                .arg("-d")
                .arg(serde_json::json!({ "query": query }).to_string())
                .arg(url),
        )?;
        Ok(response.data.epoch)
    };
    let current = query("{ epoch { epochId startTimestamp } }")
        .with_context(|| format!("could not read the current Sui epoch from {url}"))?;
    let epoch = current
        .epoch_id
        .ok_or_else(|| anyhow!("could not read the current Sui epoch from {url}"))?;
    let start = seconds(&current.start_timestamp)?;
    let previous = query(&format!(
        "{{ epoch(epochId: {}) {{ startTimestamp }} }}",
        epoch.saturating_sub(1)
    ))
    .with_context(|| format!("could not read the previous Sui epoch from {url}"))?;
    Ok(Window::new(
        epoch,
        start,
        seconds(&previous.start_timestamp)?,
        now,
    ))
}

/// Stops unless the Sui epoch, and hashi's committee with it, stays put while guardians switch, and the serving guardian
/// holds this epoch's committee. hashi's leader hands the guardian each new committee once per epoch, and a standby the
/// proxy fronts before its activation takes none, which leaves it a committee behind until the next epoch.
pub fn require_epoch_window(window: &Window, committee_epoch: Option<&str>) -> Result<()> {
    if let Some(refusal) = window.refusal() {
        anyhow::bail!("{refusal}");
    }
    let epoch = window.epoch;
    if committee_epoch != Some(epoch.to_string().as_str()) {
        anyhow::bail!(
            "the serving guardian is at committee epoch {}, but Sui is at epoch {epoch}; wait for hashi's committee handoff to reach it",
            committee_epoch.unwrap_or("none")
        );
    }
    Ok(())
}

/// A GraphQL timestamp in whole seconds since the Unix epoch.
fn seconds(timestamp: &str) -> Result<i64> {
    Ok(timestamp
        .parse::<jiff::Timestamp>()
        .with_context(|| format!("{timestamp} is not a timestamp"))?
        .as_second())
}

pub fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

/// A duration as hours and minutes, for messages.
pub fn duration(secs: i64) -> String {
    let minutes = secs / 60;
    if minutes.abs() < 60 {
        format!("{minutes} min")
    } else {
        format!("{} h {} min", minutes / 60, (minutes % 60).abs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_the_window() {
        let start = seconds("2026-10-14T21:24:13.402Z").unwrap();
        let previous = seconds("2026-10-13T21:24:13Z").unwrap();
        let window = Window::new(1254, start, previous, start + 3 * 3600);
        assert_eq!(window.since, 3 * 3600);
        assert_eq!(window.remaining, 21 * 3600);
        assert_eq!(window.refusal(), None);
        assert!(
            Window::new(1254, start, previous, start + 20 * 60)
                .refusal()
                .unwrap()
                .starts_with("Sui epoch 1254 began 20 minutes ago;")
        );
        assert!(
            Window::new(1254, start, previous, start + 23 * 3600 + 1)
                .refusal()
                .unwrap()
                .starts_with("Sui epoch 1254 ends in about 59 minutes;")
        );
        assert_eq!(duration(3 * 3600 + 25 * 60), "3 h 25 min");
        assert_eq!(duration(20 * 60), "20 min");
    }
}
