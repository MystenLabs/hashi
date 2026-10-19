// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! What a guardian reports about itself: through a slot's tunnel, through the proxy's relay, and on the proxy's
//! public `/info`. gRPC answers are decoded by grpcurl with the guardian commit's own protos, so this tool never
//! reads a guardian with another build's field or enum numbering.

use std::fmt;
use std::path::Path;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use base64ct::Base64;
use base64ct::Encoding;
use serde::Deserialize;

use crate::Ctx;
use crate::commit::Tree;
use crate::exec::Cmd;
use crate::exec::read_json;
use crate::stack::Role;
use crate::stack::SlotView;
use crate::stack::Stack;
use crate::stack::is_hex;

/// A guardian's mode and stage, such as `withdraw/ACTIVATED`, or `none` before operator initialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lifecycle(String);

impl Lifecycle {
    pub fn is(&self, name: &str) -> bool {
        self.0 == name
    }

    /// Whether key provisioners are mid-round with this guardian. A provisioning round's shares live only in the relay's
    /// memory; a ceremony's confirmations go straight to the guardian, but a proxy restart still cuts the round off.
    pub fn in_kp_round(&self) -> bool {
        self.is("withdraw/OPERATOR_INITIALIZED")
            || self.is("ceremony/AWAITING_KEY_PROVISIONER_CONFIRMATIONS")
    }
}

impl fmt::Display for Lifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The parts of a guardian's `GuardianInfoData` the steps read, with bytes as hex.
#[derive(Clone, Debug)]
pub struct GuardianInfo {
    pub signing_key: Option<String>,
    pub btc_key: Option<String>,
    pub lifecycle: Lifecycle,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InfoData {
    signing_pub_key: Option<String>,
    enclave_btc_pubkey: Option<String>,
    withdraw: Option<String>,
    ceremony: Option<String>,
}

impl InfoData {
    fn decode(self) -> Result<GuardianInfo> {
        let lifecycle = match (self.withdraw, self.ceremony) {
            (Some(stage), _) => format!(
                "withdraw/{}",
                stage.strip_prefix("WITHDRAW_STAGE_").unwrap_or(&stage)
            ),
            (None, Some(stage)) => format!(
                "ceremony/{}",
                stage.strip_prefix("CEREMONY_STAGE_").unwrap_or(&stage)
            ),
            (None, None) => "none".to_owned(),
        };
        Ok(GuardianInfo {
            signing_key: hex_of(self.signing_pub_key)?,
            btc_key: hex_of(self.enclave_btc_pubkey)?,
            lifecycle: Lifecycle(lifecycle),
        })
    }
}

/// grpcurl prints bytes as base64, where `/info` and the CLIs print hex.
fn hex_of(base64: Option<String>) -> Result<Option<String>> {
    base64
        .map(|text| {
            Base64::decode_vec(&text)
                .map(hex::encode)
                .map_err(|_| anyhow!("the guardian reported {text}, which is not base64"))
        })
        .transpose()
}

/// The guardian's own report, unsigned, from its enclave through the slot's tunnel.
pub fn slot_info(ctx: &Ctx, tree: &Tree, view: &SlotView) -> Result<GuardianInfo> {
    #[derive(Deserialize)]
    struct Response {
        info: Option<InfoData>,
    }
    let response: Response = read_json(
        ctx.exec,
        &grpcurl(&tree.protos(), "guardian_service.proto")
            .args(["-plaintext", "-max-time", "15"])
            .args(["-d", "{}"])
            .arg(format!("127.0.0.1:{}", view.port))
            .arg("sui.hashi.v1alpha.GuardianService/GetGuardianInfo"),
    )
    .with_context(|| view.tunnel_down())?;
    response
        .info
        .ok_or_else(|| anyhow!("slot {}'s guardian reported no info", view.slot))?
        .decode()
}

/// The report of the guardian the proxy's relay sends key provisioners to.
pub fn relay_info(ctx: &Ctx, tree: &Tree) -> Result<GuardianInfo> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Response {
        signed_info: Option<Signed>,
    }
    #[derive(Deserialize)]
    struct Signed {
        data: Option<InfoData>,
    }
    let authority = ctx.env.proxy_url()?.authority;
    let response: Response = read_json(
        ctx.exec,
        &grpcurl(&tree.protos(), "guardian_relay_service.proto")
            .args(["-max-time", "20"])
            .args(["-d", "{}"])
            .arg(&authority)
            .arg("sui.hashi.v1alpha.GuardianRelayService/GetProvisioningTargetInfo"),
    )
    .with_context(|| format!("the proxy's relay does not answer at {authority}"))?;
    response
        .signed_info
        .and_then(|signed| signed.data)
        .ok_or_else(|| anyhow!("the proxy's relay reported no guardian info"))?
        .decode()
}

fn grpcurl(protos: &Path, proto: &str) -> Cmd {
    Cmd::new("grpcurl")
        .arg("-import-path")
        .arg(protos)
        .arg("-proto")
        .arg(format!("sui/hashi/v1alpha/{proto}"))
}

/// How old `/info` can be and still show that the proxy reaches its guardian: the proxy caches it for 30 seconds by
/// default, and serves its last view, however old, while a refresh is in flight or failing.
pub const CURRENT_FOR: Duration = Duration::from_secs(90);

/// The proxy's public `/info`, which describes the guardian it fronts. Its u64s are strings.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyInfo {
    pub signing_pub_key: Option<String>,
    pub btc_pubkey: Option<String>,
    pub git_revision: Option<String>,
    pub committee_epoch: Option<String>,
    /// When the guardian answered, in milliseconds since the epoch.
    pub timestamp_ms: Option<String>,
}

impl ProxyInfo {
    /// How long ago the guardian answered, or `None` when `/info` doesn't say.
    pub fn age(&self) -> Option<Duration> {
        let answered = Duration::from_millis(self.timestamp_ms.as_deref()?.parse().ok()?);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        Some(now.saturating_sub(answered))
    }
}

pub fn proxy_info(ctx: &Ctx) -> Result<ProxyInfo> {
    let url = ctx.env.proxy_url()?.url;
    read_json(
        ctx.exec,
        &Cmd::new("curl")
            .args(["-q", "-fsS", "--max-time", "15"])
            .arg(format!("{url}/info")),
    )
    .with_context(|| format!("could not read the proxy's {url}/info"))
}

/// A slot's guardian, as reached through its tunnel and as the proxy leads to it.
pub struct Reached {
    pub info: GuardianInfo,
    pub signing_key: String,
    /// The proxy's `/info`, read when the slot is active.
    pub proxy: Option<ProxyInfo>,
}

/// Stops unless the proxy leads key provisioners and nodes to the slot's guardian as its role says: the proxy fronts
/// the active slot, and its relay sends key provisioners to a standby.
pub fn require_reached(ctx: &Ctx, stack: &Stack, view: &SlotView, tree: &Tree) -> Result<Reached> {
    view.require_instance(stack)?;
    view.require_deployed(stack)?;
    let info = slot_info(ctx, tree, view)?;
    let Some(signing_key) = info.signing_key.clone().filter(|key| is_hex(key, 64)) else {
        bail!(
            "slot {}'s guardian reported no signing key at {}",
            view.slot,
            view.endpoint
        );
    };
    if view.role == Role::Active {
        let proxy = proxy_info(ctx)?;
        match proxy.age() {
            Some(age) if age <= CURRENT_FOR => {}
            Some(age) => bail!(
                "the proxy's /info is {}s old, too old to show that the proxy still reaches slot {}'s guardian; run this step again, and if it stays this old, check the proxy's logs",
                age.as_secs(),
                view.slot
            ),
            None => bail!(
                "the proxy's /info does not say when its guardian answered, so it does not show that the proxy reaches slot {}'s guardian",
                view.slot
            ),
        }
        let fronted = proxy.signing_pub_key.as_deref().unwrap_or("none");
        if fronted != signing_key {
            bail!(
                "the proxy fronts guardian {fronted}, but {} reaches slot {}'s {signing_key}; the proxy caches its view for 30 seconds by default: run this step again; if they still differ, check that the tunnel is slot {}'s",
                view.endpoint,
                view.slot,
                view.slot
            );
        }
        return Ok(Reached {
            info,
            signing_key,
            proxy: Some(proxy),
        });
    }
    let relay = relay_info(ctx, tree)?;
    let target = relay.signing_key.as_deref().unwrap_or("none");
    if target != signing_key {
        bail!(
            "the proxy's relay sends key provisioners to guardian {target}, but {} reaches slot {}'s {signing_key}; check that the tunnel is slot {}'s",
            view.endpoint,
            view.slot,
            view.slot
        );
    }
    // Until the proxy follows a new standby, its relay leads to the active guardian, so a tunnel that reaches that one
    // passes the check above.
    if proxy_info(ctx)?.signing_pub_key.as_deref() == Some(signing_key.as_str()) {
        bail!(
            "{} reaches the guardian the proxy fronts, {signing_key}, not slot {}'s standby; check that the tunnel is slot {}'s",
            view.endpoint,
            view.slot,
            view.slot
        );
    }
    Ok(Reached {
        info,
        signing_key,
        proxy: None,
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// What grpcurl prints for a guardian's `GuardianInfoData`.
    pub fn info_json(key: &str, btc: Option<&str>, lifecycle: &str) -> serde_json::Value {
        let b64 = |hex_text: &str| Base64::encode_string(&hex::decode(hex_text).unwrap());
        let mut data = serde_json::json!({
            "signingPubKey": b64(key),
            "deploymentInfo": { "gitRevision": "0873917ea" },
        });
        if let Some(btc) = btc {
            data["enclaveBtcPubkey"] = b64(btc).into();
        }
        match lifecycle.split_once('/') {
            Some(("withdraw", stage)) => {
                data["withdraw"] = format!("WITHDRAW_STAGE_{stage}").into()
            }
            Some(("ceremony", stage)) => {
                data["ceremony"] = format!("CEREMONY_STAGE_{stage}").into()
            }
            _ => {}
        }
        data
    }

    #[test]
    fn decodes_what_grpcurl_prints() {
        let data: InfoData = serde_json::from_value(info_json(
            &"aa".repeat(32),
            Some(&"7a".repeat(32)),
            "withdraw/ACTIVATED",
        ))
        .unwrap();
        let info = data.decode().unwrap();
        assert_eq!(info.signing_key.unwrap(), "aa".repeat(32));
        assert_eq!(info.btc_key.unwrap(), "7a".repeat(32));
        assert!(info.lifecycle.is("withdraw/ACTIVATED"));

        let data: InfoData =
            serde_json::from_value(info_json(&"bb".repeat(32), None, "none")).unwrap();
        let info = data.decode().unwrap();
        assert_eq!(info.lifecycle.to_string(), "none");
        assert!(info.btc_key.is_none());

        let data: InfoData = serde_json::from_value(serde_json::json!({
            "signingPubKey": "not base64!",
            "ceremony": "CEREMONY_STAGE_COMPLETED",
        }))
        .unwrap();
        assert!(data.decode().is_err());
    }

    #[test]
    fn reads_the_proxys_info() {
        // As the proxy's contract test writes it.
        let info: ProxyInfo = serde_json::from_str(
            r#"{"signingPubKey": "aa", "btcPubkey": "bb", "gitRevision": "cc", "committeeEpoch": "7", "timestampMs": "1720000000123", "limiter": null}"#,
        )
        .unwrap();
        assert_eq!(info.committee_epoch.as_deref(), Some("7"));
        assert!(info.age().unwrap() > CURRENT_FOR);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let current = ProxyInfo {
            timestamp_ms: Some((now.as_millis() - 5_000).to_string()),
            ..info.clone()
        };
        assert!(current.age().unwrap() < CURRENT_FOR);
        let unknown = ProxyInfo {
            timestamp_ms: None,
            ..info
        };
        assert_eq!(unknown.age(), None);
    }
}
