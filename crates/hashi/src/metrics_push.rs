// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Push Prometheus metrics from hashi-server to a sui-proxy `/publish/metrics`
//! endpoint.
//!
//! ## Wire format
//!
//! Matches the format `sui-metrics-push-client` uses for sui-node / sui-bridge
//! — sui-proxy authenticates clients identically regardless of which service
//! is pushing:
//!
//! - `POST` to the configured URL
//! - mTLS client auth: self-signed x509 cert wrapping the operator's Ed25519
//!   `tls_private_key`. The public half is on chain as
//!   `MemberInfo.tls_public_key`, which sui-proxy's hashi resolver reads.
//! - Body: length-delimited Prometheus protobuf, Snappy-frame-compressed.
//! - Headers: `Content-Type: application/x-protobuf`,
//!   `Content-Encoding: snappy`, `Content-Length`,
//!   `X-Mysten-Proxy: hashi-server/<version>`.
//!
//! ## Why this lives in hashi instead of depending on `sui-metrics-push-client`
//!
//! `sui-metrics-push-client` pulls in `sui-types` which transitively requires
//! a yanked `core2 0.4.0` through old `multihash` / `multiaddr` / `mysten-network`.
//! Until that chain is updated, inlining the (small) push logic here is cleaner
//! than churning hashi's pinned sui rev.
//!
//! The cert generation path mirrors `sui-tls::SelfSignedCertificate`: build a
//! PKCS#8 v1 DER from the Ed25519 secret seed, hand it to `rcgen`, self-sign
//! with `server_name = "sui"` so sui-proxy's SNI handler accepts it.

use crate::config::MetricsPushConfig;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use prometheus::Encoder;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// sui-proxy expects the SNI / DNS-name in the client cert to be `"sui"` (see
/// `sui_tls::SUI_VALIDATOR_SERVER_NAME`). Hardcoding the constant here avoids
/// taking a dependency on sui-tls just for one literal.
const PROXY_SERVER_NAME: &str = "sui";

const DEFAULT_PUSH_INTERVAL: Duration = Duration::from_secs(60);
const PUSH_TIMEOUT: Duration = Duration::from_secs(45);
const CONSECUTIVE_FAILS_BEFORE_ERROR: u32 = 10;

/// Spawn the metrics push task. Returns immediately; pushing happens in the
/// background and surfaces failures via `tracing::warn!` / `tracing::error!`.
pub fn start(
    cfg: MetricsPushConfig,
    tls_private_key: ed25519_dalek::SigningKey,
) -> anyhow::Result<()> {
    let interval = cfg
        .push_interval_seconds
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_PUSH_INTERVAL);
    let url = reqwest::Url::parse(&cfg.push_url)
        .map_err(|e| anyhow::anyhow!("invalid metrics_push.push_url '{}': {e}", cfg.push_url))?;

    let identity_pem = build_identity_pem(&tls_private_key)?;
    let mut client = build_client(&identity_pem)?;
    let user_agent = format!("hashi-server/{}", env!("CARGO_PKG_VERSION"));

    tokio::spawn(async move {
        tracing::info!(push_url =% url, interval =? interval, "started hashi metrics push task");

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut consecutive_errors: u32 = 0;
        loop {
            ticker.tick().await;

            match push_once(&client, &url, &user_agent).await {
                Ok(()) => consecutive_errors = 0,
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= CONSECUTIVE_FAILS_BEFORE_ERROR {
                        tracing::error!(
                            consecutive_errors,
                            "unable to push metrics: {e:#}; rebuilding client",
                        );
                    } else {
                        tracing::warn!(
                            consecutive_errors,
                            "unable to push metrics: {e:#}; rebuilding client",
                        );
                    }
                    // Match sui-metrics-push-client's behavior: aggressively
                    // recreate the connection on failure rather than rely on
                    // reqwest's pool to recover.
                    match build_client(&identity_pem) {
                        Ok(c) => client = c,
                        Err(e) => {
                            tracing::error!("failed to rebuild metrics-push client: {e:#}");
                        }
                    }
                }
            }
        }
    });
    Ok(())
}

/// Build the PEM that reqwest's `Identity::from_pem` expects: cert PEM
/// concatenated with the PKCS#8 private-key PEM. We compute this once at
/// startup; reqwest reparses it each time we rebuild the client on failure.
fn build_identity_pem(tls_private_key: &ed25519_dalek::SigningKey) -> anyhow::Result<String> {
    // PKCS#8 v1 DER of the Ed25519 secret seed. `ring` (which rustls /
    // rcgen-ed25519 use under the hood) only accepts v1; this is also what
    // `sui-tls::SelfSignedCertificate::new` does for sui-node.
    let pkcs8 = tls_private_key
        .to_pkcs8_der()
        .map_err(|e| anyhow::anyhow!("failed to PKCS#8-encode tls_private_key: {e}"))?;

    let private_key_der =
        rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8.as_bytes().to_vec().into());

    // Hand the PKCS#8 DER directly to rcgen — same path `sui-tls` takes.
    let keypair = rcgen::KeyPair::from_der_and_sign_algo(&private_key_der, &rcgen::PKCS_ED25519)
        .map_err(|e| anyhow::anyhow!("rcgen rejected Ed25519 PKCS#8 DER: {e}"))?;

    let cert = rcgen::CertificateParams::new(vec![PROXY_SERVER_NAME.to_owned()])
        .map_err(|e| anyhow::anyhow!("rcgen CertificateParams construction failed: {e}"))?
        .self_signed(&keypair)
        .map_err(|e| anyhow::anyhow!("rcgen self_signed failed: {e}"))?;

    // Concatenate cert + private-key PEM in the format reqwest expects.
    // `to_pkcs8_pem` returns `Zeroizing<String>`; deref into a &str for format!.
    let cert_pem = cert.pem();
    let key_pem = tls_private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("PEM encoding of PKCS#8 key failed: {e}"))?;
    Ok(format!("{cert_pem}\n{}", &*key_pem))
}

/// Build a reqwest client with the operator's mTLS identity loaded. sui-proxy
/// verifies the client cert's public key against `MemberInfo.tls_public_key`
/// for that validator on chain.
fn build_client(identity_pem: &str) -> anyhow::Result<reqwest::Client> {
    let identity = reqwest::tls::Identity::from_pem(identity_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("reqwest rejected identity PEM: {e}"))?;
    let mut builder = reqwest::Client::builder()
        .identity(identity)
        .timeout(PUSH_TIMEOUT);

    // Local-testing escape hatch: when targeting a sui-proxy with a self-signed
    // server cert (i.e. a developer's localhost), reqwest's rustls backend
    // doesn't honor SSL_CERT_FILE and the default webpki-roots trust store
    // won't include it. Setting this env var lets the developer bypass server
    // cert validation. The proxy still authenticates US via mTLS, so the
    // hashi -> proxy direction stays gated; only the server-cert trust check
    // is relaxed. **Never** set this in production: a MITM would be free to
    // present any cert.
    if std::env::var("HASHI_METRICS_PUSH_INSECURE_TLS")
        .ok()
        .as_deref()
        == Some("1")
    {
        tracing::warn!(
            "HASHI_METRICS_PUSH_INSECURE_TLS=1: server cert validation DISABLED for metrics push. \
             This is for local testing against a self-signed sui-proxy only.",
        );
        builder = builder.danger_accept_invalid_certs(true);
    }

    builder
        .build()
        .map_err(|e| anyhow::anyhow!("reqwest client build failed: {e}"))
}

async fn push_once(
    client: &reqwest::Client,
    url: &reqwest::Url,
    user_agent: &str,
) -> anyhow::Result<()> {
    // Stamp every series with a single collection time. Mimir rejects samples
    // too far in the future or past, so use server wall-clock now.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("clock before unix epoch: {e}"))?
        .as_millis() as i64;

    let mut metric_families = prometheus::default_registry().gather();
    for mf in metric_families.iter_mut() {
        for m in mf.mut_metric() {
            m.set_timestamp_ms(now_ms);
        }
    }

    // Length-delimited Prometheus protobuf — what sui-proxy's middleware decodes.
    let mut buf = Vec::new();
    let encoder = prometheus::ProtobufEncoder::new();
    encoder
        .encode(&metric_families, &mut buf)
        .map_err(|e| anyhow::anyhow!("protobuf encoding failed: {e}"))?;

    // Snappy *raw* block compression (NOT the frame format). sui-proxy's
    // middleware decodes via `snap::raw::Decoder`; using `snap::write::FrameEncoder`
    // here would produce a stream with frame headers that `raw::Decoder` rejects
    // as "corrupt input". Stay aligned with the proxy's decoder choice.
    let compressed = snap::raw::Encoder::new()
        .compress_vec(&buf)
        .map_err(|e| anyhow::anyhow!("snappy raw compression failed: {e}"))?;

    let response = client
        .post(url.clone())
        // sui-proxy's middleware accepts exactly `prometheus::PROTOBUF_FORMAT`
        // (the verbose `application/vnd.google.protobuf; proto=...; encoding=delimited`
        // string). Anything else returns 400 from the expect_mysten_proxy_header
        // middleware — sourcing it from the same crate the proxy reads keeps us in lockstep.
        .header(reqwest::header::CONTENT_TYPE, prometheus::PROTOBUF_FORMAT)
        .header(reqwest::header::CONTENT_ENCODING, "snappy")
        .header(reqwest::header::CONTENT_LENGTH, compressed.len())
        .header(reqwest::header::USER_AGENT, user_agent)
        .header("X-Mysten-Proxy", user_agent)
        .body(compressed)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("HTTP send failed: {e}"))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("sui-proxy returned {status}: {body}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn build_identity_pem_produces_parseable_reqwest_identity() {
        // End-to-end smoke test: from a fresh ed25519_dalek key, we must be able
        // to produce a PEM bundle that reqwest accepts as a TLS identity. If
        // this fails the production push task can never authenticate.
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pem = build_identity_pem(&key).expect("identity PEM construction");
        reqwest::tls::Identity::from_pem(pem.as_bytes())
            .expect("reqwest accepts the identity PEM we produce");
    }

    #[test]
    fn build_client_succeeds_for_valid_identity() {
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pem = build_identity_pem(&key).expect("identity PEM");
        let _client = build_client(&pem).expect("client build");
    }
}
