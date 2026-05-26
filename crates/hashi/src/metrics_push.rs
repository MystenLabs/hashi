// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Push hashi-server metrics to a sui-proxy `/publish/metrics` endpoint via
//! the same mTLS protocol sui-node and sui-bridge use.

use crate::config::MetricsPushConfig;
use anyhow::Context;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use prometheus::Encoder;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// SNI/DNS name in the client cert; sui-proxy's TLS verifier checks this.
/// Mirrors `sui_tls::SUI_VALIDATOR_SERVER_NAME` — inlined to avoid a sui-tls dep.
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
        .with_context(|| format!("invalid metrics_push.push_url '{}'", cfg.push_url))?;

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
                    // Match sui-metrics-push-client's behavior: rebuild the connection
                    // on failure rather than rely on reqwest's pool to recover.
                    match build_client(&identity_pem) {
                        Ok(c) => client = c,
                        Err(e) => {
                            // Keep the previous client; we'll try to rebuild again on the next failure.
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
/// concatenated with the PKCS#8 private-key PEM.
fn build_identity_pem(tls_private_key: &ed25519_dalek::SigningKey) -> anyhow::Result<String> {
    // PKCS#8 v1 DER of the Ed25519 seed; what `ring` (via rustls/rcgen) accepts.
    let pkcs8 = tls_private_key
        .to_pkcs8_der()
        .context("PKCS#8-encode tls_private_key")?;

    let private_key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8.as_bytes().to_vec().into());
    let keypair = rcgen::KeyPair::from_der_and_sign_algo(&private_key_der, &rcgen::PKCS_ED25519)
        .context("rcgen Ed25519 PKCS#8 DER")?;

    let cert = rcgen::CertificateParams::new(vec![PROXY_SERVER_NAME.to_owned()])
        .context("rcgen CertificateParams construction")?
        .self_signed(&keypair)
        .context("rcgen self_signed")?;

    let cert_pem = cert.pem();
    let key_pem = tls_private_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("PEM encoding of PKCS#8 key")?;
    // `to_pkcs8_pem` returns Zeroizing<String>; deref into &str for format!.
    Ok(format!("{cert_pem}\n{}", &*key_pem))
}

/// Build a reqwest client with the operator's mTLS identity loaded. sui-proxy
/// verifies the client cert's public key against `MemberInfo.tls_public_key`
/// for that validator on chain.
fn build_client(identity_pem: &str) -> anyhow::Result<reqwest::Client> {
    let identity = reqwest::tls::Identity::from_pem(identity_pem.as_bytes())
        .context("reqwest Identity::from_pem")?;
    reqwest::Client::builder()
        .identity(identity)
        .timeout(PUSH_TIMEOUT)
        .build()
        .context("reqwest client build")
}

async fn push_once(
    client: &reqwest::Client,
    url: &reqwest::Url,
    user_agent: &str,
) -> anyhow::Result<()> {
    // Stamp every series with a single collection time.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before unix epoch")?
        .as_millis() as i64;

    let mut metric_families = prometheus::default_registry().gather();
    for mf in metric_families.iter_mut() {
        for m in mf.mut_metric() {
            m.set_timestamp_ms(now_ms);
        }
    }

    let mut buf = Vec::new();
    let encoder = prometheus::ProtobufEncoder::new();
    encoder
        .encode(&metric_families, &mut buf)
        .context("protobuf encoding")?;

    // Snappy raw block (NOT frame). sui-proxy decodes via `snap::raw::Decoder`;
    // frame format would arrive as "corrupt input" on the decoder side.
    let compressed = snap::raw::Encoder::new()
        .compress_vec(&buf)
        .context("snappy raw compression")?;

    let response = client
        .post(url.clone())
        // `prometheus::PROTOBUF_FORMAT` (the verbose vnd.google.protobuf string) — sui-proxy's
        // middleware accepts only this exact value; sourcing from the proxy's crate keeps us in lockstep.
        .header(reqwest::header::CONTENT_TYPE, prometheus::PROTOBUF_FORMAT)
        .header(reqwest::header::CONTENT_ENCODING, "snappy")
        .header(reqwest::header::CONTENT_LENGTH, compressed.len())
        .header(reqwest::header::USER_AGENT, user_agent)
        .header("X-Mysten-Proxy", user_agent)
        .body(compressed)
        .send()
        .await
        .context("HTTP send")?;

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
        // If reqwest rejects the PEM bundle we generate, the production push task
        // can never authenticate.
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
