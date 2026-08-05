// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Push the proxy's metrics to a Prometheus remote-write endpoint (Mimir).
//!
//! The proxy runs on Fargate while the scrapers run in GKE, so nothing can
//! reach `/metrics`. Pushing from in-process keeps the task single-container: a
//! collector sidecar would share this task's IAM role, which carries
//! `s3:GetObject` on the guardian's withdrawal log.

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;
use anyhow::Result;
use prometheus::proto::MetricFamily;
use prometheus::proto::MetricType;
use prometheus::Registry;
use tracing::debug;
use tracing::info;
use tracing::warn;

const USER_AGENT: &str = concat!("hashi-guardian-proxy/", env!("CARGO_PKG_VERSION"));
const PUSH_TIMEOUT: Duration = Duration::from_secs(30);
const NAME_LABEL: &str = "__name__";

pub struct RemoteWriteConfig {
    pub url: String,
    pub username: String,
    pub password: String,
    pub interval: Duration,
    pub external_labels: Vec<(String, String)>,
}

/// Spawn the push task. Returns immediately; a failed push is logged and
/// retried on the next tick, since metrics must never take the proxy down and
/// a briefly unreachable Mimir is not a proxy fault.
pub fn start(config: RemoteWriteConfig, registry: Registry) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(PUSH_TIMEOUT)
        .build()
        .context("remote-write client build")?;
    let authorization = basic_auth(&config.username, &config.password)?;

    tokio::spawn(async move {
        info!(url = %config.url, interval =? config.interval, "Started the metrics push task.");
        let mut ticker = tokio::time::interval(config.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(e) = push_once(&client, &config, &authorization, &registry).await {
                warn!("unable to push metrics: {e:#}");
            }
        }
    });
    Ok(())
}

async fn push_once(
    client: &reqwest::Client,
    config: &RemoteWriteConfig,
    authorization: &reqwest::header::HeaderValue,
    registry: &Registry,
) -> Result<()> {
    // Stamp every series with a single collection time.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before unix epoch")?
        .as_millis() as i64;

    let request = WriteRequest {
        timeseries: to_timeseries(&registry.gather(), &config.external_labels, now_ms),
    };
    if request.timeseries.is_empty() {
        return Ok(());
    }
    // Snappy raw block (NOT frame), as the remote-write spec requires; the
    // frame format arrives as "corrupt input" on the receiving end.
    let body = snap::raw::Encoder::new()
        .compress_vec(&prost::Message::encode_to_vec(&request))
        .context("snappy raw compression")?;

    let response = client
        .post(&config.url)
        .header(reqwest::header::AUTHORIZATION, authorization.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .header(reqwest::header::CONTENT_ENCODING, "snappy")
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .header("X-Prometheus-Remote-Write-Version", "0.1.0")
        .body(body)
        .send()
        .await
        .context("HTTP send")?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("remote-write returned {status}: {}", body.trim());
    }
    debug!(series = request.timeseries.len(), "Pushed metrics.");
    Ok(())
}

/// Expand gathered families into remote-write series. Histograms fan out into
/// the `_bucket`/`_sum`/`_count` series Prometheus's data model defines; every
/// series carries `__name__` plus the external labels.
fn to_timeseries(
    families: &[MetricFamily],
    external_labels: &[(String, String)],
    timestamp: i64,
) -> Vec<TimeSeries> {
    let mut out = Vec::new();
    for family in families {
        let name = family.name();
        for metric in family.get_metric() {
            // External labels win: a series carrying the same label name twice
            // is rejected outright, so a metric must not shadow them.
            let mut common: Vec<Label> = metric
                .get_label()
                .iter()
                .filter(|l| !external_labels.iter().any(|(k, _)| k == l.name()))
                .map(|l| Label::new(l.name(), l.value()))
                .collect();
            common.extend(external_labels.iter().map(|(k, v)| Label::new(k, v)));

            let mut push = |name: &str, extra: Option<Label>, value: f64| {
                let mut labels = common.clone();
                labels.push(Label::new(NAME_LABEL, name));
                labels.extend(extra);
                labels.sort_by(|a, b| a.name.cmp(&b.name));
                out.push(TimeSeries {
                    labels,
                    samples: vec![Sample { value, timestamp }],
                });
            };

            match family.get_field_type() {
                MetricType::COUNTER => push(name, None, metric.get_counter().value()),
                MetricType::GAUGE => push(name, None, metric.get_gauge().value()),
                MetricType::HISTOGRAM => {
                    let histogram = metric.get_histogram();
                    let bucket = format!("{name}_bucket");
                    for b in histogram.get_bucket() {
                        let le = Label::new("le", &b.upper_bound().to_string());
                        push(&bucket, Some(le), b.cumulative_count() as f64);
                    }
                    let count = histogram.sample_count() as f64;
                    // `prometheus` leaves the open-ended bucket implicit.
                    push(&bucket, Some(Label::new("le", "+Inf")), count);
                    push(&format!("{name}_sum"), None, histogram.sample_sum());
                    push(&format!("{name}_count"), None, count);
                }
                // `prometheus` exposes no summary or untyped metric, so this is
                // reachable only through a hand-written Collector. Say so rather
                // than dropping the series and leaving a gap nobody can see.
                other => warn!(
                    metric = name,
                    ?other,
                    "Unsupported metric type; not pushed."
                ),
            }
        }
    }
    out
}

/// Built once at startup so a credential that cannot be a header value fails
/// the task rather than every tick. Sensitive to keep it out of debug output.
fn basic_auth(username: &str, password: &str) -> Result<reqwest::header::HeaderValue> {
    use base64ct::Encoding as _;
    let encoded = base64ct::Base64::encode_string(format!("{username}:{password}").as_bytes());
    let mut value: reqwest::header::HeaderValue = format!("Basic {encoded}")
        .parse()
        .context("the Mimir credentials are not a valid HTTP header value")?;
    value.set_sensitive(true);
    Ok(value)
}

/// The subset of `prometheus/prompb` a v1 write request needs.
#[derive(prost::Message)]
struct WriteRequest {
    #[prost(message, repeated, tag = "1")]
    timeseries: Vec<TimeSeries>,
}

#[derive(prost::Message)]
struct TimeSeries {
    #[prost(message, repeated, tag = "1")]
    labels: Vec<Label>,
    #[prost(message, repeated, tag = "2")]
    samples: Vec<Sample>,
}

#[derive(Clone, prost::Message)]
struct Label {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    value: String,
}

impl Label {
    fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

#[derive(prost::Message)]
struct Sample {
    #[prost(double, tag = "1")]
    value: f64,
    #[prost(int64, tag = "2")]
    timestamp: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Histogram;
    use prometheus::HistogramOpts;
    use prometheus::IntCounterVec;
    use prometheus::Opts;

    fn network_label() -> Vec<(String, String)> {
        vec![("network".to_string(), "testnet".to_string())]
    }

    /// Render a series the way PromQL names it, so the assertions below read
    /// like the queries a dashboard would run.
    fn rendered(series: &TimeSeries) -> String {
        let name = &series
            .labels
            .iter()
            .find(|l| l.name == NAME_LABEL)
            .expect("__name__")
            .value;
        let rest: Vec<String> = series
            .labels
            .iter()
            .filter(|l| l.name != NAME_LABEL)
            .map(|l| format!("{}=\"{}\"", l.name, l.value))
            .collect();
        format!("{name}{{{}}} {}", rest.join(","), series.samples[0].value)
    }

    /// Histograms are the case the data model is easy to get wrong: buckets
    /// belong under `_bucket`, not the bare family name, or `histogram_quantile`
    /// finds nothing.
    #[test]
    fn histograms_expand_to_the_series_promql_expects() {
        let registry = Registry::new();
        let scan_lists =
            Histogram::with_opts(HistogramOpts::new("scan_lists", "help").buckets(vec![2.0, 5.0]))
                .unwrap();
        registry.register(Box::new(scan_lists.clone())).unwrap();
        scan_lists.observe(3.0);
        scan_lists.observe(99.0);

        let series = to_timeseries(&registry.gather(), &network_label(), 42);
        let rendered: Vec<String> = series.iter().map(rendered).collect();
        assert_eq!(
            rendered,
            vec![
                r#"scan_lists_bucket{le="2",network="testnet"} 0"#,
                r#"scan_lists_bucket{le="5",network="testnet"} 1"#,
                r#"scan_lists_bucket{le="+Inf",network="testnet"} 2"#,
                r#"scan_lists_sum{network="testnet"} 102"#,
                r#"scan_lists_count{network="testnet"} 2"#,
            ]
        );
        assert!(series.iter().all(|s| s.samples[0].timestamp == 42));
    }

    #[test]
    fn counters_keep_their_labels_and_external_labels_win() {
        let registry = Registry::new();
        let requests =
            IntCounterVec::new(Opts::new("requests_total", "help"), &["outcome", "network"])
                .unwrap();
        registry.register(Box::new(requests.clone())).unwrap();
        // A metric label that collides with an external one: keeping both would
        // duplicate `network` in the series and Mimir would reject the write.
        requests
            .with_label_values(&["l1_hit", "from-the-metric"])
            .inc();

        let series = to_timeseries(&registry.gather(), &network_label(), 42);
        assert_eq!(
            series.iter().map(rendered).collect::<Vec<_>>(),
            vec![r#"requests_total{network="testnet",outcome="l1_hit"} 1"#]
        );
    }

    /// The one thing that fails closed and silently: without it Mimir 401s
    /// every tick behind a `warn!`.
    #[test]
    fn credentials_are_encoded_and_marked_sensitive() {
        use base64ct::Encoding as _;
        const USER: &str = "test-user";
        const PASSWORD: &str = "test-password-not-a-real-one";

        let value = basic_auth(USER, PASSWORD).unwrap();
        assert!(value.is_sensitive(), "credentials must not reach logs");
        // Decoded rather than compared to a literal: a hardcoded `Basic <b64>`
        // trips secret scanners whatever it actually encodes.
        let encoded = value
            .to_str()
            .unwrap()
            .strip_prefix("Basic ")
            .expect("basic scheme");
        let decoded = base64ct::Base64::decode_vec(encoded).unwrap();
        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            format!("{USER}:{PASSWORD}")
        );
    }
}
