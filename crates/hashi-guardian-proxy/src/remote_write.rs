// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Push the proxy's metrics to a Prometheus remote-write endpoint (Mimir).
//!
//! The proxy runs on Fargate while the scrapers run in GKE, so nothing can
//! reach `/metrics`. Pushing from in-process keeps the task single-container: a
//! collector sidecar would share this task's IAM role, which carries
//! `s3:GetObject` on the guardian's withdrawal log.

use std::future::Future;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;
use anyhow::Result;
use bytes::Bytes;
use prometheus::proto::MetricFamily;
use prometheus::proto::MetricType;
use prometheus::Registry;
use reqwest::StatusCode;
use reqwest::Url;
use tokio::time::Instant;
use tracing::debug;
use tracing::info;
use tracing::warn;

const USER_AGENT: &str = concat!("hashi-guardian-proxy/", env!("CARGO_PKG_VERSION"));
const PUSH_TIMEOUT: Duration = Duration::from_secs(30);
/// Delay before the first retry of a transient failure; doubles per attempt.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(16);
const NAME_LABEL: &str = "__name__";
/// The label histogram buckets carry; the encoder adds it itself.
const BUCKET_LABEL: &str = "le";

pub struct RemoteWriteConfig {
    pub url: Url,
    pub username: String,
    pub password: String,
    pub interval: Duration,
    pub external_labels: Vec<(String, String)>,
}

/// Spawn the push task. Returns immediately; metrics must never take the proxy
/// down, and a briefly unreachable Mimir is not a proxy fault: a push that
/// keeps failing is retried until the next one is due, then dropped in favour
/// of the fresh snapshot.
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
            let deadline = Instant::now() + config.interval;
            if let Err(e) = push(&client, &config, &authorization, &registry, deadline).await {
                warn!("unable to push metrics: {e:#}");
            }
        }
    });
    Ok(())
}

/// Gather the registry into one write request and send it, resending the same
/// body on transient failures until `deadline`. The body keeps its original
/// timestamps, so a retry lands as one late sample rather than a gap.
async fn push(
    client: &reqwest::Client,
    config: &RemoteWriteConfig,
    authorization: &reqwest::header::HeaderValue,
    registry: &Registry,
    deadline: Instant,
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
    let body = Bytes::from(
        snap::raw::Encoder::new()
            .compress_vec(&prost::Message::encode_to_vec(&request))
            .context("snappy raw compression")?,
    );

    retry_until(deadline, || {
        send(client, &config.url, authorization, body.clone())
    })
    .await?;
    debug!(series = request.timeseries.len(), "Pushed metrics.");
    Ok(())
}

/// Whether a failed push is worth resending unchanged. Per the remote-write
/// spec the receiver asks for a retry with 5xx (and 429); any other 4xx means
/// the request itself is bad and would fail the same way again.
enum PushError {
    Transient(anyhow::Error),
    Permanent(anyhow::Error),
}

/// Run `attempt` until it succeeds, fails permanently, or the next retry would
/// land past `deadline`; transient failures back off exponentially in between.
async fn retry_until<F, Fut>(deadline: Instant, mut attempt: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), PushError>>,
{
    let mut backoff = INITIAL_BACKOFF;
    loop {
        let error = match attempt().await {
            Ok(()) => return Ok(()),
            Err(PushError::Permanent(e)) => return Err(e),
            Err(PushError::Transient(e)) => e,
        };
        if Instant::now() + backoff >= deadline {
            return Err(error.context("gave up, the next push is due"));
        }
        warn!(retry_in =? backoff, "Transient push failure, retrying: {error:#}");
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn send(
    client: &reqwest::Client,
    url: &Url,
    authorization: &reqwest::header::HeaderValue,
    body: Bytes,
) -> Result<(), PushError> {
    let response = client
        .post(url.clone())
        .header(reqwest::header::AUTHORIZATION, authorization.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
        .header(reqwest::header::CONTENT_ENCODING, "snappy")
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .header("X-Prometheus-Remote-Write-Version", "0.1.0")
        .body(body)
        .send()
        .await
        .map_err(|e| PushError::Transient(anyhow::Error::new(e).context("HTTP send")))?;

    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let detail = response.text().await.unwrap_or_default();
    let error = anyhow::anyhow!("remote-write returned {status}: {}", detail.trim());
    if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        Err(PushError::Transient(error))
    } else {
        Err(PushError::Permanent(error))
    }
}

/// Parse comma-separated `name=value` labels to pin on every pushed series.
/// Anything the receiver would reject fails here rather than once a tick: a
/// malformed name, a name given twice, or one the encoder sets itself
/// (`__name__` — Prometheus reserves every `__` prefix — and `le` on
/// histogram buckets), since a series carrying a label twice is refused whole.
pub fn parse_external_labels(raw: &str) -> Result<Vec<(String, String)>> {
    let mut labels: Vec<(String, String)> = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (name, value) = entry
            .split_once('=')
            .with_context(|| format!("label {entry:?} must be name=value"))?;
        let (name, value) = (name.trim(), value.trim());
        anyhow::ensure!(
            is_label_name(name) && !value.is_empty(),
            "label {entry:?} needs a prometheus label name ([a-zA-Z_][a-zA-Z0-9_]*) \
             and a non-empty value"
        );
        anyhow::ensure!(
            !name.starts_with("__") && name != BUCKET_LABEL,
            "label {name:?} is reserved for the encoder"
        );
        anyhow::ensure!(
            !labels.iter().any(|(existing, _)| existing == name),
            "label {name:?} is set more than once"
        );
        labels.push((name.to_string(), value.to_string()));
    }
    Ok(labels)
}

fn is_label_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
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
                        let le = Label::new(BUCKET_LABEL, &b.upper_bound().to_string());
                        push(&bucket, Some(le), b.cumulative_count() as f64);
                    }
                    let count = histogram.sample_count() as f64;
                    // `prometheus` leaves the open-ended bucket implicit.
                    push(&bucket, Some(Label::new(BUCKET_LABEL, "+Inf")), count);
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
    use std::cell::Cell;

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

    #[test]
    fn external_labels_parse_and_reject_what_the_receiver_would() {
        let labels = parse_external_labels(" network = testnet , cluster=hashi-guardian,").unwrap();
        let expected = vec![
            ("network".to_string(), "testnet".to_string()),
            ("cluster".to_string(), "hashi-guardian".to_string()),
        ];
        assert_eq!(labels, expected);
        assert!(parse_external_labels("").unwrap().is_empty());
        assert!(parse_external_labels("network").is_err());
        assert!(parse_external_labels("net work=testnet").is_err());
        assert!(parse_external_labels("1network=testnet").is_err());
        assert!(parse_external_labels("network=").is_err());
        // Repeated within the list, or already set by the encoder.
        assert!(parse_external_labels("network=a,network=b").is_err());
        assert!(parse_external_labels("__name__=foo").is_err());
        assert!(parse_external_labels("__meta=foo").is_err());
        assert!(parse_external_labels("le=foo").is_err());
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

    /// Drive `retry_until` with a scripted outcome per attempt; returns the
    /// result and how many attempts it took.
    async fn retry_script(
        deadline: Duration,
        mut outcomes: Vec<Option<bool>>,
    ) -> (Result<()>, u32) {
        let attempts = Cell::new(0);
        let result = retry_until(Instant::now() + deadline, || {
            attempts.set(attempts.get() + 1);
            // `None` = success; `Some(true)` = transient; `Some(false)` = permanent.
            let outcome = if outcomes.is_empty() {
                None
            } else {
                outcomes.remove(0)
            };
            async move {
                match outcome {
                    None => Ok(()),
                    Some(true) => Err(PushError::Transient(anyhow::anyhow!("503"))),
                    Some(false) => Err(PushError::Permanent(anyhow::anyhow!("400"))),
                }
            }
        })
        .await;
        (result, attempts.get())
    }

    /// Two transient failures then success: three attempts of the same request.
    #[tokio::test(start_paused = true)]
    async fn transient_failures_are_retried_with_backoff() {
        let started = Instant::now();
        let (result, attempts) =
            retry_script(Duration::from_secs(60), vec![Some(true), Some(true)]).await;
        result.unwrap();
        assert_eq!(attempts, 3);
        assert_eq!(started.elapsed(), Duration::from_secs(1 + 2));
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_failures_are_not_retried() {
        let (result, attempts) = retry_script(Duration::from_secs(60), vec![Some(false)]).await;
        assert!(result.unwrap_err().to_string().contains("400"));
        assert_eq!(attempts, 1);
    }

    /// Retries stop once the next push is due, so a receiver that stays down
    /// costs one warning per interval and never a pile-up of stale snapshots.
    #[tokio::test(start_paused = true)]
    async fn retries_give_up_when_the_next_push_is_due() {
        let (result, attempts) = retry_script(Duration::from_secs(5), vec![Some(true); 10]).await;
        let error = result.unwrap_err();
        assert!(error.to_string().contains("next push is due"), "{error:#}");
        // 1s + 2s of backoff fit inside 5s; the third wait of 4s would not.
        assert_eq!(attempts, 3);
    }

    /// A receiver answering with a fixed status, to check how `send` classes it.
    async fn receiver(status: StatusCode) -> Url {
        let app =
            axum::Router::new().route("/push", axum::routing::post(move || async move { status }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/push", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    }

    async fn send_to(url: Url) -> Result<(), PushError> {
        let client = reqwest::Client::new();
        let authorization = basic_auth("u", "p").unwrap();
        send(&client, &url, &authorization, Bytes::from_static(b"body")).await
    }

    /// The receiver's verdicts, per the remote-write spec: 5xx and 429 ask for
    /// a retry, any other 4xx is final, and no receiver at all is transient.
    #[tokio::test]
    async fn responses_are_classed_for_retry() {
        assert!(send_to(receiver(StatusCode::NO_CONTENT).await)
            .await
            .is_ok());
        for status in [StatusCode::BAD_GATEWAY, StatusCode::TOO_MANY_REQUESTS] {
            assert!(
                matches!(
                    send_to(receiver(status).await).await,
                    Err(PushError::Transient(_))
                ),
                "{status}"
            );
        }
        for status in [StatusCode::BAD_REQUEST, StatusCode::UNAUTHORIZED] {
            assert!(
                matches!(
                    send_to(receiver(status).await).await,
                    Err(PushError::Permanent(_))
                ),
                "{status}"
            );
        }
        // A port nothing listens on: the connection is refused before any status.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unreachable: Url = format!("http://{}/push", closed.local_addr().unwrap())
            .parse()
            .unwrap();
        drop(closed);
        assert!(matches!(
            send_to(unreachable).await,
            Err(PushError::Transient(_))
        ));
    }
}
