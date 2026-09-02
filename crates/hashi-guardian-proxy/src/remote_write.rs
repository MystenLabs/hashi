// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Push the proxy's metrics to a Prometheus remote-write endpoint (Mimir).
//! The proxy runs on Fargate and the scrapers in GKE, so nothing can reach
//! `/metrics`; pushing in-process avoids a collector sidecar, which would
//! share this task's role and its read of the guardian's withdrawal log.

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
/// Longer than Mimir's 5m query lookback and instant queries go blank.
pub const MAX_INTERVAL: Duration = Duration::from_secs(300);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(16);
const NAME_LABEL: &str = "__name__";
const BUCKET_LABEL: &str = "le";

pub struct RemoteWriteConfig {
    pub url: Url,
    pub username: String,
    pub password: String,
    pub interval: Duration,
    pub external_labels: Vec<(String, String)>,
}

/// Spawn the push task. A failing push is retried until the next one is due,
/// then dropped for the fresh snapshot; metrics never take the proxy down.
pub fn start(config: RemoteWriteConfig, registry: Registry) -> Result<()> {
    let client = client()?;
    let authorization = basic_auth(&config.username, &config.password)?;

    tokio::spawn(async move {
        info!(url = %config.url, interval =? config.interval, "Started the metrics push task.");
        let mut ticker = tokio::time::interval(config.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            // `tick()` yields the tick's scheduled instant, so this is the next
            // tick even when this one fired late.
            let deadline = ticker.tick().await + config.interval;
            if let Err(e) = push(&client, &config, &authorization, &registry, deadline).await {
                warn!("unable to push metrics: {e:#}");
            }
        }
    });
    Ok(())
}

/// No redirects: reqwest would turn the POST into a bodyless GET whose 2xx
/// reads as a successful push.
fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(PUSH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("remote-write client build")
}

/// Gather the registry into one write request and send it, retrying the same
/// body (and timestamps) until `deadline`.
async fn push(
    client: &reqwest::Client,
    config: &RemoteWriteConfig,
    authorization: &reqwest::header::HeaderValue,
    registry: &Registry,
    deadline: Instant,
) -> Result<()> {
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
    // Raw snappy block, not the frame format, which the receiver rejects as corrupt.
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

/// Per the remote-write spec: 5xx and 429 ask for a retry, any other 4xx
/// would fail the same way again.
enum PushError {
    Transient(anyhow::Error),
    Permanent(anyhow::Error),
}

/// Retry `attempt` with exponential backoff until it succeeds, fails
/// permanently, or `deadline` passes; an attempt still in flight at the
/// deadline is cut off.
async fn retry_until<F, Fut>(deadline: Instant, mut attempt: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), PushError>>,
{
    let mut backoff = INITIAL_BACKOFF;
    loop {
        let error = match tokio::time::timeout_at(deadline, attempt()).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(PushError::Permanent(e))) => return Err(e),
            Ok(Err(PushError::Transient(e))) => e,
            Err(_) => anyhow::anyhow!("attempt timed out"),
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
        .map_err(|e| {
            // A builder error is the request itself (scheme, header); resending cannot fix it.
            let class = if e.is_builder() {
                PushError::Permanent
            } else {
                PushError::Transient
            };
            class(anyhow::Error::new(e).context("HTTP send"))
        })?;

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

/// Parse the endpoint, requiring a scheme reqwest can send to: any other
/// fails only inside `send`, on every tick.
pub fn parse_url(raw: &str) -> Result<Url> {
    let url: Url = raw.parse().context("not a valid URL")?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "must be an http(s) URL"
    );
    Ok(url)
}

/// Parse comma-separated `name=value` labels pinned on every pushed series.
/// Rejects repeats and the names the encoder adds itself (`__name__`, `le`):
/// a series carrying a label twice is refused whole.
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

/// Expand gathered families into remote-write series; histograms fan out into
/// `_bucket`/`_sum`/`_count`.
fn to_timeseries(
    families: &[MetricFamily],
    external_labels: &[(String, String)],
    timestamp: i64,
) -> Vec<TimeSeries> {
    let mut out = Vec::new();
    for family in families {
        let name = family.name();
        for metric in family.get_metric() {
            let mut common: Vec<Label> = metric
                .get_label()
                .iter()
                .map(|l| Label::new(l.name(), l.value()))
                .collect();
            // Prometheus's rule: a metric's own label wins over an external one
            // of the same name, so its children stay distinct series.
            for (name, value) in external_labels {
                if !common.iter().any(|l| &l.name == name) {
                    common.push(Label::new(name, value));
                }
            }

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
                // Only a hand-written Collector can produce these; say so rather
                // than drop them silently.
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

/// Built once so a bad credential fails startup, not every tick; marked
/// sensitive to keep it out of logs.
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
    use axum::http::header::LOCATION;
    use prometheus::Histogram;
    use prometheus::HistogramOpts;
    use prometheus::IntCounterVec;
    use prometheus::Opts;
    use std::cell::Cell;

    fn network_label() -> Vec<(String, String)> {
        vec![("network".to_string(), "testnet".to_string())]
    }

    /// Render a series the way PromQL names it.
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

    /// An external label that a metric also carries must not collapse the
    /// metric's children into one series of same-timestamp samples.
    #[test]
    fn metric_labels_win_over_external_labels() {
        let registry = Registry::new();
        let requests =
            IntCounterVec::new(Opts::new("requests_total", "help"), &["outcome"]).unwrap();
        registry.register(Box::new(requests.clone())).unwrap();
        requests.with_label_values(&["l1_hit"]).inc();
        requests.with_label_values(&["s3_hit"]).inc_by(2);

        let external = vec![
            ("outcome".to_string(), "external".to_string()),
            ("network".to_string(), "testnet".to_string()),
        ];
        let series = to_timeseries(&registry.gather(), &external, 42);
        assert_eq!(
            series.iter().map(rendered).collect::<Vec<_>>(),
            vec![
                r#"requests_total{network="testnet",outcome="l1_hit"} 1"#,
                r#"requests_total{network="testnet",outcome="s3_hit"} 2"#,
            ]
        );
    }

    #[test]
    fn urls_need_a_scheme_reqwest_can_send_to() {
        assert!(parse_url("https://mimir.example/api/v1/push").is_ok());
        assert!(parse_url("http://127.0.0.1:9009/api/v1/push").is_ok());
        assert!(parse_url("ftp://mimir.example/api/v1/push").is_err());
        assert!(parse_url("mimir.example/api/v1/push").is_err());
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
        assert!(parse_external_labels("network=a,network=b").is_err());
        assert!(parse_external_labels("__name__=foo").is_err());
        assert!(parse_external_labels("__meta=foo").is_err());
        assert!(parse_external_labels("le=foo").is_err());
    }

    #[test]
    fn credentials_are_encoded_and_marked_sensitive() {
        use base64ct::Encoding as _;
        const USER: &str = "test-user";
        const PASSWORD: &str = "test-password-not-a-real-one";

        let value = basic_auth(USER, PASSWORD).unwrap();
        assert!(value.is_sensitive(), "credentials must not reach logs");
        // Decoded rather than compared to a literal, which would trip secret scanners.
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

    /// `None` = success, `Some(true)` = transient, `Some(false)` = permanent.
    async fn retry_script(
        deadline: Duration,
        mut outcomes: Vec<Option<bool>>,
    ) -> (Result<()>, u32) {
        let attempts = Cell::new(0);
        let result = retry_until(Instant::now() + deadline, || {
            attempts.set(attempts.get() + 1);
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

    #[tokio::test(start_paused = true)]
    async fn retries_give_up_when_the_next_push_is_due() {
        let (result, attempts) = retry_script(Duration::from_secs(5), vec![Some(true); 10]).await;
        let error = result.unwrap_err();
        assert!(error.to_string().contains("next push is due"), "{error:#}");
        // 1s + 2s of backoff fit inside 5s; the third wait of 4s would not.
        assert_eq!(attempts, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn an_attempt_still_in_flight_is_cut_off_at_the_deadline() {
        let started = Instant::now();
        let deadline = started + Duration::from_secs(5);
        let attempts = Cell::new(0);
        let result = retry_until(deadline, || {
            attempts.set(attempts.get() + 1);
            std::future::pending::<Result<(), PushError>>()
        })
        .await;
        let error = result.unwrap_err();
        assert!(error.to_string().contains("next push is due"), "{error:#}");
        assert_eq!(attempts.get(), 1);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    /// A receiver answering `/push` with `status`, plus a `/moved` route a
    /// redirect could land on.
    async fn receiver(status: StatusCode) -> Url {
        let app = axum::Router::new()
            .route(
                "/push",
                axum::routing::post(move || async move { (status, [(LOCATION, "/moved")]) }),
            )
            .route("/moved", axum::routing::get(|| async { StatusCode::OK }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/push", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    }

    async fn send_to(url: Url) -> Result<(), PushError> {
        let client = client().unwrap();
        let authorization = basic_auth("u", "p").unwrap();
        send(&client, &url, &authorization, Bytes::from_static(b"body")).await
    }

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
        // A redirect must not be followed into a bodyless GET that "succeeds".
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::SEE_OTHER,
        ] {
            assert!(
                matches!(
                    send_to(receiver(status).await).await,
                    Err(PushError::Permanent(_))
                ),
                "{status}"
            );
        }
        // A port nothing listens on: refused before any status.
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
