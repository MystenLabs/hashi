// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context as _;

use sui_crypto::simple::SimpleKeypair;
use sui_sdk_types::Address;

use crate::constants::HASHI_MAINNET_OBJECT_ID;
use crate::constants::HASHI_MAINNET_PACKAGE_ID;
use crate::constants::SUI_MAINNET_CHAIN_ID;

const DEFAULT_WITHDRAWAL_SIGNING_CONCURRENCY: usize = 25;
const DEFAULT_MPC_SIGNING_CHUNK_SIZE: usize = 64;
const DEFAULT_WITHDRAWAL_SIGNING_PER_CALLER_LIMIT: usize = 4;
/// Tonic's 4 MiB default is too small to scrape a large on-chain state or
/// receive large MPC round messages.
pub(crate) const DEFAULT_GRPC_MAX_DECODING_MESSAGE_SIZE: usize = 32 * 1024 * 1024;
pub(crate) const DEFAULT_GRPC_PER_PEER_INFLIGHT_LIMIT: u32 = 200;
pub(crate) const DEFAULT_GRPC_PER_PEER_CONNECTION_LIMIT: usize = 4;
/// Core's short fee-estimation horizon. Longer targets are answered from
/// horizons that lag the fee market by hours to days.
const MAX_WITHDRAWAL_FEE_CONF_TARGET: u16 = 12;

fn deserialize_backup_pgp_cert<'de, D>(
    deserializer: D,
) -> Result<hashi_types::pgp::PgpPublicCert, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;

    let path = Path::new(&value);
    let armored = if path.is_file() {
        std::fs::read_to_string(path).map_err(serde::de::Error::custom)?
    } else {
        value
    };

    hashi_types::pgp::PgpPublicCert::new(armored).map_err(serde::de::Error::custom)
}

#[derive(Clone, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_private_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_private_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_address: Option<Address>,

    /// The local address to bind the gRPC+TLS server on.
    ///
    /// Defaults to `0.0.0.0:443` if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_address: Option<SocketAddr>,

    /// The publicly reachable URL advertised to other validators on-chain
    /// (e.g. `https://validator1.example.com:8443`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,

    /// Configure the address to listen on for http metrics, which also serves
    /// `/health` for liveness probes.
    ///
    /// Defaults to `127.0.0.1:9180` if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_http_address: Option<SocketAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sui_chain_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_chain_id: Option<String>,

    /// Defaults to the published mainnet ids, matching the `sui_chain_id`
    /// default. Startup refuses any other ids on Sui mainnet, and the mainnet
    /// ids on every other chain, so every other chain must set this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashi_ids: Option<HashiIds>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sui_rpc: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_rpc: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_rpc_auth: Option<crate::btc_monitor::config::BtcRpcAuth>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_start_height: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_trusted_peers: Option<Vec<String>>,

    /// Database path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db: Option<PathBuf>,

    /// Armored OpenPGP certificate or certificate file path used for node backups.
    #[serde(deserialize_with = "deserialize_backup_pgp_cert")]
    pub backup_pgp_cert: hashi_types::pgp::PgpPublicCert,

    /// Directory to write automatic encrypted backups into.
    pub backup_dir: PathBuf,

    /// Optional remote destination for encrypted node backups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_remote: Option<BackupRemoteConfig>,

    /// Force validator to run as leader, or never run as leader
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_run_as_leader: Option<ForceRunAsLeader>,

    /// Weight divisor for testing. Reduces validator weights to improve integration test performance.
    /// Can only be set if `sui_chain_id` is not mainnet or testnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_weight_divisor: Option<u16>,

    /// Override `BATCH_SIZE_PER_WEIGHT` for testing smaller presignature batches.
    /// Can only be set if `sui_chain_id` is not mainnet or testnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_batch_size_per_weight: Option<u16>,

    /// TRM Labs API key used to screen deposits and withdrawals. When not
    /// set, AML screening is skipped. TRM only screens mainnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trm_api_key: Option<String>,

    /// The guardian's node endpoint, used only when the chain has no
    /// `guardian_node_url` at startup; the node keeps it until restarted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guardian_endpoint: Option<String>,

    /// Maximum gRPC decoding message size in bytes.
    ///
    /// Defaults to 32 MiB if not specified. Tonic's built-in default is 4 MiB,
    /// which is too small to scrape a large on-chain state or receive large MPC
    /// round messages. BridgeService requests are limited to 128 KiB, or to
    /// this if lower.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_max_decoding_message_size: Option<usize>,

    /// Maximum requests served concurrently for one registered peer across all
    /// its connections; requests above it are shed with `Unavailable`. MPC
    /// requests that take the MPC lock also get a separate limit of this size.
    ///
    /// Defaults to 200. Zero is rejected at load.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_per_peer_inflight_limit: Option<u32>,

    /// Maximum request and response bytes in flight for one registered peer across
    /// all its connections; requests and responses above it are shed with
    /// `Unavailable`. Responses count until handed to HTTP/2. MPC requests that
    /// take the MPC lock also get a separate budget of this size.
    ///
    /// Defaults to, and is never below, room for two maximum-size requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_per_peer_inflight_bytes: Option<u64>,

    /// Maximum live connections one registered peer's requests are served on;
    /// requests on any other connection are shed with `Unavailable`.
    ///
    /// Defaults to 4, and is never below 3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_per_peer_connection_limit: Option<usize>,

    /// Maximum number of tasks each leader job family (unapproved and approved
    /// deposit processing, withdrawal approval, signing, broadcast, block checks)
    /// runs concurrently. The cap is per family, not a global budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent_leader_job_tasks: Option<usize>,

    /// Minimum time (ms) the leader waits after the oldest approved withdrawal
    /// request was submitted before committing a batch. The batch fires earlier
    /// if it reaches `withdrawal_max_batch_size`.
    ///
    /// Defaults to 300,000 ms (5 minutes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal_batching_delay_ms: Option<u64>,

    /// Maximum number of withdrawal requests to include in a single Bitcoin
    /// transaction. The batch commits immediately once this many requests are
    /// ready, without waiting for `withdrawal_batching_delay_ms` to elapse.
    ///
    /// Defaults to 447 (the algorithm's hard upper bound, set by the Sui
    /// commit transaction's runtime-object budget under the deferred-archival
    /// package; a chain still executing v1 bytecode is additionally capped
    /// at 298 at batch-build time). Note that large batches
    /// automatically shrink the input side: coin selection reserves the
    /// commit object budget for requests first, so a full batch spends only
    /// a handful of funding inputs and performs no consolidation.
    ///
    /// The leader only fills batches past 40 requests while the queue is
    /// deeper than the available UTXO pool (drain mode); otherwise it caps
    /// batches at 40 so each keeps its full consolidation budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal_max_batch_size: Option<usize>,

    /// Capacity of the channel carrying one `sign_withdrawal_transaction`
    /// stream's signatures to the caller.
    ///
    /// Defaults to 25.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal_signing_concurrency: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal_signing_per_caller_limit: Option<usize>,

    /// Number of per-input MPC signatures the leader writes to chain in one
    /// `commit_input_signatures` PTB — the on-chain write batch size `M`. Trades
    /// durability granularity (work lost on a leader crash) against the number of
    /// commit PTBs per withdrawal. Purely a leader-side batching choice: the
    /// contract certs over exactly the indices written, so any size is valid up
    /// to Sui's 16 KiB pure-arg limit (~250 × 64B sigs).
    ///
    /// Defaults to 64.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpc_signing_chunk_size: Option<usize>,

    /// Maximum number of mempool-only (0-confirmation) ancestors a UTXO may
    /// have and still be eligible as a coin-selection input. Constrains how
    /// deep the chain of unconfirmed transactions can grow, staying within
    /// Bitcoin's relay policy limits.
    ///
    /// Defaults to 5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_mempool_chain_depth: Option<usize>,

    /// Confirmation target (blocks) passed to `estimatesmartfee` when
    /// pricing withdrawal miner fees.
    ///
    /// Defaults to 3. Values outside 1-12 are rejected at load.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal_fee_conf_target: Option<u16>,

    /// Floor (sat/vB) for the withdrawal settlement fee rate, applied
    /// after `estimatesmartfee`. Raising this is the lever for rescuing a
    /// stalled settlement: the CPFP boost only covers the amount by which
    /// this floor exceeds what the stalled ancestor already paid.
    ///
    /// Defaults to `CoinSelectionParams::DEFAULT_MIN_FEE_RATE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal_min_fee_rate_sat_vb: Option<u64>,

    /// Test-only: corrupt AVSS shares sent to this address, triggering the
    /// complaint recovery flow. Must not be set on mainnet or testnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_corrupt_shares_for: Option<Address>,

    /// Which complaints this node answers with its recovery shares.
    /// Complaints are still verified and logged, and withheld ones counted in
    /// `hashi_mpc_complaints_withheld_total`; this only decides whether the
    /// response is returned.
    ///
    /// Defaults to an empty allow-list, i.e. no complaint is answered.
    ///
    /// Allow-listing a dealer is a coordinated decision:
    /// a wrong entry can leak private shares to the dealer.    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complaint_response_policy: Option<ComplaintResponsePolicy>,

    /// Configure pushing Prometheus metrics out to a sui-proxy instance. When
    /// unset, the push task is not started and the only metrics surface is the
    /// local scrape endpoint at `metrics_http_address`.
    ///
    /// The push uses the same `tls_private_key` already registered on chain in
    /// `MemberInfo.tls_public_key`, so no additional credential setup is
    /// required for operators that have already completed hashi committee
    /// registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_push: Option<MetricsPushConfig>,
}

#[derive(Clone, Debug, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct MetricsPushConfig {
    /// sui-proxy `/publish/metrics` URL (e.g. `https://metrics-proxy.testnet.example.com/publish/metrics`).
    pub push_url: String,

    /// How often to push. Defaults to 60s if unset (matches sui-node default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_interval_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForceRunAsLeader {
    /// Use default leader selection, taking turns
    #[default]
    Default,
    /// Always run as leader
    Always,
    /// Never run as aleader
    Never,
}

/// Which complaints a node answers with its recovery shares.
#[derive(Clone, Debug, PartialEq, Eq, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum ComplaintResponsePolicy {
    /// Answer every complaint that verifies.
    AllowAll,
    /// Answer only complaints about messages from these dealers.
    AllowList { dealers: Vec<AllowedDealer> },
}

/// A dealer whose messages in `epoch` this node answers complaints about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AllowedDealer {
    pub epoch: u64,
    pub dealer: Address,
}

/// The default policy: an empty allow-list, answering no complaint.
static DENY_ALL_COMPLAINTS: ComplaintResponsePolicy = ComplaintResponsePolicy::AllowList {
    dealers: Vec::new(),
};

impl ComplaintResponsePolicy {
    pub fn allows(&self, epoch: u64, dealer: &Address) -> bool {
        match self {
            Self::AllowAll => true,
            Self::AllowList { dealers } => dealers
                .iter()
                .any(|allowed| allowed.epoch == epoch && allowed.dealer == *dealer),
        }
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field(
                "tls_private_key",
                &self.tls_private_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "operator_private_key",
                &self.operator_private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("validator_address", &self.validator_address)
            .field("hashi_ids", &self.hashi_ids)
            .field("sui_chain_id", &self.sui_chain_id)
            .field("bitcoin_chain_id", &self.bitcoin_chain_id)
            .field("listen_address", &self.listen_address)
            .field("endpoint_url", &self.endpoint_url)
            .field("sui_rpc", &self.sui_rpc)
            .field("bitcoin_rpc", &self.bitcoin_rpc)
            .field("bitcoin_rpc_auth", &self.bitcoin_rpc_auth)
            .field("db", &self.db)
            .finish_non_exhaustive()
    }
}

/// Remote destination settings. Credentials come from the provider's default chain.
#[derive(Debug, Clone)]
pub enum BackupRemoteConfig {
    S3(S3BackupConfig),
    Gcs(GcsBackupConfig),
}

#[derive(Debug, Clone)]
pub struct S3BackupConfig {
    bucket: String,
    region: String,
}

#[derive(Debug, Clone)]
pub struct GcsBackupConfig {
    bucket: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackupProvider {
    S3,
    Gcs,
}

impl BackupProvider {
    pub(crate) fn scheme(self) -> &'static str {
        match self {
            Self::S3 => "s3",
            Self::Gcs => "gs",
        }
    }
}

/// A local OS path or a validated remote URI, without normalizing object keys.
#[derive(Debug)]
pub(crate) enum BackupLocation<'a> {
    Local(&'a Path),
    Remote(RemoteBackupLocation<'a>),
}

#[derive(Debug)]
pub(crate) struct RemoteBackupLocation<'a> {
    provider: BackupProvider,
    bucket: &'a str,
    key: &'a str,
}

impl<'a> BackupLocation<'a> {
    pub(crate) fn parse(source: &'a Path) -> anyhow::Result<Self> {
        let Some((scheme, rest)) = source.to_str().and_then(|s| s.split_once("://")) else {
            return Ok(Self::Local(source));
        };
        if !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            || !scheme
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
        {
            return Ok(Self::Local(source));
        }
        let provider = match scheme {
            "s3" => BackupProvider::S3,
            "gs" => BackupProvider::Gcs,
            _ => anyhow::bail!("unsupported backup URI scheme: {scheme}"),
        };
        let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
        match provider {
            BackupProvider::S3 => S3BackupConfig::validate_bucket(bucket)?,
            BackupProvider::Gcs => GcsBackupConfig::validate_bucket(bucket)?,
        }
        anyhow::ensure!(
            !key.contains(['?', '#']) && !key.chars().any(char::is_control),
            "backup URI key must not contain a query, fragment, or control characters"
        );
        Ok(Self::Remote(RemoteBackupLocation {
            provider,
            bucket,
            key,
        }))
    }
}

impl<'a> RemoteBackupLocation<'a> {
    pub(crate) fn provider(&self) -> BackupProvider {
        self.provider
    }

    pub(crate) fn key(&self) -> &'a str {
        self.key
    }

    pub(crate) fn into_config(self, region: Option<String>) -> anyhow::Result<BackupRemoteConfig> {
        match self.provider {
            BackupProvider::S3 => {
                let region = region
                    .ok_or_else(|| anyhow::anyhow!("backup-remote.region is required for S3"))?;
                S3BackupConfig::validate_region(&region)?;
                Ok(BackupRemoteConfig::S3(S3BackupConfig {
                    bucket: self.bucket.to_owned(),
                    region,
                }))
            }
            BackupProvider::Gcs => {
                anyhow::ensure!(
                    region.is_none(),
                    "backup-remote.region is forbidden for GCS"
                );
                Ok(BackupRemoteConfig::Gcs(GcsBackupConfig {
                    bucket: self.bucket.to_owned(),
                }))
            }
        }
    }
}

impl S3BackupConfig {
    pub fn new(bucket: String, region: String) -> anyhow::Result<Self> {
        Self::validate_bucket(&bucket)?;
        Self::validate_region(&region)?;
        Ok(Self { bucket, region })
    }

    fn validate_bucket(bucket: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            !bucket.is_empty()
                && bucket
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.'),
            "backup-remote.destination must contain only an S3 bucket, without credentials, port, prefix, query, or fragment"
        );
        Ok(())
    }

    fn validate_region(region: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            !region.trim().is_empty(),
            "backup-remote.region must be nonempty"
        );
        Ok(())
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn region(&self) -> &str {
        &self.region
    }
}

impl GcsBackupConfig {
    pub fn new(bucket: String) -> anyhow::Result<Self> {
        Self::validate_bucket(&bucket)?;
        Ok(Self { bucket })
    }

    fn validate_bucket(bucket: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            !bucket.is_empty()
                && bucket.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_')
                }),
            "backup-remote.destination must contain only a GCS bucket, without credentials, port, prefix, query, or fragment"
        );
        Ok(())
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }
}

impl BackupRemoteConfig {
    /// Parse a bucket-only S3 or GCS URI, allowing one optional trailing slash.
    pub fn new(destination: &str, region: Option<String>) -> anyhow::Result<Self> {
        let BackupLocation::Remote(location) = BackupLocation::parse(Path::new(destination))?
        else {
            anyhow::bail!("backup-remote.destination must be an s3:// or gs:// bucket URI");
        };
        anyhow::ensure!(
            location.key().is_empty(),
            "backup-remote.destination must contain only a bucket, without a key"
        );
        location.into_config(region)
    }

    pub fn bucket(&self) -> &str {
        match self {
            Self::S3(config) => config.bucket(),
            Self::Gcs(config) => config.bucket(),
        }
    }

    pub fn scheme(&self) -> &'static str {
        self.provider().scheme()
    }

    pub(crate) fn provider(&self) -> BackupProvider {
        match self {
            Self::S3(_) => BackupProvider::S3,
            Self::Gcs(_) => BackupProvider::Gcs,
        }
    }
}

impl<'de> serde::Deserialize<'de> for BackupRemoteConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde_derive::Deserialize)]
        #[serde(rename_all = "kebab-case", deny_unknown_fields)]
        struct Input {
            destination: String,
            region: Option<String>,
        }

        let input = <Input as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(&input.destination, input.region).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for BackupRemoteConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        struct Destination<'a>(&'a BackupRemoteConfig);
        impl serde::Serialize for Destination<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(&format_args!("{}://{}/", self.0.scheme(), self.0.bucket()))
            }
        }

        match self {
            Self::S3(config) => {
                let mut output = serializer.serialize_struct("BackupRemoteConfig", 2)?;
                output.serialize_field("destination", &Destination(self))?;
                output.serialize_field("region", config.region())?;
                output.end()
            }
            Self::Gcs(_) => {
                let mut output = serializer.serialize_struct("BackupRemoteConfig", 1)?;
                output.serialize_field("destination", &Destination(self))?;
                output.end()
            }
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, anyhow::Error> {
        let file = std::fs::read(path)?;
        let config: Self = toml::from_slice(&file)?;
        anyhow::ensure!(
            config.grpc_per_peer_inflight_limit != Some(0),
            "grpc_per_peer_inflight_limit must be at least 1"
        );
        anyhow::ensure!(
            config
                .grpc_max_decoding_message_size
                .is_none_or(|limit| u32::try_from(limit).is_ok()),
            "grpc_max_decoding_message_size must fit the 4-byte gRPC length prefix"
        );
        anyhow::ensure!(
            config.withdrawal_signing_per_caller_limit != Some(0),
            "withdrawal_signing_per_caller_limit must be at least 1"
        );
        anyhow::ensure!(
            config
                .withdrawal_fee_conf_target
                .is_none_or(|target| (1..=MAX_WITHDRAWAL_FEE_CONF_TARGET).contains(&target)),
            "withdrawal_fee_conf_target must be between 1 and {MAX_WITHDRAWAL_FEE_CONF_TARGET} blocks"
        );
        config.validate_backup_remote()?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<(), anyhow::Error> {
        let toml = toml::to_string(self)?;
        std::fs::write(path, toml).map_err(Into::into)
    }

    /// Validate remote backup settings without deriving or allocating a destination.
    /// Local-only configurations do not require deployment or validator identity.
    pub fn validate_backup_remote(&self) -> anyhow::Result<()> {
        if self.backup_remote.is_none() {
            return Ok(());
        }
        let chain_id = self.sui_chain_id();
        anyhow::ensure!(
            !chain_id.is_empty()
                && chain_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
            "backup-remote requires a nonempty sui-chain-id usable as a namespace component"
        );
        let ids = self.hashi_ids();
        anyhow::ensure!(
            ids.hashi_object_id != Address::ZERO,
            "backup-remote requires a nonzero hashi-object-id"
        );
        self.validator_address
            .context("backup-remote requires validator-address")?;
        Ok(())
    }

    /// Canonical object-key prefix, including the trailing slash.
    /// Call `validate_backup_remote` before deriving a configured destination.
    pub fn backup_remote_namespace(&self) -> Option<String> {
        self.backup_remote.as_ref()?;
        Some(format!(
            "{}/{}/{}/",
            self.sui_chain_id(),
            self.hashi_ids().hashi_object_id,
            self.validator_address?,
        ))
    }

    pub fn tls_private_key(&self) -> Result<ed25519_dalek::SigningKey, anyhow::Error> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;

        let raw = self
            .tls_private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no tls_private_key configured"))?;

        if let Ok(private_key) = ed25519_dalek::SigningKey::read_pkcs8_pem_file(raw) {
            Ok(private_key)
        } else if let Ok(private_key) = ed25519_dalek::SigningKey::read_pkcs8_der_file(raw) {
            Ok(private_key)
        } else if let Ok(private_key) = ed25519_dalek::SigningKey::from_pkcs8_pem(raw) {
            Ok(private_key)
        } else {
            // maybe some other format?
            Err(anyhow::anyhow!("unable to load tls_private_key"))
        }
    }

    pub fn tls_public_key(&self) -> Result<ed25519_dalek::VerifyingKey, anyhow::Error> {
        let tls_private_key = self.tls_private_key()?;

        Ok(ed25519_dalek::VerifyingKey::from(&tls_private_key))
    }

    /// Load the operator signing keypair from `operator-private-key`.
    ///
    /// The configured value may be a file path or an inline key; see
    /// [`crate::keys::load_keypair`] for the accepted formats.
    pub fn operator_private_key(&self) -> Result<SimpleKeypair, anyhow::Error> {
        let raw = self
            .operator_private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no operator_private_key configured"))?;

        crate::keys::load_keypair(raw).context("unable to load the operator private key")
    }

    pub fn validator_address(&self) -> Result<Address, anyhow::Error> {
        self.validator_address
            .ok_or_else(|| anyhow::anyhow!("no validator address configured"))
    }

    pub fn listen_address(&self) -> SocketAddr {
        self.listen_address
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 443)))
    }

    pub fn endpoint_url(&self) -> Option<&str> {
        self.endpoint_url.as_deref()
    }

    pub fn metrics_http_address(&self) -> SocketAddr {
        self.metrics_http_address
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 9180)))
    }

    pub fn sui_chain_id(&self) -> &str {
        self.sui_chain_id.as_deref().unwrap_or(SUI_MAINNET_CHAIN_ID)
    }

    pub fn bitcoin_chain_id(&self) -> &str {
        self.bitcoin_chain_id
            .as_deref()
            .unwrap_or(crate::constants::BITCOIN_MAINNET_CHAIN_ID)
    }

    pub fn bitcoin_network(&self) -> crate::btc_monitor::config::Network {
        crate::btc_monitor::config::network_from_chain_id(self.bitcoin_chain_id()).unwrap()
    }

    pub fn bitcoin_rpc(&self) -> &str {
        self.bitcoin_rpc
            .as_deref()
            .unwrap_or("http://localhost:8332")
    }

    pub fn bitcoin_start_height(&self) -> u32 {
        self.bitcoin_start_height.unwrap_or_else(|| {
            crate::btc_monitor::config::default_start_height(self.bitcoin_network())
        })
    }

    pub fn bitcoin_rpc_auth(&self) -> corepc_client::client_sync::Auth {
        self.bitcoin_rpc_auth
            .as_ref()
            .unwrap_or(&crate::btc_monitor::config::BtcRpcAuth::None)
            .to_corepc_auth()
    }

    /// Parse configured Bitcoin peer strings into kyoto trusted peers.
    /// Hostnames are not resolved here — kyoto resolves them at connection
    /// time, and the monitor's supervisor rebuilds the node on disconnect
    /// to re-resolve and follow IP changes (e.g., Kubernetes pod rotation).
    pub fn bitcoin_trusted_peers(&self) -> anyhow::Result<Vec<kyoto::TrustedPeer>> {
        let Some(peer_strs) = self.bitcoin_trusted_peers.as_ref() else {
            return Ok(Vec::new());
        };

        let mut peers = Vec::new();
        for s in peer_strs {
            let (host, port_str) = s.rsplit_once(':').ok_or_else(|| {
                anyhow::anyhow!("Invalid bitcoin peer '{s}': expected 'host:port' format")
            })?;
            let port = port_str
                .parse::<u16>()
                .map_err(|e| anyhow::anyhow!("Invalid port in bitcoin peer '{s}': {e}"))?;
            peers.push(kyoto::TrustedPeer::from_hostname(host, port));
        }
        Ok(peers)
    }

    pub fn hashi_ids(&self) -> HashiIds {
        self.hashi_ids.unwrap_or(HashiIds {
            package_id: HASHI_MAINNET_PACKAGE_ID,
            hashi_object_id: HASHI_MAINNET_OBJECT_ID,
        })
    }

    pub fn force_run_as_leader(&self) -> ForceRunAsLeader {
        self.force_run_as_leader.clone().unwrap_or_default()
    }

    pub fn complaint_response_policy(&self) -> &ComplaintResponsePolicy {
        self.complaint_response_policy
            .as_ref()
            .unwrap_or(&DENY_ALL_COMPLAINTS)
    }

    pub fn test_weight_divisor(&self) -> u16 {
        self.test_weight_divisor.unwrap_or(1)
    }

    pub fn trm_api_key(&self) -> Option<&str> {
        self.trm_api_key.as_deref()
    }

    pub fn guardian_endpoint(&self) -> Option<&str> {
        self.guardian_endpoint.as_deref()
    }

    pub fn grpc_max_decoding_message_size(&self) -> usize {
        self.grpc_max_decoding_message_size
            .unwrap_or(DEFAULT_GRPC_MAX_DECODING_MESSAGE_SIZE)
    }

    pub fn grpc_per_peer_inflight_limit(&self) -> u32 {
        self.grpc_per_peer_inflight_limit
            .unwrap_or(DEFAULT_GRPC_PER_PEER_INFLIGHT_LIMIT)
    }

    pub fn grpc_per_peer_inflight_bytes(&self) -> Option<u64> {
        self.grpc_per_peer_inflight_bytes
    }

    pub fn grpc_per_peer_connection_limit(&self) -> Option<usize> {
        self.grpc_per_peer_connection_limit
    }

    pub fn max_concurrent_leader_job_tasks(&self) -> usize {
        self.max_concurrent_leader_job_tasks.unwrap_or(32)
    }

    pub fn withdrawal_batching_delay_ms(&self) -> u64 {
        self.withdrawal_batching_delay_ms.unwrap_or(300_000)
    }

    pub fn withdrawal_max_batch_size(&self) -> usize {
        self.withdrawal_max_batch_size
            .unwrap_or(crate::utxo_pool::CoinSelectionParams::MAX_WITHDRAWAL_REQUESTS)
            .min(crate::utxo_pool::CoinSelectionParams::MAX_WITHDRAWAL_REQUESTS)
    }

    pub fn withdrawal_signing_concurrency(&self) -> usize {
        self.withdrawal_signing_concurrency
            .unwrap_or(DEFAULT_WITHDRAWAL_SIGNING_CONCURRENCY)
            .max(1)
    }

    pub fn withdrawal_signing_per_caller_limit(&self) -> usize {
        self.withdrawal_signing_per_caller_limit
            .unwrap_or(DEFAULT_WITHDRAWAL_SIGNING_PER_CALLER_LIMIT)
    }

    pub fn mpc_signing_chunk_size(&self) -> usize {
        self.mpc_signing_chunk_size
            .unwrap_or(DEFAULT_MPC_SIGNING_CHUNK_SIZE)
            .max(1)
    }

    pub fn max_mempool_chain_depth(&self) -> usize {
        self.max_mempool_chain_depth
            .unwrap_or(crate::utxo_pool::CoinSelectionParams::DEFAULT_MAX_MEMPOOL_CHAIN_DEPTH)
    }

    pub fn withdrawal_fee_conf_target(&self) -> u16 {
        self.withdrawal_fee_conf_target.unwrap_or(3)
    }

    pub fn withdrawal_min_fee_rate(&self) -> bitcoin::FeeRate {
        self.withdrawal_min_fee_rate_sat_vb
            .and_then(bitcoin::FeeRate::from_sat_per_vb)
            .unwrap_or(crate::utxo_pool::CoinSelectionParams::DEFAULT_MIN_FEE_RATE)
    }

    // Creates a new config suitable for testing. In particular this config will:
    // - have randomly generated private key material
    // - localhost only listen addresses using available ports
    pub fn new_for_testing() -> Self {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use std::ops::Deref;

        let mut config = Config {
            tls_private_key: None,
            operator_private_key: None,
            validator_address: None,
            listen_address: None,
            endpoint_url: None,
            metrics_http_address: None,
            sui_chain_id: None,
            bitcoin_chain_id: None,
            hashi_ids: None,
            sui_rpc: None,
            bitcoin_rpc: None,
            bitcoin_rpc_auth: None,
            bitcoin_start_height: None,
            bitcoin_trusted_peers: None,
            db: None,
            backup_pgp_cert: hashi_types::pgp::test_utils::mock_pgp_cert(),
            backup_dir: std::env::temp_dir().join(format!(
                "hashi-test-backups-{:032x}",
                rand::random::<u128>()
            )),
            backup_remote: None,
            force_run_as_leader: None,
            test_weight_divisor: None,
            test_batch_size_per_weight: None,
            trm_api_key: None,
            guardian_endpoint: None,
            grpc_max_decoding_message_size: None,
            grpc_per_peer_inflight_limit: None,
            grpc_per_peer_inflight_bytes: None,
            grpc_per_peer_connection_limit: None,
            max_concurrent_leader_job_tasks: None,
            withdrawal_batching_delay_ms: None,
            withdrawal_max_batch_size: None,
            withdrawal_signing_concurrency: None,
            withdrawal_signing_per_caller_limit: None,
            mpc_signing_chunk_size: None,
            max_mempool_chain_depth: None,
            withdrawal_fee_conf_target: None,
            withdrawal_min_fee_rate_sat_vb: None,
            test_corrupt_shares_for: None,
            complaint_response_policy: None,
            metrics_push: None,
        };

        let tls_private_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

        config.tls_private_key = Some(
            tls_private_key
                .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
                .unwrap()
                .deref()
                .to_owned(),
        );

        let listen_addr = SocketAddr::from(([127, 0, 0, 1], get_available_port()));
        config.listen_address = Some(listen_addr);
        config.endpoint_url = Some(format!("https://{listen_addr}"));
        config.metrics_http_address =
            Some(SocketAddr::from(([127, 0, 0, 1], get_available_port())));

        config
    }
}

/// Relevant Onchain Ids for the hashi protocol.
#[derive(Debug, Clone, Copy, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HashiIds {
    /// The original package id of the `hashi` package.
    pub package_id: Address,
    /// Id of the main `Hashi` shared object.
    pub hashi_object_id: Address,
}

/// Return an ephemeral, available port. On unix systems, the port returned will be in the
/// TIME_WAIT state ensuring that the OS won't hand out this port for some grace period.
/// Callers should be able to bind to this port given they use SO_REUSEADDR.
pub fn get_available_port() -> u16 {
    const MAX_PORT_RETRIES: u32 = 1000;

    for _ in 0..MAX_PORT_RETRIES {
        if let Ok(port) = get_ephemeral_port() {
            return port;
        }
    }

    panic!("Error: could not find an available port on localhost");
}

fn get_ephemeral_port() -> std::io::Result<u16> {
    use std::net::TcpListener;
    use std::net::TcpStream;

    // Request a random available port from the OS
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = listener.local_addr()?;

    // Create and accept a connection (which we'll promptly drop) in order to force the port
    // into the TIME_WAIT state, ensuring that the port will be reserved from some limited
    // amount of time (roughly 60s on some Linux systems)
    let _sender = TcpStream::connect(addr)?;
    let _incoming = listener.accept()?;

    Ok(addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_remote_config_is_optional_and_validated_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::new_for_testing();
        config.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap();
        assert!(loaded.backup_remote.is_none());
        assert!(loaded.backup_remote_namespace().is_none());

        config.backup_remote =
            Some(BackupRemoteConfig::new("s3://hashi-backups/", Some("us-west-2".into())).unwrap());
        let load = |config: &Config| {
            config.save(&path).unwrap();
            Config::load(&path)
        };
        config.sui_chain_id = Some("AbCdEF12".into());
        config.hashi_ids = Some(HashiIds {
            package_id: Address::ZERO,
            hashi_object_id: Address::ZERO,
        });
        assert!(load(&config).is_err());
        config.hashi_ids.as_mut().unwrap().hashi_object_id = "0x1".parse().unwrap();
        assert!(load(&config).is_err());
        config.validator_address = Some("0x2".parse().unwrap());
        let loaded = load(&config).unwrap();
        let remote = loaded.backup_remote.as_ref().unwrap();
        assert_eq!(remote.bucket(), "hashi-backups");
        let BackupRemoteConfig::S3(s3) = remote else {
            panic!("expected S3 config");
        };
        assert_eq!(s3.region(), "us-west-2");
        assert_eq!(
            loaded.backup_remote_namespace().unwrap(),
            "AbCdEF12/0x0000000000000000000000000000000000000000000000000000000000000001/0x0000000000000000000000000000000000000000000000000000000000000002/"
        );
        config.sui_chain_id = None;
        let default_config = load(&config).unwrap();
        assert!(
            default_config
                .backup_remote_namespace()
                .unwrap()
                .starts_with(&format!("{SUI_MAINNET_CHAIN_ID}/"))
        );

        for chain in ["", " ", "../chain", "a/b"] {
            config.sui_chain_id = Some(chain.into());
            assert!(load(&config).is_err());
        }
        // Invalid remote identities remain irrelevant when remote backup is disabled.
        config.backup_remote = None;
        config.sui_chain_id = Some("../invalid".into());
        config.hashi_ids = None;
        config.validator_address = None;
        assert!(load(&config).is_ok());
    }

    #[test]
    fn backup_remote_uses_mainnet_ids_when_omitted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config::new_for_testing();
        config.backup_remote =
            Some(BackupRemoteConfig::new("s3://hashi-backups/", Some("us-west-2".into())).unwrap());
        config.validator_address = Some("0x2".parse().unwrap());

        for chain_id in [None, Some(SUI_MAINNET_CHAIN_ID.to_string())] {
            config.sui_chain_id = chain_id;
            config.save(&path).unwrap();
            let loaded = Config::load(&path).unwrap();
            assert!(loaded.hashi_ids.is_none());
            assert_eq!(
                loaded.backup_remote_namespace().unwrap(),
                format!(
                    "{SUI_MAINNET_CHAIN_ID}/{HASHI_MAINNET_OBJECT_ID}/0x0000000000000000000000000000000000000000000000000000000000000002/"
                )
            );
        }
    }

    #[test]
    fn hashi_ids_default_to_the_mainnet_ids() {
        let mut config = Config::new_for_testing();

        for chain_id in [
            None,
            Some(SUI_MAINNET_CHAIN_ID),
            Some(crate::constants::SUI_TESTNET_CHAIN_ID),
            Some("AbCdEF12"),
        ] {
            config.sui_chain_id = chain_id.map(str::to_string);
            let ids = config.hashi_ids();
            assert_eq!(ids.package_id, HASHI_MAINNET_PACKAGE_ID, "{chain_id:?}");
            assert_eq!(ids.hashi_object_id, HASHI_MAINNET_OBJECT_ID, "{chain_id:?}");
        }
    }

    #[test]
    fn configured_hashi_ids_override_the_mainnet_default() {
        let package_id: Address = "0x1".parse().unwrap();
        let hashi_object_id: Address = "0x2".parse().unwrap();
        let mut config = Config::new_for_testing();
        config.hashi_ids = Some(HashiIds {
            package_id,
            hashi_object_id,
        });

        for chain_id in [None, Some("AbCdEF12".to_string())] {
            config.sui_chain_id = chain_id;
            let ids = config.hashi_ids();
            assert_eq!(ids.package_id, package_id);
            assert_eq!(ids.hashi_object_id, hashi_object_id);
        }
    }

    #[test]
    fn backup_remote_rejects_partial_and_unknown_settings() {
        for settings in [
            "",
            "destination = 's3://hashi-backups/'",
            "region = 'us-west-2'",
            "destination = 's3://hashi-backups/'\nregion = 'us-west-2'\nprefix = 'custom/'",
            "destination = 's3://hashi-backups/'\nregion = 'us-west-2'\naccess-key = 'secret'",
            "destination = 'gs://hashi-backups/'\ncredentials = 'secret'",
            "bucket = 'hashi-backups'\nregion = 'us-west-2'",
        ] {
            assert!(
                toml::from_str::<BackupRemoteConfig>(settings).is_err(),
                "{settings}"
            );
        }
        let base = toml::to_string(&Config::new_for_testing()).unwrap();
        let legacy =
            format!("{base}\n[backup-s3]\nbucket = 'hashi-backups'\nregion = 'us-west-2'\n");
        assert!(toml::from_str::<Config>(&legacy).is_err());
    }

    #[test]
    fn backup_remote_destination_is_bucket_only() {
        for destination in ["s3://bucket", "s3://bucket/"] {
            let remote = BackupRemoteConfig::new(destination, Some("us-west-2".into())).unwrap();
            assert_eq!(remote.bucket(), "bucket");
            let serialized = toml::to_string(&remote).unwrap();
            let fields: toml::Table = toml::from_str(&serialized).unwrap();
            assert_eq!(fields["destination"].as_str(), Some("s3://bucket/"));
            let decoded: BackupRemoteConfig = toml::from_str(&serialized).unwrap();
            assert_eq!(decoded.bucket(), remote.bucket());
            let BackupRemoteConfig::S3(s3) = decoded else {
                panic!("expected S3 config");
            };
            assert_eq!(s3.region(), "us-west-2");
        }
        for destination in ["s3://bucket/prefix", "s3://bucket//"] {
            assert!(
                BackupRemoteConfig::new(destination, Some("us-west-2".into())).is_err(),
                "{destination}"
            );
        }
        assert!(S3BackupConfig::new("bucket/key".into(), "us-west-2".into()).is_err());
        assert!(S3BackupConfig::new("bucket".into(), " \t".into()).is_err());
    }

    #[test]
    fn gcs_backup_remote_roundtrips_without_region() {
        for destination in ["gs://backup_bucket.example", "gs://backup_bucket.example/"] {
            let remote = BackupRemoteConfig::new(destination, None).unwrap();
            assert_eq!(remote.scheme(), "gs");
            assert_eq!(remote.bucket(), "backup_bucket.example");
            let serialized = toml::to_string(&remote).unwrap();
            let fields: toml::Table = toml::from_str(&serialized).unwrap();
            assert_eq!(
                fields["destination"].as_str(),
                Some("gs://backup_bucket.example/")
            );
            assert!(!fields.contains_key("region"));
            let decoded: BackupRemoteConfig = toml::from_str(&serialized).unwrap();
            assert!(matches!(decoded, BackupRemoteConfig::Gcs(_)));
            assert_eq!(decoded.bucket(), remote.bucket());
        }
        assert!(GcsBackupConfig::new("bucket/key".into()).is_err());
    }

    #[test]
    fn gcs_backup_remote_rejects_any_region() {
        for region in ["", "us-west-2"] {
            let settings = format!("destination = 'gs://bucket/'\nregion = '{region}'");
            assert!(toml::from_str::<BackupRemoteConfig>(&settings).is_err());
        }
    }

    #[test]
    fn backup_location_preserves_paths_and_literal_keys() {
        for local in [
            "backup.tar",
            "/tmp/archive://backup.tar",
            "./gs://backup.tar",
            "1s3://backup.tar",
        ] {
            let path = Path::new(local);
            assert!(
                matches!(BackupLocation::parse(path).unwrap(), BackupLocation::Local(source) if source == path)
            );
        }
        for key in [
            "",
            "backup.tar.asc",
            "nested//./../backup.tar.asc",
            "/backup.tar.asc",
            "nested/a%2Fb%3Fc%23d%20e.tar.asc",
            "nested/backup with spaces.tar.asc",
        ] {
            for (scheme, provider) in [("s3", BackupProvider::S3), ("gs", BackupProvider::Gcs)] {
                let uri = format!("{scheme}://backup-bucket.example/{key}");
                let BackupLocation::Remote(location) =
                    BackupLocation::parse(Path::new(&uri)).unwrap()
                else {
                    panic!("expected remote location");
                };
                assert_eq!(location.provider(), provider);
                assert_eq!(location.key(), key);
            }
        }
    }

    #[test]
    fn backup_location_rejects_invalid_uris() {
        for uri in [
            "https://bucket",
            "gcs://bucket",
            "gs://",
            "gs://user@bucket",
            "gs://bucket:443",
            "gs://bucket?query",
            "gs://bucket#fragment",
            "gs://bucket/key?generation=1",
            "gs://bucket/key#fragment",
            "gs://bucket/key\n",
            "s3://",
            "s3://user@bucket",
            "s3://bucket:443",
            "s3://buck et",
            "s3://buck%65t",
            "s3://buck\\et",
            "s3://bucket?query",
            "s3://bucket#fragment",
            "s3://bucket/backup.tar.asc?versionId=x",
            "s3://bucket/backup.tar.asc#fragment",
            "s3://bucket/backup\n.tar.asc",
            "s3://bucket/backup\0.tar.asc",
        ] {
            assert!(BackupLocation::parse(Path::new(uri)).is_err(), "{uri:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn backup_location_preserves_non_utf8_local_paths() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/\xff/backup.tar"));
        assert!(matches!(
            BackupLocation::parse(path).unwrap(),
            BackupLocation::Local(source) if source.as_os_str().as_bytes() == path.as_os_str().as_bytes()
        ));
    }

    #[test]
    fn test_new_for_testing() {
        let config = Config::new_for_testing();
        let localhost = std::net::Ipv4Addr::new(127, 0, 0, 1);

        // Test addresses use localhost
        assert_eq!(config.listen_address().ip(), localhost);
        assert_eq!(config.metrics_http_address().ip(), localhost);

        // Test ports are different
        let listen_port = config.listen_address().port();
        let metrics_port = config.metrics_http_address().port();
        assert_ne!(listen_port, metrics_port);

        // Test endpoint_url is derived from listen_address
        let endpoint_url = config.endpoint_url().unwrap();
        assert_eq!(endpoint_url, format!("https://127.0.0.1:{listen_port}"));

        // Test TLS key is generated and valid PEM format
        assert!(config.tls_private_key.is_some());
        let tls_key = config.tls_private_key.as_ref().unwrap();
        assert!(tls_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(tls_key.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn backup_pgp_cert_accepts_file_path() {
        let dir = tempfile::Builder::new().tempdir().unwrap();
        let cert_path = dir.path().join("backup-cert.asc");
        let config_path = dir.path().join("config.toml");
        let (public_cert, _) = hashi_types::pgp::test_utils::mock_pgp_keypair();
        std::fs::write(&cert_path, &public_cert).unwrap();

        let mut config = toml::Table::new();
        config.insert(
            "backup-pgp-cert".to_string(),
            toml::Value::String(cert_path.to_string_lossy().into_owned()),
        );
        config.insert(
            "backup-dir".to_string(),
            toml::Value::String(dir.path().join("backups").to_string_lossy().into_owned()),
        );
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();

        let config = Config::load(&config_path).unwrap();
        assert_eq!(config.backup_pgp_cert.armored(), public_cert.as_str());
    }

    #[test]
    fn withdrawal_fee_conf_target_is_bounded_at_load() {
        let dir = tempfile::Builder::new().tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let (public_cert, _) = hashi_types::pgp::test_utils::mock_pgp_keypair();
        let load = |target: i64| {
            let mut config = toml::Table::new();
            config.insert(
                "backup-pgp-cert".to_string(),
                toml::Value::String(public_cert.clone()),
            );
            config.insert(
                "backup-dir".to_string(),
                toml::Value::String(dir.path().join("backups").to_string_lossy().into_owned()),
            );
            config.insert(
                "withdrawal-fee-conf-target".to_string(),
                toml::Value::Integer(target),
            );
            std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
            Config::load(&config_path)
        };

        assert_eq!(load(12).unwrap().withdrawal_fee_conf_target(), 12);
        for target in [0, 13, 100] {
            let error = load(target).unwrap_err().to_string();
            assert!(error.contains("withdrawal_fee_conf_target"), "{error}");
        }
    }

    #[test]
    fn rejects_unknown_root_field() {
        let error = toml::from_str::<Config>("databse = '/var/lib/hashi/db'")
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `databse`"), "{error}");
    }

    #[test]
    fn rejects_root_field_nested_under_hashi_ids() {
        let address = Address::ZERO;
        let config = format!(
            "[hashi-ids]\npackage-id = '{address}'\nhashi-object-id = '{address}'\ndb = '/var/lib/hashi/db'\n"
        );

        let error = toml::from_str::<Config>(&config).unwrap_err().to_string();
        assert!(error.contains("unknown field `db`"), "{error}");
        assert!(
            error.contains("expected `package-id` or `hashi-object-id`"),
            "{error}"
        );
    }

    #[test]
    fn test_get_available_port_unique_ports() {
        let port1 = get_available_port();
        let port2 = get_available_port();
        assert_ne!(port1, port2, "Should return different ports");
    }

    #[test]
    fn test_withdrawal_max_batch_size_defaults_to_absolute_cap() {
        let config = Config::new_for_testing();
        // The config clamp is the v2 cap; the leader additionally applies
        // the version-aware cap at batch-build time, so a v1-active chain
        // still gets the legacy 298.
        assert_eq!(config.withdrawal_max_batch_size(), 447);
    }

    #[test]
    fn bitcoin_start_height_defaults_per_network() {
        // Unset on Signet uses the Signet deployment anchor, not the 800k default.
        let mut signet = Config::new_for_testing();
        signet.bitcoin_chain_id = Some(crate::constants::BITCOIN_SIGNET_CHAIN_ID.to_string());
        signet.bitcoin_start_height = None;
        assert_eq!(signet.bitcoin_start_height(), 300_000);

        // Unset on Mainnet keeps the existing default.
        let mut mainnet = Config::new_for_testing();
        mainnet.bitcoin_chain_id = Some(crate::constants::BITCOIN_MAINNET_CHAIN_ID.to_string());
        mainnet.bitcoin_start_height = None;
        assert_eq!(mainnet.bitcoin_start_height(), 800_000);

        // An explicit value always wins.
        let mut overridden = Config::new_for_testing();
        overridden.bitcoin_chain_id = Some(crate::constants::BITCOIN_SIGNET_CHAIN_ID.to_string());
        overridden.bitcoin_start_height = Some(123_456);
        assert_eq!(overridden.bitcoin_start_height(), 123_456);
    }

    #[test]
    fn test_withdrawal_max_batch_size_clamps_to_absolute_cap() {
        let mut config = Config::new_for_testing();
        config.withdrawal_max_batch_size = Some(1_000);
        assert_eq!(config.withdrawal_max_batch_size(), 447);
    }

    #[test]
    fn test_withdrawal_max_batch_size_accepts_values_below_the_cap() {
        let mut config = Config::new_for_testing();
        config.withdrawal_max_batch_size = Some(70);
        assert_eq!(config.withdrawal_max_batch_size(), 70);
    }

    #[test]
    fn test_complaint_response_policy_defaults_to_deny_all() {
        let config = Config::new_for_testing();
        assert_eq!(
            config.complaint_response_policy(),
            &ComplaintResponsePolicy::AllowList { dealers: vec![] }
        );
        assert!(
            !config
                .complaint_response_policy()
                .allows(1, &Address::new([1; 32]))
        );
    }

    #[test]
    fn test_complaint_response_policy_allows() {
        let dealer = Address::new([1; 32]);
        let other = Address::new([2; 32]);
        assert!(ComplaintResponsePolicy::AllowAll.allows(7, &dealer));

        let list = ComplaintResponsePolicy::AllowList {
            dealers: vec![AllowedDealer { epoch: 7, dealer }],
        };
        assert!(list.allows(7, &dealer));
        assert!(!list.allows(8, &dealer));
        assert!(!list.allows(7, &other));
    }

    #[test]
    fn test_complaint_response_policy_toml() {
        let dealer = Address::new([1; 32]);
        let parse = |toml: &str| -> ComplaintResponsePolicy {
            #[derive(serde_derive::Deserialize)]
            #[serde(rename_all = "kebab-case")]
            struct Wrapper {
                complaint_response_policy: ComplaintResponsePolicy,
            }
            toml::from_str::<Wrapper>(toml)
                .unwrap()
                .complaint_response_policy
        };
        assert_eq!(
            parse(r#"complaint-response-policy = "allow-all""#),
            ComplaintResponsePolicy::AllowAll
        );
        assert_eq!(
            parse(&format!(
                "[complaint-response-policy.allow-list]\n\
                 dealers = [{{ epoch = 7, dealer = \"{dealer}\" }}]\n"
            )),
            ComplaintResponsePolicy::AllowList {
                dealers: vec![AllowedDealer { epoch: 7, dealer }],
            }
        );
    }
}
