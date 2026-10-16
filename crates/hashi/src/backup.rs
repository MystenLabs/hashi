// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Core backup logic for creating encrypted backup archives and restoring backup archives.
//!
//! This module handles the mechanics of building backup manifests, encrypting
//! files into OpenPGP-wrapped, compressed tar archives, and extracting encrypted or
//! unencrypted tar archives. CLI-specific orchestration (config loading, DB-open locking policy, and user output)
//! lives in [`crate::cli::commands::backup`].

mod recovery;

use anyhow::Context;
use anyhow::Result;
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use fastcrypto::hash::HashFunction;
use fastcrypto::hash::Sha256;
use fjall::KeyspaceCreateOptions;
use fjall::Readable;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::armored_encrypt_writer;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use sui_futures::service::Service;
use tokio::sync::mpsc;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::Hashi;
use crate::backup_s3::BackupS3Client;
use crate::db::Database;

pub use recovery::MpcRecoveryRecord;
pub use recovery::MpcRecoveryRecordV1;
pub use recovery::RecoveredMpcKey;
pub use recovery::RecoveredMpcKeyV1;
pub use recovery::read_mpc_recovery_record;
pub use recovery::reconstruct_root_scalar;

pub const BACKUP_FILE_NAME_PREFIX: &str = "hashi-backup";
pub const BACKUP_MANIFEST_FILE_NAME: &str = "hashi-backup-manifest.toml";
pub const DB_SNAPSHOT_TAR_PREFIX: &str = "hashi-db-snapshot";

const BACKUP_FILE_NAME_SUFFIX_FORMAT: &str = "-%Y%m%dT%H%M%SZ.tar.asc";
const BACKUP_STAGING_FILE_NAME_PREFIX: &str = ".hashi-backup-";
pub(crate) const RESTORE_STAGING_DIR_NAME_PREFIX: &str = ".hashi-restore-";
/// How old an archive may get while a newer one exists.
const BACKUP_RETENTION: jiff::SignedDuration = jiff::SignedDuration::from_hours(14 * 24);
/// How old the newest archive may get before it is deleted too.
const LAST_ARCHIVE_RETENTION: jiff::SignedDuration = jiff::SignedDuration::from_hours(30 * 24);
/// Check daily, but publish a new same-epoch recovery archive only every three days.
const MPC_RECOVERY_CHECK_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);
const MPC_RECOVERY_FRESHNESS: jiff::SignedDuration = jiff::SignedDuration::from_hours(3 * 24);
const _: () = assert!(
    LAST_ARCHIVE_RETENTION.as_secs() > BACKUP_RETENTION.as_secs(),
    "LAST_ARCHIVE_RETENTION must exceed BACKUP_RETENTION, or the newest archive would expire \
     while older ones outlive it"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupArchiveFormat {
    Encrypted,
    Unencrypted,
}

pub enum BackupAction {
    CleanupOnly,
    SaveNodeState,
    SaveWithRecovery(Box<MpcRecoveryRecord>),
}

impl BackupAction {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::CleanupOnly => "cleanup_only",
            Self::SaveNodeState => "save_node_state",
            Self::SaveWithRecovery(_) => "save_with_recovery",
        }
    }
}

enum BackupMaintenanceRequest {
    EpochChange { epoch: u64, action: BackupAction },
    RefreshRecovery,
}

#[derive(Clone, Debug)]
pub struct BackupHandle {
    sender: mpsc::UnboundedSender<BackupMaintenanceRequest>,
}

impl BackupHandle {
    pub fn maintain_backups_after_epoch_change(&self, epoch: u64, action: BackupAction) {
        let kind = action.kind();
        if self
            .sender
            .send(BackupMaintenanceRequest::EpochChange { epoch, action })
            .is_err()
        {
            warn!(
                epoch,
                action = kind,
                "Skipping epoch backup maintenance: backup service is stopped"
            );
        }
    }

    pub(crate) fn refresh_mpc_recovery_for_test(&self) {
        self.sender
            .send(BackupMaintenanceRequest::RefreshRecovery)
            .expect("backup service is stopped");
    }
}

pub struct BackupService {
    inner: Arc<Hashi>,
    receiver: mpsc::UnboundedReceiver<BackupMaintenanceRequest>,
    s3_client: Option<BackupS3Client>,
    recovery: Option<Box<MpcRecoveryRecord>>,
}

impl BackupService {
    pub fn new(hashi: Arc<Hashi>) -> (Self, BackupHandle) {
        hashi.metrics.record_backup_s3_config(&hashi.config);
        let (sender, receiver) = mpsc::unbounded_channel();
        let service = Self {
            inner: hashi,
            receiver,
            s3_client: None,
            recovery: None,
        };
        let handle = BackupHandle { sender };
        (service, handle)
    }

    pub fn start(self) -> Service {
        Service::new().spawn_aborting(async move {
            self.run().await;
            Ok(())
        })
    }

    async fn run(mut self) {
        let mut refresh = tokio::time::interval(MPC_RECOVERY_CHECK_INTERVAL);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let Some(request) = self.next_request(&mut refresh).await else {
                break;
            };
            let (epoch, action) = match request {
                BackupMaintenanceRequest::EpochChange { epoch, action } => (epoch, action),
                BackupMaintenanceRequest::RefreshRecovery => {
                    let Some(recovery) = self.recovery.take() else {
                        continue;
                    };
                    match self.recovery_status(&recovery) {
                        RecoveryRefreshStatus::Active => {}
                        RecoveryRefreshStatus::AwaitingMirror => {
                            self.recovery = Some(recovery);
                            continue;
                        }
                        RecoveryRefreshStatus::Obsolete => continue,
                    }
                    let MpcRecoveryRecord::V1(record) = recovery.as_ref();
                    (record.epoch, BackupAction::SaveWithRecovery(recovery))
                }
            };
            if self.recovery.as_ref().is_some_and(|record| {
                self.recovery_status(record) == RecoveryRefreshStatus::Obsolete
            }) {
                self.recovery = None;
            }
            let kind = action.kind();
            if let Err(e) = self.process_epoch_change(epoch, action).await {
                error!(
                    epoch,
                    action = kind,
                    "Epoch backup maintenance failed: {e:#}"
                );
            }
        }
        info!("Backup service stopped");
    }

    async fn next_request(
        &mut self,
        refresh: &mut tokio::time::Interval,
    ) -> Option<BackupMaintenanceRequest> {
        tokio::select! {
            request = self.receiver.recv() => request,
            _ = refresh.tick() => Some(BackupMaintenanceRequest::RefreshRecovery),
        }
    }

    fn recovery_status(&self, recovery: &MpcRecoveryRecord) -> RecoveryRefreshStatus {
        let Some(onchain_state) = self.inner.onchain_state_opt() else {
            return RecoveryRefreshStatus::Obsolete;
        };
        let state = onchain_state.state();
        recovery_refresh_status(recovery, &state.hashi().committees)
    }

    async fn process_epoch_change(&mut self, epoch: u64, action: BackupAction) -> Result<()> {
        let hashi = self.inner.clone();
        let with_recovery = matches!(&action, BackupAction::SaveWithRecovery(_));
        if let BackupAction::SaveWithRecovery(record) = &action {
            record.validate()?;
        }
        let (archive, action) = tokio::task::spawn_blocking(move || {
            let archive = hashi.maintain_backups_after_epoch_change(epoch, &action);
            (archive, action)
        })
        .await
        .context("Epoch backup maintenance failed to join")?;
        if let BackupAction::SaveWithRecovery(record) = action
            && self.recovery_status(&record) != RecoveryRefreshStatus::Obsolete
            && self.recovery.as_ref().is_none_or(|cached| {
                let MpcRecoveryRecord::V1(cached) = cached.as_ref();
                let MpcRecoveryRecord::V1(incoming) = record.as_ref();
                incoming.epoch >= cached.epoch
            })
        {
            // Keep validated material even when local creation or upload fails.
            // The next daily check uses this same serialized maintenance path.
            self.recovery = Some(record);
        }
        let archive = archive?;
        if let Some(archive) = archive {
            match upload(&self.inner.config, &mut self.s3_client, &archive).await {
                Ok(Some((uri, _receipt))) => {
                    self.inner.metrics.backup_scheduled_remote_successes.inc();
                    info!(epoch, %uri, "Scheduled remote backup completed");
                }
                Ok(None) => {}
                Err(error) if with_recovery && is_precondition_failed(&error) => {
                    info!(
                        epoch,
                        path = %archive.display(),
                        "Scheduled remote backup already exists; remote contents not verified"
                    );
                }
                Err(error) => {
                    self.inner.metrics.backup_scheduled_remote_failures.inc();
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryRefreshStatus {
    Active,
    AwaitingMirror,
    Obsolete,
}

fn recovery_refresh_status(
    recovery: &MpcRecoveryRecord,
    committees: &crate::onchain::types::CommitteeSet,
) -> RecoveryRefreshStatus {
    let MpcRecoveryRecord::V1(record) = recovery;
    // SaveWithRecovery is only produced for reconstructed or confirmed epochs.
    // A successful end_reconfig transaction can precede our mirror update:
    // retain that confirmed material, but do not periodically archive it yet.
    if record.epoch > committees.epoch() && !record.key_shares.shares.is_empty() {
        RecoveryRefreshStatus::AwaitingMirror
    } else if recovery_matches_committee(recovery, committees) {
        RecoveryRefreshStatus::Active
    } else {
        RecoveryRefreshStatus::Obsolete
    }
}

fn recovery_matches_committee(
    recovery: &MpcRecoveryRecord,
    committees: &crate::onchain::types::CommitteeSet,
) -> bool {
    let MpcRecoveryRecord::V1(record) = recovery;
    record.epoch == committees.epoch()
        && !record.key_shares.shares.is_empty()
        && committees
            .current_committee()
            .is_some_and(|committee| committee.index_of(&record.validator_address).is_some())
}

fn is_precondition_failed(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<
            aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::put_object::PutObjectError>,
        >()
        .and_then(|error| error.raw_response())
        .is_some_and(|response| response.status().as_u16() == 412)
}

/// Upload a published local archive if S3 is configured. Initialization failures
/// leave the client empty so the next scheduled backup can try initialization again.
pub(crate) async fn upload(
    config: &crate::config::Config,
    client: &mut Option<BackupS3Client>,
    archive: &Path,
) -> Result<Option<(String, PutObjectOutput)>> {
    let Some(s3) = &config.backup_s3 else {
        return Ok(None);
    };
    let namespace = config.backup_s3_namespace().expect("S3 is configured");
    let filename = archive
        .file_name()
        .and_then(|name| name.to_str())
        .context("backup archive must have a UTF-8 filename")?;
    let key = format!("{namespace}{filename}");
    let uri = format!("s3://{}/{key}", s3.bucket);
    let receipt = async {
        if client.is_none() {
            *client = Some(BackupS3Client::connect(&s3.region).await?);
        }
        client
            .as_ref()
            .expect("S3 client initialized")
            .upload(&s3.bucket, &key, archive)
            .await
    }
    .await
    .with_context(|| {
        format!(
            "failed to upload backup to {uri}; local archive retained at {}",
            archive.display()
        )
    })?;
    info!(
        %uri,
        version_id = receipt.version_id(),
        e_tag = receipt.e_tag(),
        "Remote backup uploaded"
    );
    Ok(Some((uri, receipt)))
}

/// Open `path` for writing with mode `0o600`, failing if anything already
/// exists there. The `AlreadyExists` case is mapped to a clear "refusing to
/// overwrite" error so callers don't have to repeat the same pattern.
fn create_file_strict(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| match e.kind() {
            ErrorKind::AlreadyExists => {
                anyhow::anyhow!("Refusing to overwrite existing file: {}", path.display())
            }
            _ => anyhow::Error::from(e).context(format!("Failed to create {}", path.display())),
        })
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct BackupManifest {
    pub paths: Vec<BackupManifestEntry>,
    pub db: DbManifestEntry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<PathBuf>,
}

pub const MPC_RECOVERY_FILE_NAME: &str = "hashi-mpc-recovery.bcs";

fn validate_recovery_manifest(manifest: &BackupManifest) -> Result<()> {
    if let Some(path) = &manifest.recovery {
        anyhow::ensure!(
            path.as_os_str() == std::ffi::OsStr::new(MPC_RECOVERY_FILE_NAME),
            "Recovery entry must be at the fixed tar root path"
        );
    }
    for path in manifest
        .paths
        .iter()
        .map(|entry| &entry.archive_name)
        .chain(manifest.db.archive_entries.iter())
    {
        anyhow::ensure!(
            path.file_name().is_none_or(
                |name| name != MPC_RECOVERY_FILE_NAME && name != BACKUP_MANIFEST_FILE_NAME
            ),
            "Reserved backup entry cannot be declared as a config or database entry"
        );
    }
    Ok(())
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct DbManifestEntry {
    pub original_path: PathBuf,
    pub archive_entries: Vec<PathBuf>,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct BackupManifestEntry {
    pub archive_name: PathBuf,
    pub original_path: PathBuf,
}

pub fn build_backup_manifest(files: &[PathBuf], db_original_path: &Path) -> Result<BackupManifest> {
    let db_archive_entries = backup_keyspace_archive_entries(Path::new(DB_SNAPSHOT_TAR_PREFIX));
    // Reserve the db snapshot directory prefix and every keyspace archive
    // basename so a user file with one of those names gets disambiguated
    // instead of silently colliding with a backed-up database entry.
    let mut archive_names = HashSet::new();
    archive_names.insert(DB_SNAPSHOT_TAR_PREFIX.to_string());
    archive_names.insert(BACKUP_MANIFEST_FILE_NAME.to_string());
    archive_names.insert(MPC_RECOVERY_FILE_NAME.to_string());
    for entry in &db_archive_entries {
        let name = entry.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            anyhow::anyhow!(
                "Database backup entry does not have a valid file name: {}",
                entry.display()
            )
        })?;
        archive_names.insert(name.to_string());
    }
    let mut manifest_paths = Vec::new();

    for file in files {
        let base_name = file
            .file_name()
            .ok_or_else(|| {
                anyhow::anyhow!("Backup input does not have a file name: {}", file.display())
            })?
            .to_string_lossy();

        let archive_name = if archive_names.contains(base_name.as_ref()) {
            let stem = Path::new(base_name.as_ref())
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy();
            let ext = Path::new(base_name.as_ref())
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy()))
                .unwrap_or_default();

            let mut suffix = 2u32;
            loop {
                let candidate = format!("{stem}-{suffix}{ext}");
                if archive_names.insert(candidate.clone()) {
                    info!(
                        original = %file.display(),
                        renamed = %candidate,
                        "Archive name collision for {base_name}",
                    );
                    break PathBuf::from(candidate);
                }
                suffix += 1;
            }
        } else {
            archive_names.insert(base_name.to_string());
            PathBuf::from(base_name.as_ref())
        };

        manifest_paths.push(BackupManifestEntry {
            archive_name,
            original_path: file.clone(),
        });
    }

    Ok(BackupManifest {
        paths: manifest_paths,
        recovery: None,
        db: DbManifestEntry {
            original_path: db_original_path.to_path_buf(),
            archive_entries: db_archive_entries,
        },
    })
}

pub fn encrypt_files_to_pgp_archive(
    manifest: &BackupManifest,
    db: &Database,
    recipient: &PgpPublicCert,
    output_path: &Path,
    recovery: Option<&MpcRecoveryRecord>,
) -> Result<()> {
    validate_recovery_manifest(manifest)?;
    anyhow::ensure!(
        manifest.recovery.is_some() == recovery.is_some(),
        "Recovery declaration and payload must both be present or absent"
    );
    if let Some(record) = recovery {
        record.validate()?;
    }
    // Stage beside the destination so retention sees only fully finalized archives.
    let parent = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staging = tempfile::Builder::new()
        .prefix(BACKUP_STAGING_FILE_NAME_PREFIX)
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "Failed to create backup staging file in {}",
                parent.display()
            )
        })?;
    let mut encrypted = armored_encrypt_writer(staging.as_file_mut(), recipient)?;
    {
        let mut archive = tar::Builder::new(&mut encrypted);
        append_backup_manifest(&mut archive, manifest)?;
        if let Some(record) = recovery {
            let bytes = bcs::to_bytes(record).context("Failed to serialize MPC recovery record")?;
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o600);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive.append_data(&mut header, MPC_RECOVERY_FILE_NAME, bytes.as_slice())?;
        }

        for entry in &manifest.paths {
            archive.append_path_with_name(&entry.original_path, &entry.archive_name)?;
            info!(
                original = %entry.original_path.display(),
                archive_name = %entry.archive_name.display(),
                "Added file to backup archive",
            );
        }

        append_db_backup_to_tar(db, &mut archive, &manifest.db.archive_entries)?;
        info!("Added database backup to backup archive");

        archive.finish()?;
    }
    encrypted.finalize()?;
    staging
        .as_file()
        .sync_all()
        .context("Failed to sync backup staging file")?;
    staging
        .persist_noclobber(output_path)
        // Drop the temporary file even if the caller retains the error.
        .map_err(|e| e.error)
        .with_context(|| format!("Failed to publish backup {}", output_path.display()))?;
    if let Err(error) = File::open(parent).and_then(|directory| directory.sync_all()) {
        error!(
            directory = %parent.display(),
            "Backup published, but syncing its directory failed: {error}"
        );
    }

    Ok(())
}

pub fn save(
    node_config_path: &Path,
    node_config: &crate::config::Config,
    db: &Database,
    recipient: &PgpPublicCert,
    output_dir: &Path,
    epoch: Option<u64>,
    recovery: Option<&MpcRecoveryRecord>,
) -> Result<PathBuf> {
    let files = backup_file_paths(node_config_path, node_config)?;

    for file in &files {
        if !file.exists() {
            anyhow::bail!("Backup input does not exist: {}", file.display());
        }
    }

    let db_path = node_config.db.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Node config at {} does not specify a database path",
            node_config_path.display()
        )
    })?;

    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory {}", output_dir.display()))?;

    let mut manifest = build_backup_manifest(&files, db_path)?;
    manifest.recovery = recovery.map(|_| PathBuf::from(MPC_RECOVERY_FILE_NAME));

    info!(
        file_count = files.len(),
        %recipient,
        "Backing up files + database",
    );

    let kind = match recovery {
        Some(MpcRecoveryRecord::V1(record)) => BackupKind::Mpc(record.epoch),
        None => epoch.map_or(BackupKind::Manual, BackupKind::Node),
    };
    let output_path = output_dir.join(encrypted_backup_file_name(kind, recipient));
    encrypt_files_to_pgp_archive(&manifest, db, recipient, &output_path, recovery)?;

    Ok(output_path)
}

/// All file paths which must be backed up to enable full node recovery
/// (other than the db, which is backed up separately).
fn backup_file_paths(
    node_config_path: &Path,
    node_config: &crate::config::Config,
) -> Result<Vec<PathBuf>> {
    let mut paths = vec![node_config_path.to_path_buf()];
    paths.extend(node_config_referenced_files(node_config)?);
    Ok(paths)
}

/// Return the set of external files referenced by path-style node config
/// fields.
///
/// Both `tls_private_key` and `operator_private_key` are `Option<String>`
/// holding either a file path or inline key material (in any format
/// `crate::keys` accepts). The backup either includes the referenced file
/// or, when the value is inline, relies on the node config file itself to
/// capture the key material. A path-shaped value that doesn't resolve to a
/// file is an error: it would mean the node config points at a missing key,
/// and silently skipping it would produce a backup that can't actually
/// restore the node.
fn node_config_referenced_files(node_config: &crate::config::Config) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();

    for (field_name, raw) in [
        ("tls_private_key", node_config.tls_private_key.as_deref()),
        (
            "operator_private_key",
            node_config.operator_private_key.as_deref(),
        ),
    ] {
        let Some(raw) = raw else { continue };

        let referenced = crate::keys::referenced_key_file(raw).with_context(|| {
            format!(
                "node config field `{field_name}` cannot be backed up; fix the value or remove \
                 it before running backup"
            )
        })?;
        if let Some(path) = referenced {
            paths.push(path.to_path_buf());
        }
    }

    Ok(paths)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackupKind {
    Manual,
    Node(u64),
    Mpc(u64),
}

fn backup_recipient_hash(recipient: &PgpPublicCert) -> String {
    hex::encode(Sha256::digest(recipient.armored().as_bytes()).digest)
}

fn encrypted_backup_file_name(kind: BackupKind, recipient: &PgpPublicCert) -> PathBuf {
    // ISO 8601 basic format in UTC, e.g. 20260409T230419Z. Compact, sorts
    // lexicographically, and contains no characters that need escaping on any
    // common filesystem.
    let now = jiff::Timestamp::now().to_zoned(jiff::tz::TimeZone::UTC);
    let timestamp = now.strftime(BACKUP_FILE_NAME_SUFFIX_FORMAT);
    match kind {
        BackupKind::Manual => format!("{BACKUP_FILE_NAME_PREFIX}{timestamp}"),
        BackupKind::Node(epoch) => format!("{BACKUP_FILE_NAME_PREFIX}-epoch-{epoch}{timestamp}"),
        BackupKind::Mpc(epoch) => {
            let hash = backup_recipient_hash(recipient);
            format!("{BACKUP_FILE_NAME_PREFIX}-epoch-{epoch}-mpc-{hash}{timestamp}")
        }
    }
    .into()
}

fn parse_backup_file_name(name: &str) -> Option<(BackupKind, Option<&str>, jiff::Timestamp)> {
    let suffix = name.strip_prefix(BACKUP_FILE_NAME_PREFIX)?;
    let (kind, hash, suffix) = if let Some(rest) = suffix.strip_prefix("-epoch-") {
        let (epoch, rest) = rest.split_once('-')?;
        if epoch.is_empty()
            || !epoch.bytes().all(|byte| byte.is_ascii_digit())
            || (epoch.len() > 1 && epoch.starts_with('0'))
        {
            return None;
        }
        let epoch = epoch.parse().ok()?;
        match rest.strip_prefix("mpc-") {
            Some(rest) => {
                let (hash, timestamp) = match rest.split_once('-') {
                    Some((hash, timestamp)) => {
                        if hash.len() != 64
                            || !hash
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                        {
                            return None;
                        }
                        (Some(hash), timestamp)
                    }
                    None => (None, rest),
                };
                (BackupKind::Mpc(epoch), hash, timestamp)
            }
            None => (BackupKind::Node(epoch), None, rest),
        }
    } else {
        (BackupKind::Manual, None, suffix.strip_prefix('-')?)
    };
    let timestamp = suffix.strip_suffix(".tar.asc")?;
    if timestamp.len() != 16
        || timestamp.as_bytes()[8] != b'T'
        || timestamp.as_bytes()[15] != b'Z'
        || !timestamp
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 8 || index == 15 || byte.is_ascii_digit())
    {
        return None;
    }
    let created_at = jiff::civil::DateTime::strptime("%Y%m%dT%H%M%SZ", timestamp)
        .ok()?
        .to_zoned(jiff::tz::TimeZone::UTC)
        .ok()?
        .timestamp();
    Some((kind, hash, created_at))
}

pub(crate) fn find_mpc_backup(
    output_dir: &Path,
    epoch: u64,
    recipient: &PgpPublicCert,
) -> Result<Option<PathBuf>> {
    find_fresh_mpc_backup(output_dir, epoch, recipient, jiff::Timestamp::now())
}

fn find_fresh_mpc_backup(
    output_dir: &Path,
    epoch: u64,
    recipient: &PgpPublicCert,
    now: jiff::Timestamp,
) -> Result<Option<PathBuf>> {
    let entries = match fs::read_dir(output_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let recipient_hash = backup_recipient_hash(recipient);
    let freshness_cutoff = now.checked_sub(MPC_RECOVERY_FRESHNESS)?;
    let mut newest = None;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some((kind, hash, timestamp)) = name.to_str().and_then(parse_backup_file_name) else {
            continue;
        };
        if kind != BackupKind::Mpc(epoch)
            || hash != Some(recipient_hash.as_str())
            || timestamp > now
            || timestamp <= freshness_cutoff
            || !entry.file_type()?.is_file()
        {
            continue;
        }
        if newest
            .as_ref()
            .is_none_or(|(latest, _)| timestamp > *latest)
        {
            newest = Some((timestamp, entry.path()));
        }
    }
    Ok(newest.map(|(_, path)| path))
}

#[derive(Default)]
pub(crate) struct CleanupStats {
    pub(crate) removed: usize,
    pub(crate) failed: usize,
}

/// Remove expired archives and abandoned staging entries.
pub(crate) fn cleanup_old_backups(
    output_dir: &Path,
    now: jiff::Timestamp,
    save_may_follow: bool,
) -> Result<CleanupStats> {
    let cutoff = now.checked_sub(BACKUP_RETENTION)?;
    let staging_cutoff: std::time::SystemTime = cutoff.into();
    let mut stats = CleanupStats::default();
    let entries = match fs::read_dir(output_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(stats),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Failed to read backup directory {}", output_dir.display())
            });
        }
    };
    let mut newest: Option<(jiff::Timestamp, PathBuf)> = None;
    let mut newest_mpc: Option<(jiff::Timestamp, PathBuf)> = None;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                stats.failed += 1;
                warn!(
                    directory = %output_dir.display(),
                    "Failed to read backup directory entry: {error}"
                );
                continue;
            }
        };
        let file_name = entry.file_name();
        let file_name = file_name.as_encoded_bytes();
        let restore_staging = file_name.starts_with(RESTORE_STAGING_DIR_NAME_PREFIX.as_bytes());
        if restore_staging || file_name.starts_with(BACKUP_STAGING_FILE_NAME_PREFIX.as_bytes()) {
            let path = entry.path();
            // DirEntry::metadata does not follow symlinks.
            let modified = entry.metadata().and_then(|metadata| {
                if (restore_staging && metadata.is_dir())
                    || (!restore_staging && metadata.is_file())
                {
                    metadata.modified().map(Some)
                } else {
                    Ok(None)
                }
            });
            match modified {
                Ok(Some(modified)) if modified < staging_cutoff => {
                    let removed = if restore_staging {
                        fs::remove_dir_all(&path)
                    } else {
                        fs::remove_file(&path)
                    };
                    if let Err(error) = removed {
                        stats.failed += 1;
                        warn!(
                            path = %path.display(),
                            "Failed to remove expired staging entry: {error}"
                        );
                    } else {
                        stats.removed += 1;
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    stats.failed += 1;
                    warn!(
                        path = %path.display(),
                        "Failed to read staging entry metadata: {error}"
                    );
                }
            }
            continue;
        }
        let Some((kind, _, created_at)) = std::str::from_utf8(file_name)
            .ok()
            .and_then(parse_backup_file_name)
        else {
            continue;
        };
        if created_at > now {
            continue;
        }
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                stats.failed += 1;
                warn!(
                    path = %path.display(),
                    "Failed to read backup file type: {error}"
                );
                continue;
            }
        };
        if !file_type.is_file() {
            continue;
        }
        let candidate = (created_at, path);
        let newest = if matches!(kind, BackupKind::Mpc(_)) {
            &mut newest_mpc
        } else {
            &mut newest
        };
        let (created_at, path) = match newest.as_mut() {
            Some(newest) if candidate.0 > newest.0 => std::mem::replace(newest, candidate),
            Some(_) => candidate,
            None => {
                *newest = Some(candidate);
                continue;
            }
        };
        if created_at >= cutoff {
            continue;
        }
        remove_expired_backup(&mut stats, &path);
    }
    // Ordinary archives cannot displace the last MPC archive. Once a newer
    // MPC archive is published, older MPC archives follow normal retention.
    if let Some((created_at, path)) = newest.as_ref()
        && newest_mpc
            .as_ref()
            .is_some_and(|(mpc_created_at, _)| mpc_created_at > created_at)
        && *created_at < cutoff
    {
        remove_expired_backup(&mut stats, path);
        newest = None;
    }
    if let Some((created_at, path)) = newest
        && !save_may_follow
        && created_at < now.checked_sub(LAST_ARCHIVE_RETENTION)?
        && remove_expired_backup(&mut stats, &path)
    {
        warn!(path = %path.display(), "Expired the newest backup archive");
    }
    Ok(stats)
}

fn remove_expired_backup(stats: &mut CleanupStats, path: &Path) -> bool {
    match fs::remove_file(path) {
        Ok(()) => {
            stats.removed += 1;
            true
        }
        Err(error) => {
            stats.failed += 1;
            warn!(
                path = %path.display(),
                "Failed to remove expired backup: {error}"
            );
            false
        }
    }
}

fn append_backup_manifest<W: std::io::Write>(
    archive: &mut tar::Builder<W>,
    manifest: &BackupManifest,
) -> Result<()> {
    let manifest_bytes = toml::to_string_pretty(manifest)?.into_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(
        &mut header,
        BACKUP_MANIFEST_FILE_NAME,
        manifest_bytes.as_slice(),
    )?;
    Ok(())
}

#[derive(serde::Deserialize, serde::Serialize)]
struct DbBackupRecord {
    key: Vec<u8>,
    value: Vec<u8>,
}

fn backup_keyspace_archive_entries(tar_prefix: &Path) -> Vec<PathBuf> {
    Database::backup_keyspace_names()
        .into_iter()
        .map(|name| tar_prefix.join(format!("{name}.bin")))
        .collect()
}

fn backup_keyspace_name_from_file_name(file_name: &str) -> Option<&'static str> {
    let name = file_name.strip_suffix(".bin")?;
    Database::backup_keyspace_names()
        .into_iter()
        .find(|keyspace_name| *keyspace_name == name)
}

fn append_db_backup_to_tar<W: Write>(
    db: &Database,
    archive: &mut tar::Builder<W>,
    archive_entries: &[PathBuf],
) -> Result<()> {
    let snapshot = db.snapshot();
    let keyspaces = db.backup_keyspaces();

    for archive_path in archive_entries {
        validate_db_archive_path(archive_path)?;
        let file_name = archive_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("Database entry has no valid file name"))?;
        let name = backup_keyspace_name_from_file_name(file_name).ok_or_else(|| {
            anyhow::anyhow!(
                "Database entry must be a known keyspace .bin file: {}",
                archive_path.display()
            )
        })?;
        let source_ks = keyspaces
            .iter()
            .find_map(|(keyspace_name, keyspace)| (*keyspace_name == name).then_some(*keyspace))
            .expect("backup_keyspace_name_from_file_name matched a backup keyspace");
        let mut records = Vec::new();
        for guard in snapshot.iter(source_ks) {
            let (key, value) = guard.into_inner()?;
            records.push(DbBackupRecord {
                key: key.to_vec(),
                value: value.to_vec(),
            });
        }
        let bytes = bcs::to_bytes(&records)
            .with_context(|| format!("failed to serialize backup keyspace {name}"))?;
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(&mut header, archive_path, bytes.as_slice())
            .with_context(|| {
                format!(
                    "failed to append database backup entry {}",
                    archive_path.display()
                )
            })?;
    }

    Ok(())
}

/// Determine the format of a backup tarball from its file name.
///
/// `.tar.asc` backups are OpenPGP-encrypted; `.tar` backups are already plaintext.
pub fn archive_format(backup_tarball: &Path) -> Result<BackupArchiveFormat> {
    let file_name = backup_tarball
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Backup tarball path has no file name: {}",
                backup_tarball.display()
            )
        })?;

    if file_name.ends_with(".tar.asc") {
        Ok(BackupArchiveFormat::Encrypted)
    } else if file_name.ends_with(".tar") {
        Ok(BackupArchiveFormat::Unencrypted)
    } else {
        anyhow::bail!(
            "Backup tarball must have a .tar or .tar.asc suffix: {}",
            backup_tarball.display()
        );
    }
}

/// Determine the directory name to extract a backup tarball into.
///
/// Strips the `.tar.asc` or `.tar` suffix from the tarball's file name, so
/// `<backup-prefix>-20260409T230419Z.tar.asc` and
/// `<backup-prefix>-20260409T230419Z.tar` both become
/// `<backup-prefix>-20260409T230419Z`. An input without one of those
/// suffixes is rejected rather than silently used verbatim, to avoid
/// surprising extraction directory names when users point at the wrong file.
pub fn extract_dir_name(backup_tarball: &Path) -> Result<PathBuf> {
    let file_name = backup_tarball
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Backup tarball path has no file name: {}",
                backup_tarball.display()
            )
        })?;

    let stem = if let Some(stem) = file_name.strip_suffix(".tar.asc") {
        stem
    } else if let Some(stem) = file_name.strip_suffix(".tar") {
        stem
    } else {
        anyhow::bail!(
            "Backup tarball must have a .tar or .tar.asc suffix: {}",
            backup_tarball.display()
        );
    };

    // Require the stem to be exactly one plain directory component when
    // joined under the user's output dir. Catches both the empty case (zero
    // components) and traversal attempts like `../../tmp/pwn.tar.asc` (a
    // `ParentDir` component, not `Normal`).
    let stem_path = Path::new(stem);
    let mut components = stem_path.components();
    let only = components.next();
    let extra = components.next();
    if extra.is_some() || !matches!(only, Some(Component::Normal(_))) {
        anyhow::bail!(
            "Backup tarball file name must be a single path component without separators or `..`: {}",
            backup_tarball.display()
        );
    }

    Ok(PathBuf::from(stem))
}

pub fn read_backup_manifest<R: Read>(
    mut entry: tar::Entry<'_, R>,
) -> Result<(BackupManifest, String)> {
    let path = entry.path()?.into_owned();
    if path.as_os_str() != std::ffi::OsStr::new(BACKUP_MANIFEST_FILE_NAME)
        || entry.header().entry_type() != tar::EntryType::Regular
    {
        anyhow::bail!(
            "Expected backup manifest {} as the first tar entry, found {}",
            BACKUP_MANIFEST_FILE_NAME,
            path.display()
        );
    }

    let mut manifest_toml = String::new();
    entry.read_to_string(&mut manifest_toml)?;
    let manifest: BackupManifest = toml::from_str(&manifest_toml)?;
    validate_recovery_manifest(&manifest)?;

    Ok((manifest, manifest_toml))
}

pub fn write_manifest_to_extract_dir(extract_dir: &Path, manifest_toml: &str) -> Result<()> {
    let manifest_path = extract_dir.join(BACKUP_MANIFEST_FILE_NAME);
    let mut file = create_file_strict(&manifest_path)?;
    io::Write::write_all(&mut file, manifest_toml.as_bytes())
        .with_context(|| format!("Failed to write manifest to {}", manifest_path.display()))?;
    info!(path = %manifest_path.display(), "Restored manifest");
    Ok(())
}

pub fn restore_backup_entries<R: Read>(
    entries: tar::Entries<'_, R>,
    output_dir: &Path,
    manifest: &BackupManifest,
) -> Result<()> {
    validate_recovery_manifest(manifest)?;
    let mut restored_recovery = false;
    let db_prefix = Path::new(DB_SNAPSHOT_TAR_PREFIX);
    let expected_files: HashSet<PathBuf> = manifest
        .paths
        .iter()
        .map(|entry| entry.archive_name.clone())
        .collect();
    let expected_db_entries: HashSet<PathBuf> =
        manifest.db.archive_entries.iter().cloned().collect();
    let mut restored_db_entries = HashSet::new();
    let mut restored_count: usize = 0;
    let db_path = output_dir.join(DB_SNAPSHOT_TAR_PREFIX);
    let db = fjall::Database::builder(&db_path).open().map_err(|e| {
        anyhow::Error::new(e).context(format!(
            "failed to open destination database at {}",
            db_path.display()
        ))
    })?;

    for entry in entries {
        let mut entry = entry?;
        let archive_path = entry.path()?.into_owned();

        if archive_path
            .file_name()
            .is_some_and(|name| name == MPC_RECOVERY_FILE_NAME)
        {
            anyhow::ensure!(
                archive_path.as_os_str() == std::ffi::OsStr::new(MPC_RECOVERY_FILE_NAME),
                "Recovery entry must be at the fixed tar root path"
            );
            anyhow::ensure!(manifest.recovery.is_some(), "Undeclared recovery entry");
            anyhow::ensure!(!restored_recovery, "Duplicate recovery entry");
            anyhow::ensure!(
                entry.header().entry_type() == tar::EntryType::Regular,
                "Recovery entry must be a regular file"
            );
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let record: MpcRecoveryRecord =
                bcs::from_bytes(&bytes).context("Malformed MPC recovery record")?;
            record.validate().context("Invalid MPC recovery record")?;
            let mut file = create_file_strict(&output_dir.join(MPC_RECOVERY_FILE_NAME))?;
            file.write_all(&bytes)?;
            restored_recovery = true;
        } else if archive_path.starts_with(db_prefix) {
            validate_db_archive_path(&archive_path)?;
            if !expected_db_entries.contains(&archive_path) {
                anyhow::bail!(
                    "Backup archive contains unexpected database entry: {}",
                    archive_path.display()
                );
            }
            if !restored_db_entries.insert(archive_path.clone()) {
                anyhow::bail!(
                    "Backup archive contains duplicate database entry: {}",
                    archive_path.display()
                );
            }
            restore_db_entry(&mut entry, &archive_path, &db)?;
        } else {
            restore_config_entry(&mut entry, &archive_path, output_dir, &expected_files)?;
            restored_count += 1;
        }
    }
    anyhow::ensure!(
        restored_recovery == manifest.recovery.is_some(),
        "Missing recovery entry"
    );

    if restored_count != expected_files.len() {
        anyhow::bail!(
            "Backup archive is missing file entries: expected {}, restored {}",
            expected_files.len(),
            restored_count
        );
    }

    if restored_db_entries != expected_db_entries {
        let mut missing_db_entries: Vec<_> = expected_db_entries
            .difference(&restored_db_entries)
            .cloned()
            .collect();
        missing_db_entries.sort();
        anyhow::bail!(
            "Backup archive is missing database entries: {}",
            missing_db_entries
                .into_iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    db.persist(fjall::PersistMode::SyncAll)?;

    Ok(())
}

fn validate_db_archive_path(archive_path: &Path) -> Result<()> {
    let mut components = archive_path.components();
    if !matches!(components.next(), Some(Component::Normal(prefix)) if prefix == DB_SNAPSHOT_TAR_PREFIX)
    {
        anyhow::bail!(
            "Database entry must live under {}: {}",
            DB_SNAPSHOT_TAR_PREFIX,
            archive_path.display()
        );
    }

    let file_name = match (components.next(), components.next()) {
        (Some(Component::Normal(file_name)), None) => file_name,
        _ => {
            anyhow::bail!(
                "Database entry must be a single keyspace file under {}: {}",
                DB_SNAPSHOT_TAR_PREFIX,
                archive_path.display()
            );
        }
    };

    file_name.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "Database entry file name is not valid UTF-8: {}",
            archive_path.display()
        )
    })?;

    Ok(())
}

fn restore_db_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    archive_path: &Path,
    db: &fjall::Database,
) -> Result<()> {
    let entry_type = entry.header().entry_type();
    if entry_type != tar::EntryType::Regular {
        anyhow::bail!(
            "Database entry {} has unexpected type {entry_type:?}; only regular files are supported",
            archive_path.display(),
        );
    }

    let file_name = archive_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("Database entry has no valid file name"))?;
    let keyspace_name = backup_keyspace_name_from_file_name(file_name).ok_or_else(|| {
        anyhow::anyhow!(
            "Database entry must be a known keyspace .bin file: {}",
            archive_path.display()
        )
    })?;
    restore_db_backup_keyspace(db, keyspace_name, entry).with_context(|| {
        format!(
            "Failed to restore database entry {}",
            archive_path.display()
        )
    })?;
    Ok(())
}

fn restore_db_backup_keyspace<R: Read>(
    db: &fjall::Database,
    keyspace_name: &str,
    mut reader: R,
) -> Result<()> {
    let dest_ks = db.keyspace(keyspace_name, KeyspaceCreateOptions::default)?;
    let mut ingestion = dest_ks.start_ingestion()?;

    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read backup keyspace {keyspace_name}"))?;
    let records: Vec<DbBackupRecord> = bcs::from_bytes(&bytes)
        .with_context(|| format!("failed to deserialize backup keyspace {keyspace_name}"))?;
    for record in records {
        ingestion.write(&record.key, &record.value)?;
    }

    ingestion.finish()?;
    Ok(())
}

/// Extract a single config-file tar entry into `output_dir`. Config entries
/// must be regular files at the tar root and must appear in the manifest;
/// anything else is rejected so a tampered archive can't sneak unexpected
/// files past the restore.
fn restore_config_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    archive_path: &Path,
    output_dir: &Path,
    expected_files: &HashSet<PathBuf>,
) -> Result<()> {
    let archive_name = PathBuf::from(archive_path.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "Backup entry does not have a file name: {}",
            archive_path.display()
        )
    })?);

    let entry_type = entry.header().entry_type();
    if entry_type != tar::EntryType::Regular {
        anyhow::bail!(
            "Backup entry {} has unexpected type {entry_type:?}; only regular files are supported",
            archive_name.display(),
        );
    }

    if archive_path != archive_name {
        anyhow::bail!(
            "Backup entry must be at the tar root: {}",
            archive_path.display()
        );
    }

    if !expected_files.contains(&archive_name) {
        anyhow::bail!(
            "Backup archive contains unexpected file: {}",
            archive_name.display()
        );
    }

    let output_path = output_dir.join(&archive_name);
    let mut output_file = create_file_strict(&output_path)?;
    io::copy(entry, &mut output_file).with_context(|| {
        format!(
            "Failed to write restored file contents to {}",
            output_path.display()
        )
    })?;
    info!(
        archive_name = %archive_name.display(),
        output = %output_path.display(),
        "Restored file",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::pgp::PgpPublicCert;
    use hashi_types::pgp::test_utils;
    use hashi_types::pgp::test_utils::mock_pgp_cert;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use std::io::Cursor;
    use std::process::Command;

    fn temp_gnupg_home() -> tempfile::TempDir {
        let homedir = tempfile::Builder::new().tempdir().unwrap();
        test_utils::prepare_gnupg_home(homedir.path());
        homedir
    }

    fn db_only_manifest() -> BackupManifest {
        BackupManifest {
            paths: Vec::new(),
            recovery: None,
            db: DbManifestEntry {
                original_path: PathBuf::from("/var/lib/hashi/db"),
                archive_entries: backup_keyspace_archive_entries(Path::new(DB_SNAPSHOT_TAR_PREFIX)),
            },
        }
    }

    #[test]
    fn recovery_round_trip_is_encrypted_and_restores_a_private_standalone_file() {
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::tempdir().unwrap();
        let db = Database::open(src.path()).unwrap();
        let out = tempfile::tempdir().unwrap();
        let record = recovery::test_record();
        let expected = bcs::to_bytes(&record).unwrap();
        let mut manifest = db_only_manifest();
        manifest.recovery = Some(PathBuf::from(MPC_RECOVERY_FILE_NAME));
        let (cert, secret_key) = mock_pgp_keypair();
        let recipient = PgpPublicCert::new(cert).unwrap();
        let output_path = out.path().join("recovery.tar.asc");
        encrypt_files_to_pgp_archive(&manifest, &db, &recipient, &output_path, Some(&record))
            .unwrap();
        let encrypted = fs::read(&output_path).unwrap();
        assert!(encrypted.starts_with(b"-----BEGIN PGP MESSAGE-----"));
        assert!(
            !encrypted
                .windows(expected.len())
                .any(|window| window == expected)
        );
        assert_eq!(fs::read_dir(out.path()).unwrap().count(), 1);

        let homedir = temp_gnupg_home();
        test_utils::gpg_import_secret_key(homedir.path(), &secret_key);
        let decrypted = Command::new("gpg")
            .env("GNUPGHOME", homedir.path())
            .arg("--decrypt")
            .arg(&output_path)
            .output()
            .unwrap();
        test_utils::assert_command_success(&decrypted, "gpg --decrypt");
        let mut archive = tar::Archive::new(Cursor::new(decrypted.stdout));
        let mut entries = archive.entries().unwrap();
        let (manifest, _) = read_backup_manifest(entries.next().unwrap().unwrap()).unwrap();
        assert_eq!(
            manifest.recovery.as_deref(),
            Some(Path::new(MPC_RECOVERY_FILE_NAME))
        );
        assert!(manifest.paths.is_empty());
        let restored = tempfile::tempdir().unwrap();
        restore_backup_entries(entries, restored.path(), &manifest).unwrap();
        let recovery_path = restored.path().join(MPC_RECOVERY_FILE_NAME);
        assert_eq!(fs::read(&recovery_path).unwrap(), expected);
        assert_eq!(
            fs::metadata(&recovery_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let reopened = Database::open(&restored.path().join(DB_SNAPSHOT_TAR_PREFIX)).unwrap();
        assert!(reopened.get_encryption_key(7).unwrap().is_none());
    }

    #[test]
    fn recovery_restore_rejects_invalid_archive_entries() {
        let record = bcs::to_bytes(&recovery::test_record()).unwrap();
        for (case, expected_error) in [
            ("undeclared", "Undeclared"),
            ("missing", "Missing"),
            ("duplicate", "Duplicate"),
            ("symlink", "regular file"),
            ("nested", "tar root"),
            ("malformed", "Malformed"),
        ] {
            let mut manifest = db_only_manifest();
            manifest.db.archive_entries.clear();
            manifest.recovery =
                (case != "undeclared").then(|| PathBuf::from(MPC_RECOVERY_FILE_NAME));
            let mut bytes = Vec::new();
            {
                let mut archive = tar::Builder::new(&mut bytes);
                let copies = match case {
                    "missing" => 0,
                    "duplicate" => 2,
                    _ => 1,
                };
                for _ in 0..copies {
                    if case == "symlink" {
                        let mut header = tar::Header::new_gnu();
                        header.set_entry_type(tar::EntryType::Symlink);
                        header.set_mode(0o777);
                        header.set_size(0);
                        header.set_link_name("outside").unwrap();
                        header.set_cksum();
                        archive
                            .append_data(&mut header, MPC_RECOVERY_FILE_NAME, &[][..])
                            .unwrap();
                    } else {
                        let path = if case == "nested" {
                            "nested/hashi-mpc-recovery.bcs"
                        } else {
                            MPC_RECOVERY_FILE_NAME
                        };
                        let payload: &[u8] = if case == "malformed" { &[255] } else { &record };
                        append_regular_file(&mut archive, path, payload);
                    }
                }
                archive.finish().unwrap();
            }
            let dest = tempfile::tempdir().unwrap();
            let mut archive = tar::Archive::new(Cursor::new(bytes));
            let error = restore_backup_entries(archive.entries().unwrap(), dest.path(), &manifest)
                .unwrap_err();
            assert!(
                format!("{error:#}").contains(expected_error),
                "{case}: {error:#}"
            );
            if case != "duplicate" {
                assert!(!dest.path().join(MPC_RECOVERY_FILE_NAME).exists(), "{case}");
            }
        }
    }

    #[test]
    fn recovery_manifest_reserves_internal_names_and_rejects_aliases() {
        let manifest = build_backup_manifest(
            &[
                PathBuf::from(MPC_RECOVERY_FILE_NAME),
                PathBuf::from(BACKUP_MANIFEST_FILE_NAME),
            ],
            Path::new("db"),
        )
        .unwrap();
        assert_eq!(
            manifest.paths[0].archive_name,
            Path::new("hashi-mpc-recovery-2.bcs")
        );
        assert_eq!(
            manifest.paths[1].archive_name,
            Path::new("hashi-backup-manifest-2.toml")
        );
        let mut manifest = db_only_manifest();
        manifest.recovery = Some(PathBuf::from("nested/hashi-mpc-recovery.bcs"));
        assert!(validate_recovery_manifest(&manifest).is_err());
        manifest.recovery = None;
        manifest.paths.push(BackupManifestEntry {
            archive_name: PathBuf::from(MPC_RECOVERY_FILE_NAME),
            original_path: PathBuf::from("config.toml"),
        });
        assert!(validate_recovery_manifest(&manifest).is_err());
        manifest.paths.clear();
        manifest
            .db
            .archive_entries
            .push(PathBuf::from("hashi-db-snapshot/hashi-mpc-recovery.bcs"));
        assert!(validate_recovery_manifest(&manifest).is_err());
    }

    fn append_regular_file<W: std::io::Write>(
        archive: &mut tar::Builder<W>,
        path: &str,
        contents: &[u8],
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o600);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        archive.append_data(&mut header, path, contents).unwrap();
    }

    fn build_archive_bytes(manifest: &BackupManifest, db_files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut tar_bytes);
            append_backup_manifest(&mut archive, manifest).unwrap();
            for (path, contents) in db_files {
                append_regular_file(&mut archive, path, contents);
            }
            archive.finish().unwrap();
        }
        tar_bytes
    }

    #[test]
    fn read_mpc_recovery_record_rejects_missing_and_duplicate_entries() {
        let record = bcs::to_bytes(&recovery::test_record()).unwrap();
        let mut manifest = db_only_manifest();
        manifest.recovery = Some(PathBuf::from(MPC_RECOVERY_FILE_NAME));
        for (entries, expected_error) in [
            (vec![], "Missing recovery entry"),
            (
                vec![
                    (MPC_RECOVERY_FILE_NAME, record.as_slice()),
                    (MPC_RECOVERY_FILE_NAME, record.as_slice()),
                ],
                "Duplicate recovery entry",
            ),
        ] {
            let bytes = build_archive_bytes(&manifest, &entries);
            let error = read_mpc_recovery_record(bytes.as_slice()).err().unwrap();
            assert!(error.to_string().contains(expected_error));
        }
    }

    #[test]
    fn read_mpc_recovery_record_checks_decrypted_reader_eof() {
        struct FailAtEof(Cursor<Vec<u8>>);

        impl Read for FailAtEof {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let count = self.0.read(buf)?;
                if count == 0 && !buf.is_empty() {
                    return Err(io::Error::other("late decryption failure"));
                }
                Ok(count)
            }
        }

        let record = bcs::to_bytes(&recovery::test_record()).unwrap();
        let mut manifest = db_only_manifest();
        manifest.recovery = Some(PathBuf::from(MPC_RECOVERY_FILE_NAME));
        let bytes = build_archive_bytes(
            &manifest,
            &[
                (MPC_RECOVERY_FILE_NAME, record.as_slice()),
                ("ignored/config.toml", b"not extracted"),
            ],
        );
        let recovered = read_mpc_recovery_record(bytes.as_slice()).unwrap();
        assert_eq!(bcs::to_bytes(&recovered).unwrap(), record);
        let error = read_mpc_recovery_record(FailAtEof(Cursor::new(bytes)))
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("late decryption failure"));
    }

    fn backup_service_fixture(
        remote: bool,
        config_path_present: bool,
    ) -> (BackupService, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.toml");
        let mut config = crate::config::Config::new_for_testing();
        config.db = Some(directory.path().join("db"));
        config.backup_dir = directory.path().join("backups");
        config.backup_pgp_cert = mock_pgp_cert();
        if remote {
            config.backup_s3 = Some(crate::config::BackupS3Config {
                bucket: "backup-bucket".to_owned(),
                region: "us-east-1".to_owned(),
            });
            config.sui_chain_id = Some("aB12Cd34".to_owned());
            config.hashi_ids = Some(crate::config::HashiIds {
                package_id: "0x1".parse().unwrap(),
                hashi_object_id: "0x2".parse().unwrap(),
            });
            config.validator_address = Some("0x3".parse().unwrap());
        }
        config.save(&config_path).unwrap();
        let hashi = Hashi::new_with_registry(
            crate::ServerVersion::new("unknown", "unknown"),
            config_path_present.then_some(config_path),
            config,
            &prometheus::Registry::new(),
        )
        .unwrap();
        let (service, _) = BackupService::new(hashi);
        (service, directory)
    }

    fn restart_backup_service(service: BackupService) -> BackupService {
        let config = service.inner.config.clone();
        let config_path = service.inner.config_path.clone();
        drop(service);
        let hashi = Hashi::new_with_registry(
            crate::ServerVersion::new("unknown", "unknown"),
            config_path,
            config,
            &prometheus::Registry::new(),
        )
        .unwrap();
        BackupService::new(hashi).0
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_worker_checks_daily_without_mpc_requests() {
        let (fixture, _directory) = backup_service_fixture(false, true);
        let (mut worker, handle) = BackupService::new(fixture.inner.clone());
        let mut refresh = tokio::time::interval(MPC_RECOVERY_CHECK_INTERVAL);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        assert!(matches!(
            worker.next_request(&mut refresh).await,
            Some(BackupMaintenanceRequest::RefreshRecovery),
        ));
        let next = tokio::spawn(async move { worker.next_request(&mut refresh).await });
        tokio::time::advance(MPC_RECOVERY_CHECK_INTERVAL - std::time::Duration::from_secs(1)).await;
        assert!(!next.is_finished());
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        assert!(matches!(
            next.await.unwrap(),
            Some(BackupMaintenanceRequest::RefreshRecovery),
        ));
        drop(handle);
    }

    #[test]
    fn recovery_refresh_tracks_active_epoch_not_pending_target_or_removed_members() {
        use hashi_types::committee::Bls12381PrivateKey;
        use hashi_types::committee::Committee;
        use hashi_types::committee::CommitteeMember;
        use hashi_types::committee::EncryptionPrivateKey;
        use sui_sdk_types::Address;

        let record = recovery::test_record();
        let MpcRecoveryRecord::V1(current) = &record;
        let member = CommitteeMember::new(
            current.validator_address,
            Bls12381PrivateKey::generate(&mut rand::thread_rng()).public_key(),
            EncryptionPrivateKey::new(&mut rand::thread_rng()).public_key(),
            1,
        );
        let mut committees = crate::onchain::types::CommitteeSet::new(Address::ZERO, Address::ZERO);
        committees.set_epoch(42).set_committees(
            [
                (42, Committee::new(vec![member.clone()], 42, 0, 5_000)),
                (43, Committee::new(vec![member], 43, 0, 5_000)),
            ]
            .into(),
        );
        assert!(recovery_matches_committee(&record, &committees));
        committees.set_pending_epoch_change(Some(43));
        assert!(recovery_matches_committee(&record, &committees));
        let mut target = record.clone();
        let MpcRecoveryRecord::V1(target_record) = &mut target;
        target_record.epoch = 43;
        assert!(!recovery_matches_committee(&target, &committees));
        // A confirmed transaction can arrive while the mirror still reports
        // the target pending. Keep it without refreshing until visibility.
        assert_eq!(
            recovery_refresh_status(&target, &committees),
            RecoveryRefreshStatus::AwaitingMirror,
        );
        committees.set_epoch(43).set_pending_epoch_change(None);
        assert!(!recovery_matches_committee(&record, &committees));
        assert!(recovery_matches_committee(&target, &committees));
        assert_eq!(
            recovery_refresh_status(&record, &committees),
            RecoveryRefreshStatus::Obsolete,
        );
        assert_eq!(
            recovery_refresh_status(&target, &committees),
            RecoveryRefreshStatus::Active,
        );
        let mut public_only = target.clone();
        let MpcRecoveryRecord::V1(public_only_record) = &mut public_only;
        public_only_record.key_shares.shares.clear();
        assert!(!recovery_matches_committee(&public_only, &committees));
        assert_eq!(
            recovery_refresh_status(&public_only, &committees),
            RecoveryRefreshStatus::Obsolete,
        );
        committees.set_committees(Default::default());
        assert!(!recovery_matches_committee(&target, &committees));
        assert_eq!(
            recovery_refresh_status(&target, &committees),
            RecoveryRefreshStatus::Obsolete,
        );
    }

    #[test]
    fn recovery_discovery_ignores_non_root_and_non_mpc_archives() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("backups");
        let recipient = mock_pgp_cert();
        let hash = backup_recipient_hash(&recipient);
        assert_eq!(find_mpc_backup(&root, 42, &recipient).unwrap(), None);
        fs::create_dir(&root).unwrap();
        for name in [
            "hashi-backup-20260101T000000Z.tar.asc".to_owned(),
            "hashi-backup-epoch-42-20260101T000000Z.tar.asc".to_owned(),
            "hashi-backup-epoch-42-mpc-20260105T000000Z.tar.asc".to_owned(),
            format!("hashi-backup-epoch-43-mpc-{hash}-20260101T000000Z.tar.asc"),
            format!("hashi-backup-epoch-042-mpc-{hash}-20260101T000000Z.tar.asc"),
            format!("hashi-backup-epoch-42-mpc-{hash}-20260230T000000Z.tar.asc"),
            format!("hashi-backup-epoch-42-mpc-{hash}-20260101T000000Z.tar.asc.partial"),
            format!(".hashi-backup-epoch-42-mpc-{hash}-20260101T000000Z.tar.asc"),
            format!(
                "hashi-backup-epoch-42-mpc-{}-20260105T000000Z.tar.asc",
                backup_recipient_hash(&mock_pgp_cert()),
            ),
        ] {
            fs::write(root.join(name), b"not a completed matching archive").unwrap();
        }
        let nested = root.join("nested");
        fs::create_dir(&nested).unwrap();
        let name = format!("hashi-backup-epoch-42-mpc-{hash}-20260103T000000Z.tar.asc");
        fs::write(nested.join(&name), b"nested archive").unwrap();
        std::os::unix::fs::symlink(nested.join(&name), root.join(&name)).unwrap();
        fs::create_dir(root.join(format!(
            "hashi-backup-epoch-42-mpc-{hash}-20260104T000000Z.tar.asc"
        )))
        .unwrap();
        assert_eq!(find_mpc_backup(&root, 42, &recipient).unwrap(), None);
        let older = root.join(format!(
            "hashi-backup-epoch-42-mpc-{hash}-20260101T000000Z.tar.asc"
        ));
        let newer = root.join(format!(
            "hashi-backup-epoch-42-mpc-{hash}-20260102T000000Z.tar.asc"
        ));
        fs::write(&newer, b"newer").unwrap();
        fs::write(&older, b"older").unwrap();
        assert_eq!(
            find_fresh_mpc_backup(
                &root,
                42,
                &recipient,
                "2026-01-03T00:00:00Z".parse().unwrap()
            )
            .unwrap(),
            Some(newer),
        );
    }

    #[test]
    fn recovery_freshness_excludes_future_and_three_day_old_archives() {
        let directory = tempfile::tempdir().unwrap();
        let recipient = mock_pgp_cert();
        let hash = backup_recipient_hash(&recipient);
        let archive = directory.path().join(format!(
            "hashi-backup-epoch-42-mpc-{hash}-20260101T000000Z.tar.asc"
        ));
        fs::write(&archive, b"published").unwrap();
        let find = |now: &str| {
            find_fresh_mpc_backup(directory.path(), 42, &recipient, now.parse().unwrap()).unwrap()
        };
        assert_eq!(find("2025-12-31T23:59:59Z"), None);
        assert_eq!(find("2026-01-01T00:00:00Z"), Some(archive.clone()));
        assert_eq!(find("2026-01-03T23:59:59Z"), Some(archive));
        assert_eq!(find("2026-01-04T00:00:00Z"), None);
        assert_eq!(find("2026-02-01T00:00:00Z"), None);
    }

    #[test]
    fn retention_protects_only_latest_mpc_independently_of_ordinary_archives() {
        let directory = tempfile::tempdir().unwrap();
        let hash = backup_recipient_hash(&mock_pgp_cert());
        let previous = directory.path().join(format!(
            "hashi-backup-epoch-41-mpc-{hash}-20260101T000000Z.tar.asc"
        ));
        let latest = directory.path().join(format!(
            "hashi-backup-epoch-42-mpc-{hash}-20260102T000000Z.tar.asc"
        ));
        let ordinary = directory
            .path()
            .join("hashi-backup-epoch-43-20260201T000000Z.tar.asc");
        for path in [&previous, &latest, &ordinary] {
            fs::write(path, b"archive").unwrap();
        }
        cleanup_old_backups(
            directory.path(),
            "2026-03-15T00:00:00Z".parse().unwrap(),
            false,
        )
        .unwrap();
        assert!(!previous.exists());
        assert!(!ordinary.exists());
        assert!(
            latest.is_file(),
            "last MPC archive does not expire after 30 days"
        );
    }

    #[test]
    fn scheduled_recovery_reuses_published_archive_after_restart() {
        let (service, _directory) = backup_service_fixture(false, true);
        let ordinary = service
            .inner
            .maintain_backups_after_epoch_change(42, &BackupAction::SaveNodeState)
            .unwrap()
            .unwrap();
        let action = BackupAction::SaveWithRecovery(Box::new(recovery::test_record()));
        let archive = service
            .inner
            .maintain_backups_after_epoch_change(99, &action)
            .unwrap()
            .unwrap();
        assert_ne!(ordinary, archive);
        assert!(
            archive
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("hashi-backup-epoch-42-mpc-")
        );
        let bytes = fs::read(&archive).unwrap();
        assert_eq!(
            service.inner.metrics.backup_scheduled_local_successes.get(),
            2
        );
        let original_archive = archive;
        let original_bytes = bytes;
        let (cert, secret_key) = mock_pgp_keypair();
        let mut config = service.inner.config.clone();
        config.backup_pgp_cert = PgpPublicCert::new(cert).unwrap();
        let config_path = service.inner.config_path.clone();
        config.save(config_path.as_ref().unwrap()).unwrap();
        drop(service);
        let hashi = Hashi::new_with_registry(
            crate::ServerVersion::new("unknown", "unknown"),
            config_path,
            config,
            &prometheus::Registry::new(),
        )
        .unwrap();
        let service = BackupService::new(hashi).0;
        let archive = service
            .inner
            .maintain_backups_after_epoch_change(42, &action)
            .unwrap()
            .unwrap();
        assert_ne!(archive, original_archive);
        let homedir = temp_gnupg_home();
        test_utils::gpg_import_secret_key(homedir.path(), &secret_key);
        let decrypted = Command::new("gpg")
            .env("GNUPGHOME", homedir.path())
            .arg("--decrypt")
            .arg(&archive)
            .output()
            .unwrap();
        test_utils::assert_command_success(&decrypted, "gpg --decrypt");
        let recovered = read_mpc_recovery_record(decrypted.stdout.as_slice()).unwrap();
        assert_eq!(
            bcs::to_bytes(&recovered).unwrap(),
            bcs::to_bytes(&recovery::test_record()).unwrap(),
        );
        let bytes = fs::read(&archive).unwrap();
        let service = restart_backup_service(service);
        assert_eq!(
            service
                .inner
                .maintain_backups_after_epoch_change(100, &action)
                .unwrap(),
            Some(archive.clone())
        );
        assert_eq!(fs::read(&archive).unwrap(), bytes);
        assert_eq!(
            service.inner.metrics.backup_scheduled_local_successes.get(),
            0
        );
        assert_eq!(
            fs::read_dir(&service.inner.config.backup_dir)
                .unwrap()
                .count(),
            3
        );
        let mut invalid = recovery::test_record();
        let MpcRecoveryRecord::V1(record) = &mut invalid;
        record.chain_id.clear();
        assert!(
            service
                .inner
                .maintain_backups_after_epoch_change(
                    42,
                    &BackupAction::SaveWithRecovery(Box::new(invalid)),
                )
                .is_err()
        );
        assert_eq!(fs::read(archive).unwrap(), bytes);
        assert_eq!(fs::read(original_archive).unwrap(), original_bytes);
    }

    #[test]
    fn scheduled_recovery_preserves_expired_match_until_replacement_is_published() {
        let (service, _directory) = backup_service_fixture(false, true);
        let root = &service.inner.config.backup_dir;
        fs::create_dir(root).unwrap();
        let recipient = &service.inner.config.backup_pgp_cert;
        let hash = backup_recipient_hash(recipient);
        let expired = root.join(format!(
            "hashi-backup-epoch-42-mpc-{hash}-20000101T000000Z.tar.asc"
        ));
        fs::write(&expired, b"expired recovery").unwrap();
        let newer = root.join(encrypted_backup_file_name(BackupKind::Node(43), recipient));
        fs::write(&newer, b"newer node archive").unwrap();
        cleanup_old_backups(root, jiff::Timestamp::now(), false).unwrap();
        assert!(
            expired.is_file(),
            "ordinary archives must not displace MPC recovery"
        );
        let config_path = service.inner.config_path.as_ref().unwrap();
        let config = fs::read(config_path).unwrap();
        fs::remove_file(config_path).unwrap();
        assert!(
            service
                .inner
                .maintain_backups_after_epoch_change(
                    42,
                    &BackupAction::SaveWithRecovery(Box::new(recovery::test_record())),
                )
                .is_err()
        );
        assert_eq!(fs::read(&expired).unwrap(), b"expired recovery");
        fs::write(config_path, config).unwrap();
        let archive = service
            .inner
            .maintain_backups_after_epoch_change(
                42,
                &BackupAction::SaveWithRecovery(Box::new(recovery::test_record())),
            )
            .unwrap()
            .unwrap();
        assert!(!expired.exists());
        assert_ne!(archive, expired);
        assert!(archive.is_file());
        assert_eq!(find_mpc_backup(root, 42, recipient).unwrap(), Some(archive));
        assert_eq!(
            service.inner.metrics.backup_scheduled_local_successes.get(),
            1
        );
    }

    #[tokio::test]
    async fn scheduled_recovery_restart_retries_same_object_and_classifies_collisions() {
        use axum::body::Bytes;
        use axum::http::HeaderMap;
        use axum::http::StatusCode;
        use axum::http::Uri;
        use std::sync::Mutex;

        let (mut service, _directory) = backup_service_fixture(true, true);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let router = axum::Router::new().fallback_service(axum::routing::put(
            move |uri: Uri, headers: HeaderMap, body: Bytes| {
                let captured = captured.clone();
                async move {
                    assert_eq!(headers.get("if-none-match").unwrap(), "*");
                    let mut captured = captured.lock().unwrap();
                    captured.push((uri.path().to_owned(), body));
                    match captured.len() {
                        1 => (
                            StatusCode::SERVICE_UNAVAILABLE,
                            "<Error><Code>SlowDown</Code></Error>",
                        ),
                        2 => (StatusCode::OK, ""),
                        3 | 5 | 6 => (
                            StatusCode::PRECONDITION_FAILED,
                            "<Error><Code>PreconditionFailed</Code></Error>",
                        ),
                        4 => (
                            StatusCode::CONFLICT,
                            "<Error><Code>ConditionalRequestConflict</Code></Error>",
                        ),
                        _ => panic!("unexpected additional request"),
                    }
                }
            },
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        service.s3_client = Some(BackupS3Client::for_test_endpoint(&endpoint));
        let recovery_action = || BackupAction::SaveWithRecovery(Box::new(recovery::test_record()));
        assert!(
            service
                .process_epoch_change(42, recovery_action())
                .await
                .is_err()
        );
        let archive = find_mpc_backup(
            &service.inner.config.backup_dir,
            42,
            &service.inner.config.backup_pgp_cert,
        )
        .unwrap()
        .unwrap();
        let bytes = fs::read(&archive).unwrap();
        assert_eq!(
            service.inner.metrics.backup_scheduled_local_successes.get(),
            1
        );
        assert_eq!(
            service.inner.metrics.backup_scheduled_remote_failures.get(),
            1
        );

        service = restart_backup_service(service);
        service.s3_client = Some(BackupS3Client::for_test_endpoint(&endpoint));
        service
            .process_epoch_change(42, recovery_action())
            .await
            .unwrap();
        assert_eq!(
            service.inner.metrics.backup_scheduled_local_successes.get(),
            0
        );
        assert_eq!(
            service
                .inner
                .metrics
                .backup_scheduled_remote_successes
                .get(),
            1
        );
        assert_eq!(
            service.inner.metrics.backup_scheduled_remote_failures.get(),
            0
        );
        {
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[0], requests[1]);
            assert!(
                requests[0]
                    .0
                    .ends_with(archive.file_name().unwrap().to_str().unwrap())
            );
        }
        service
            .process_epoch_change(42, recovery_action())
            .await
            .unwrap();
        assert_eq!(
            service.inner.metrics.backup_scheduled_local_successes.get(),
            0
        );
        assert_eq!(
            service
                .inner
                .metrics
                .backup_scheduled_remote_successes
                .get(),
            1
        );
        assert_eq!(
            service.inner.metrics.backup_scheduled_remote_failures.get(),
            0
        );
        assert!(
            service
                .process_epoch_change(42, recovery_action())
                .await
                .is_err()
        );
        assert_eq!(
            service.inner.metrics.backup_scheduled_remote_failures.get(),
            1
        );
        assert_eq!(fs::read(&archive).unwrap(), bytes);
        assert_eq!(
            fs::read_dir(&service.inner.config.backup_dir)
                .unwrap()
                .count(),
            1
        );

        // The same HTTP status remains an error for ordinary scheduled and manual uploads.
        assert!(
            service
                .process_epoch_change(42, BackupAction::SaveNodeState)
                .await
                .is_err()
        );
        assert_eq!(
            service.inner.metrics.backup_scheduled_local_successes.get(),
            1
        );
        assert_eq!(
            service.inner.metrics.backup_scheduled_remote_failures.get(),
            2
        );
        assert!(
            upload(&service.inner.config, &mut service.s3_client, &archive)
                .await
                .is_err()
        );
        assert_eq!(requests.lock().unwrap().len(), 6);
        server.abort();
    }

    #[tokio::test]
    async fn scheduled_skips_and_local_failure_do_not_initialize_s3_or_count_remote_results() {
        for (config_path_present, action, remove_config) in [
            (true, BackupAction::CleanupOnly, false),
            (false, BackupAction::SaveNodeState, false),
            (
                false,
                BackupAction::SaveWithRecovery(Box::new(recovery::test_record())),
                false,
            ),
            (true, BackupAction::SaveNodeState, true),
        ] {
            let (mut service, directory) = backup_service_fixture(true, config_path_present);
            if remove_config {
                fs::remove_file(directory.path().join("config.toml")).unwrap();
            }
            let result = service.process_epoch_change(6, action).await;
            assert_eq!(result.is_err(), remove_config);
            assert!(service.s3_client.is_none());
            assert_eq!(
                service.inner.metrics.backup_scheduled_local_successes.get(),
                0
            );
            assert_eq!(
                service
                    .inner
                    .metrics
                    .backup_scheduled_remote_successes
                    .get(),
                0
            );
            assert_eq!(
                service.inner.metrics.backup_scheduled_remote_failures.get(),
                0
            );
        }
    }

    #[tokio::test]
    async fn scheduled_local_only_completes_without_initializing_s3() {
        let (mut service, _directory) = backup_service_fixture(false, true);
        service
            .process_epoch_change(6, BackupAction::SaveNodeState)
            .await
            .unwrap();
        let archive = fs::read_dir(&service.inner.config.backup_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert!(
            archive
                .file_name()
                .to_str()
                .unwrap()
                .starts_with("hashi-backup-epoch-6-")
        );
        assert!(service.s3_client.is_none());
        assert_eq!(
            service.inner.metrics.backup_scheduled_local_successes.get(),
            1
        );
        assert_eq!(
            service
                .inner
                .metrics
                .backup_scheduled_remote_successes
                .get(),
            0
        );
        assert_eq!(
            service.inner.metrics.backup_scheduled_remote_failures.get(),
            0
        );
        assert_eq!(
            fs::read_dir(&service.inner.config.backup_dir)
                .unwrap()
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn scheduled_upload_counts_only_completed_stages_and_preserves_local_on_failure() {
        use axum::body::Bytes;
        use axum::http::HeaderMap;
        use axum::http::StatusCode;
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;

        for fail in [false, true] {
            let (mut service, _directory) = backup_service_fixture(true, true);
            let hashi = service.inner.clone();
            let requests = Arc::new(AtomicUsize::new(0));
            let request_count = requests.clone();
            let router = axum::Router::new().fallback_service(axum::routing::put(
                move |headers: HeaderMap, body: Bytes| {
                    let hashi = hashi.clone();
                    let requests = request_count.clone();
                    async move {
                        requests.fetch_add(1, Ordering::SeqCst);
                        // Publication and the local counter must precede the HTTP request.
                        let archive = fs::read_dir(&hashi.config.backup_dir)
                            .unwrap()
                            .next()
                            .unwrap()
                            .unwrap()
                            .path();
                        let archive_bytes = fs::read(archive).unwrap();
                        assert!(!archive_bytes.is_empty());
                        if let Some(decoded_length) = headers.get("x-amz-decoded-content-length") {
                            assert_eq!(
                                decoded_length.to_str().unwrap().parse::<usize>().unwrap(),
                                archive_bytes.len()
                            );
                        } else {
                            assert_eq!(archive_bytes.as_slice(), body.as_ref());
                        }
                        assert_eq!(hashi.metrics.backup_scheduled_local_successes.get(), 1);
                        assert_eq!(hashi.metrics.backup_scheduled_remote_successes.get(), 0);
                        assert_eq!(hashi.metrics.backup_scheduled_remote_failures.get(), 0);
                        if fail {
                            (
                                StatusCode::SERVICE_UNAVAILABLE,
                                "<Error><Code>SlowDown</Code><Message>try later</Message></Error>",
                            )
                        } else {
                            (StatusCode::OK, "")
                        }
                    }
                },
            ));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            service.s3_client = Some(BackupS3Client::for_test_endpoint(&endpoint));
            let server = tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            });
            let result = service
                .process_epoch_change(6, BackupAction::SaveNodeState)
                .await;
            server.abort();
            assert_eq!(requests.load(Ordering::SeqCst), 1);
            assert_eq!(
                service.inner.metrics.backup_scheduled_local_successes.get(),
                1
            );
            assert_eq!(
                service
                    .inner
                    .metrics
                    .backup_scheduled_remote_successes
                    .get(),
                u64::from(!fail)
            );
            assert_eq!(
                service.inner.metrics.backup_scheduled_remote_failures.get(),
                u64::from(fail)
            );
            let archive = fs::read_dir(&service.inner.config.backup_dir)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            assert!(archive.is_file());
            if fail {
                let error = format!("{:#}", result.unwrap_err());
                assert!(error.contains(&archive.display().to_string()), "{error}");
                let namespace = service.inner.config.backup_s3_namespace().unwrap();
                let uri = format!(
                    "s3://backup-bucket/{namespace}{}",
                    archive.file_name().unwrap().to_string_lossy()
                );
                assert!(error.contains(&uri), "{error}");
                assert!(error.contains("local archive retained"), "{error}");
                assert!(error.contains("SlowDown"), "{error}");
                assert!(error.contains("try later"), "{error}");
            } else {
                result.unwrap();
            }
        }
    }

    #[test]
    fn cleanup_old_backups_accepts_missing_directory() {
        let tmpdir = tempfile::tempdir().unwrap();
        let missing = tmpdir.path().join("missing");

        let stats =
            cleanup_old_backups(&missing, "2026-09-08T12:00:00Z".parse().unwrap(), false).unwrap();
        assert_eq!(stats.removed, 0);
        assert_eq!(stats.failed, 0);

        assert!(!missing.exists());
    }

    #[test]
    fn cleanup_old_backups_recognizes_generated_archive_name() {
        let tmpdir = tempfile::tempdir().unwrap();
        let now = jiff::Timestamp::now();
        let older = tmpdir.path().join(format!(
            "{BACKUP_FILE_NAME_PREFIX}{}",
            now.checked_sub(jiff::SignedDuration::from_hours(24))
                .unwrap()
                .to_zoned(jiff::tz::TimeZone::UTC)
                .strftime(BACKUP_FILE_NAME_SUFFIX_FORMAT)
        ));
        let generated = tmpdir.path().join(encrypted_backup_file_name(
            BackupKind::Mpc(42),
            &mock_pgp_cert(),
        ));
        fs::write(&older, b"older archive").unwrap();
        fs::write(&generated, b"generated recovery archive").unwrap();
        let sweep_time = now
            .checked_add(BACKUP_RETENTION)
            .unwrap()
            .checked_add(jiff::SignedDuration::from_hours(24))
            .unwrap();

        cleanup_old_backups(tmpdir.path(), sweep_time, false).unwrap();

        assert!(!older.exists());
        assert_eq!(fs::read(generated).unwrap(), b"generated recovery archive");
    }

    #[test]
    fn cleanup_old_backups_uses_timestamps_across_manual_and_epoch_names() {
        let directory = tempfile::tempdir().unwrap();
        let cases = [
            ("hashi-backup-epoch-10-20260817T000000Z.tar.asc", false),
            ("hashi-backup-epoch-10-mpc-20260818T000000Z.tar.asc", true),
            ("hashi-backup-20260819T000000Z.tar.asc", false),
            ("hashi-backup-epoch-2-20260820T000000Z.tar.asc", true),
            ("hashi-backup-epoch-invalid-20260821T000000Z.tar.asc", true),
        ];
        for (name, _) in cases {
            fs::write(directory.path().join(name), b"archive").unwrap();
        }

        let stats = cleanup_old_backups(
            directory.path(),
            "2026-09-08T12:00:00Z".parse().unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(stats.removed, 2);
        assert_eq!(stats.failed, 0);
        for (name, retained) in cases {
            assert_eq!(directory.path().join(name).exists(), retained, "{name}");
        }
    }

    #[test]
    fn cleanup_old_backups_removes_only_expired_restore_staging_directories() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();
        let now: jiff::Timestamp = "2026-09-08T12:00:00Z".parse().unwrap();
        let cutoff: std::time::SystemTime = now.checked_sub(BACKUP_RETENTION).unwrap().into();
        let expired = dir.join(format!("{RESTORE_STAGING_DIR_NAME_PREFIX}expired"));
        let boundary = dir.join(format!("{RESTORE_STAGING_DIR_NAME_PREFIX}boundary"));
        let recent = dir.join(format!("{RESTORE_STAGING_DIR_NAME_PREFIX}recent"));
        let contents = [
            ("operator.key", b"secret key".as_slice()),
            ("config.toml", b"node config".as_slice()),
            (
                "hashi-db-snapshot/keyspace/segment",
                b"database data".as_slice(),
            ),
        ];
        for (path, modified) in [
            (&expired, cutoff - std::time::Duration::from_secs(1)),
            (&boundary, cutoff),
            (&recent, now.into()),
        ] {
            fs::create_dir_all(path.join("hashi-db-snapshot/keyspace")).unwrap();
            for (name, data) in contents {
                fs::write(path.join(name), data).unwrap();
            }
            // Set the directory's mtime last; child files deliberately have fresh mtimes.
            File::open(path)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(modified))
                .unwrap();
        }

        let stats = cleanup_old_backups(dir, now, false).unwrap();
        assert_eq!(stats.removed, 1);
        assert_eq!(stats.failed, 0);

        assert!(!expired.exists());
        for path in [boundary, recent] {
            for (name, data) in contents {
                assert_eq!(fs::read(path.join(name)).unwrap(), data);
            }
        }
    }

    #[test]
    fn cleanup_old_backups_preserves_restore_symlink_targets_and_unrelated_entries() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("secret.key");
        fs::write(&target, b"outside secret").unwrap();
        let old: jiff::Timestamp = "2026-08-01T00:00:00Z".parse().unwrap();
        let times = fs::FileTimes::new().set_modified(old.into());
        File::open(outside.path())
            .unwrap()
            .set_times(times)
            .unwrap();
        let staging = dir.join(format!("{RESTORE_STAGING_DIR_NAME_PREFIX}abandoned"));
        fs::create_dir(&staging).unwrap();
        std::os::unix::fs::symlink(outside.path(), staging.join("linked-db")).unwrap();
        File::open(&staging).unwrap().set_times(times).unwrap();
        let link = dir.join(format!("{RESTORE_STAGING_DIR_NAME_PREFIX}symlink"));
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        let wrong_type = dir.join(format!("{RESTORE_STAGING_DIR_NAME_PREFIX}regular-file"));
        fs::write(&wrong_type, b"not a staging directory").unwrap();
        File::open(&wrong_type).unwrap().set_times(times).unwrap();
        let completed = dir.join(
            extract_dir_name(&encrypted_backup_file_name(
                BackupKind::Manual,
                &mock_pgp_cert(),
            ))
            .unwrap(),
        );
        let db_restore = dir.join(".hashi-db-restore-abandoned");
        for path in [&completed, &db_restore] {
            fs::create_dir(path).unwrap();
            fs::write(path.join("config.toml"), b"preserved config").unwrap();
            File::open(path).unwrap().set_times(times).unwrap();
        }

        cleanup_old_backups(dir, "2026-09-08T12:00:00Z".parse().unwrap(), false).unwrap();

        assert!(!staging.exists());
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read(target).unwrap(), b"outside secret");
        assert_eq!(fs::read(wrong_type).unwrap(), b"not a staging directory");
        for path in [completed, db_restore] {
            assert_eq!(
                fs::read(path.join("config.toml")).unwrap(),
                b"preserved config"
            );
        }
    }

    #[test]
    fn cleanup_old_backups_removes_only_expired_staging_files() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();
        let now: jiff::Timestamp = "2026-09-08T12:00:00Z".parse().unwrap();
        let cutoff: std::time::SystemTime = now.checked_sub(BACKUP_RETENTION).unwrap().into();
        let expired = dir.join(format!("{BACKUP_STAGING_FILE_NAME_PREFIX}expired"));
        let boundary = dir.join(format!("{BACKUP_STAGING_FILE_NAME_PREFIX}boundary"));
        let recent = dir.join(format!("{BACKUP_STAGING_FILE_NAME_PREFIX}recent"));
        for (path, modified) in [
            (&expired, cutoff - std::time::Duration::from_secs(1)),
            (&boundary, cutoff),
            (&recent, now.into()),
        ] {
            let mut file = File::create(path).unwrap();
            file.write_all(b"staged data").unwrap();
            file.set_times(fs::FileTimes::new().set_modified(modified))
                .unwrap();
        }

        cleanup_old_backups(dir, now, false).unwrap();

        assert!(!expired.exists());
        assert_eq!(fs::read(boundary).unwrap(), b"staged data");
        assert_eq!(fs::read(recent).unwrap(), b"staged data");
    }

    #[test]
    fn cleanup_old_backups_ignores_staging_directories_and_symlinks() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();
        let old: jiff::Timestamp = "2026-08-01T00:00:00Z".parse().unwrap();
        let times = fs::FileTimes::new().set_modified(old.into());
        let nested = dir.join(format!("{BACKUP_STAGING_FILE_NAME_PREFIX}directory"));
        fs::create_dir(&nested).unwrap();
        let nested_file = nested.join(format!("{BACKUP_STAGING_FILE_NAME_PREFIX}nested"));
        fs::write(&nested_file, b"nested data").unwrap();
        File::open(&nested_file).unwrap().set_times(times).unwrap();
        File::open(&nested).unwrap().set_times(times).unwrap();
        let link = dir.join(format!("{BACKUP_STAGING_FILE_NAME_PREFIX}symlink"));
        std::os::unix::fs::symlink(&nested_file, &link).unwrap();

        cleanup_old_backups(dir, "2026-09-08T12:00:00Z".parse().unwrap(), false).unwrap();

        assert_eq!(fs::read(nested_file).unwrap(), b"nested data");
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    fn cleanup_old_backups_preserves_boundary_and_unrelated_entries() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();
        let expired = dir.join("hashi-backup-20260825T115959Z.tar.asc");
        fs::write(&expired, b"expired despite fresh mtime").unwrap();
        let preserved = [
            "hashi-backup-20260825T120000Z.tar.asc",
            "hashi-backup-20260908T120000Z.tar.asc",
            "hashi-backup-20260230T000000Z.tar.asc",
            "hashi-backup-20260801T000000Z.tar.asc.partial",
            "other-backup-20260801T000000Z.tar.asc",
        ];
        for name in preserved {
            fs::write(dir.join(name), b"keep").unwrap();
        }

        cleanup_old_backups(dir, "2026-09-08T12:00:00Z".parse().unwrap(), false).unwrap();

        assert!(!expired.exists());
        for name in preserved {
            assert_eq!(fs::read(dir.join(name)).unwrap(), b"keep", "{name}");
        }
    }

    #[test]
    fn cleanup_old_backups_preserves_newest_expired_archive_inside_the_floor_bound() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();
        let newest = dir.join("hashi-backup-20260820T000000Z.tar.asc");
        fs::write(&newest, b"newest recovery archive").unwrap();
        let staging = dir.join(format!("{BACKUP_STAGING_FILE_NAME_PREFIX}abandoned"));
        fs::write(&staging, b"not a recovery archive").unwrap();
        let staging_modified: jiff::Timestamp = "2026-08-24T00:00:00Z".parse().unwrap();
        File::open(&staging)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(staging_modified.into()))
            .unwrap();
        let older = [
            dir.join("hashi-backup-20260801T000000Z.tar.asc"),
            dir.join("hashi-backup-20260802T000000Z.tar.asc"),
        ];
        for archive in &older {
            fs::write(archive, b"older archive with newer mtime").unwrap();
        }
        let unrelated = [
            "hashi-backup-20260831T000000Z.tar.asc.partial",
            "other-backup-20260831T000000Z.tar.asc",
            "hashi-backup-20260931T000000Z.tar.asc",
        ];
        for name in unrelated {
            fs::write(dir.join(name), b"unrelated").unwrap();
        }
        let nested = dir.join("hashi-backup-20260804T000000Z.tar.asc");
        fs::create_dir(&nested).unwrap();
        let nested_archive = nested.join("hashi-backup-20260801T000000Z.tar.asc");
        fs::write(&nested_archive, b"nested").unwrap();
        let link = dir.join("hashi-backup-20260805T000000Z.tar.asc");
        std::os::unix::fs::symlink(&newest, &link).unwrap();

        let stats =
            cleanup_old_backups(dir, "2026-09-08T12:00:00Z".parse().unwrap(), false).unwrap();
        assert_eq!(stats.removed, 3);
        assert_eq!(stats.failed, 0);

        assert_eq!(fs::read(newest).unwrap(), b"newest recovery archive");
        assert!(!staging.exists());
        for archive in older {
            assert!(!archive.exists());
        }
        for name in unrelated {
            assert_eq!(fs::read(dir.join(name)).unwrap(), b"unrelated");
        }
        assert_eq!(fs::read(nested_archive).unwrap(), b"nested");
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    fn cleanup_old_backups_keeps_the_last_archive_inside_the_floor_bound() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();
        let last = dir.join("hashi-backup-20260820T000000Z.tar.asc");
        fs::write(&last, b"last").unwrap();

        let stats =
            cleanup_old_backups(dir, "2026-09-08T12:00:00Z".parse().unwrap(), false).unwrap();

        assert_eq!(stats.removed, 0);
        assert_eq!(stats.failed, 0);
        assert_eq!(fs::read(&last).unwrap(), b"last");
    }

    #[test]
    fn cleanup_old_backups_keeps_the_last_archive_exactly_on_the_floor_bound() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();
        let on_bound = dir.join("hashi-backup-20260809T120000Z.tar.asc");
        let past_bound = dir.join("hashi-backup-20260809T115959Z.tar.asc");
        fs::write(&on_bound, b"on").unwrap();
        fs::write(&past_bound, b"past").unwrap();

        let stats =
            cleanup_old_backups(dir, "2026-09-08T12:00:00Z".parse().unwrap(), false).unwrap();

        assert_eq!(stats.removed, 1);
        assert_eq!(stats.failed, 0);
        assert_eq!(fs::read(&on_bound).unwrap(), b"on");
        assert!(!past_bound.exists());
    }

    #[test]
    fn cleanup_old_backups_spares_the_last_archive_when_a_save_may_follow() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();
        let last = dir.join("hashi-backup-20260803T000000Z.tar.asc");
        fs::write(&last, b"last").unwrap();

        let stats =
            cleanup_old_backups(dir, "2026-09-08T12:00:00Z".parse().unwrap(), true).unwrap();

        assert_eq!(stats.removed, 0);
        assert_eq!(stats.failed, 0);
        assert_eq!(fs::read(&last).unwrap(), b"last");
    }

    #[test]
    fn cleanup_old_backups_ignores_future_dated_archives_when_choosing_the_newest() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();
        let future = dir.join("hashi-backup-20270101T000000Z.tar.asc");
        let real = dir.join("hashi-backup-20260820T000000Z.tar.asc");
        let older = dir.join("hashi-backup-20260801T000000Z.tar.asc");
        fs::write(&future, b"future").unwrap();
        fs::write(&real, b"real").unwrap();
        fs::write(&older, b"older").unwrap();

        let stats =
            cleanup_old_backups(dir, "2026-09-08T12:00:00Z".parse().unwrap(), false).unwrap();

        assert_eq!(stats.removed, 1);
        assert_eq!(fs::read(&real).unwrap(), b"real");
        assert!(!older.exists());
    }

    #[test]
    fn cleanup_old_backups_expires_the_last_archive_past_the_floor_bound() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();
        let last = dir.join("hashi-backup-20260809T115959Z.tar.asc");
        fs::write(&last, b"last").unwrap();

        let stats =
            cleanup_old_backups(dir, "2026-09-08T12:00:00Z".parse().unwrap(), false).unwrap();

        assert_eq!(stats.removed, 1);
        assert_eq!(stats.failed, 0);
        assert!(!last.exists());
    }

    #[test]
    fn manifest_disambiguates_user_file_colliding_with_db_prefix() {
        // A user-backed-up file whose basename equals DB_SNAPSHOT_TAR_PREFIX
        // must be renamed so it doesn't collide with the db snapshot
        // directory the archive uses for keyspace entries.
        let files = vec![PathBuf::from("/etc/hashi/hashi-db-snapshot")];
        let db_path = PathBuf::from("/var/lib/hashi/db");

        let manifest = build_backup_manifest(&files, &db_path).unwrap();

        assert_eq!(manifest.paths.len(), 1);
        assert_eq!(manifest.db.original_path, db_path);

        // The user's file should have been renamed away from the reserved prefix.
        let user_entry = &manifest.paths[0];
        assert_eq!(
            user_entry.original_path,
            PathBuf::from("/etc/hashi/hashi-db-snapshot")
        );
        assert_eq!(
            user_entry.archive_name,
            PathBuf::from("hashi-db-snapshot-2")
        );
    }

    #[test]
    fn manifest_disambiguates_user_file_colliding_with_keyspace_basename() {
        // A user file whose basename equals one of the reserved keyspace
        // archive basenames must be renamed so it doesn't collide with the
        // logical database backup entries.
        let files = vec![PathBuf::from("/etc/hashi/encryption_keys.bin")];
        let db_path = PathBuf::from("/var/lib/hashi/db");

        let manifest = build_backup_manifest(&files, &db_path).unwrap();

        assert_eq!(manifest.paths.len(), 1);
        assert_eq!(
            manifest.paths[0].archive_name,
            PathBuf::from("encryption_keys-2.bin")
        );
    }

    #[test]
    fn manifest_disambiguates_chain_of_collisions_with_db_prefix() {
        // Two user files: one basenamed `hashi-db-snapshot` (collides with
        // the reserved db prefix) and one basenamed `hashi-db-snapshot-2`
        // (collides with the first file's renamed slot).
        //
        // The disambiguator always derives its candidate suffixes from the
        // original basename, so the second file lands at
        // `hashi-db-snapshot-2-2` rather than `hashi-db-snapshot-3`. Both
        // names are unique and deterministic, which is all we need; this
        // test pins that exact behaviour so a future refactor doesn't
        // silently change the output layout.
        let files = vec![
            PathBuf::from("/etc/hashi/hashi-db-snapshot"),
            PathBuf::from("/etc/hashi/hashi-db-snapshot-2"),
        ];
        let db_path = PathBuf::from("/var/lib/hashi/db");

        let manifest = build_backup_manifest(&files, &db_path).unwrap();

        assert_eq!(manifest.paths.len(), 2);
        assert_eq!(
            manifest.paths[0].archive_name,
            PathBuf::from("hashi-db-snapshot-2")
        );
        assert_eq!(
            manifest.paths[1].archive_name,
            PathBuf::from("hashi-db-snapshot-2-2")
        );
    }

    #[test]
    fn manifest_records_db_entry() {
        let files = Vec::new();
        let db_path = PathBuf::from("/var/lib/hashi/db");

        let manifest = build_backup_manifest(&files, &db_path).unwrap();

        assert_eq!(manifest.db.original_path, db_path);
        assert_eq!(
            manifest.db.archive_entries,
            backup_keyspace_archive_entries(Path::new(DB_SNAPSHOT_TAR_PREFIX))
        );
        assert!(manifest.paths.is_empty());
    }

    #[test]
    fn manifest_round_trips_through_toml() {
        let db_path = PathBuf::from("/var/lib/hashi/db");
        let manifest =
            build_backup_manifest(&[PathBuf::from("/etc/hashi/hashi-cli.toml")], &db_path).unwrap();

        let toml = toml::to_string_pretty(&manifest).unwrap();
        let parsed: BackupManifest = toml::from_str(&toml).unwrap();

        assert_eq!(parsed.db.original_path, db_path);
        assert_eq!(
            parsed.db.archive_entries,
            backup_keyspace_archive_entries(Path::new(DB_SNAPSHOT_TAR_PREFIX))
        );
        assert_eq!(parsed.paths.len(), 1);
        assert_eq!(
            parsed.paths[0].archive_name,
            PathBuf::from("hashi-cli.toml")
        );
    }

    #[test]
    fn restore_backup_entries_rejects_missing_db_entries() {
        let manifest = db_only_manifest();
        let tar_bytes = build_archive_bytes(&manifest, &[]);
        let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
        let mut entries = archive.entries().unwrap();
        let manifest_entry = entries.next().unwrap().unwrap();
        let (parsed_manifest, _) = read_backup_manifest(manifest_entry).unwrap();
        let output_dir = tempfile::tempdir().unwrap();

        let err = restore_backup_entries(entries, output_dir.path(), &parsed_manifest).unwrap_err();

        let chain = format!("{err:#}");
        assert!(
            chain.contains("Backup archive is missing database entries"),
            "unexpected error: {chain}"
        );
        for entry in backup_keyspace_archive_entries(Path::new(DB_SNAPSHOT_TAR_PREFIX)) {
            assert!(
                chain.contains(entry.to_str().unwrap()),
                "missing-entries error did not mention {}: {chain}",
                entry.display()
            );
        }
    }

    #[test]
    fn restore_backup_entries_rejects_unexpected_db_entries() {
        let manifest = db_only_manifest();
        let empty_records = bcs::to_bytes(&Vec::<DbBackupRecord>::new()).unwrap();
        let tar_bytes = build_archive_bytes(
            &manifest,
            &[
                ("hashi-db-snapshot/encryption_keys.bin", &empty_records),
                ("hashi-db-snapshot/dealer_messages.bin", &empty_records),
                ("hashi-db-snapshot/rotation_messages.bin", &empty_records),
                ("hashi-db-snapshot/extra.bin", &empty_records),
            ],
        );
        let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
        let mut entries = archive.entries().unwrap();
        let manifest_entry = entries.next().unwrap().unwrap();
        let (parsed_manifest, _) = read_backup_manifest(manifest_entry).unwrap();
        let output_dir = tempfile::tempdir().unwrap();

        let err = restore_backup_entries(entries, output_dir.path(), &parsed_manifest).unwrap_err();

        assert!(
            err.to_string().contains(
                "Backup archive contains unexpected database entry: hashi-db-snapshot/extra.bin"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn restore_backup_entries_rejects_db_parent_dir_traversal() {
        let err = validate_db_archive_path(Path::new("hashi-db-snapshot/../escape")).unwrap_err();

        assert!(
            err.to_string()
                .contains("Database entry must be a single keyspace file under hashi-db-snapshot")
        );
    }

    #[test]
    fn restore_backup_entries_rejects_absolute_db_path() {
        let err = validate_db_archive_path(Path::new("/hashi-db-snapshot/escape")).unwrap_err();

        assert!(
            err.to_string()
                .contains("Database entry must live under hashi-db-snapshot")
        );
    }

    #[test]
    fn restore_backup_entries_rejects_unknown_keyspace_file_name() {
        let manifest = BackupManifest {
            paths: Vec::new(),
            recovery: None,
            db: DbManifestEntry {
                original_path: PathBuf::from("/var/lib/hashi/db"),
                archive_entries: vec![PathBuf::from("hashi-db-snapshot/something_else.bin")],
            },
        };
        let empty_records = bcs::to_bytes(&Vec::<DbBackupRecord>::new()).unwrap();
        let tar_bytes = build_archive_bytes(
            &manifest,
            &[("hashi-db-snapshot/something_else.bin", &empty_records)],
        );
        let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
        let mut entries = archive.entries().unwrap();
        let manifest_entry = entries.next().unwrap().unwrap();
        let (parsed_manifest, _) = read_backup_manifest(manifest_entry).unwrap();
        let output_dir = tempfile::tempdir().unwrap();

        let err = restore_backup_entries(entries, output_dir.path(), &parsed_manifest).unwrap_err();

        assert!(
            err.to_string()
                .contains("Database entry must be a known keyspace .bin file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn restore_backup_entries_rejects_duplicate_db_entries() {
        let manifest = db_only_manifest();
        let empty_records = bcs::to_bytes(&Vec::<DbBackupRecord>::new()).unwrap();
        let tar_bytes = build_archive_bytes(
            &manifest,
            &[
                ("hashi-db-snapshot/encryption_keys.bin", &empty_records),
                ("hashi-db-snapshot/encryption_keys.bin", &empty_records),
            ],
        );
        let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
        let mut entries = archive.entries().unwrap();
        let manifest_entry = entries.next().unwrap().unwrap();
        let (parsed_manifest, _) = read_backup_manifest(manifest_entry).unwrap();
        let output_dir = tempfile::tempdir().unwrap();

        let err = restore_backup_entries(entries, output_dir.path(), &parsed_manifest).unwrap_err();

        assert!(
            err.to_string().contains(
                "Backup archive contains duplicate database entry: hashi-db-snapshot/encryption_keys.bin"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn restore_db_backup_keyspace_rejects_malformed_bcs() {
        let dest_dir = tempfile::Builder::new().tempdir().unwrap();
        let dest_path = dest_dir.path().join(DB_SNAPSHOT_TAR_PREFIX);
        let db = fjall::Database::builder(&dest_path).open().unwrap();

        let bogus = b"not valid bcs bytes".as_slice();
        let err = restore_db_backup_keyspace(&db, "encryption_keys", bogus).unwrap_err();

        assert!(
            format!("{err:#}").contains("failed to deserialize backup keyspace encryption_keys"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn failed_encrypted_archive_leaves_no_partial_backup_for_retention() {
        let src = tempfile::tempdir().unwrap();
        let db = Database::open(src.path()).unwrap();
        let out = tempfile::tempdir().unwrap();
        let recovery = out.path().join("hashi-backup-20260801T000000Z.tar.asc");
        fs::write(&recovery, b"last recovery archive").unwrap();
        let output = out.path().join("hashi-backup-20260802T000000Z.tar.asc");
        let mut manifest = db_only_manifest();
        manifest.paths.push(BackupManifestEntry {
            original_path: src.path().join("missing-config.toml"),
            archive_name: PathBuf::from("config.toml"),
        });

        let result = encrypt_files_to_pgp_archive(&manifest, &db, &mock_pgp_cert(), &output, None);

        assert!(result.is_err());
        assert_eq!(
            fs::read_dir(out.path())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>(),
            vec![recovery.clone()],
        );
        cleanup_old_backups(out.path(), "2026-09-08T12:00:00Z".parse().unwrap(), true).unwrap();
        assert_eq!(fs::read(recovery).unwrap(), b"last recovery archive");
    }

    #[test]
    fn encrypted_archive_collision_preserves_existing_backup() {
        let src = tempfile::tempdir().unwrap();
        let db = Database::open(src.path()).unwrap();
        let out = tempfile::tempdir().unwrap();
        let output = out.path().join("hashi-backup-20260801T000000Z.tar.asc");
        fs::write(&output, b"existing recovery archive").unwrap();
        let recipient = mock_pgp_cert();
        let collision =
            encrypt_files_to_pgp_archive(&db_only_manifest(), &db, &recipient, &output, None);
        assert!(collision.is_err());
        assert_eq!(fs::read(&output).unwrap(), b"existing recovery archive");
        assert_eq!(
            fs::read_dir(out.path())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>(),
            vec![output],
        );
    }

    #[test]
    fn save_works_while_db_is_open_and_names_the_captured_epoch() {
        let src = tempfile::Builder::new().tempdir().unwrap();
        let db_path = src.path().join("db");
        let node_config_path = src.path().join("config.toml");
        let mut node_config = crate::config::Config::new_for_testing();
        node_config.db = Some(db_path.clone());
        node_config.save(&node_config_path).unwrap();

        let db = Database::open(&db_path).unwrap();
        let recipient = mock_pgp_cert();
        let recovery = recovery::test_record();
        let mpc_prefix = format!(
            "hashi-backup-epoch-42-mpc-{}",
            backup_recipient_hash(&recipient)
        );
        for (epoch, recovery, prefix) in [
            (None, None, "hashi-backup"),
            (Some(43), None, "hashi-backup-epoch-43"),
            (Some(43), Some(&recovery), mpc_prefix.as_str()),
        ] {
            let out = tempfile::tempdir().unwrap();
            let output_path = save(
                &node_config_path,
                &node_config,
                &db,
                &recipient,
                out.path(),
                epoch,
                recovery,
            )
            .unwrap();

            assert!(output_path.is_file());
            let name = output_path.file_name().unwrap().to_str().unwrap();
            let suffix = name.strip_prefix(prefix).unwrap();
            jiff::civil::DateTime::strptime(BACKUP_FILE_NAME_SUFFIX_FORMAT, suffix).unwrap();
        }
    }

    #[test]
    fn backup_tarball_can_be_manually_decrypted_with_gpg() {
        let src = tempfile::Builder::new().tempdir().unwrap();
        let db_path = src.path().join("db");
        let node_config_path = src.path().join("config.toml");
        let (public_cert, secret_key) = mock_pgp_keypair();
        let recipient = PgpPublicCert::new(public_cert).unwrap();
        let mut node_config = crate::config::Config::new_for_testing();
        node_config.db = Some(db_path.clone());
        node_config.backup_pgp_cert = recipient.clone();
        node_config.save(&node_config_path).unwrap();

        let db = Database::open(&db_path).unwrap();
        let out = tempfile::Builder::new().tempdir().unwrap();

        let output_path = save(
            &node_config_path,
            &node_config,
            &db,
            &recipient,
            out.path(),
            None,
            None,
        )
        .unwrap();

        let homedir = temp_gnupg_home();
        test_utils::gpg_import_secret_key(homedir.path(), &secret_key);

        let output = Command::new("gpg")
            .env("GNUPGHOME", homedir.path())
            .arg("--decrypt")
            .arg(&output_path)
            .output()
            .unwrap();
        test_utils::assert_command_success(&output, "gpg --decrypt");

        // gpg --decrypt inflates the OpenPGP compression layer, so its stdout
        // is the raw tar.
        let mut archive = tar::Archive::new(Cursor::new(output.stdout));
        let has_manifest = archive
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().into_owned())
            .any(|path| path == Path::new(BACKUP_MANIFEST_FILE_NAME));
        assert!(
            has_manifest,
            "manual gpg decrypt did not produce a valid backup tarball"
        );
    }

    #[test]
    fn round_trip_covers_backed_up_keyspaces_and_excludes_avid_state() {
        use hashi_types::committee::EncryptionPrivateKey;
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let src_dir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(src_dir.path()).unwrap();
        let dealer = sui_sdk_types::Address::new([3u8; 32]);
        let enc_key = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let dealer_msg = crate::db::tests::create_test_message();
        let avid_state = crate::db::tests::create_test_avid_round_state();
        let mut rotation_msgs: BTreeMap<
            NonZeroU16,
            fastcrypto_tbls::threshold_schnorr::avss::Message,
        > = BTreeMap::new();
        rotation_msgs.insert(
            NonZeroU16::new(1).unwrap(),
            crate::db::tests::create_test_message(),
        );

        db.store_encryption_key(7, &enc_key).unwrap();
        db.store_dealer_message(7, &dealer, &dealer_msg).unwrap();
        db.store_rotation_messages(7, &dealer, &rotation_msgs)
            .unwrap();
        db.store_avid_round_state(7, 0, &dealer, &avid_state)
            .unwrap();

        let mut tar_bytes = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut tar_bytes);
            append_db_backup_to_tar(
                &db,
                &mut archive,
                &backup_keyspace_archive_entries(Path::new(DB_SNAPSHOT_TAR_PREFIX)),
            )
            .unwrap();
            archive.finish().unwrap();
        }
        drop(db);

        let dest_dir = tempfile::Builder::new().tempdir().unwrap();
        let dest_path = dest_dir.path().join(DB_SNAPSHOT_TAR_PREFIX);
        let db = fjall::Database::builder(&dest_path).open().unwrap();
        let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().into_owned();
            let file_name = path.file_name().unwrap().to_str().unwrap();
            let keyspace_name = backup_keyspace_name_from_file_name(file_name).unwrap();
            restore_db_backup_keyspace(&db, keyspace_name, &mut entry).unwrap();
        }
        db.persist(fjall::PersistMode::SyncAll).unwrap();
        drop(db);

        let restored = Database::open(&dest_path).unwrap();

        assert_eq!(restored.get_encryption_key(7).unwrap().unwrap(), enc_key);
        let restored_dealer = restored.get_dealer_message(7, &dealer).unwrap().unwrap();
        assert_eq!(restored_dealer, bcs::to_bytes(&dealer_msg).unwrap());
        let restored_rotation = restored.list_all_rotation_messages(7).unwrap();
        assert_eq!(restored_rotation.len(), 1);
        assert_eq!(restored_rotation[0].0, dealer);

        assert!(
            restored
                .get_avid_round_state(7, 0, &dealer)
                .unwrap()
                .is_none(),
            "avid_round_states is not in BACKUP_KEYSPACES and must not survive a backup round trip"
        );
    }

    #[test]
    fn round_trip_succeeds_for_empty_database() {
        let src_dir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(src_dir.path()).unwrap();

        let mut tar_bytes = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut tar_bytes);
            append_db_backup_to_tar(
                &db,
                &mut archive,
                &backup_keyspace_archive_entries(Path::new(DB_SNAPSHOT_TAR_PREFIX)),
            )
            .unwrap();
            archive.finish().unwrap();
        }
        drop(db);

        let dest_dir = tempfile::Builder::new().tempdir().unwrap();
        let dest_path = dest_dir.path().join(DB_SNAPSHOT_TAR_PREFIX);
        let db = fjall::Database::builder(&dest_path).open().unwrap();
        let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().into_owned();
            let file_name = path.file_name().unwrap().to_str().unwrap();
            let keyspace_name = backup_keyspace_name_from_file_name(file_name).unwrap();
            restore_db_backup_keyspace(&db, keyspace_name, &mut entry).unwrap();
        }
        db.persist(fjall::PersistMode::SyncAll).unwrap();
        drop(db);

        let restored = Database::open(&dest_path).unwrap();
        assert!(restored.latest_encryption_key_epoch().unwrap().is_none());
        assert!(restored.list_all_dealer_messages(0).unwrap().is_empty());
        assert!(restored.list_all_rotation_messages(0).unwrap().is_empty());
    }
}
