// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Core backup logic for creating and restoring encrypted backup archives.
//!
//! This module handles the mechanics of building backup manifests, encrypting
//! files into age-wrapped tar archives, and extracting them. CLI-specific
//! orchestration (config loading, recipient resolution, user output) lives in
//! [`crate::cli::commands::backup`].

use anyhow::Context;
use anyhow::Result;
use std::collections::HashSet;
use std::fmt;
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
use std::str::FromStr;
use tracing::info;

use crate::db::Database;

use age::Encryptor;
use age::plugin;
use age::x25519;
use fjall::KeyspaceCreateOptions;
use fjall::Readable;

pub const BACKUP_MANIFEST_FILE_NAME: &str = "hashi-config-backup-manifest.toml";
pub const DB_SNAPSHOT_TAR_PREFIX: &str = "hashi-db-snapshot";

/// An age recipient that can be used as the target of a backup.
///
/// Supports both native x25519 recipients (`age1...`) and plugin recipients
/// (`age1<plugin-name>1...`, e.g. `age1yubikey1...`). Plugin recipients are only
/// resolved against a plugin binary at encryption time, so storing one in the
/// config does not require the plugin to be installed.
#[derive(Clone)]
pub enum BackupRecipient {
    Native(x25519::Recipient),
    Plugin(plugin::Recipient),
}

impl FromStr for BackupRecipient {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(recipient) = x25519::Recipient::from_str(s) {
            return Ok(Self::Native(recipient));
        }
        match plugin::Recipient::from_str(s) {
            Ok(recipient) => Ok(Self::Plugin(recipient)),
            Err(plugin_err) => anyhow::bail!(
                "failed to parse age recipient '{s}': not a valid x25519 recipient, and not a valid plugin recipient ({plugin_err})"
            ),
        }
    }
}

impl fmt::Display for BackupRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(r) => write!(f, "{r}"),
            Self::Plugin(r) => write!(f, "{r}"),
        }
    }
}

impl fmt::Debug for BackupRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BackupRecipient({self})")
    }
}

pub mod optional_age_recipient {
    use super::BackupRecipient;
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;
    use std::str::FromStr;

    pub fn serialize<S>(value: &Option<BackupRecipient>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(recipient) => serializer.serialize_some(&recipient.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<BackupRecipient>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .map(|value| BackupRecipient::from_str(&value).map_err(serde::de::Error::custom))
            .transpose()
    }
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

/// Create directory `path` non-recursively, failing if anything already
/// exists at that exact location. Caller is responsible for ensuring the
/// parent exists.
fn create_dir_strict(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(false)
        .create(path)
        .map_err(|e| match e.kind() {
            ErrorKind::AlreadyExists => {
                anyhow::anyhow!(
                    "Refusing to overwrite existing directory: {}",
                    path.display()
                )
            }
            _ => anyhow::Error::from(e)
                .context(format!("Failed to create directory {}", path.display())),
        })
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct BackupManifest {
    pub paths: Vec<BackupManifestEntry>,
    pub db: DbManifestEntry,
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
        db: DbManifestEntry {
            original_path: db_original_path.to_path_buf(),
            archive_entries: db_archive_entries,
        },
    })
}

pub fn encrypt_files_to_age_archive(
    manifest: &BackupManifest,
    db: &Database,
    recipient: &dyn age::Recipient,
    output_path: &Path,
) -> Result<()> {
    let output = create_file_strict(output_path)?;
    let encryptor = Encryptor::with_recipients(std::iter::once(recipient))?;
    let mut encrypted = encryptor.wrap_output(output)?;
    {
        let mut archive = tar::Builder::new(&mut encrypted);
        append_backup_manifest(&mut archive, manifest)?;

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
    encrypted.finish()?;

    Ok(())
}

pub fn encrypted_backup_file_name() -> PathBuf {
    // ISO 8601 basic format in UTC, e.g. 20260409T230419Z. Compact, sorts
    // lexicographically, and contains no characters that need escaping on any
    // common filesystem.
    let timestamp = jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .strftime("%Y%m%dT%H%M%SZ")
        .to_string();
    PathBuf::from(format!("hashi-config-backup-{timestamp}.tar.age"))
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

/// Determine the directory name to extract a backup tarball into.
///
/// Strips the `.tar.age` or `.age` suffix from the tarball's file name, so
/// `hashi-config-backup-20260409T230419Z.tar.age` becomes
/// `hashi-config-backup-20260409T230419Z`. An input without one of those
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

    let stem = file_name
        .strip_suffix(".tar.age")
        .or_else(|| file_name.strip_suffix(".age"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Backup tarball must have a .tar.age or .age suffix: {}",
                backup_tarball.display()
            )
        })?;

    // Require the stem to be exactly one plain directory component when
    // joined under the user's output dir. Catches both the empty case (zero
    // components) and traversal attempts like `../../tmp/pwn.tar.age` (a
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
    let file_name = path.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "First tar entry does not have a file name: {}",
            path.display()
        )
    })?;
    if file_name != BACKUP_MANIFEST_FILE_NAME {
        anyhow::bail!(
            "Expected backup manifest {} as the first tar entry, found {}",
            BACKUP_MANIFEST_FILE_NAME,
            path.display()
        );
    }

    let mut manifest_toml = String::new();
    entry.read_to_string(&mut manifest_toml)?;
    let manifest: BackupManifest = toml::from_str(&manifest_toml)?;

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

        if archive_path.starts_with(db_prefix) {
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

/// Copy each restored config file from the extract directory to its original
/// path as recorded in the manifest. Refuses to overwrite anything.
///
/// `extract_dir` is where the tarball was unpacked; this function joins it
/// with each entry's `archive_name` to find the source. The reconstructed
/// database directory is restored separately by
/// [`copy_db_snapshot_to_original_path`].
pub fn copy_restored_files_to_original_paths(
    extract_dir: &Path,
    manifest: &BackupManifest,
) -> Result<()> {
    for file in manifest.paths.iter() {
        let restored_path = extract_dir.join(&file.archive_name);

        if let Some(parent) = file.original_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create parent directory {}", parent.display())
            })?;
        }

        let mut source = File::open(&restored_path)
            .with_context(|| format!("Failed to open {}", restored_path.display()))?;
        // Custom AlreadyExists message: "original path" hints that the
        // collision is with a path the manifest pointed at, not a freshly
        // chosen output location.
        let mut dest = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&file.original_path)
            .map_err(|e| match e.kind() {
                ErrorKind::AlreadyExists => anyhow::anyhow!(
                    "Refusing to overwrite existing original path: {}",
                    file.original_path.display()
                ),
                _ => anyhow::Error::from(e)
                    .context(format!("Failed to create {}", file.original_path.display())),
            })?;
        io::copy(&mut source, &mut dest).with_context(|| {
            format!(
                "Failed to copy {} to {}",
                restored_path.display(),
                file.original_path.display()
            )
        })?;
        info!(
            from = %restored_path.display(),
            to = %file.original_path.display(),
            "Copied restored file to original path",
        );
    }

    Ok(())
}

/// Copy the extracted database snapshot directory to its original path.
///
/// The reconstructed fjall DB directory at
/// `extract_dir / DB_SNAPSHOT_TAR_PREFIX` is recursively copied into a
/// sibling staging directory of the manifest's DB original path and then
/// renamed into place on success. The rename is atomic on a single
/// filesystem, so a crash mid-copy leaves the staging directory behind
/// without ever creating a half-populated DB at `dest`. The staging
/// directory is created with `tempdir_in(dest.parent())`, so it lives on
/// the same filesystem as `dest`; that same-filesystem placement is
/// required because `rename` does not work across mount points.
///
/// If `dest` already exists, it must be an empty directory. This supports
/// restoring into mounted volume roots that cannot be deleted, while still
/// refusing to merge restored database state with existing files.
pub fn copy_db_snapshot_to_original_path(
    extract_dir: &Path,
    manifest: &BackupManifest,
) -> Result<()> {
    let source = extract_dir.join(DB_SNAPSHOT_TAR_PREFIX);
    let dest = &manifest.db.original_path;

    if dest
        .try_exists()
        .with_context(|| format!("Failed to stat database destination {}", dest.display()))?
    {
        if !dest.is_dir() {
            anyhow::bail!(
                "Refusing to overwrite existing database path: {}",
                dest.display()
            );
        }
        if fs::read_dir(dest)
            .with_context(|| format!("Failed to read database directory {}", dest.display()))?
            .next()
            .transpose()?
            .is_some()
        {
            anyhow::bail!(
                "Refusing to restore database into non-empty directory: {}",
                dest.display()
            );
        }

        copy_dir_recursive_strict(&source, dest).with_context(|| {
            format!(
                "Failed to copy database snapshot from {} to empty destination {}",
                source.display(),
                dest.display()
            )
        })?;

        info!(
            from = %source.display(),
            to = %dest.display(),
            "Copied database snapshot to empty original path",
        );

        return Ok(());
    }

    let parent = dest.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "Database destination has no parent directory: {}",
            dest.display()
        )
    })?;
    fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create parent directory {}", parent.display()))?;

    // Stage into a sibling temp directory so the entire copy is invisible
    // until the final rename. Using a sibling guarantees we're on the same
    // filesystem, which is required for `rename` to be atomic.
    let staging = tempfile::Builder::new()
        .prefix(".hashi-db-restore-")
        .tempdir_in(parent)
        .with_context(|| {
            format!(
                "Failed to create db staging directory in {}",
                parent.display()
            )
        })?;

    copy_dir_recursive_strict(&source, staging.path()).with_context(|| {
        format!(
            "Failed to copy database snapshot from {} to staging directory {}",
            source.display(),
            staging.path().display()
        )
    })?;

    // Convert the TempDir into an owned path before rename so we can do
    // explicit best-effort cleanup ourselves if the rename fails.
    let staging_path = staging.keep();
    // `staging_path` was created as a sibling of `dest`, so this rename stays
    // on one filesystem rather than crossing mounts; `fs::rename` does not
    // work across mount points.
    fs::rename(&staging_path, dest).map_err(|e| {
        // Best-effort cleanup of the staging directory if the rename failed,
        // since `into_path` consumed the auto-deleting guard.
        let _ = fs::remove_dir_all(&staging_path);
        match e.kind() {
            ErrorKind::AlreadyExists => anyhow::anyhow!(
                "Refusing to overwrite existing database directory: {}",
                dest.display()
            ),
            _ => anyhow::Error::from(e).context(format!(
                "Failed to move staged database into place at {}",
                dest.display()
            )),
        }
    })?;

    info!(
        from = %source.display(),
        to = %dest.display(),
        "Copied database snapshot to original path",
    );

    Ok(())
}

/// Recursively copy a directory tree from `src` to `dest` without ever
/// overwriting existing files.
///
/// - The root `dest` is assumed to have already been created by the caller.
/// - Subdirectories below the root use `create_dir` (non-recursive), so any
///   collision surfaces as an error rather than merging into existing state.
/// - Files are opened with `create_new(true)` and mode `0o600`, matching the
///   protection `copy_restored_files_to_original_paths` applies to config
///   files. fjall on-disk files are not sensitive individually, but we keep
///   the mode consistent so the restored DB never advertises looser
///   permissions than the backup did.
/// - Symlinks are rejected outright.
fn copy_dir_recursive_strict(src: &Path, dest: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(src).min_depth(1) {
        let entry = entry?;

        if entry.file_type().is_symlink() {
            anyhow::bail!(
                "Refusing to restore symlink from database snapshot: {}",
                entry.path().display()
            );
        }

        let relative = entry.path().strip_prefix(src).expect("walkdir under src");
        let target = dest.join(relative);

        if entry.file_type().is_dir() {
            create_dir_strict(&target)?;
        } else {
            let mut source_file = File::open(entry.path())
                .with_context(|| format!("Failed to open {}", entry.path().display()))?;
            let mut dest_file = create_file_strict(&target)?;
            io::copy(&mut source_file, &mut dest_file).with_context(|| {
                format!(
                    "Failed to copy {} to {}",
                    entry.path().display(),
                    target.display()
                )
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn db_only_manifest() -> BackupManifest {
        BackupManifest {
            paths: Vec::new(),
            db: DbManifestEntry {
                original_path: PathBuf::from("/var/lib/hashi/db"),
                archive_entries: backup_keyspace_archive_entries(Path::new(DB_SNAPSHOT_TAR_PREFIX)),
            },
        }
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
    fn round_trip_covers_all_backed_up_keyspaces_and_excludes_nonces() {
        use hashi_types::committee::EncryptionPrivateKey;
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        // Populate every keyspace we care about, including the one that
        // must NOT survive a backup round trip (nonce_messages).
        let src_dir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(src_dir.path()).unwrap();
        let dealer = sui_sdk_types::Address::new([3u8; 32]);
        let enc_key = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let dealer_msg = crate::db::tests::create_test_message();
        let nonce_msg = crate::db::tests::create_test_nonce_message();
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
        db.store_nonce_message(7, 0, &dealer, &nonce_msg).unwrap();

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

        // All three backed-up keyspaces survive intact.
        assert_eq!(restored.get_encryption_key(7).unwrap().unwrap(), enc_key);
        let restored_dealer = restored.get_dealer_message(7, &dealer).unwrap().unwrap();
        assert_eq!(
            bcs::to_bytes(&restored_dealer).unwrap(),
            bcs::to_bytes(&dealer_msg).unwrap()
        );
        let restored_rotation = restored.list_all_rotation_messages(7).unwrap();
        assert_eq!(restored_rotation.len(), 1);
        assert_eq!(restored_rotation[0].0, dealer);

        // nonce_messages must NOT come through the backup.
        assert!(
            restored.get_nonce_message(7, 0, &dealer).unwrap().is_none(),
            "nonce_messages keyspace must not be included in backups"
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
