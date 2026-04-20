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
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use tracing::info;

use age::Encryptor;

pub const BACKUP_MANIFEST_FILE_NAME: &str = "hashi-config-backup-manifest.toml";
pub const DB_SNAPSHOT_TAR_PREFIX: &str = "hashi-db-snapshot";

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
    pub db_archive_entries: Vec<PathBuf>,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct BackupManifestEntry {
    pub archive_name: PathBuf,
    pub original_path: PathBuf,
}

pub fn build_backup_manifest(
    files: &[PathBuf],
    db_original_path: &Path,
    db_snapshot_dir: &Path,
) -> Result<BackupManifest> {
    let mut archive_names = HashSet::new();
    // Reserve the db snapshot prefix so a user file with the same basename
    // gets disambiguated instead of silently colliding with the db entry.
    archive_names.insert(DB_SNAPSHOT_TAR_PREFIX.to_string());
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

    manifest_paths.push(BackupManifestEntry {
        archive_name: PathBuf::from(DB_SNAPSHOT_TAR_PREFIX),
        original_path: db_original_path.to_path_buf(),
    });

    Ok(BackupManifest {
        paths: manifest_paths,
        db_archive_entries: collect_db_archive_entries(
            db_snapshot_dir,
            Path::new(DB_SNAPSHOT_TAR_PREFIX),
        )?,
    })
}

fn collect_db_archive_entries(src_dir: &Path, tar_prefix: &Path) -> Result<Vec<PathBuf>> {
    let mut archive_entries = Vec::new();

    for entry in walkdir::WalkDir::new(src_dir).min_depth(1) {
        let entry = entry.with_context(|| {
            format!(
                "Failed to walk database snapshot directory {}",
                src_dir.display()
            )
        })?;

        if entry.file_type().is_symlink() {
            anyhow::bail!(
                "Refusing to archive symlink inside database snapshot directory: {}",
                entry.path().display()
            );
        }

        let relative = entry
            .path()
            .strip_prefix(src_dir)
            .expect("walkdir entry is always under src_dir");
        archive_entries.push(tar_prefix.join(relative));
    }

    archive_entries.sort();
    Ok(archive_entries)
}

pub fn encrypt_files_to_age_archive(
    manifest: &BackupManifest,
    db_snapshot_dir: &Path,
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
            if entry.archive_name == Path::new(DB_SNAPSHOT_TAR_PREFIX) {
                continue;
            }
            archive.append_path_with_name(&entry.original_path, &entry.archive_name)?;
            info!(
                original = %entry.original_path.display(),
                archive_name = %entry.archive_name.display(),
                "Added file to backup archive",
            );
        }

        append_dir_recursive(
            &mut archive,
            db_snapshot_dir,
            Path::new(DB_SNAPSHOT_TAR_PREFIX),
        )?;
        info!("Added database snapshot to backup archive");

        archive.finish()?;
    }
    encrypted.finish()?;

    Ok(())
}

/// Recursively append all files under `src_dir` into the tar archive under
/// `tar_prefix`. For example, if `src_dir` contains `file.sst` and
/// `tar_prefix` is `db`, the archive entry will be `db/file.sst`.
///
/// Symlinks are rejected: fjall does not create them in its data directories,
/// so the presence of one is either tampering or misconfiguration, and the
/// restore path does not currently handle symlink tar entries correctly.
fn append_dir_recursive<W: std::io::Write>(
    archive: &mut tar::Builder<W>,
    src_dir: &Path,
    tar_prefix: &Path,
) -> Result<()> {
    for entry in walkdir::WalkDir::new(src_dir).min_depth(1) {
        let entry = entry.with_context(|| {
            format!(
                "Failed to walk database snapshot directory {}",
                src_dir.display()
            )
        })?;

        if entry.file_type().is_symlink() {
            anyhow::bail!(
                "Refusing to archive symlink inside database snapshot directory: {}",
                entry.path().display()
            );
        }

        let relative = entry
            .path()
            .strip_prefix(src_dir)
            .expect("walkdir entry is always under src_dir");
        let archive_path = tar_prefix.join(relative);

        if entry.file_type().is_dir() {
            archive.append_dir(&archive_path, entry.path())?;
        } else {
            archive.append_path_with_name(entry.path(), &archive_path)?;
        }
    }
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
        .filter(|entry| entry.archive_name != db_prefix)
        .map(|entry| entry.archive_name.clone())
        .collect();
    let expected_db_entries: HashSet<PathBuf> =
        manifest.db_archive_entries.iter().cloned().collect();
    let mut restored_db_entries = HashSet::new();
    let mut restored_count: usize = 0;

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
            restore_db_entry(&mut entry, &archive_path, output_dir)?;
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

    Ok(())
}

/// Extract a single tar entry that lives under the db/ prefix into
/// `output_dir`, preserving the relative directory structure. Directory
/// entries are created (recursively, since the tar may stream them in any
/// order); file entries are written with mode 0o600.
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

    if archive_path
        .components()
        .skip(1)
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        anyhow::bail!(
            "Database entry must not contain `..`, `.`, or absolute path components: {}",
            archive_path.display()
        );
    }

    Ok(())
}

fn restore_db_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    archive_path: &Path,
    output_dir: &Path,
) -> Result<()> {
    let output_path = output_dir.join(archive_path);
    if entry.header().entry_type() == tar::EntryType::Directory {
        fs::create_dir_all(&output_path)
            .with_context(|| format!("Failed to create directory {}", output_path.display()))?;
        return Ok(());
    }

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }
    let mut output_file = create_file_strict(&output_path)?;
    io::copy(entry, &mut output_file).with_context(|| {
        format!(
            "Failed to write restored file contents to {}",
            output_path.display()
        )
    })?;
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
/// with each entry's `archive_name` to find the source. The DB entry is
/// skipped — restoring the snapshot dir is handled by
/// [`copy_db_snapshot_to_original_path`].
pub fn copy_restored_files_to_original_paths(
    extract_dir: &Path,
    manifest: &BackupManifest,
) -> Result<()> {
    let db_prefix = Path::new(DB_SNAPSHOT_TAR_PREFIX);

    for file in manifest
        .paths
        .iter()
        .filter(|entry| entry.archive_name != db_prefix)
    {
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
/// Looks up the DB entry in the manifest to determine the original path,
/// then recursively copies the extracted `db/` directory into a sibling
/// staging directory and renames it into place on success. The rename is
/// atomic on a single filesystem, so a crash mid-copy leaves the staging
/// directory behind without ever creating a half-populated DB at `dest`.
/// The staging directory is created with `tempdir_in(dest.parent())`, so it
/// lives on the same filesystem as `dest`; that same-filesystem placement is
/// required because `rename` does not work across mount points.
///
/// Fails if `dest` already exists.
pub fn copy_db_snapshot_to_original_path(
    extract_dir: &Path,
    manifest: &BackupManifest,
) -> Result<()> {
    let db_prefix = Path::new(DB_SNAPSHOT_TAR_PREFIX);
    let db_entry = manifest
        .paths
        .iter()
        .find(|entry| entry.archive_name == db_prefix)
        .ok_or_else(|| anyhow::anyhow!("Backup manifest does not contain a database entry"))?;

    let source = extract_dir.join(DB_SNAPSHOT_TAR_PREFIX);
    let dest = &db_entry.original_path;

    // Pre-flight: refuse early if the destination already exists. This is
    // checked again implicitly by the final rename, but failing here gives a
    // clear error before doing all the copy work.
    if dest
        .try_exists()
        .with_context(|| format!("Failed to stat database destination {}", dest.display()))?
    {
        anyhow::bail!(
            "Refusing to overwrite existing database directory: {}",
            dest.display()
        );
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

    fn create_empty_db_snapshot_dir() -> tempfile::TempDir {
        let parent = tempfile::tempdir().unwrap();
        fs::create_dir(parent.path().join("db")).unwrap();
        parent
    }

    fn db_only_manifest(db_archive_entries: Vec<PathBuf>) -> BackupManifest {
        BackupManifest {
            paths: vec![BackupManifestEntry {
                archive_name: PathBuf::from(DB_SNAPSHOT_TAR_PREFIX),
                original_path: PathBuf::from("/var/lib/hashi/db"),
            }],
            db_archive_entries,
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
        // must be renamed so it doesn't collide with the db snapshot entry.
        let files = vec![PathBuf::from("/etc/hashi/hashi-db-snapshot")];
        let db_path = PathBuf::from("/var/lib/hashi/db");
        let snapshot_parent = create_empty_db_snapshot_dir();

        let manifest =
            build_backup_manifest(&files, &db_path, &snapshot_parent.path().join("db")).unwrap();

        assert_eq!(manifest.paths.len(), 2);
        assert!(manifest.db_archive_entries.is_empty());

        // The user's file should have been renamed away from the reserved prefix.
        let user_entry = &manifest.paths[0];
        assert_eq!(
            user_entry.original_path,
            PathBuf::from("/etc/hashi/hashi-db-snapshot")
        );
        assert_ne!(
            user_entry.archive_name,
            PathBuf::from(DB_SNAPSHOT_TAR_PREFIX)
        );
        assert_eq!(
            user_entry.archive_name,
            PathBuf::from("hashi-db-snapshot-2")
        );

        // The db snapshot entry should still own the reserved prefix.
        let db_entry = &manifest.paths[1];
        assert_eq!(db_entry.archive_name, PathBuf::from(DB_SNAPSHOT_TAR_PREFIX));
        assert_eq!(db_entry.original_path, db_path);
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
        let snapshot_parent = create_empty_db_snapshot_dir();

        let manifest =
            build_backup_manifest(&files, &db_path, &snapshot_parent.path().join("db")).unwrap();

        assert_eq!(manifest.paths.len(), 3);
        assert!(manifest.db_archive_entries.is_empty());
        assert_eq!(
            manifest.paths[0].archive_name,
            PathBuf::from("hashi-db-snapshot-2")
        );
        assert_eq!(
            manifest.paths[1].archive_name,
            PathBuf::from("hashi-db-snapshot-2-2")
        );
        assert_eq!(
            manifest.paths[2].archive_name,
            PathBuf::from(DB_SNAPSHOT_TAR_PREFIX)
        );
    }

    #[test]
    fn manifest_records_db_archive_entries() {
        let files = Vec::new();
        let db_path = PathBuf::from("/var/lib/hashi/db");
        let snapshot_parent = tempfile::tempdir().unwrap();
        let snapshot_dir = snapshot_parent.path().join("db");
        fs::create_dir(&snapshot_dir).unwrap();
        fs::create_dir(snapshot_dir.join("partitions")).unwrap();
        fs::write(snapshot_dir.join("CURRENT"), b"manifest").unwrap();
        fs::write(snapshot_dir.join("partitions").join("0001.sst"), b"sst").unwrap();

        let manifest = build_backup_manifest(&files, &db_path, &snapshot_dir).unwrap();

        assert_eq!(
            manifest.db_archive_entries,
            vec![
                PathBuf::from("hashi-db-snapshot/CURRENT"),
                PathBuf::from("hashi-db-snapshot/partitions"),
                PathBuf::from("hashi-db-snapshot/partitions/0001.sst"),
            ]
        );
    }

    #[test]
    fn restore_backup_entries_rejects_missing_db_entries() {
        let manifest = db_only_manifest(vec![PathBuf::from("hashi-db-snapshot/CURRENT")]);
        let tar_bytes = build_archive_bytes(&manifest, &[]);
        let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
        let mut entries = archive.entries().unwrap();
        let manifest_entry = entries.next().unwrap().unwrap();
        let (parsed_manifest, _) = read_backup_manifest(manifest_entry).unwrap();
        let output_dir = tempfile::tempdir().unwrap();

        let err = restore_backup_entries(entries, output_dir.path(), &parsed_manifest).unwrap_err();

        assert!(
            err.to_string()
                .contains("Backup archive is missing database entries: hashi-db-snapshot/CURRENT")
        );
    }

    #[test]
    fn restore_backup_entries_rejects_unexpected_db_entries() {
        let manifest = db_only_manifest(vec![PathBuf::from("hashi-db-snapshot/CURRENT")]);
        let tar_bytes = build_archive_bytes(
            &manifest,
            &[
                ("hashi-db-snapshot/CURRENT", b"ok"),
                ("hashi-db-snapshot/EXTRA", b"nope"),
            ],
        );
        let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
        let mut entries = archive.entries().unwrap();
        let manifest_entry = entries.next().unwrap().unwrap();
        let (parsed_manifest, _) = read_backup_manifest(manifest_entry).unwrap();
        let output_dir = tempfile::tempdir().unwrap();

        let err = restore_backup_entries(entries, output_dir.path(), &parsed_manifest).unwrap_err();

        assert!(err.to_string().contains(
            "Backup archive contains unexpected database entry: hashi-db-snapshot/EXTRA"
        ));
    }

    #[test]
    fn restore_backup_entries_rejects_db_parent_dir_traversal() {
        let err = validate_db_archive_path(Path::new("hashi-db-snapshot/../escape")).unwrap_err();

        assert!(
            err.to_string()
                .contains("Database entry must not contain `..`, `.`, or absolute path components")
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
}
