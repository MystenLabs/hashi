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
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use tracing::info;

use age::Encryptor;

pub const BACKUP_MANIFEST_FILE_NAME: &str = "hashi-config-backup-manifest.toml";

#[derive(serde::Deserialize, serde::Serialize)]
pub struct BackupManifest {
    pub files: Vec<BackupManifestFile>,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct BackupManifestFile {
    pub archive_name: PathBuf,
    pub original_path: PathBuf,
}

pub fn build_backup_manifest(files: &[PathBuf]) -> Result<BackupManifest> {
    let mut archive_names = HashSet::new();
    let mut manifest_files = Vec::with_capacity(files.len());

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

        manifest_files.push(BackupManifestFile {
            archive_name,
            original_path: file.clone(),
        });
    }

    Ok(BackupManifest {
        files: manifest_files,
    })
}

pub fn encrypt_files_to_age_archive(
    manifest: &BackupManifest,
    recipient: &dyn age::Recipient,
    output_path: &Path,
) -> Result<()> {
    let output = File::create(output_path)
        .with_context(|| format!("Failed to create {}", output_path.display()))?;
    let encryptor = Encryptor::with_recipients(std::iter::once(recipient))?;
    let mut encrypted = encryptor.wrap_output(output)?;
    {
        let mut archive = tar::Builder::new(&mut encrypted);
        append_backup_manifest(&mut archive, manifest)?;

        for file in &manifest.files {
            archive.append_path_with_name(&file.original_path, &file.archive_name)?;
            info!(
                original = %file.original_path.display(),
                archive_name = %file.archive_name.display(),
                "Added file to backup archive",
            );
        }

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

/// Determine the directory name to extract a backup tarball into.
///
/// Uses the tarball's file name with the `.tar.age` suffix stripped, so
/// `hashi-config-backup-20260409T230419Z.tar.age` becomes
/// `hashi-config-backup-20260409T230419Z`.
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
        .unwrap_or(file_name);

    if stem.is_empty() {
        anyhow::bail!(
            "Cannot derive extract directory name from {}",
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
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&manifest_path)
        .map_err(|e| match e.kind() {
            ErrorKind::AlreadyExists => anyhow::anyhow!(
                "Refusing to overwrite existing file: {}",
                manifest_path.display()
            ),
            _ => anyhow::Error::from(e)
                .context(format!("Failed to create {}", manifest_path.display())),
        })?;
    io::Write::write_all(&mut file, manifest_toml.as_bytes())
        .with_context(|| format!("Failed to write manifest to {}", manifest_path.display()))?;
    info!(path = %manifest_path.display(), "Restored manifest");
    Ok(())
}

pub fn restore_backup_entries<R: Read>(
    entries: tar::Entries<'_, R>,
    output_dir: &Path,
    manifest: &BackupManifest,
) -> Result<HashMap<PathBuf, PathBuf>> {
    let expected_files: HashMap<_, _> = manifest
        .files
        .iter()
        .map(|file| (file.archive_name.clone(), file))
        .collect();
    let mut restored_files = HashMap::new();

    for entry in entries {
        let mut entry = entry?;
        let archive_path = entry.path()?.into_owned();
        let archive_name = PathBuf::from(archive_path.file_name().ok_or_else(|| {
            anyhow::anyhow!(
                "Backup entry does not have a file name: {}",
                archive_path.display()
            )
        })?);

        let entry_type = entry.header().entry_type();
        if entry_type != tar::EntryType::Regular {
            anyhow::bail!(
                "Backup entry {} has unexpected type {:?}; only regular files are supported",
                archive_name.display(),
                entry_type
            );
        }

        if archive_path != archive_name {
            anyhow::bail!(
                "Backup entry must be at the tar root: {}",
                archive_path.display()
            );
        }

        if !expected_files.contains_key(&archive_name) {
            anyhow::bail!(
                "Backup archive contains unexpected file: {}",
                archive_name.display()
            );
        }

        let output_path = output_dir.join(&archive_name);
        let mut output_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&output_path)
            .map_err(|e| match e.kind() {
                ErrorKind::AlreadyExists => anyhow::anyhow!(
                    "Refusing to overwrite existing file: {}",
                    output_path.display()
                ),
                _ => anyhow::Error::from(e)
                    .context(format!("Failed to create {}", output_path.display())),
            })?;
        io::copy(&mut entry, &mut output_file).with_context(|| {
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
        restored_files.insert(archive_name, output_path);
    }

    if restored_files.len() != manifest.files.len() {
        anyhow::bail!(
            "Backup archive is missing file entries: expected {}, restored {}",
            manifest.files.len(),
            restored_files.len()
        );
    }

    Ok(restored_files)
}

pub fn copy_restored_files_to_original_paths(
    restored_files: &HashMap<PathBuf, PathBuf>,
    manifest: &BackupManifest,
) -> Result<()> {
    for file in &manifest.files {
        let restored_path = restored_files.get(&file.archive_name).ok_or_else(|| {
            anyhow::anyhow!(
                "Restored file missing for archive entry {}",
                file.archive_name.display()
            )
        })?;

        if let Some(parent) = file.original_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create parent directory {}", parent.display())
            })?;
        }

        let mut source = File::open(restored_path)
            .with_context(|| format!("Failed to open {}", restored_path.display()))?;
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
