// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Backup command implementations

use age::Decryptor;
use age::Encryptor;
use age::IdentityFile;
use age::cli_common::UiCallbacks;
use age::plugin;
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
use std::str::FromStr;

use crate::cli::config::BackupRecipient;
use crate::cli::config::CliConfig;
use crate::cli::print_info;
use crate::cli::print_success;

const BACKUP_MANIFEST_FILE_NAME: &str = "hashi-config-backup-manifest.toml";

#[derive(serde::Deserialize, serde::Serialize)]
struct BackupManifest {
    files: Vec<BackupManifestFile>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct BackupManifestFile {
    archive_name: PathBuf,
    original_path: PathBuf,
}

/// Save an encrypted backup of the current config and referenced files
pub fn save(
    config: &CliConfig,
    backup_age_pubkey_override: Option<String>,
    output_dir: &Path,
) -> Result<()> {
    let recipient = backup_age_pubkey_override
        .map(|value| BackupRecipient::from_str(&value))
        .transpose()?
        .or_else(|| config.backup_age_pubkey.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No age public key configured. Pass --backup-age-pubkey or set backup_age_pubkey in the config file."
            )
        })?;

    if config.loaded_from_path.is_none() {
        anyhow::bail!(
            "No config file is currently in use. Pass --config with a config file path before running backup."
        );
    }

    let files = config.backup_file_paths();

    for file in &files {
        if !file.exists() {
            anyhow::bail!("Backup input does not exist: {}", file.display());
        }
    }

    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory {}", output_dir.display()))?;

    let manifest = build_backup_manifest(&files)?;

    print_info(&format!(
        "Backing up {} file(s) using age recipient {}",
        files.len(),
        recipient
    ));

    let encryptor_recipient = build_encryptor_recipient(&recipient)?;

    let output_path = output_dir.join(encrypted_backup_file_name());
    encrypt_files_to_age_archive(&manifest, encryptor_recipient.as_ref(), &output_path)?;

    print_success(&format!("Backup completed: {}", output_path.display()));

    Ok(())
}

/// Materialize a `BackupRecipient` into a concrete `age::Recipient` trait object
/// suitable for passing to `Encryptor::with_recipients`.
///
/// For plugin recipients, this is where `age-plugin-<name>` is looked up on
/// `$PATH`, so this call will fail if the plugin binary is not installed.
fn build_encryptor_recipient(recipient: &BackupRecipient) -> Result<Box<dyn age::Recipient>> {
    match recipient {
        BackupRecipient::Native(r) => Ok(Box::new(r.clone())),
        BackupRecipient::Plugin(r) => {
            let plugin_name = r.plugin().to_string();
            let recipient_plugin =
                plugin::RecipientPluginV1::new(&plugin_name, std::slice::from_ref(r), &[], UiCallbacks)
                    .with_context(|| {
                        format!(
                            "Failed to initialize age plugin '{plugin_name}'. Is `age-plugin-{plugin_name}` installed and on $PATH?"
                        )
                    })?;
            Ok(Box::new(recipient_plugin))
        }
    }
}

pub fn restore(
    backup_tarball: &Path,
    backup_age_identity: &Path,
    output_dir: &Path,
    copy_to_original_paths: bool,
) -> Result<()> {
    let identities = load_backup_identities(backup_age_identity)?;

    let extract_dir = output_dir.join(extract_dir_name(backup_tarball)?);
    fs::create_dir_all(&extract_dir).with_context(|| {
        format!(
            "Failed to create output directory {}",
            extract_dir.display()
        )
    })?;

    let input = File::open(backup_tarball)
        .with_context(|| format!("Failed to open backup tarball {}", backup_tarball.display()))?;
    let decryptor = Decryptor::new(input)
        .with_context(|| format!("Failed to parse age header of {}", backup_tarball.display()))?;
    let mut decrypted = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))
        .with_context(|| {
            format!(
                "Failed to decrypt {}; is {} the correct age identity?",
                backup_tarball.display(),
                backup_age_identity.display()
            )
        })?;
    let mut archive = tar::Archive::new(&mut decrypted);
    let mut entries = archive.entries()?;
    let manifest_entry = entries
        .next()
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!("Backup archive is empty"))?;
    let (manifest, manifest_toml) = read_backup_manifest(manifest_entry)?;
    write_manifest_to_extract_dir(&extract_dir, &manifest_toml)?;
    let restored_files = restore_backup_entries(entries, &extract_dir, &manifest)?;

    if copy_to_original_paths {
        copy_restored_files_to_original_paths(&restored_files, &manifest)?;
    }

    print_success(&format!(
        "Restore completed from {} into {}",
        backup_tarball.display(),
        extract_dir.display()
    ));

    Ok(())
}

/// Determine the directory name to extract a backup tarball into.
///
/// Uses the tarball's file name with the `.tar.age` suffix stripped, so
/// `hashi-config-backup-20260409T230419Z.tar.age` becomes
/// `hashi-config-backup-20260409T230419Z`.
fn extract_dir_name(backup_tarball: &Path) -> Result<PathBuf> {
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

/// Write the raw manifest TOML into the extract directory so the user can
/// inspect it alongside the restored files.
fn write_manifest_to_extract_dir(extract_dir: &Path, manifest_toml: &str) -> Result<()> {
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
    print_info(&format!("Restored manifest to {}", manifest_path.display()));
    Ok(())
}

fn encrypt_files_to_age_archive(
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
            print_info(&format!(
                "Added {} to {}",
                file.original_path.display(),
                file.archive_name.display()
            ));
        }

        archive.finish()?;
    }
    encrypted.finish()?;

    Ok(())
}

fn encrypted_backup_file_name() -> PathBuf {
    // ISO 8601 basic format in UTC, e.g. 20260409T230419Z. Compact, sorts
    // lexicographically, and contains no characters that need escaping on any
    // common filesystem.
    let timestamp = jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .strftime("%Y%m%dT%H%M%SZ")
        .to_string();
    PathBuf::from(format!("hashi-config-backup-{timestamp}.tar.age"))
}

fn build_backup_manifest(files: &[PathBuf]) -> Result<BackupManifest> {
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
                    print_info(&format!(
                        "Archive name collision for {base_name}: renamed to {candidate} (original: {})",
                        file.display()
                    ));
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

fn load_backup_identities(
    backup_age_identity: &Path,
) -> Result<Vec<Box<dyn age::Identity + Send + Sync>>> {
    let path_str = backup_age_identity.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "Age identity path is not valid UTF-8: {}",
            backup_age_identity.display()
        )
    })?;
    IdentityFile::from_file(path_str.to_string())?
        .with_callbacks(UiCallbacks)
        .into_identities()
        .map_err(Into::into)
}

fn read_backup_manifest<R: Read>(mut entry: tar::Entry<'_, R>) -> Result<(BackupManifest, String)> {
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

fn restore_backup_entries<R: Read>(
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
        print_info(&format!(
            "Restored {} to {}",
            archive_name.display(),
            output_path.display()
        ));
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

fn copy_restored_files_to_original_paths(
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
        print_info(&format!(
            "Copied {} to {}",
            restored_path.display(),
            file.original_path.display()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config::BitcoinConfig;
    use age::secrecy::ExposeSecret;
    use age::x25519;
    use tempfile::TempDir;

    const CONFIG_CONTENTS: &[u8] = b"sui_rpc_url = \"https://fullnode.mainnet.sui.io:443\"\n";
    const KEYPAIR_CONTENTS: &[u8] = b"test-ed25519-keypair-bytes";
    const BTC_KEY_CONTENTS: &[u8] = b"test-bitcoin-wif-bytes";

    /// Fixture holding a populated source directory and a matching CliConfig.
    struct TestFixture {
        _src: TempDir,
        config: CliConfig,
        config_path: PathBuf,
        keypair_path: PathBuf,
        btc_key_path: PathBuf,
    }

    impl TestFixture {
        /// Create a new fixture with a config file and two referenced key files on disk.
        fn new() -> Self {
            let src = tempfile::Builder::new().tempdir().unwrap();
            let config_path = src.path().join("hashi-cli.toml");
            let keypair_path = src.path().join("keypair.pem");
            let btc_key_path = src.path().join("btc.wif");

            fs::write(&config_path, CONFIG_CONTENTS).unwrap();
            fs::write(&keypair_path, KEYPAIR_CONTENTS).unwrap();
            fs::write(&btc_key_path, BTC_KEY_CONTENTS).unwrap();

            let config = CliConfig {
                loaded_from_path: Some(config_path.clone()),
                keypair_path: Some(keypair_path.clone()),
                bitcoin: Some(BitcoinConfig {
                    private_key_path: Some(btc_key_path.clone()),
                    ..BitcoinConfig::default()
                }),
                ..CliConfig::default()
            };

            Self {
                _src: src,
                config,
                config_path,
                keypair_path,
                btc_key_path,
            }
        }
    }

    /// State produced by a successful `save` call, ready for a follow-up `restore`.
    struct SavedBackup {
        _dir: TempDir,
        tarball: PathBuf,
        identity_file: PathBuf,
    }

    /// Run `save` with a freshly generated age identity and return everything `restore` needs.
    fn save_with_fresh_identity(config: &CliConfig) -> SavedBackup {
        let dir = tempfile::Builder::new().tempdir().unwrap();

        let identity = x25519::Identity::generate();
        let recipient = identity.to_public();

        save(config, Some(recipient.to_string()), dir.path()).unwrap();

        let tarball = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.extension().and_then(|ext| ext.to_str()) == Some("age")
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(|name| name.starts_with("hashi-config-backup-"))
                        .unwrap_or(false)
            })
            .expect("save() did not produce a tarball");

        let identity_file = dir.path().join("identity.txt");
        fs::write(&identity_file, identity.to_string().expose_secret()).unwrap();

        SavedBackup {
            _dir: dir,
            tarball,
            identity_file,
        }
    }

    fn assert_file_eq(path: &Path, expected: &[u8]) {
        let actual =
            fs::read(path).unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        assert_eq!(
            actual,
            expected,
            "contents of {} did not match expected",
            path.display()
        );
    }

    fn assert_mode_0600(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o600,
            "{} has mode {:o}, expected 600",
            path.display(),
            mode
        );
    }

    /// Compute the nested directory that `restore` will extract into, given the
    /// tarball path and the user-supplied output directory.
    fn expected_extract_dir(tarball: &Path, output_dir: &Path) -> PathBuf {
        output_dir.join(super::extract_dir_name(tarball).unwrap())
    }

    #[test]
    fn round_trip_restores_files_to_output_dir() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_identity(&fixture.config);

        let out = tempfile::Builder::new().tempdir().unwrap();
        restore(&backup.tarball, &backup.identity_file, out.path(), false).unwrap();

        let extract_dir = expected_extract_dir(&backup.tarball, out.path());
        assert_file_eq(&extract_dir.join("hashi-cli.toml"), CONFIG_CONTENTS);
        assert_file_eq(&extract_dir.join("keypair.pem"), KEYPAIR_CONTENTS);
        assert_file_eq(&extract_dir.join("btc.wif"), BTC_KEY_CONTENTS);

        // All restored files should be owner-only read/write.
        assert_mode_0600(&extract_dir.join("hashi-cli.toml"));
        assert_mode_0600(&extract_dir.join("keypair.pem"));
        assert_mode_0600(&extract_dir.join("btc.wif"));

        // The manifest should also be extracted alongside the restored files.
        let manifest_path = extract_dir.join(BACKUP_MANIFEST_FILE_NAME);
        assert!(
            manifest_path.exists(),
            "manifest not extracted to {}",
            manifest_path.display()
        );
        assert_mode_0600(&manifest_path);
        let manifest_toml = fs::read_to_string(&manifest_path).unwrap();
        assert!(
            manifest_toml.contains("hashi-cli.toml"),
            "extracted manifest missing expected entries: {manifest_toml}"
        );
    }

    #[test]
    fn round_trip_copy_to_original_paths_rewrites_originals() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_identity(&fixture.config);

        // Delete the originals so copy_to_original_paths can recreate them.
        fs::remove_file(&fixture.config_path).unwrap();
        fs::remove_file(&fixture.keypair_path).unwrap();
        fs::remove_file(&fixture.btc_key_path).unwrap();

        let out = tempfile::Builder::new().tempdir().unwrap();
        restore(&backup.tarball, &backup.identity_file, out.path(), true).unwrap();

        // Both the nested extraction dir and the originals should now hold the right bytes.
        let extract_dir = expected_extract_dir(&backup.tarball, out.path());
        assert_file_eq(&extract_dir.join("hashi-cli.toml"), CONFIG_CONTENTS);
        assert_file_eq(&extract_dir.join("keypair.pem"), KEYPAIR_CONTENTS);
        assert_file_eq(&extract_dir.join("btc.wif"), BTC_KEY_CONTENTS);

        assert_file_eq(&fixture.config_path, CONFIG_CONTENTS);
        assert_file_eq(&fixture.keypair_path, KEYPAIR_CONTENTS);
        assert_file_eq(&fixture.btc_key_path, BTC_KEY_CONTENTS);

        assert_mode_0600(&fixture.config_path);
        assert_mode_0600(&fixture.keypair_path);
        assert_mode_0600(&fixture.btc_key_path);
    }

    #[test]
    fn restore_refuses_to_overwrite_existing_original_paths() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_identity(&fixture.config);

        // Delete keypair and btc key but leave the config in place. The config file is
        // the first entry in `backup_file_paths()`, so the copy-back loop will bail on
        // its very first iteration without touching any other files.
        fs::remove_file(&fixture.keypair_path).unwrap();
        fs::remove_file(&fixture.btc_key_path).unwrap();

        let out = tempfile::Builder::new().tempdir().unwrap();
        let err = restore(&backup.tarball, &backup.identity_file, out.path(), true).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("Refusing to overwrite existing original path"),
            "error chain did not mention overwrite refusal: {chain}"
        );
        assert!(
            chain.contains("hashi-cli.toml"),
            "error chain did not mention the colliding file: {chain}"
        );

        // The pre-existing config must be untouched, and the deleted originals must
        // still be absent.
        assert_file_eq(&fixture.config_path, CONFIG_CONTENTS);
        assert!(!fixture.keypair_path.exists());
        assert!(!fixture.btc_key_path.exists());
    }

    #[test]
    fn basename_collision_disambiguates_and_copy_to_original_paths_restores_correctly() {
        // Set up two key files with the same basename in different directories.
        let src = tempfile::Builder::new().tempdir().unwrap();
        let config_path = src.path().join("hashi-cli.toml");
        let sui_dir = src.path().join("sui");
        let btc_dir = src.path().join("btc");
        fs::create_dir_all(&sui_dir).unwrap();
        fs::create_dir_all(&btc_dir).unwrap();

        let keypair_path = sui_dir.join("key.pem");
        let btc_key_path = btc_dir.join("key.pem");

        fs::write(&config_path, CONFIG_CONTENTS).unwrap();
        fs::write(&keypair_path, KEYPAIR_CONTENTS).unwrap();
        fs::write(&btc_key_path, BTC_KEY_CONTENTS).unwrap();

        let config = CliConfig {
            loaded_from_path: Some(config_path.clone()),
            keypair_path: Some(keypair_path.clone()),
            bitcoin: Some(BitcoinConfig {
                private_key_path: Some(btc_key_path.clone()),
                ..BitcoinConfig::default()
            }),
            ..CliConfig::default()
        };

        let backup = save_with_fresh_identity(&config);

        // Verify the archive contains both key.pem and key-2.pem.
        let out = tempfile::Builder::new().tempdir().unwrap();
        restore(&backup.tarball, &backup.identity_file, out.path(), false).unwrap();

        let extract_dir = expected_extract_dir(&backup.tarball, out.path());
        assert_file_eq(&extract_dir.join("key.pem"), KEYPAIR_CONTENTS);
        assert_file_eq(&extract_dir.join("key-2.pem"), BTC_KEY_CONTENTS);

        // Now test that --copy-to-original-paths uses the real paths, not the
        // disambiguated archive names.
        fs::remove_file(&config_path).unwrap();
        fs::remove_file(&keypair_path).unwrap();
        fs::remove_file(&btc_key_path).unwrap();

        let out2 = tempfile::Builder::new().tempdir().unwrap();
        restore(&backup.tarball, &backup.identity_file, out2.path(), true).unwrap();

        assert_file_eq(&keypair_path, KEYPAIR_CONTENTS);
        assert_file_eq(&btc_key_path, BTC_KEY_CONTENTS);
    }
}
