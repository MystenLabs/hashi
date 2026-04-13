// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! CLI backup command implementations
//!
//! Orchestrates config loading, recipient/identity resolution, and user-facing
//! output. The core archive logic lives in [`crate::backup`].

use age::Decryptor;
use age::IdentityFile;
use age::cli_common::UiCallbacks;
use age::plugin;
use anyhow::Context;
use anyhow::Result;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::str::FromStr;

use crate::backup;
use crate::cli::config::BackupRecipient;
use crate::cli::config::CliConfig;
use crate::cli::print_info;
use crate::cli::print_success;

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

    let manifest = backup::build_backup_manifest(&files)?;

    print_info(&format!(
        "Backing up {} file(s) using age recipient {}",
        files.len(),
        recipient
    ));

    let encryptor_recipient = build_encryptor_recipient(&recipient)?;

    let output_path = output_dir.join(backup::encrypted_backup_file_name());
    backup::encrypt_files_to_age_archive(&manifest, encryptor_recipient.as_ref(), &output_path)?;

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

    let extract_dir = output_dir.join(backup::extract_dir_name(backup_tarball)?);
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
    let (manifest, manifest_toml) = backup::read_backup_manifest(manifest_entry)?;
    backup::write_manifest_to_extract_dir(&extract_dir, &manifest_toml)?;
    let restored_files = backup::restore_backup_entries(entries, &extract_dir, &manifest)?;

    if copy_to_original_paths {
        backup::copy_restored_files_to_original_paths(&restored_files, &manifest)?;
    }

    print_success(&format!(
        "Restore completed from {} into {}",
        backup_tarball.display(),
        extract_dir.display()
    ));

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config::BitcoinConfig;
    use age::secrecy::ExposeSecret;
    use age::x25519;
    use std::path::Path;
    use std::path::PathBuf;
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
        output_dir.join(backup::extract_dir_name(tarball).unwrap())
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
        let manifest_path = extract_dir.join(backup::BACKUP_MANIFEST_FILE_NAME);
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
