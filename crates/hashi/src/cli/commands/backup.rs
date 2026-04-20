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

use tracing::info;

use crate::backup;
use crate::cli::config::BackupRecipient;
use crate::cli::config::CliConfig;
use crate::cli::print_success;

/// Save an encrypted backup of the current config, referenced files, and database
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

    // `backup_file_paths` enforces all the structural invariants we need
    // (CLI config in use, node config path set, node config loadable, key
    // file paths actually exist).
    let files = config.backup_file_paths()?;

    for file in &files {
        if !file.exists() {
            anyhow::bail!("Backup input does not exist: {}", file.display());
        }
    }

    // The DB path lives in the node config and isn't part of `files`, so we
    // load the node config a second time here. `backup_file_paths` already
    // proved this load succeeds, so an error here would have to be a TOCTOU
    // — fine to surface as-is.
    let node_config_path = config
        .node_config_path
        .as_ref()
        .expect("backup_file_paths verified node_config_path is set");
    let node_config = crate::config::Config::load(node_config_path).with_context(|| {
        format!(
            "Failed to load node config from {}",
            node_config_path.display()
        )
    })?;
    let db_path = node_config.db.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Node config at {} does not specify a database path",
            node_config_path.display()
        )
    })?;

    // Refuse to silently create an empty DB at a typo'd path. `fjall` would
    // otherwise happily `create_dir_all` on open and we'd ship a zero-row
    // backup with no warning.
    if !db_path
        .try_exists()
        .with_context(|| format!("Failed to stat database path {}", db_path.display()))?
    {
        anyhow::bail!(
            "Database path {} does not exist. Fix the `db` field in {} before running backup save.",
            db_path.display(),
            node_config_path.display(),
        );
    }

    // Open the database — fails with a clear message if the node is running.
    // `Database::open` preserves `fjall::Error` as the source, so the
    // downcast below matches on the underlying variant.
    let db = crate::db::Database::open(db_path).map_err(|e| {
        if e.downcast_ref::<fjall::Error>()
            .is_some_and(|fe| matches!(fe, fjall::Error::Locked))
        {
            anyhow::anyhow!(
                "Cannot open database at {}: it is locked by a running hashi node. \
                 Stop the node before running backup save.",
                db_path.display()
            )
        } else {
            e.context(format!("Failed to open database at {}", db_path.display()))
        }
    })?;

    // Snapshot the database into a subdirectory of a temp dir. `snapshot_to_path`
    // requires a non-existent destination, so we create the parent tempdir and
    // point at a yet-to-be-created child.
    let tmp_parent = tempfile::Builder::new()
        .prefix("hashi-db-snapshot-")
        .tempdir()
        .context("Failed to create temp directory for database snapshot")?;
    let snapshot_path = tmp_parent.path().join("db");
    db.snapshot_to_path(&snapshot_path)
        .context("Failed to snapshot database")?;
    drop(db);

    info!(source = %db_path.display(), "Database snapshot created");

    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory {}", output_dir.display()))?;

    let manifest = backup::build_backup_manifest(&files, db_path, &snapshot_path)?;

    info!(
        file_count = files.len(),
        %recipient,
        "Backing up files + database",
    );

    let encryptor_recipient = build_encryptor_recipient(&recipient)?;

    let output_path = output_dir.join(backup::encrypted_backup_file_name());
    backup::encrypt_files_to_age_archive(
        &manifest,
        &snapshot_path,
        encryptor_recipient.as_ref(),
        &output_path,
    )?;
    drop(tmp_parent);

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
    if extract_dir
        .try_exists()
        .with_context(|| format!("Failed to stat {}", extract_dir.display()))?
    {
        anyhow::bail!(
            "Refusing to overwrite existing extract directory: {}",
            extract_dir.display()
        );
    }
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory {}", output_dir.display()))?;

    // Extract into a sibling staging directory and rename into place on
    // success. A failure mid-extract leaves the staging dir behind (auto-
    // cleaned on `TempDir` drop) so the user can retry without manual cleanup
    // and the final `extract_dir` never appears half-populated.
    let staging = tempfile::Builder::new()
        .prefix(".hashi-restore-")
        .tempdir_in(output_dir)
        .with_context(|| {
            format!(
                "Failed to create staging directory in {}",
                output_dir.display()
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
    backup::restore_backup_entries(entries, staging.path(), &manifest)?;
    // Manifest is written last so it acts as a marker that extraction finished
    // successfully. Any earlier failure leaves the staging dir without a
    // manifest, so partial state can never be confused for a complete restore.
    backup::write_manifest_to_extract_dir(staging.path(), &manifest_toml)?;

    // Promote the staged dir into its final location atomically. Same-
    // filesystem rename is required for atomicity, which `tempdir_in` of a
    // sibling guarantees.
    let staging_path = staging.keep();
    fs::rename(&staging_path, &extract_dir).map_err(|e| {
        let _ = fs::remove_dir_all(&staging_path);
        anyhow::Error::from(e).context(format!(
            "Failed to move staged restore into place at {}",
            extract_dir.display()
        ))
    })?;

    if copy_to_original_paths {
        backup::copy_restored_files_to_original_paths(&extract_dir, &manifest)?;
        backup::copy_db_snapshot_to_original_path(&extract_dir, &manifest)?;
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
        fn db_path(&self) -> PathBuf {
            let node_config =
                crate::config::Config::load(self.config.node_config_path.as_ref().unwrap())
                    .unwrap();
            node_config.db.unwrap()
        }

        /// Create a new fixture with a config file, two referenced key files,
        /// a node config pointing to a database, and an empty database on disk.
        fn new() -> Self {
            let src = tempfile::Builder::new().tempdir().unwrap();
            let config_path = src.path().join("hashi-cli.toml");
            let keypair_path = src.path().join("keypair.pem");
            let btc_key_path = src.path().join("btc.wif");
            let db_path = src.path().join("db");

            fs::write(&config_path, CONFIG_CONTENTS).unwrap();
            fs::write(&keypair_path, KEYPAIR_CONTENTS).unwrap();
            fs::write(&btc_key_path, BTC_KEY_CONTENTS).unwrap();

            // Create a node config file with a db path and initialise the database.
            // Drop the handle immediately so subsequent opens can acquire the lock.
            let node_config_path = src.path().join("config.toml");
            let node_config = crate::config::Config {
                db: Some(db_path.clone()),
                ..Default::default()
            };
            node_config.save(&node_config_path).unwrap();
            drop(crate::db::Database::open(&db_path).unwrap());

            let config = CliConfig {
                loaded_from_path: Some(config_path.clone()),
                keypair_path: Some(keypair_path.clone()),
                node_config_path: Some(node_config_path),
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
    fn save_with_fresh_identity(fixture: &TestFixture) -> SavedBackup {
        let dir = tempfile::Builder::new().tempdir().unwrap();

        let identity = x25519::Identity::generate();
        let recipient = identity.to_public();

        save(&fixture.config, Some(recipient.to_string()), dir.path()).unwrap();

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
        let backup = save_with_fresh_identity(&fixture);

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
        let backup = save_with_fresh_identity(&fixture);

        let db_path = fixture.db_path();

        // Delete the originals so copy_to_original_paths can recreate them.
        fs::remove_file(&fixture.config_path).unwrap();
        fs::remove_file(fixture.config.node_config_path.as_ref().unwrap()).unwrap();
        fs::remove_file(&fixture.keypair_path).unwrap();
        fs::remove_file(&fixture.btc_key_path).unwrap();
        fs::remove_dir_all(&db_path).unwrap();

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

        // The restored database should be openable.
        let _db = crate::db::Database::open(&db_path).unwrap();
    }

    #[test]
    fn restore_refuses_to_overwrite_existing_original_paths() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_identity(&fixture);

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
        let db_path = src.path().join("db");

        fs::write(&config_path, CONFIG_CONTENTS).unwrap();
        fs::write(&keypair_path, KEYPAIR_CONTENTS).unwrap();
        fs::write(&btc_key_path, BTC_KEY_CONTENTS).unwrap();

        let node_config_path = src.path().join("config.toml");
        let node_config = crate::config::Config {
            db: Some(db_path.clone()),
            ..Default::default()
        };
        node_config.save(&node_config_path).unwrap();
        drop(crate::db::Database::open(&db_path).unwrap());

        let config = CliConfig {
            loaded_from_path: Some(config_path.clone()),
            keypair_path: Some(keypair_path.clone()),
            node_config_path: Some(node_config_path),
            bitcoin: Some(BitcoinConfig {
                private_key_path: Some(btc_key_path.clone()),
                ..BitcoinConfig::default()
            }),
            ..CliConfig::default()
        };

        let fixture = TestFixture {
            _src: src,
            config,
            config_path: config_path.clone(),
            keypair_path: keypair_path.clone(),
            btc_key_path: btc_key_path.clone(),
        };

        let backup = save_with_fresh_identity(&fixture);

        // Verify the archive contains both key.pem and key-2.pem.
        let out = tempfile::Builder::new().tempdir().unwrap();
        restore(&backup.tarball, &backup.identity_file, out.path(), false).unwrap();

        let extract_dir = expected_extract_dir(&backup.tarball, out.path());
        assert_file_eq(&extract_dir.join("key.pem"), KEYPAIR_CONTENTS);
        assert_file_eq(&extract_dir.join("key-2.pem"), BTC_KEY_CONTENTS);

        // Now test that --copy-to-original-paths uses the real paths, not the
        // disambiguated archive names.
        let db_path = fixture.db_path();
        fs::remove_file(&config_path).unwrap();
        fs::remove_file(fixture.config.node_config_path.as_ref().unwrap()).unwrap();
        fs::remove_file(&keypair_path).unwrap();
        fs::remove_file(&btc_key_path).unwrap();
        fs::remove_dir_all(&db_path).unwrap();

        let out2 = tempfile::Builder::new().tempdir().unwrap();
        restore(&backup.tarball, &backup.identity_file, out2.path(), true).unwrap();

        assert_file_eq(&keypair_path, KEYPAIR_CONTENTS);
        assert_file_eq(&btc_key_path, BTC_KEY_CONTENTS);
    }

    #[test]
    fn round_trip_preserves_db_contents_after_extraction() {
        use hashi_types::committee::EncryptionPrivateKey;

        let fixture = TestFixture::new();
        let db_path = fixture.db_path();

        // Write a known row to the source db before taking the backup.
        let enc_key = EncryptionPrivateKey::new(&mut rand::thread_rng());
        {
            let db = crate::db::Database::open(&db_path).unwrap();
            db.store_encryption_key(42, &enc_key).unwrap();
        }

        let backup = save_with_fresh_identity(&fixture);

        let out = tempfile::Builder::new().tempdir().unwrap();
        restore(&backup.tarball, &backup.identity_file, out.path(), false).unwrap();

        // Open the extracted snapshot directory directly — no copy-to-original step.
        // This is the real test of the stated goal: a decrypted/extracted snapshot
        // dir is immediately usable as a fjall db.
        let extract_dir = expected_extract_dir(&backup.tarball, out.path());
        let snapshot_dir = extract_dir.join(backup::DB_SNAPSHOT_TAR_PREFIX);
        let restored_db = crate::db::Database::open(&snapshot_dir).unwrap();

        let restored_key = restored_db.get_encryption_key(42).unwrap().unwrap();
        assert_eq!(restored_key, enc_key);
    }

    #[test]
    fn save_errors_when_node_config_path_unset() {
        // If the CLI config doesn't declare `node_config_path`, save must
        // refuse — otherwise we'd silently back up without the DB.
        let fixture = TestFixture::new();
        let mut config = fixture.config.clone();
        config.node_config_path = None;

        let out = tempfile::Builder::new().tempdir().unwrap();
        let identity = x25519::Identity::generate();
        let err = save(&config, Some(identity.to_public().to_string()), out.path()).unwrap_err();

        let chain = format!("{err:#}");
        assert!(
            chain.contains("node_config_path is not set"),
            "expected node_config_path error, got: {chain}"
        );
    }

    #[test]
    fn save_errors_when_db_path_does_not_exist() {
        // A typo'd `db` field in the node config would otherwise let fjall
        // silently `create_dir_all` and produce an empty backup.
        let fixture = TestFixture::new();
        let db_path = fixture.db_path();
        fs::remove_dir_all(&db_path).unwrap();

        let out = tempfile::Builder::new().tempdir().unwrap();
        let identity = x25519::Identity::generate();
        let err = save(
            &fixture.config,
            Some(identity.to_public().to_string()),
            out.path(),
        )
        .unwrap_err();

        let chain = format!("{err:#}");
        assert!(
            chain.contains("does not exist"),
            "expected missing-db error, got: {chain}"
        );
        assert!(
            chain.contains(&db_path.display().to_string()),
            "error chain did not mention db path: {chain}"
        );
        // The DB directory must not have been created as a side-effect.
        assert!(
            !db_path.exists(),
            "save should not create the db dir when it was missing"
        );
    }

    #[test]
    fn save_surfaces_locked_db_error_when_node_is_running() {
        // Simulate a running node by holding the fjall lock ourselves while
        // save runs. The friendly "node is running" message proves the
        // fjall::Error::Locked downcast in save() is actually reachable,
        // which was broken before because Database::open stringified errors.
        let fixture = TestFixture::new();
        let db_path = fixture.db_path();
        let _running_node = crate::db::Database::open(&db_path).unwrap();

        let out = tempfile::Builder::new().tempdir().unwrap();
        let identity = x25519::Identity::generate();
        let err = save(
            &fixture.config,
            Some(identity.to_public().to_string()),
            out.path(),
        )
        .unwrap_err();

        let chain = format!("{err:#}");
        assert!(
            chain.contains("locked by a running hashi node"),
            "expected locked-db friendly error, got: {chain}"
        );
    }

    #[test]
    fn save_includes_path_style_node_config_key_files() {
        // `tls_private_key` / `operator_private_key` in the node config are
        // path-or-inline-PEM strings. When a path is used, the referenced
        // file must be captured in the backup so the key material survives.
        let fixture = TestFixture::new();

        // Point the node config at two real key files on disk.
        let tls_key_path = fixture._src.path().join("tls.pem");
        let op_key_path = fixture._src.path().join("operator.pem");
        fs::write(&tls_key_path, b"tls-key-bytes").unwrap();
        fs::write(&op_key_path, b"operator-key-bytes").unwrap();

        let mut node_config =
            crate::config::Config::load(fixture.config.node_config_path.as_ref().unwrap()).unwrap();
        node_config.tls_private_key = Some(tls_key_path.to_string_lossy().into_owned());
        node_config.operator_private_key = Some(op_key_path.to_string_lossy().into_owned());
        node_config
            .save(fixture.config.node_config_path.as_ref().unwrap())
            .unwrap();

        let backup = save_with_fresh_identity(&fixture);

        let out = tempfile::Builder::new().tempdir().unwrap();
        restore(&backup.tarball, &backup.identity_file, out.path(), false).unwrap();

        let extract_dir = expected_extract_dir(&backup.tarball, out.path());
        assert_file_eq(&extract_dir.join("tls.pem"), b"tls-key-bytes");
        assert_file_eq(&extract_dir.join("operator.pem"), b"operator-key-bytes");
    }

    #[test]
    fn save_errors_when_node_config_key_path_does_not_exist() {
        // A path-shaped value pointing at a missing file is almost certainly a
        // typo. Silently skipping it would produce a backup that can't restore
        // the node, so we bail instead.
        let fixture = TestFixture::new();

        let mut node_config =
            crate::config::Config::load(fixture.config.node_config_path.as_ref().unwrap()).unwrap();
        node_config.tls_private_key = Some("/this/path/definitely/does/not/exist.pem".to_string());
        node_config
            .save(fixture.config.node_config_path.as_ref().unwrap())
            .unwrap();

        let out = tempfile::Builder::new().tempdir().unwrap();
        let identity = x25519::Identity::generate();
        let err = save(
            &fixture.config,
            Some(identity.to_public().to_string()),
            out.path(),
        )
        .unwrap_err();

        let chain = format!("{err:#}");
        assert!(
            chain.contains("tls_private_key"),
            "expected error to name the offending field, got: {chain}"
        );
        assert!(
            chain.contains("neither inline PEM nor an existing file"),
            "expected missing-key error, got: {chain}"
        );
    }

    #[test]
    fn save_ignores_inline_pem_node_config_key_values() {
        // When tls_private_key is inline PEM (not a real file), it must not
        // leak into backup_file_paths as a bogus path. The node config file
        // itself already captures inline values.
        let fixture = TestFixture::new();

        let mut node_config =
            crate::config::Config::load(fixture.config.node_config_path.as_ref().unwrap()).unwrap();
        node_config.tls_private_key = Some(
            "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n"
                .to_string(),
        );
        node_config
            .save(fixture.config.node_config_path.as_ref().unwrap())
            .unwrap();

        // Just running save without error is the assertion: if the inline
        // PEM were treated as a path, the pre-flight `file.exists()` check
        // in save() would bail.
        let _ = save_with_fresh_identity(&fixture);
    }

    #[test]
    fn restore_rejects_tarball_without_age_suffix() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_identity(&fixture);

        // Rename the tarball to strip the suffix entirely.
        let bad = backup.tarball.with_file_name("totally-not-a-backup");
        fs::rename(&backup.tarball, &bad).unwrap();

        let out = tempfile::Builder::new().tempdir().unwrap();
        let err = restore(&bad, &backup.identity_file, out.path(), false).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains(".tar.age or .age suffix"),
            "expected suffix-required error, got: {chain}"
        );
    }

    #[test]
    fn restore_copy_to_original_paths_refuses_to_overwrite_existing_db_dir() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_identity(&fixture);

        let db_path = fixture.db_path();

        // Delete the config-file originals so the config-copy loop succeeds and we
        // reach the db-copy step, but leave the db dir in place.
        fs::remove_file(&fixture.config_path).unwrap();
        fs::remove_file(fixture.config.node_config_path.as_ref().unwrap()).unwrap();
        fs::remove_file(&fixture.keypair_path).unwrap();
        fs::remove_file(&fixture.btc_key_path).unwrap();
        assert!(db_path.exists(), "db dir should still exist for this test");

        let out = tempfile::Builder::new().tempdir().unwrap();
        let err = restore(&backup.tarball, &backup.identity_file, out.path(), true).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("Refusing to overwrite existing database directory"),
            "error chain did not mention db overwrite refusal: {chain}"
        );
        assert!(
            chain.contains(&db_path.display().to_string()),
            "error chain did not mention the colliding db path: {chain}"
        );
    }
}
