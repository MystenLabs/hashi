// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! CLI backup command implementations
//!
//! Orchestrates config loading, recipient/identity resolution, and user-facing
//! output. The core archive logic lives in [`crate::backup`].

use anyhow::Context;
use anyhow::Result;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::decrypt_with_gpg;
use hashi_types::pgp::decrypt_with_secret_key;
use std::fs;
use std::fs::File;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use crate::backup;
use crate::backup_s3::BackupS3Client;
use crate::backup_s3::parse_s3_uri;
use crate::cli::print_success;
use crate::config::Config;
use crate::db::Database;

pub enum RestoreDecryptor {
    Unencrypted,
    LocalSecretKey { secret_key_path: PathBuf },
    GpgAgent { homedir: Option<PathBuf> },
}

/// Save an encrypted backup of the node config, referenced files, and database
pub async fn save(
    node_config_path: &Path,
    backup_pgp_cert_override: Option<String>,
    output_dir: &Path,
    local_only: bool,
) -> Result<PathBuf> {
    let node_config = Config::load(node_config_path).with_context(|| {
        format!(
            "Failed to load node config from {}",
            node_config_path.display()
        )
    })?;

    let recipient = resolve_backup_recipient(&node_config, backup_pgp_cert_override)?;

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
    let db = Database::open(db_path).map_err(|e| {
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

    let output_path = backup::save(node_config_path, &node_config, &db, &recipient, output_dir)?;
    // Release the database lock before potentially slow remote I/O.
    drop(db);

    print_success(&format!("Backup completed: {}", output_path.display()));
    if !local_only {
        let mut client = None;
        if let Some(uri) = backup::upload(&node_config, &mut client, &output_path).await? {
            print_success(&format!("Backup uploaded: {uri}"));
        }
    }

    Ok(output_path)
}

pub(crate) fn resolve_backup_recipient(
    node_config: &Config,
    backup_pgp_cert_override: Option<String>,
) -> Result<PgpPublicCert> {
    Ok(backup_pgp_cert_override
        .map(|value| {
            let path = Path::new(&value);
            let cert = if path.is_file() {
                fs::read_to_string(path)
                    .with_context(|| format!("Failed to read OpenPGP certificate from {value}"))?
            } else {
                value
            };
            PgpPublicCert::new(cert)
        })
        .transpose()?
        .unwrap_or_else(|| node_config.backup_pgp_cert.clone()))
}

/// Identify remote input without requiring local paths to be UTF-8.
pub(crate) fn s3_restore_source(
    source: &Path,
    region: Option<&str>,
    version_id: Option<&str>,
) -> Result<bool> {
    let remote = source
        .to_str()
        .is_some_and(|source| source.starts_with("s3://"));
    if remote {
        anyhow::ensure!(
            region.is_some_and(|region| !region.trim().is_empty()),
            "S3 restore requires a nonempty --region"
        );
        anyhow::ensure!(
            version_id.is_none_or(|version| !version.is_empty()),
            "--version-id must not be empty"
        );
    } else {
        anyhow::ensure!(
            region.is_none() && version_id.is_none(),
            "--region and --version-id are only valid for S3 restores"
        );
    }
    Ok(remote)
}

fn remote_restore_archive(uri: &str) -> Result<(&str, &str, &Path)> {
    let (bucket, key) = parse_s3_uri(uri)?;
    // S3 key prefixes are never interpreted as local directories.
    let name = key.rsplit('/').next().unwrap_or_default();
    anyhow::ensure!(
        !name.is_empty() && !name.contains(['\\', '\0']),
        "S3 backup key must end in a safe archive file name"
    );
    Ok((bucket, key, Path::new(name)))
}

fn validate_remote_restore(
    archive: &Path,
    decryptor: &RestoreDecryptor,
    output_dir: &Path,
) -> Result<()> {
    let format = backup::archive_format(archive)?;
    anyhow::ensure!(
        matches!(format, backup::BackupArchiveFormat::Encrypted),
        "S3 restore requires an encrypted .tar.asc archive; restore plaintext .tar archives from a local path"
    );
    anyhow::ensure!(
        matches!(
            decryptor,
            RestoreDecryptor::LocalSecretKey { .. } | RestoreDecryptor::GpgAgent { .. }
        ),
        "Restore backend does not match the backup archive format"
    );
    let extract_dir = output_dir.join(backup::extract_dir_name(archive)?);
    anyhow::ensure!(
        !extract_dir
            .try_exists()
            .with_context(|| format!("Failed to stat {}", extract_dir.display()))?,
        "Refusing to overwrite existing extract directory: {}",
        extract_dir.display()
    );
    Ok(())
}

/// Download one S3 object and restore it without needing the original node config.
pub async fn restore_from_s3(
    uri: &str,
    region: &str,
    version_id: Option<&str>,
    decryptor: RestoreDecryptor,
    output_dir: &Path,
) -> Result<()> {
    s3_restore_source(Path::new(uri), Some(region), version_id)?;
    let (_, _, archive) = remote_restore_archive(uri)?;
    validate_remote_restore(archive, &decryptor, output_dir)?;
    let client = BackupS3Client::connect(region).await?;
    restore_from_s3_with_client(&client, uri, version_id, decryptor, output_dir).await
}

async fn restore_from_s3_with_client(
    client: &BackupS3Client,
    uri: &str,
    version_id: Option<&str>,
    decryptor: RestoreDecryptor,
    output_dir: &Path,
) -> Result<()> {
    let (bucket, key, archive) = remote_restore_archive(uri)?;
    validate_remote_restore(archive, &decryptor, output_dir)?;
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory {}", output_dir.display()))?;
    // TempDir owns cleanup across download errors, cancellation, and restore errors.
    let mut builder = tempfile::Builder::new();
    builder.prefix(".hashi-download-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    let download_dir = builder
        .tempdir_in(output_dir)
        .context("Failed to create private backup download directory")?;
    let archive_path = download_dir.path().join(archive);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&archive_path)
        .context("Failed to create private backup download file")?;
    let mut file = tokio::fs::File::from_std(file);
    client.download(bucket, key, version_id, &mut file).await?;
    drop(file);
    restore(&archive_path, decryptor, output_dir)
}

pub fn restore(
    backup_tarball: &Path,
    decryptor: RestoreDecryptor,
    output_dir: &Path,
) -> Result<()> {
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
        .prefix(backup::RESTORE_STAGING_DIR_NAME_PREFIX)
        .tempdir_in(output_dir)
        .with_context(|| {
            format!(
                "Failed to create staging directory in {}",
                output_dir.display()
            )
        })?;

    // Encrypted backups yield the decompressed tar after OpenPGP decryption.
    // Unencrypted backups are already raw tar archives.
    let mut backup_stream: Box<dyn io::Read> = match decryptor {
        RestoreDecryptor::Unencrypted => {
            Box::new(File::open(backup_tarball).with_context(|| {
                format!("Failed to open backup tarball {}", backup_tarball.display())
            })?)
        }
        RestoreDecryptor::LocalSecretKey { secret_key_path } => Box::new(
            decrypt_with_local_secret_key(backup_tarball, &secret_key_path)?,
        ),
        RestoreDecryptor::GpgAgent { homedir } => {
            Box::new(decrypt_with_gpg(backup_tarball, homedir.as_deref())?)
        }
    };
    let manifest_toml = {
        let mut archive = tar::Archive::new(&mut backup_stream);
        let mut entries = archive.entries()?;
        let manifest_entry = entries
            .next()
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("Backup archive is empty"))?;
        let (manifest, manifest_toml) = backup::read_backup_manifest(manifest_entry)?;
        backup::restore_backup_entries(entries, staging.path(), &manifest)?;
        manifest_toml
    };
    io::copy(&mut backup_stream, &mut io::sink())
        .context("Failed to finish reading backup stream")?;
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

    print_success(&format!(
        "Restore completed from {} into {}",
        backup_tarball.display(),
        extract_dir.display()
    ));

    Ok(())
}

fn decrypt_with_local_secret_key(
    backup_tarball: &Path,
    secret_key_path: &Path,
) -> Result<impl io::Read + use<>> {
    let input = File::open(backup_tarball)
        .with_context(|| format!("Failed to open backup tarball {}", backup_tarball.display()))?;
    let secret_key = fs::read(secret_key_path).with_context(|| {
        format!(
            "Failed to read OpenPGP secret key from {}",
            secret_key_path.display()
        )
    })?;
    decrypt_with_secret_key(input, &secret_key).with_context(|| {
        format!(
            "Failed to decrypt {}; is {} the correct OpenPGP secret key?",
            backup_tarball.display(),
            secret_key_path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::Encoding as _;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use tempfile::TempDir;

    const CLI_CONFIG_CONTENTS: &[u8] = b"sui_rpc_url = \"https://fullnode.mainnet.sui.io:443\"\n";
    const KEYPAIR_CONTENTS: &[u8] = b"test-ed25519-keypair-bytes";
    const BTC_KEY_CONTENTS: &[u8] = b"test-bitcoin-wif-bytes";

    /// Fixture holding a populated source directory and node config.
    struct TestFixture {
        _src: TempDir,
        node_config_path: PathBuf,
    }

    impl TestFixture {
        fn db_path(&self) -> PathBuf {
            let node_config = crate::config::Config::load(&self.node_config_path).unwrap();
            node_config.db.unwrap()
        }

        /// Create a new fixture with CLI-only files, a node config pointing to
        /// a database, and an empty database on disk.
        fn new() -> Self {
            let src = tempfile::Builder::new().tempdir().unwrap();
            let config_path = src.path().join("hashi-cli.toml");
            let keypair_path = src.path().join("keypair.pem");
            let btc_key_path = src.path().join("btc.wif");
            let db_path = src.path().join("db");

            fs::write(&config_path, CLI_CONFIG_CONTENTS).unwrap();
            fs::write(&keypair_path, KEYPAIR_CONTENTS).unwrap();
            fs::write(&btc_key_path, BTC_KEY_CONTENTS).unwrap();

            // Create a node config file with a db path and initialise the database.
            // Drop the handle immediately so subsequent opens can acquire the lock.
            let node_config_path = src.path().join("config.toml");
            let mut node_config = crate::config::Config::new_for_testing();
            node_config.db = Some(db_path.clone());
            node_config.save(&node_config_path).unwrap();
            drop(crate::db::Database::open(&db_path).unwrap());

            Self {
                _src: src,
                node_config_path,
            }
        }
    }

    /// State produced by a successful `save` call, ready for a follow-up `restore`.
    struct SavedBackup {
        _dir: TempDir,
        tarball: PathBuf,
        secret_key_file: PathBuf,
    }

    /// Run `save` with a freshly generated OpenPGP key and return everything `restore` needs.
    async fn save_with_fresh_pgp_key(fixture: &TestFixture) -> SavedBackup {
        let dir = tempfile::Builder::new().tempdir().unwrap();
        let (public_cert, secret_key) = mock_pgp_keypair();

        let tarball = save(
            &fixture.node_config_path,
            Some(public_cert),
            dir.path(),
            false,
        )
        .await
        .unwrap();

        let secret_key_file = dir.path().join("secret-key.asc");
        fs::write(&secret_key_file, secret_key).unwrap();

        SavedBackup {
            _dir: dir,
            tarball,
            secret_key_file,
        }
    }

    fn local_secret_key_decryptor(backup: &SavedBackup) -> RestoreDecryptor {
        RestoreDecryptor::LocalSecretKey {
            secret_key_path: backup.secret_key_file.clone(),
        }
    }

    fn write_unencrypted_tar_backup(backup: &SavedBackup) -> PathBuf {
        let secret_key = fs::read(&backup.secret_key_file).unwrap();
        let encrypted = File::open(&backup.tarball).unwrap();
        let mut decrypted = hashi_types::pgp::decrypt_with_secret_key(encrypted, &secret_key)
            .expect("encrypted backup should decrypt");

        let tarball = backup.tarball.with_extension("");
        let mut output = File::create(&tarball).unwrap();
        io::copy(&mut decrypted, &mut output).unwrap();
        tarball
    }

    async fn serve_download(
        body: Vec<u8>,
        status: &str,
        extra_length: usize,
    ) -> (
        BackupS3Client,
        tokio::task::JoinHandle<()>,
        Arc<AtomicUsize>,
    ) {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let header = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len() + extra_length
        );
        let connections = Arc::new(AtomicUsize::new(0));
        let server_connections = Arc::clone(&connections);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            server_connections.fetch_add(1, Ordering::Relaxed);
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                assert_eq!(socket.read(&mut byte).await.unwrap(), 1);
                request.push(byte[0]);
            }
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        (
            BackupS3Client::for_test_endpoint(&endpoint),
            server,
            connections,
        )
    }

    #[test]
    fn restore_source_flags_are_remote_only() {
        let uri = Path::new("s3://bucket/backup.tar.asc");
        assert!(s3_restore_source(uri, None, None).is_err());
        assert!(s3_restore_source(uri, Some(" \t"), None).is_err());
        assert!(s3_restore_source(uri, Some("us-east-1"), Some("")).is_err());
        assert!(s3_restore_source(uri, Some("us-east-1"), Some("version")).unwrap());
        for (region, version) in [(Some("us-east-1"), None), (None, Some("version"))] {
            assert!(s3_restore_source(Path::new("backup.tar"), region, version).is_err());
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let path = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/\xff/backup.tar"));
            assert!(!s3_restore_source(path, None, None).unwrap());
        }
    }

    #[tokio::test]
    async fn remote_restore_rejects_invalid_input_before_connecting() {
        let out = tempfile::tempdir().unwrap();
        for uri in [
            "s3://bucket/",
            "s3://bucket/backup.tar?versionId=x",
            "s3://bucket/backup.zip",
            "s3://bucket/.tar",
            "s3://bucket/...tar",
            "s3://bucket/unsafe\\backup.tar",
        ] {
            assert!(
                restore_from_s3(
                    uri,
                    "us-east-1",
                    None,
                    RestoreDecryptor::Unencrypted,
                    out.path()
                )
                .await
                .is_err(),
                "{uri}"
            );
        }
        assert!(
            restore_from_s3(
                "s3://bucket/backup.tar.asc",
                "us-east-1",
                None,
                RestoreDecryptor::Unencrypted,
                out.path()
            )
            .await
            .is_err()
        );
        assert_eq!(fs::read_dir(out.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn remote_restore_downloads_encrypted_archive() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_pgp_key(&fixture).await;
        let name = backup.tarball.file_name().unwrap().to_str().unwrap();
        let uri = format!("s3://bucket/nested/prefix/{name}");
        let (client, server, _) =
            serve_download(fs::read(&backup.tarball).unwrap(), "200 OK", 0).await;
        let out = tempfile::tempdir().unwrap();
        restore_from_s3_with_client(
            &client,
            &uri,
            Some("version-1"),
            local_secret_key_decryptor(&backup),
            out.path(),
        )
        .await
        .unwrap();
        server.await.unwrap();
        let extract_dir = expected_extract_dir(&backup.tarball, out.path());
        assert!(extract_dir.join("config.toml").is_file());
        assert!(extract_dir.join(backup::DB_SNAPSHOT_TAR_PREFIX).is_dir());
        assert_eq!(fs::read_dir(out.path()).unwrap().count(), 1);
        assert!(!out.path().join("nested").exists());
    }

    #[tokio::test]
    async fn remote_restore_rejects_valid_plaintext_without_downloading() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_pgp_key(&fixture).await;
        let plaintext = write_unencrypted_tar_backup(&backup);
        let name = plaintext.file_name().unwrap().to_str().unwrap();
        let uri = format!("s3://bucket/{name}");
        for decryptor in [
            RestoreDecryptor::Unencrypted,
            local_secret_key_decryptor(&backup),
        ] {
            let (client, server, connections) =
                serve_download(fs::read(&plaintext).unwrap(), "200 OK", 0).await;
            let out = tempfile::tempdir().unwrap();
            assert!(
                restore_from_s3_with_client(&client, &uri, None, decryptor, out.path())
                    .await
                    .is_err()
            );
            assert_eq!(fs::read_dir(out.path()).unwrap().count(), 0);
            assert_eq!(connections.load(Ordering::Relaxed), 0);
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
        }
    }

    #[tokio::test]
    async fn remote_restore_cleans_failed_downloads_and_invalid_archives() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_pgp_key(&fixture).await;
        // A complete valid archive must still fail when the HTTP body is truncated.
        for (status, body, extra_length) in [
            ("403 Forbidden", b"access denied".to_vec(), 0),
            ("200 OK", fs::read(&backup.tarball).unwrap(), 100),
            ("200 OK", b"not a tar archive".to_vec(), 0),
        ] {
            let (client, server, _) = serve_download(body, status, extra_length).await;
            let out = tempfile::tempdir().unwrap();
            fs::write(out.path().join("keep"), b"unchanged").unwrap();
            assert!(
                restore_from_s3_with_client(
                    &client,
                    "s3://bucket/backup.tar.asc",
                    None,
                    local_secret_key_decryptor(&backup),
                    out.path()
                )
                .await
                .is_err()
            );
            server.await.unwrap();
            assert_file_eq(&out.path().join("keep"), b"unchanged");
            assert!(!out.path().join("backup").exists());
            assert_eq!(fs::read_dir(out.path()).unwrap().count(), 1);
        }
    }

    #[tokio::test]
    async fn remote_restore_refuses_existing_output_before_connecting() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_pgp_key(&fixture).await;
        let out = tempfile::tempdir().unwrap();
        let existing = out.path().join("backup");
        fs::create_dir(&existing).unwrap();
        fs::write(existing.join("keep"), b"unchanged").unwrap();
        let error = restore_from_s3(
            "s3://bucket/backup.tar.asc",
            "us-east-1",
            None,
            local_secret_key_decryptor(&backup),
            out.path(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("Refusing to overwrite"));
        assert_file_eq(&existing.join("keep"), b"unchanged");
        assert_eq!(fs::read_dir(out.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn remote_restore_cancellation_removes_private_download() {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        let fixture = TestFixture::new();
        let backup = save_with_fresh_pgp_key(&fixture).await;
        let decryptor = local_secret_key_decryptor(&backup);
        let body = fs::read(&backup.tarball).unwrap();
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            body.len() + 100
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (ready, received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                assert_eq!(socket.read(&mut byte).await.unwrap(), 1);
                request.push(byte[0]);
            }
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let out = tempfile::tempdir().unwrap();
        let output_dir = out.path().to_path_buf();
        let download = tokio::spawn(async move {
            let client = BackupS3Client::for_test_endpoint(&endpoint);
            restore_from_s3_with_client(
                &client,
                "s3://bucket/nested/backup.tar.asc",
                None,
                decryptor,
                &output_dir,
            )
            .await
        });
        received.await.unwrap();
        let staging = fs::read_dir(out.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let archive = staging.join("backup.tar.asc");
        assert!(archive.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&staging).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        download.abort();
        assert!(download.await.unwrap_err().is_cancelled());
        server.abort();
        assert_eq!(fs::read_dir(out.path()).unwrap().count(), 0);
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

    #[tokio::test]
    async fn round_trip_restores_files_to_output_dir() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_pgp_key(&fixture).await;

        let out = tempfile::Builder::new().tempdir().unwrap();
        restore(
            &backup.tarball,
            local_secret_key_decryptor(&backup),
            out.path(),
        )
        .unwrap();

        let extract_dir = expected_extract_dir(&backup.tarball, out.path());
        assert!(extract_dir.join("config.toml").is_file());
        assert!(!extract_dir.join("hashi-cli.toml").exists());
        assert!(!extract_dir.join("keypair.pem").exists());
        assert!(!extract_dir.join("btc.wif").exists());

        // All restored files should be owner-only read/write.
        assert_mode_0600(&extract_dir.join("config.toml"));

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
            manifest_toml.contains("config.toml"),
            "extracted manifest missing expected entries: {manifest_toml}"
        );
        assert!(
            !manifest_toml.contains("hashi-cli.toml"),
            "manifest should not include CLI config: {manifest_toml}"
        );
    }

    #[tokio::test]
    async fn restore_rejects_truncated_backup_before_finalizing_extract_dir() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_pgp_key(&fixture).await;

        let original = fs::read(&backup.tarball).unwrap();
        assert!(original.len() > 32, "backup unexpectedly small");
        fs::write(&backup.tarball, &original[..original.len() - 32]).unwrap();

        let out = tempfile::Builder::new().tempdir().unwrap();
        let extract_dir = expected_extract_dir(&backup.tarball, out.path());
        let err = restore(
            &backup.tarball,
            local_secret_key_decryptor(&backup),
            out.path(),
        )
        .unwrap_err();

        let chain = format!("{err:#}");
        assert!(
            chain.contains("Failed to finish reading backup stream")
                || chain.contains("OpenPGP")
                || chain.contains("unexpected end of file"),
            "expected truncated backup error, got: {chain}"
        );
        assert!(
            !extract_dir.exists(),
            "restore must not finalize {} after a truncated backup",
            extract_dir.display()
        );
    }

    #[tokio::test]
    async fn basename_collision_disambiguates_extracted_files() {
        // Set up two key files with the same basename in different directories.
        let src = tempfile::Builder::new().tempdir().unwrap();
        let tls_dir = src.path().join("tls");
        let op_dir = src.path().join("operator");
        fs::create_dir_all(&tls_dir).unwrap();
        fs::create_dir_all(&op_dir).unwrap();

        let tls_key_path = tls_dir.join("key.pem");
        let op_key_path = op_dir.join("key.pem");
        let db_path = src.path().join("db");

        fs::write(&tls_key_path, b"tls-key-bytes").unwrap();
        fs::write(&op_key_path, b"operator-key-bytes").unwrap();

        let node_config_path = src.path().join("config.toml");
        let mut node_config = crate::config::Config::new_for_testing();
        node_config.db = Some(db_path.clone());
        node_config.tls_private_key = Some(tls_key_path.to_string_lossy().into_owned());
        node_config.operator_private_key = Some(op_key_path.to_string_lossy().into_owned());
        node_config.save(&node_config_path).unwrap();
        drop(crate::db::Database::open(&db_path).unwrap());

        let fixture = TestFixture {
            _src: src,
            node_config_path,
        };

        let backup = save_with_fresh_pgp_key(&fixture).await;

        // Verify the archive contains both key.pem and key-2.pem.
        let out = tempfile::Builder::new().tempdir().unwrap();
        restore(
            &backup.tarball,
            local_secret_key_decryptor(&backup),
            out.path(),
        )
        .unwrap();

        let extract_dir = expected_extract_dir(&backup.tarball, out.path());
        assert_file_eq(&extract_dir.join("key.pem"), b"tls-key-bytes");
        assert_file_eq(&extract_dir.join("key-2.pem"), b"operator-key-bytes");
    }

    #[tokio::test]
    async fn round_trip_preserves_db_contents_after_extraction() {
        use hashi_types::committee::EncryptionPrivateKey;
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let fixture = TestFixture::new();
        let db_path = fixture.db_path();

        // Write known rows to every backed-up keyspace before taking the backup.
        let dealer = sui_sdk_types::Address::new([3u8; 32]);
        let enc_key = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let dealer_msg = crate::db::tests::create_test_message();
        let mut rotation_msgs = BTreeMap::new();
        rotation_msgs.insert(
            NonZeroU16::new(1).unwrap(),
            crate::db::tests::create_test_message(),
        );
        {
            let db = crate::db::Database::open(&db_path).unwrap();
            db.store_encryption_key(42, &enc_key).unwrap();
            db.store_dealer_message(42, &dealer, &dealer_msg).unwrap();
            db.store_rotation_messages(42, &dealer, &rotation_msgs)
                .unwrap();
        }

        let backup = save_with_fresh_pgp_key(&fixture).await;

        let out = tempfile::Builder::new().tempdir().unwrap();
        restore(
            &backup.tarball,
            local_secret_key_decryptor(&backup),
            out.path(),
        )
        .unwrap();

        // Open the extracted snapshot directory directly.
        // This is the real test of the stated goal: a decrypted/extracted snapshot
        // dir is immediately usable as a fjall db.
        let extract_dir = expected_extract_dir(&backup.tarball, out.path());
        let snapshot_dir = extract_dir.join(backup::DB_SNAPSHOT_TAR_PREFIX);
        let restored_db = crate::db::Database::open(&snapshot_dir).unwrap();

        let restored_key = restored_db.get_encryption_key(42).unwrap().unwrap();
        assert_eq!(restored_key, enc_key);

        let restored_dealer_msg = restored_db
            .get_dealer_message(42, &dealer)
            .unwrap()
            .unwrap();
        assert_eq!(
            bcs::to_bytes(&restored_dealer_msg).unwrap(),
            bcs::to_bytes(&dealer_msg).unwrap()
        );

        let restored_rotation_msgs = restored_db
            .get_rotation_messages(42, &dealer)
            .unwrap()
            .unwrap();
        assert_eq!(
            bcs::to_bytes(&restored_rotation_msgs).unwrap(),
            bcs::to_bytes(&rotation_msgs).unwrap()
        );
    }

    #[tokio::test]
    async fn save_uses_node_config_backup_pgp_cert() {
        let fixture = TestFixture::new();
        let (public_cert, _) = mock_pgp_keypair();

        let mut node_config = crate::config::Config::load(&fixture.node_config_path).unwrap();
        node_config.backup_pgp_cert = PgpPublicCert::new(public_cert).unwrap();
        node_config.save(&fixture.node_config_path).unwrap();

        let dir = tempfile::Builder::new().tempdir().unwrap();
        let tarball = save(&fixture.node_config_path, None, dir.path(), false)
            .await
            .unwrap();
        assert!(tarball.is_file());
    }

    #[tokio::test]
    async fn save_local_only_skips_configured_s3_upload() {
        let fixture = TestFixture::new();
        let (public_cert, _) = mock_pgp_keypair();
        let mut node_config = Config::load(&fixture.node_config_path).unwrap();
        node_config.sui_chain_id = Some("AbCdEF12".into());
        node_config.hashi_ids = Some(crate::config::HashiIds {
            package_id: sui_sdk_types::Address::ZERO,
            hashi_object_id: "0x1".parse().unwrap(),
        });
        node_config.validator_address = Some("0x2".parse().unwrap());
        node_config.backup_s3 = Some(crate::config::BackupS3Config {
            bucket: "hashi-local-only-no-network".into(),
            region: "us-west-2".into(),
        });
        node_config.save(&fixture.node_config_path).unwrap();

        let dir = tempfile::Builder::new().tempdir().unwrap();
        let tarball = save(
            &fixture.node_config_path,
            Some(public_cert),
            dir.path(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(tarball.parent(), Some(dir.path()));
        assert!(tarball.is_file());
    }

    #[tokio::test]
    async fn save_accepts_backup_pgp_cert_file_override() {
        let fixture = TestFixture::new();
        let (public_cert, _) = mock_pgp_keypair();
        let dir = tempfile::Builder::new().tempdir().unwrap();
        let cert_path = dir.path().join("backup-cert.asc");
        fs::write(&cert_path, public_cert).unwrap();

        save(
            &fixture.node_config_path,
            Some(cert_path.to_string_lossy().into_owned()),
            dir.path(),
            false,
        )
        .await
        .unwrap();

        assert!(
            fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry
                    .path()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(backup::BACKUP_FILE_NAME_PREFIX)
                        && name.ends_with(".tar.asc"))),
            "save() did not produce a .tar.asc backup"
        );
    }

    #[tokio::test]
    async fn save_errors_when_db_path_does_not_exist() {
        // A typo'd `db` field in the node config would otherwise let fjall
        // silently `create_dir_all` and produce an empty backup.
        let fixture = TestFixture::new();
        let db_path = fixture.db_path();
        fs::remove_dir_all(&db_path).unwrap();

        let out = tempfile::Builder::new().tempdir().unwrap();
        let (public_cert, _) = mock_pgp_keypair();
        let err = save(
            &fixture.node_config_path,
            Some(public_cert),
            out.path(),
            false,
        )
        .await
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

    #[tokio::test]
    async fn save_surfaces_locked_db_error_when_node_is_running() {
        // Simulate a running node by holding the fjall lock ourselves while
        // save runs. The friendly "node is running" message proves the
        // fjall::Error::Locked downcast in save() is actually reachable,
        // which was broken before because Database::open stringified errors.
        let fixture = TestFixture::new();
        let db_path = fixture.db_path();
        let _running_node = crate::db::Database::open(&db_path).unwrap();

        let out = tempfile::Builder::new().tempdir().unwrap();
        let (public_cert, _) = mock_pgp_keypair();
        let err = save(
            &fixture.node_config_path,
            Some(public_cert),
            out.path(),
            false,
        )
        .await
        .unwrap_err();

        let chain = format!("{err:#}");
        assert!(
            chain.contains("locked by a running hashi node"),
            "expected locked-db friendly error, got: {chain}"
        );
    }

    #[tokio::test]
    async fn save_includes_path_style_node_config_key_files() {
        // `tls_private_key` / `operator_private_key` in the node config are
        // path-or-inline-PEM strings. When a path is used, the referenced
        // file must be captured in the backup so the key material survives.
        let fixture = TestFixture::new();

        // Point the node config at two real key files on disk.
        let tls_key_path = fixture._src.path().join("tls.pem");
        let op_key_path = fixture._src.path().join("operator.pem");
        fs::write(&tls_key_path, b"tls-key-bytes").unwrap();
        fs::write(&op_key_path, b"operator-key-bytes").unwrap();

        let mut node_config = crate::config::Config::load(&fixture.node_config_path).unwrap();
        node_config.tls_private_key = Some(tls_key_path.to_string_lossy().into_owned());
        node_config.operator_private_key = Some(op_key_path.to_string_lossy().into_owned());
        node_config.save(&fixture.node_config_path).unwrap();

        let backup = save_with_fresh_pgp_key(&fixture).await;

        let out = tempfile::Builder::new().tempdir().unwrap();
        restore(
            &backup.tarball,
            local_secret_key_decryptor(&backup),
            out.path(),
        )
        .unwrap();

        let extract_dir = expected_extract_dir(&backup.tarball, out.path());
        assert_file_eq(&extract_dir.join("tls.pem"), b"tls-key-bytes");
        assert_file_eq(&extract_dir.join("operator.pem"), b"operator-key-bytes");
    }

    #[tokio::test]
    async fn save_errors_when_node_config_key_path_does_not_exist() {
        // A path-shaped value pointing at a missing file is almost certainly a
        // typo. Silently skipping it would produce a backup that can't restore
        // the node, so we bail instead.
        let fixture = TestFixture::new();

        let mut node_config = crate::config::Config::load(&fixture.node_config_path).unwrap();
        node_config.tls_private_key = Some("/this/path/definitely/does/not/exist.pem".to_string());
        node_config.save(&fixture.node_config_path).unwrap();

        let out = tempfile::Builder::new().tempdir().unwrap();
        let (public_cert, _) = mock_pgp_keypair();
        let err = save(
            &fixture.node_config_path,
            Some(public_cert),
            out.path(),
            false,
        )
        .await
        .unwrap_err();

        let chain = format!("{err:#}");
        assert!(
            chain.contains("tls_private_key"),
            "expected error to name the offending field, got: {chain}"
        );
        assert!(
            chain.contains("neither inline key material nor an existing file"),
            "expected missing-key error, got: {chain}"
        );
    }

    #[tokio::test]
    async fn save_ignores_inline_suiprivkey_and_base64_node_config_key_values() {
        // The operator key may be configured inline in any format the key
        // loader accepts; none of them may be mistaken for a file path. The
        // node config file itself already captures inline values.
        let inline_values = [
            // The upstream sui-crypto test vector in both string encodings.
            "suiprivkey1qzdlfxn2qa2lj5uprl8pyhexs02sg2wrhdy7qaq50cqgnffw4c2477kg9h3",
            "AJv0mmoHVflTgR/OEl8mg9UEKcO7SeB0FH4AiaUurhVf",
        ];
        for inline in inline_values {
            let fixture = TestFixture::new();

            let mut node_config = crate::config::Config::load(&fixture.node_config_path).unwrap();
            node_config.operator_private_key = Some(inline.to_string());
            node_config.save(&fixture.node_config_path).unwrap();

            // Just running save without error is the assertion: if the
            // inline key were treated as a path, save() would bail on the
            // missing file.
            let _ = save_with_fresh_pgp_key(&fixture).await;
        }
    }

    #[tokio::test]
    async fn save_error_never_echoes_inline_key_material() {
        // A malformed inline key must fail the backup without the value
        // (potentially a private key) ending up in the error chain, which
        // automatic backups write to the log.
        let fixture = TestFixture::new();

        // Valid Base64 of secret-sized data, but not a loadable key: too
        // long for the flagged keystore payload.
        let secret = base64ct::Base64::encode_string(&[0x42; 48]);
        let mut node_config = crate::config::Config::load(&fixture.node_config_path).unwrap();
        node_config.operator_private_key = Some(secret.clone());
        node_config.save(&fixture.node_config_path).unwrap();

        let out = tempfile::Builder::new().tempdir().unwrap();
        let (public_cert, _) = mock_pgp_keypair();
        let err = save(
            &fixture.node_config_path,
            Some(public_cert),
            out.path(),
            false,
        )
        .await
        .unwrap_err();

        let chain = format!("{err:#}");
        assert!(
            chain.contains("operator_private_key"),
            "expected error to name the offending field, got: {chain}"
        );
        assert!(
            !chain.contains(&secret),
            "error echoed key material: {chain}"
        );
    }

    #[tokio::test]
    async fn save_ignores_inline_pem_node_config_key_values() {
        // When tls_private_key is inline PEM (not a real file), it must not
        // leak into backup_file_paths as a bogus path. The node config file
        // itself already captures inline values.
        let fixture = TestFixture::new();

        let mut node_config = crate::config::Config::load(&fixture.node_config_path).unwrap();
        node_config.tls_private_key = Some(
            "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n"
                .to_string(),
        );
        node_config.save(&fixture.node_config_path).unwrap();

        // Just running save without error is the assertion: if the inline
        // PEM were treated as a path, the pre-flight `file.exists()` check
        // in save() would bail.
        let _ = save_with_fresh_pgp_key(&fixture).await;
    }

    #[tokio::test]
    async fn restore_accepts_unencrypted_tar_without_decrypting() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_pgp_key(&fixture).await;
        let tarball = write_unencrypted_tar_backup(&backup);

        let out = tempfile::Builder::new().tempdir().unwrap();
        restore(&tarball, RestoreDecryptor::Unencrypted, out.path()).unwrap();

        let extract_dir = expected_extract_dir(&tarball, out.path());
        assert!(extract_dir.join("config.toml").is_file());
        assert!(extract_dir.join(backup::DB_SNAPSHOT_TAR_PREFIX).is_dir());
    }

    #[tokio::test]
    async fn restore_ignores_forged_absolute_original_paths() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_pgp_key(&fixture).await;
        let tarball = write_unencrypted_tar_backup(&backup);
        let external = tempfile::Builder::new().tempdir().unwrap();
        let config_target = external.path().join("config-parent/config.toml");
        let db_target = external.path().join("db-parent/db");
        assert!(config_target.is_absolute());
        assert!(db_target.is_absolute());

        // Forge both original destinations in an otherwise valid raw archive.
        let forged_tarball = backup._dir.path().join("forged.tar");
        let mut archive = tar::Archive::new(File::open(&tarball).unwrap());
        let mut entries = archive.entries().unwrap();
        let (mut manifest, _) =
            backup::read_backup_manifest(entries.next().unwrap().unwrap()).unwrap();
        assert_eq!(manifest.paths.len(), 1);
        manifest.paths[0].original_path = config_target.clone();
        manifest.db.original_path = db_target.clone();
        let manifest_toml = toml::to_string(&manifest).unwrap();
        let mut builder = tar::Builder::new(File::create(&forged_tarball).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest_toml.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                backup::BACKUP_MANIFEST_FILE_NAME,
                manifest_toml.as_bytes(),
            )
            .unwrap();
        for entry in entries {
            let mut entry = entry.unwrap();
            let header = entry.header().clone();
            builder.append(&header, &mut entry).unwrap();
        }
        builder.finish().unwrap();
        drop(builder);

        let out = tempfile::Builder::new().tempdir().unwrap();
        restore(&forged_tarball, RestoreDecryptor::Unencrypted, out.path()).unwrap();

        let extract_dir = expected_extract_dir(&forged_tarball, out.path());
        assert_file_eq(
            &extract_dir.join("config.toml"),
            &fs::read(&fixture.node_config_path).unwrap(),
        );
        assert_file_eq(
            &extract_dir.join(backup::BACKUP_MANIFEST_FILE_NAME),
            manifest_toml.as_bytes(),
        );
        let snapshot_dir = extract_dir.join(backup::DB_SNAPSHOT_TAR_PREFIX);
        assert!(snapshot_dir.is_dir());
        let _db = crate::db::Database::open(&snapshot_dir).unwrap();
        assert!(!config_target.exists());
        assert!(!db_target.exists());
        assert_eq!(fs::read_dir(external.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn restore_rejects_tarball_without_backup_suffix() {
        let fixture = TestFixture::new();
        let backup = save_with_fresh_pgp_key(&fixture).await;

        // Rename the tarball to strip the suffix entirely.
        let bad = backup.tarball.with_file_name("totally-not-a-backup");
        fs::rename(&backup.tarball, &bad).unwrap();

        let out = tempfile::Builder::new().tempdir().unwrap();
        let err = restore(&bad, local_secret_key_decryptor(&backup), out.path()).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains(".tar or .tar.asc suffix"),
            "expected suffix-required error, got: {chain}"
        );
    }
}
