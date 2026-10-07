// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end backup/restore round-trip test.
//!
//! Verifies that a node can be taken offline, have its config + DB backed
//! up to an encrypted archive, have the rest of the network rotate several
//! epochs without it, and then be restored from the archive and successfully
//! rejoin the network.
//!
//! This complements the unit tests in `crates/hashi/src/backup.rs` and
//! `crates/hashi/src/cli/commands/backup.rs`, which prove the archive format
//! and on-disk layout correctness. The unique value this test adds is that
//! the rest of the validator network actually accepts the restored node and
//! drives it through a key rotation.

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::path::PathBuf;

    use anyhow::Context;
    use anyhow::Result;
    use hashi::backup::DB_SNAPSHOT_TAR_PREFIX;
    use hashi::backup::extract_dir_name;
    use hashi::cli::commands;
    use hashi::cli::commands::backup::RestoreDecryptor;
    use hashi::config::BackupS3Config;
    use hashi::config::Config as HashiConfig;
    use hashi::config::HashiIds;
    use hashi::db::Database;
    use hashi_types::committee::EncryptionPrivateKey;
    use hashi_types::pgp::PgpPublicCert;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use sui_sdk_types::Address;

    use crate::HashiNodeHandle;
    use crate::TestNetworksBuilder;

    // Duplicated from the main `lib.rs` tests module so this file is
    // self-contained. The values must stay in sync with `lib.rs`.
    const DKG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
    const ROTATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(480);

    fn assert_nodes_agree_on_mpc_key(nodes: &[HashiNodeHandle]) {
        let pk = nodes[0].hashi().mpc_handle().unwrap().public_key().unwrap();
        for (i, node) in nodes.iter().enumerate().skip(1) {
            let node_pk = node.hashi().mpc_handle().unwrap().public_key().unwrap();
            assert_eq!(pk, node_pk, "Node {i} public key differs from node 0");
        }
    }

    async fn wait_for_rotation(nodes: &[HashiNodeHandle], target_epoch: u64) -> u64 {
        let futures: Vec<_> = nodes
            .iter()
            .map(|node| node.wait_for_epoch(target_epoch, ROTATION_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(futures).await;
        for (i, result) in results.into_iter().enumerate() {
            result.unwrap_or_else(|e| panic!("Node {i} failed to reach epoch {target_epoch}: {e}"));
        }
        nodes[0].current_epoch().unwrap()
    }

    /// Generate a fresh OpenPGP keypair, write its secret key to a
    /// file, and return `(public_cert, secret_key_file_path)` ready to be
    /// passed to `backup::save` and `backup::restore` respectively.
    fn generate_pgp_keypair(dir: &Path) -> (String, PathBuf) {
        let (public, secret) = mock_pgp_keypair();
        let secret_key_path = dir.join("backup-secret-key.asc");
        std::fs::write(&secret_key_path, secret).unwrap();
        (public, secret_key_path)
    }

    /// Materialise an in-memory `HashiConfig` (the node's runtime config) to
    /// a TOML file on disk. Returns the written path.
    fn write_node_config_to_disk(config: &HashiConfig, dir: &Path) -> PathBuf {
        let path = dir.join("node-config.toml");
        config.save(&path).unwrap();
        path
    }

    fn scheduled_successes(node: &HashiNodeHandle, name: &str) -> f64 {
        node.metrics_registry()
            .gather()
            .iter()
            .find(|family| family.name() == name)
            .unwrap_or_else(|| panic!("Missing scheduled backup counter {name}"))
            .get_metric()[0]
            .get_counter()
            .as_ref()
            .expect("counter")
            .value()
    }

    async fn wait_for_scheduled_backup(node: &HashiNodeHandle) -> Result<()> {
        tokio::time::timeout(ROTATION_TIMEOUT, async {
            let mut poll = tokio::time::interval(std::time::Duration::from_millis(100));
            loop {
                poll.tick().await;
                let local =
                    scheduled_successes(node, "hashi_backup_scheduled_local_successes_total");
                let remote =
                    scheduled_successes(node, "hashi_backup_scheduled_remote_successes_total");
                if local >= 1.0 && remote >= 1.0 {
                    assert_eq!(local, 1.0, "Expected one scheduled local backup");
                    assert_eq!(remote, 1.0, "Expected one scheduled S3 upload");
                    return;
                }
            }
        })
        .await
        .context("Scheduled local backup and S3 upload did not both complete")
    }

    fn live_s3_config() -> Result<BackupS3Config> {
        Ok(BackupS3Config {
            bucket: std::env::var("HASHI_BACKUP_S3_BUCKET")
                .context("Set HASHI_BACKUP_S3_BUCKET to an existing writable bucket")?,
            region: std::env::var("HASHI_BACKUP_S3_REGION")
                .context("Set HASHI_BACKUP_S3_REGION to the bucket region")?,
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires live S3 bucket, HASHI_BACKUP_S3_BUCKET, HASHI_BACKUP_S3_REGION, AWS credentials"]
    async fn test_manual_backup_to_s3_and_restore() -> Result<()> {
        const EPOCH: u64 = 42;
        let s3 = live_s3_config()?;
        let node_dir = tempfile::tempdir()?;
        let recovery_dir = tempfile::tempdir()?;
        let (recipient, secret_key_path) = generate_pgp_keypair(recovery_dir.path());
        let db_path = node_dir.path().join("db");
        let archive_dir = node_dir.path().join("archives");
        let mut config = HashiConfig::new_for_testing();
        config.db = Some(db_path.clone());
        config.backup_dir = archive_dir.clone();
        config.backup_pgp_cert = PgpPublicCert::new(recipient)?;
        config.backup_s3 = Some(s3.clone());
        config.sui_chain_id = Some("hashi-backup-e2e".into());
        config.hashi_ids = Some(HashiIds {
            package_id: Address::new(rand::random()),
            hashi_object_id: Address::new(rand::random()),
        });
        config.validator_address = Some(Address::new(rand::random()));
        let config_path = write_node_config_to_disk(&config, node_dir.path());
        let original_config = std::fs::read(&config_path)?;
        let original_key = EncryptionPrivateKey::new(&mut rand::thread_rng());
        {
            let db = Database::open(&db_path)?;
            db.store_encryption_key(EPOCH, &original_key)?;
        }

        let archive = commands::backup::save(&config_path, None, &archive_dir, false).await?;
        let uri = format!(
            "s3://{}/{}{}",
            s3.bucket,
            config.backup_s3_namespace().expect("S3 configured"),
            archive.file_name().unwrap().to_str().unwrap(),
        );
        assert!(archive.is_file(), "Manual save must retain a local archive");
        node_dir.close()?;
        assert!(!archive.exists());
        assert!(!config_path.exists());
        assert!(!db_path.exists());

        let restore_dir = tempfile::tempdir()?;
        commands::backup::restore_from_s3(
            &uri,
            &s3.region,
            None,
            RestoreDecryptor::LocalSecretKey { secret_key_path },
            restore_dir.path(),
        )
        .await?;
        let extracted_dir = restore_dir.path().join(extract_dir_name(&archive)?);
        assert_eq!(
            std::fs::read(extracted_dir.join("node-config.toml"))?,
            original_config,
        );
        let restored_db = Database::open(&extracted_dir.join(DB_SNAPSHOT_TAR_PREFIX))?;
        assert_eq!(
            restored_db
                .get_encryption_key(EPOCH)?
                .expect("Archived epoch key must survive remote recovery"),
            original_key,
        );
        assert!(!config_path.exists());
        assert!(!db_path.exists());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires live S3 bucket, HASHI_BACKUP_S3_BUCKET, HASHI_BACKUP_S3_REGION, AWS credentials, sui and bitcoind"]
    async fn test_backup_restore_from_s3_and_rejoin() -> Result<()> {
        backup_restore_round_trip_and_rejoin(Some(live_s3_config()?)).await
    }

    /// Full round-trip test:
    ///
    /// 1. DKG on 4 nodes + one key rotation so node 0's DB contains entries
    ///    across multiple keyspaces.
    /// 2. Use either a scheduled S3 archive or stop node 0 and manually save
    ///    an encrypted archive using an externally held OpenPGP keypair.
    /// 3. Delete node 0's on-disk state entirely (simulating "machine lost,
    ///    only the backup remains").
    /// 4. Force two rotations without node 0 — the rest of the network
    ///    continues operating several epochs ahead.
    /// 5. Restore into private staging, then explicitly install the config
    ///    and DB at destinations chosen by the test, not by the manifest.
    /// 6. Restart node 0 and force one more rotation so it rejoins as a
    ///    catching-up member.
    /// 7. Assert all 4 nodes still agree on the original MPC public key.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_backup_restore_round_trip_and_rejoin() -> Result<()> {
        backup_restore_round_trip_and_rejoin(None).await
    }

    async fn backup_restore_round_trip_and_rejoin(s3: Option<BackupS3Config>) -> Result<()> {
        const TEST_NUM_NODES: usize = 4;

        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        let mut test_networks = TestNetworksBuilder::new()
            .with_nodes(TEST_NUM_NODES)
            .build()
            .await?;

        // 1. DKG on all 4 nodes.
        {
            let nodes = test_networks.hashi_network().nodes();
            let futs: Vec<_> = nodes
                .iter()
                .map(|n| n.wait_for_mpc_key(DKG_TIMEOUT))
                .collect();
            let results: Vec<Result<()>> = futures::future::join_all(futs).await;
            for (i, r) in results.into_iter().enumerate() {
                r.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
            }
            assert_nodes_agree_on_mpc_key(nodes);
        }
        let original_mpc_key = test_networks.hashi_network().nodes()[0]
            .hashi()
            .mpc_handle()
            .unwrap()
            .public_key()
            .unwrap();
        // The recovery key remains outside the failed node's state.
        let config_dir = tempfile::Builder::new()
            .prefix("hashi-backup-e2e-")
            .tempdir()?;
        let (recipient, secret_key_path) = generate_pgp_keypair(config_dir.path());
        let node_config_path = config_dir.path().join("node-config.toml");
        if let Some(s3) = &s3 {
            let node = &mut test_networks.hashi_network_mut().nodes_mut()[0];
            node.shutdown().await;
            node.config_mut().backup_s3 = Some(s3.clone());
            node.config_mut().backup_pgp_cert = PgpPublicCert::new(recipient.clone())?;
            node.config().save(&node_config_path)?;
            node.config_path = Some(node_config_path.clone());
            node.start().await?;
            node.wait_for_mpc_key(DKG_TIMEOUT).await?;
            for name in [
                "hashi_backup_scheduled_local_successes_total",
                "hashi_backup_scheduled_remote_successes_total",
            ] {
                assert_eq!(scheduled_successes(node, name), 0.0);
            }
        }
        let initial_epoch = test_networks.hashi_network().nodes()[0]
            .current_epoch()
            .unwrap();

        // One pre-backup rotation so the DB has rotation_messages rows, not
        // just the initial DKG state.
        test_networks.sui_network.force_close_epoch().await?;
        wait_for_rotation(test_networks.hashi_network().nodes(), initial_epoch + 1).await;
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());
        if s3.is_some() {
            // Observe the real epoch-change worker, not a direct backup call.
            wait_for_scheduled_backup(&test_networks.hashi_network().nodes()[0]).await?;
        }

        // The on-chain epoch can advance before node 0 prepares its next
        // keys. Wait for both records before stopping it for a manual save.
        // The scheduled archive already has this ordering: next-epoch key
        // preparation precedes the backup request.
        tokio::time::timeout(ROTATION_TIMEOUT, async {
            let node = &test_networks.hashi_network().nodes()[0];
            let mut poll = tokio::time::interval(std::time::Duration::from_millis(100));
            loop {
                poll.tick().await;
                if node
                    .hashi()
                    .db
                    .get_encryption_key(initial_epoch + 2)?
                    .is_some()
                    && node
                        .hashi()
                        .db
                        .get_signing_key(initial_epoch + 2)?
                        .is_some()
                {
                    return Ok::<(), anyhow::Error>(());
                }
            }
        })
        .await
        .context("Node 0 did not prepare its next-epoch private keys before backup")??;

        // 2. Stop node 0.
        test_networks.hashi_network_mut().nodes_mut()[0]
            .shutdown()
            .await;

        // Reopening also waits for shutdown to release the DB lock. Capture
        // only the current and next epoch's private keys: both must precede
        // the selected archive, unlike arbitrary later DB writes.
        let archived_key_epochs = [initial_epoch + 1, initial_epoch + 2];
        let expected_keys = {
            let db = test_networks.hashi_network().nodes()[0].open_db()?;
            let mut keys = Vec::with_capacity(archived_key_epochs.len());
            for epoch in archived_key_epochs {
                let encryption_key = db
                    .get_encryption_key(epoch)?
                    .with_context(|| format!("Source DB lacks encryption key for epoch {epoch}"))?;
                let signing_key = db
                    .get_signing_key(epoch)?
                    .with_context(|| format!("Source DB lacks signing key for epoch {epoch}"))?;
                keys.push((epoch, encryption_key, bcs::to_bytes(&signing_key)?));
            }
            keys
        };

        // Snapshot the config now, before any deletion below touches the
        // filesystem layout.
        let node0_config = test_networks.hashi_network().nodes()[0].config().clone();
        let original_db_path = node0_config
            .db
            .as_ref()
            .expect("node 0 must have a db path")
            .clone();

        let (tarball, remote_uri) = if let Some(s3) = &s3 {
            let archives = std::fs::read_dir(&node0_config.backup_dir)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            assert_eq!(archives.len(), 1, "Expected the scheduled archive only");
            let tarball = archives.into_iter().next().unwrap();
            assert!(tarball.to_string_lossy().ends_with(".tar.asc"));
            let uri = format!(
                "s3://{}/{}{}",
                s3.bucket,
                node0_config.backup_s3_namespace().expect("S3 configured"),
                tarball.file_name().unwrap().to_str().unwrap(),
            );
            (tarball, Some(uri))
        } else {
            write_node_config_to_disk(&node0_config, config_dir.path());
            // Keep only the manual recovery copy outside the failed machine.
            let save_out_dir = config_dir.path().join("manual");
            let tarball =
                commands::backup::save(&node_config_path, Some(recipient), &save_out_dir, true)
                    .await?;
            (tarball, None)
        };

        // 4. Destroy node 0's on-disk state so recovery actually has to put
        //    things back. The config has its own tempdir; both the DB and
        //    configured backups live under the TestNetworks tempdir, which
        //    stays alive because the handle still owns it.
        std::fs::remove_dir_all(&original_db_path)?;
        std::fs::remove_file(&node_config_path)?;
        if node0_config.backup_dir.exists() {
            std::fs::remove_dir_all(&node0_config.backup_dir)?;
        }
        if remote_uri.is_some() {
            assert!(
                !tarball.exists(),
                "Remote recovery must have no local archive"
            );
        }

        // 5. Two more rotations without node 0. The surviving nodes advance
        //    the Hashi epoch; node 0's backed-up DB is now several epochs
        //    stale relative to the live network state.
        for target in 2..=3 {
            test_networks.sui_network.force_close_epoch().await?;
            wait_for_rotation(
                &test_networks.hashi_network().nodes()[1..],
                initial_epoch + target,
            )
            .await;
        }

        // 6. Restore only into private staging. Keep staging on the DB's
        //    filesystem so the explicit DB installation below can use rename.
        let restore_out_dir = tempfile::Builder::new()
            .prefix("hashi-restore-out-")
            .tempdir_in(original_db_path.parent().expect("DB must have a parent"))?;
        let decryptor = RestoreDecryptor::LocalSecretKey { secret_key_path };
        if let Some(uri) = remote_uri {
            commands::backup::restore_from_s3(
                &uri,
                &s3.as_ref().unwrap().region,
                None,
                decryptor,
                restore_out_dir.path(),
            )
            .await?;
        } else {
            commands::backup::restore(&tarball, decryptor, restore_out_dir.path())?;
        }

        // Extraction must not recreate the original locations. Installation
        // destinations come from the test's pre-backup config, never from
        // paths supplied by the archive's manifest.
        assert!(!original_db_path.exists());
        assert!(!node_config_path.exists());
        let extracted_dir = restore_out_dir.path().join(extract_dir_name(&tarball)?);
        std::fs::copy(extracted_dir.join("node-config.toml"), &node_config_path)?;
        std::fs::rename(
            extracted_dir.join(DB_SNAPSHOT_TAR_PREFIX),
            &original_db_path,
        )?;

        // Sanity: explicit installation restored the artefacts needed by
        // the node before restarting it.
        assert!(
            original_db_path.is_dir(),
            "installation did not recreate db at {}",
            original_db_path.display()
        );
        assert!(
            node_config_path.is_file(),
            "installation did not recreate node config at {}",
            node_config_path.display()
        );

        // Check actual archived private keys before startup can generate
        // replacements or recover fresh shares from the other validators.
        {
            let db = Database::open(&original_db_path)?;
            for (epoch, expected_encryption_key, expected_signing_key) in &expected_keys {
                let encryption_key = db.get_encryption_key(*epoch)?.with_context(|| {
                    format!("Restored DB lacks encryption key for epoch {epoch}")
                })?;
                let signing_key = db
                    .get_signing_key(*epoch)?
                    .with_context(|| format!("Restored DB lacks signing key for epoch {epoch}"))?;
                assert_eq!(
                    &encryption_key, expected_encryption_key,
                    "Recovery changed the encryption private key for epoch {epoch}",
                );
                assert!(
                    bcs::to_bytes(&signing_key)? == *expected_signing_key,
                    "Recovery changed the signing private key for epoch {epoch}",
                );
            }
        } // Drop the DB handle before restarting node 0.

        // 7. Restart node 0. It may not have valid shares for the current
        //    epoch yet — that's fine, we just need the server up so the
        //    upcoming rotation can deliver fresh shares.
        *test_networks.hashi_network_mut().nodes_mut()[0].config_mut() =
            HashiConfig::load(&node_config_path)?;
        test_networks.hashi_network_mut().nodes_mut()[0]
            .start()
            .await?;
        test_networks.hashi_network().nodes()[0]
            .wait_for_mpc_key(ROTATION_TIMEOUT)
            .await
            .ok();
        assert_eq!(
            test_networks.hashi_network().nodes()[0]
                .hashi()
                .metrics
                .mpc_committee_key_lost_total
                .get(),
            0,
            "Restored node must not replace lost committee keys before rejoining",
        );

        // 8. Force one more rotation; node 0 rejoins as a catching-up
        //    member and must end up with the same MPC pubkey as the rest.
        test_networks.sui_network.force_close_epoch().await?;
        let nodes = test_networks.hashi_network().nodes();
        let futs: Vec<_> = nodes
            .iter()
            .map(|n| n.wait_for_epoch(initial_epoch + 4, ROTATION_TIMEOUT))
            .collect();
        let results: Vec<Result<()>> = futures::future::join_all(futs).await;
        for (i, r) in results.into_iter().enumerate() {
            r.unwrap_or_else(|e| {
                panic!("Node {i} failed to reach epoch {}: {e}", initial_epoch + 4)
            });
        }

        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());
        assert_eq!(
            test_networks.hashi_network().nodes()[0]
                .hashi()
                .mpc_handle()
                .unwrap()
                .public_key()
                .unwrap(),
            original_mpc_key,
            "Recovery must preserve the original MPC public key",
        );
        assert_eq!(
            test_networks.hashi_network().nodes()[0]
                .hashi()
                .metrics
                .mpc_committee_key_lost_total
                .get(),
            0,
            "Restored node must rejoin without replacing lost committee keys",
        );
        Ok(())
    }
}
