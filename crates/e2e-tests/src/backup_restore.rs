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

    use age::secrecy::ExposeSecret;
    use age::x25519;
    use anyhow::Result;
    use hashi::cli::commands;
    use hashi::config::Config as HashiConfig;
    use tempfile::TempDir;

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

    /// Generate a fresh native x25519 age identity, write its secret to a
    /// file, and return `(recipient_string, identity_file_path)` ready to be
    /// passed to `backup::save` and `backup::restore` respectively.
    fn generate_age_identity_pair(dir: &Path) -> (String, PathBuf) {
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let identity_path = dir.join("backup-identity.txt");
        std::fs::write(&identity_path, identity.to_string().expose_secret()).unwrap();
        (recipient, identity_path)
    }

    /// Materialise an in-memory `HashiConfig` (the node's runtime config) to
    /// a TOML file on disk. Returns the written path.
    fn write_node_config_to_disk(config: &HashiConfig, dir: &Path) -> PathBuf {
        let path = dir.join("node-config.toml");
        config.save(&path).unwrap();
        path
    }

    /// Find the single `hashi-config-backup-*.tar.age` produced under
    /// `dir` by `backup::save`.
    fn find_backup_tarball(dir: &Path) -> PathBuf {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| {
                p.extension().and_then(|e| e.to_str()) == Some("age")
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|name| name.starts_with("hashi-config-backup-"))
            })
            .expect("backup::save did not produce a tarball")
    }

    /// Full round-trip test:
    ///
    /// 1. DKG on 4 nodes + one key rotation so node 0's DB contains entries
    ///    across multiple keyspaces.
    /// 2. Shut down node 0. Serialise its config, generate an age identity,
    ///    and run `hashi backup save` to produce an encrypted tarball.
    /// 3. Delete node 0's on-disk state entirely (simulating "machine lost,
    ///    only the backup remains").
    /// 4. Force two rotations without node 0 — the rest of the network
    ///    continues operating several epochs ahead.
    /// 5. Run `hashi backup restore --copy-to-original-paths` to put the
    ///    files back exactly where the manifest says.
    /// 6. Restart node 0 and force one more rotation so it rejoins as a
    ///    catching-up member.
    /// 7. Assert all 4 nodes agree on the current MPC public key.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_backup_restore_round_trip_and_rejoin() -> Result<()> {
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
        let initial_epoch = test_networks.hashi_network().nodes()[0]
            .current_epoch()
            .unwrap();

        // One pre-backup rotation so the DB has rotation_messages rows, not
        // just the initial DKG state.
        test_networks.sui_network.force_close_epoch().await?;
        wait_for_rotation(test_networks.hashi_network().nodes(), initial_epoch + 1).await;
        assert_nodes_agree_on_mpc_key(test_networks.hashi_network().nodes());

        // 2. Stop node 0.
        test_networks.hashi_network_mut().nodes_mut()[0]
            .shutdown()
            .await;

        // `shutdown()` can return slightly before the DB lock is observable as
        // released. Reopen the DB here to reuse the existing retry logic and
        // only proceed to `backup::save` once the lock is definitely gone.
        {
            let db = test_networks.hashi_network().nodes()[0].open_db()?;
            drop(db);
        }

        // Snapshot the config now, before any deletion below touches the
        // filesystem layout.
        let node0_config = test_networks.hashi_network().nodes()[0].config().clone();
        let original_db_path = node0_config
            .db
            .as_ref()
            .expect("node 0 must have a db path")
            .clone();

        // 3. Serialise config, generate age identity, save backup.
        let backup_dir = tempfile::Builder::new()
            .prefix("hashi-backup-e2e-")
            .tempdir()?;
        let node_config_path = write_node_config_to_disk(&node0_config, backup_dir.path());
        let (recipient, identity_path) = generate_age_identity_pair(backup_dir.path());

        let save_out_dir: TempDir = tempfile::Builder::new()
            .prefix("hashi-backup-out-")
            .tempdir()?;
        commands::backup::save(&node_config_path, Some(recipient), save_out_dir.path())?;
        let tarball = find_backup_tarball(save_out_dir.path());

        // 4. Destroy node 0's on-disk state so `restore --copy-to-original-paths`
        //    actually has to put things back. The node config lives under
        //    `backup_dir`; the DB lives under the TestNetworks tempdir, which
        //    stays alive because the handle still owns it.
        std::fs::remove_dir_all(&original_db_path)?;
        std::fs::remove_file(&node_config_path)?;

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

        // 6. Restore. `--copy-to-original-paths=true` uses the manifest's
        //    absolute paths, which are the exact paths node 0's HashiConfig
        //    still points at, so no reconfiguration is needed after this.
        let restore_out_dir = tempfile::Builder::new()
            .prefix("hashi-restore-out-")
            .tempdir()?;
        commands::backup::restore(
            &tarball,
            &identity_path,
            restore_out_dir.path(),
            /* copy_to_original_paths */ true,
        )?;

        // Sanity: the on-disk artefacts the node needs are back where the
        // manifest said they belong.
        assert!(
            original_db_path.is_dir(),
            "restore did not recreate db at {}",
            original_db_path.display()
        );
        assert!(
            node_config_path.is_file(),
            "restore did not recreate node config at {}",
            node_config_path.display()
        );

        // 7. Restart node 0. It may not have valid shares for the current
        //    epoch yet — that's fine, we just need the server up so the
        //    upcoming rotation can deliver fresh shares.
        test_networks.hashi_network_mut().nodes_mut()[0]
            .start()
            .await?;
        test_networks.hashi_network().nodes()[0]
            .wait_for_mpc_key(ROTATION_TIMEOUT)
            .await
            .ok();

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
        Ok(())
    }
}
