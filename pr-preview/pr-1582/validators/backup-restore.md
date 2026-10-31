# Backup and Restore

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> What a Hashi node backup contains, how the node writes one every epoch, and how to restore a node from a backup after machine or disk loss.

Backup key generation, including YubiKey setup with `oct`, is in the [Hashi Node Backups](../node-backup.mdx) guide. This section covers what the node backs up and how to restore a node from a backup.

## What a backup holds

The node automatically writes an encrypted backup every epoch using the required `backup-pgp-cert`: a tar archive wrapped as an ASCII-armored OpenPGP (Sequoia) message, named `hashi-backup-epoch-<epoch>-<timestamp>.tar.asc`. Local restore also accepts a `.tar` you decrypted yourself; S3 restore accepts only `.tar.asc`. Backups go to the required `backup-dir` and follow the retention policy in the [backup guide](../node-backup.mdx#configure-hashi-backups). Once a month, also copy one `-mpc-` archive to storage none of your nodes can reach; see [Monthly off-machine copy](../node-backup.mdx#monthly-off-machine-copy) for which one, how to test it, and how long to keep it. Encryption needs only the public certificate, so the private key need not be present during normal operation.

Each archive holds:

- **The validator config file.**
- **The TLS and operator key files**, when the config gives them as file paths. An inline key is already inside the config file.
- **A database snapshot:** the node's encryption and signing keys for each epoch, and the DKG and key-rotation messages it rebuilds its MPC key shares from.
- **A manifest** (`hashi-backup-manifest.toml`) that records the path each file and the database came from.
- **hashi-mpc-recovery.bcs**: this node's MPC key shares and information needed to recover the MPC key after a zero-day compromise or catastrophic data loss. Included in scheduled backups marked `-mpc-`; see [catastrophic MPC key recovery](../node-backup.mdx#catastrophic-mpc-key-recovery).

It does **not** hold the public certificate that `backup-pgp-cert` points to, the `hashi` binary, or your service unit. Keep those with your deployment files.

The optional `[backup-s3]` table in the [config template](configuration.mdx#validator-config)
enables uploads using the AWS default credential chain. Without it, backups
remain local-only. Each scheduled backup saves locally before one upload
attempt; failed uploads retain the local archive and are not queued or retried.
See [Back up to S3](../node-backup.mdx#back-up-to-s3) for the server-side
missing-`If-None-Match` deny policy, independent bucket-scoped CloudTrail
read/write data events, and Mainnet recovery-reader restrictions. Mysten Testnet
read access is unchanged; Mysten still has to provision per-node AWS credentials.

```bash
# Manual backup (stop the node first; backup save refuses while it holds the database)
hashi backup save /path/to/validator.toml \
  --backup-pgp-cert /path/to/hashi-backup-cert.asc \
  --output-dir /var/lib/hashi/backups
```

## Restoring a node

`hashi backup restore` decrypts an archive and extracts it into a directory you choose. It installs nothing, so restoring a node is: extract, put the files back, start. The example paths below follow the systemd layout in [Server](../reference/cli.mdx#server).

For **accidental machine or disk loss without suspected compromise**, follow
[Machine-loss recovery](../node-backup.mdx#machine-loss-recovery) for installation
and plaintext handling.

For **suspected compromise**, assume the host-held operator, TLS, and MPC private
keys have leaked; even a pre-compromise backup can contain those same keys.
For a single affected node with sufficient healthy peers, fence it, use the
trusted validator account authority to revoke or replace its operator and TLS
identities (see [TLS key (dedicated)](keys.mdx#tls-key-dedicated) and [Operator key (day-to-day signing)](keys.mdx#operator-key-day-to-day-signing)),
then start a fresh machine with an empty DB to generate and register fresh MPC node
keys and rejoin through [reconfiguration](epoch-changes.mdx).
Do not restore possibly exposed keys. See
[Suspected node compromise](../node-backup.mdx#suspected-node-compromise).
Quorum-wide or global MPC key compromise needs coordinated incident response:
resharing preserves the global key and cannot repair a stolen global private key.

The backup selection and restore steps below apply only to **accidental machine
or disk loss without suspected compromise**, not to compromise recovery.

**Which backup to use.** Use the newest trusted backup. For S3, use independently retained receipts and audit history to select an exact version, then pin it with `--version-id`; neither the newest object nor successful decryption proves its origin. To take part in the current epoch, the restored database must hold the encryption and signing keys recorded for your node in the current committee, and the backup the node wrote at the most recent epoch change does. An older backup, or an empty database, still gives you a working node: it registers replacement keys by itself and rejoins at the next reconfiguration, without taking part in MPC until then. There is no fixed age limit: what matters is whether the backup holds those keys, and if it does not, the cost is that wait.

**What to restore.** The database is the part you cannot recreate, so always restore it. Restore the config and key files too when the copies on the host are gone, such as on a new host or after a lost disk. If they are intact, keep them: the copies in the archive date from when the node wrote the backup.

1. **Stop the node, and keep every other copy of it stopped.** If you are moving to a new host, make sure the node on the old host cannot start again. Two running copies would both act as the same committee member.

   ```bash
   sudo systemctl stop hashi
   ```

2. **Extract the archive into a private directory.** The extracted files are plaintext keys and database contents. Use a directory only your user can read, on the same filesystem as the `db` path so you can move the database rather than copy it.

   ```bash
   umask 077
   sudo install -d -m 700 -o "$USER" /var/lib/hashi/restore

   # With a local OpenPGP secret key
   hashi backup restore /var/lib/hashi/backups/hashi-backup-<timestamp>.tar.asc \
     --backup-pgp-secret-key /path/to/secret-key.asc \
     --output-dir /var/lib/hashi/restore

   # Or via gpg-agent / YubiKey (works over a forwarded agent)
   hashi backup restore /var/lib/hashi/backups/hashi-backup-<timestamp>.tar.asc \
     --use-gpg-agent [--gpg-homedir /path/to/gnupghome] \
     --output-dir /var/lib/hashi/restore
   ```

   Because backups use OpenPGP, the YubiKey can stay plugged into your laptop: forward your `gpg-agent` to the server and decrypt there. The private key never leaves the YubiKey. Restore also accepts a `.tar` you decrypted yourself, with no key.

   The command creates one directory named after the archive and refuses to run if it already exists:

   ```text
   /var/lib/hashi/restore/hashi-backup-<timestamp>/
     validator.toml               # the config file, under its own name
     <tls-key-file>               # only if tls-private-key was a file path
     <operator-key-file>          # only if operator-private-key was a file path
     hashi-backup-manifest.toml   # where each file and the database came from
     hashi-db-snapshot/           # the database, ready to use
     hashi-mpc-recovery.bcs       # MPC key recovery after catastrophic loss (when present)
   ```

3. **Put the database in place.** Move `hashi-db-snapshot` to the `db` path in your config. If a database is already there, move it aside first; do not merge the two.

   ```bash
   cd /var/lib/hashi/restore/hashi-backup-<timestamp>
   sudo mv /var/lib/hashi/db /var/lib/hashi/db.old   # only if a database is already there
   sudo mv hashi-db-snapshot /var/lib/hashi/db
   ```

4. **Put the config and key files back, if you are restoring them.** Inspect the recovered manifest and config, then install files at the paths your deployment uses. The manifest lists the path each one came from; it is a record, not something the command acts on. Never blindly follow archived absolute paths. If the layout changed, edit `tls-private-key`, `operator-private-key`, `db`, and `backup-dir` in the config to match the new paths, and update endpoints for the new host. In the commands below and in step 6, replace `<tls-key-file>` and `<operator-key-file>` with the key file names you find in the extracted directory (the manifest records the path each came from).

   ```bash
   cat hashi-backup-manifest.toml
   sudo cp validator.toml /etc/hashi/validator.toml
   sudo cp <tls-key-file> <operator-key-file> /etc/hashi/
   ```

5. **Put the backup certificate back.** If `backup-pgp-cert` is a file path, that file must exist, and it is not in the archive. Without it the config fails to load with `invalid OpenPGP certificate`.

6. **Fix ownership and permissions.** Extracted files belong to the user who ran the restore. The node's user needs to own the database and read the config and key files.

   ```bash
   sudo chown -R hashi:hashi /var/lib/hashi/db
   sudo chown hashi:hashi /etc/hashi/validator.toml /etc/hashi/<tls-key-file> /etc/hashi/<operator-key-file>
   sudo chmod 600 /etc/hashi/<tls-key-file> /etc/hashi/<operator-key-file>
   ```

7. **Start the node and check how it rejoined.**

   ```bash
   sudo systemctl start hashi
   journalctl -u hashi -f
   ```

   - **Back in the current epoch:** the node logs `recover_mpc_state: recovered vk=...`.
   - **Waiting for the next epoch:** the node logs `no DB encryption or signing key matches the current committee record; registering fresh keys for epoch <N> so the node rejoins at that reconfig`, and `hashi_mpc_committee_key_lost_total` increases. You need to do nothing more. Leave the node running and it rejoins at that reconfiguration.

8. **Delete the extracted copy.** The directory from step 2 holds decrypted keys and nothing cleans it up for you. Do the same with `db.old` once the node is healthy.

   ```bash
   sudo rm -rf /var/lib/hashi/restore/hashi-backup-<timestamp>
   ```
