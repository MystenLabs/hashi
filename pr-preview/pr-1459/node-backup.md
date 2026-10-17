# Hashi Node Backups

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> How node operators encrypt and restore essential node data with armored PGP backups, including YubiKey restore paths.

Hashi automatically backs up the data a node needs to rejoin the committee after
data loss. Every epoch, Hashi writes the node config, referenced key files,
and database snapshot to a tar archive, then compresses and encrypts it as an
ASCII-armored PGP message. The backup files use the suffix `.tar.asc`.
The key files and database snapshot can contain the node's operator, TLS, and
MPC private keys (see [Suspected node compromise](#suspected-node-compromise)),
so treat a decrypted backup as sensitive key material.

Encryption only needs the public PGP certificate, so the backup key does not
need to be present on the server during normal operation. Restore needs access
to the matching private key, either as a local PGP secret-key file or through
`gpg-agent` for YubiKey-backed keys. Because `gpg-agent` can be forwarded over
SSH, you can restore on a remote server using a YubiKey plugged into your laptop
instead of plugging the YubiKey into the server itself.

## Prerequisites

Each item is described in detail in the section that uses it:

- For a YubiKey backup key: a [YubiKey 5 Series](https://www.yubico.com/products/yubikey-5-overview/)
  key, a machine with a physical USB port, [oct](https://codeberg.org/openpgp-card/openpgp-card-tools),
  and [gpg](https://gnupg.org/).
- For a local backup key file: [sequoia-sq](https://gitlab.com/sequoia-pgp/sequoia-sq).
- For S3 backups: AWS credentials from the default credential chain, a node role
  restricted to `s3:PutObject` within its prefix, and recovery credentials with
  `s3:GetObject` (or `s3:GetObjectVersion` for a pinned version, plus
  `s3:ListBucketVersions` to inspect version history). See [Back up to S3](#back-up-to-s3)
  for the full Mainnet baseline.

## Create a backup key

### Option 1: Create a private key on a YubiKey (recommended)

We recommend generating a PGP private key entirely on one YubiKey and using its
public key to encrypt the node backup. This makes it practically impossible for
anyone to decrypt the backup without physical access to the YubiKey.

:::warning

Do not lose the YubiKey. Without it, you cannot decrypt backups encrypted to
its public key.

:::

For the initial YubiKey setup, you must use a machine with a physical USB port.
After initial setup, you can encrypt the share to the public key of the YubiKey
on any machine, including a cloud server without a USB port.

1. Obtain a new [YubiKey 5 Series](https://www.yubico.com/products/yubikey-5-overview/).
   There are six models: the YubiKey 5C NFC, 5 NFC, 5C, 5 Nano, 5C Nano, and
   5CI. Any of these models works, though avoid the Nano models because they are
   smaller and easier to lose.

2. Install tools on the USB-capable machine:
   - [oct](https://codeberg.org/openpgp-card/openpgp-card-tools), OpenPGP card tools.
     The steps below use it to list the YubiKey, change its PINs, and generate
     the key on it.
   - [gpg](https://gnupg.org/), for testing decryption.

3. Insert a YubiKey and confirm it is visible. **Make sure no other YubiKeys or
   smartcards are plugged into the machine.**

```sh
$ oct list
```

You will see something like this:

```
Available OpenPGP cards:
0006:26883270
```

4. Save the card id and a filename for the public key:

```sh
CARD=$(oct list --idents-only | head -n1)
CARD_FILE="yubikey-public-$(echo "$CARD" | tr ':' '-').asc"
echo "$CARD"
echo "$CARD_FILE"
```

5. Change default PINs

The User PIN is used for daily cryptographic operations like decryption; the
Admin PIN is used for card configuration such as generating/importing keys.

The default PINs for new YubiKeys are:
User PIN:  123456
Admin PIN: 12345678

PINs can contain numbers, letters, and symbols (despite the name), and must be
6, 7, or 8 characters long.

Determine a new user and admin key for the YubiKey. These PINs are essential. If
you lose them, you cannot decrypt the node backups. Back up the PINs in a safe
place, such as a company password manager. Do not use the default PINs.

Change the PINs with the following commands. You will first be prompted to enter
the current (default) PIN, then prompted to enter the new PIN twice.

```sh
oct pin --card "$CARD" set-user
oct pin --card "$CARD" set-admin
```

6. Confirm the YubiKey does not already contain keys:

```sh
oct status --card "$CARD"
```

Confirm the Signature, Decryption, and Authentication key slots do not show
fingerprints. **If the card already has keys, stop here!**

7. Generate the PGP key on the YubiKey.

**This overwrites any existing keys on the YubiKey. Existing keys cannot be
recovered after they are overwritten. Any files encrypted to the old public
key will become permanently undecryptable!**

You will be prompted to enter both the new user and new admin PINs. Be sure to
update the name and email to real values. The public key will be saved to the
output file.

```sh
oct admin --card "$CARD" generate \
  --userid "Your Name <you@example.com>" \
  --output "$CARD_FILE" \
  curve25519
```

8. Test encrypting a file to the YubiKey's public key. Import the public key,
   then encrypt a test file:

```sh
gpg --import "$CARD_FILE"
```

```sh
echo "test message" > test.txt
gpg --encrypt --armor \
  --trust-model always \
  --recipient "you@example.com" \
  --output test.txt.asc \
  test.txt
```

9. Test decrypting the file with the YubiKey. With the YubiKey plugged in,
   link the card to gpg, then decrypt. You will be prompted for the User PIN,
   and to tap the YubiKey.

```sh
gpg --card-status
```

```sh
gpg --decrypt test.txt.asc
```

You may see a warning like `cipher algorithm AES not found in recipient
preferences`. You can ignore this. It happens because the public key exported by
`oct` does not include the cipher preferences that `gpg` expects, so `gpg` warns
even though encryption and decryption still work.

Confirm the output matches the original file contents, then delete the test
files.

10. Store the YubiKey in a secure location, such as a company safe. Also save
    the public key file in a secure location.

### Option 2: Create a local private key file

If you do not want to use a YubiKey, you can generate a PGP private key locally
and encrypt with it. Because the private key is stored in a normal file instead
of on a YubiKey, there is a greater risk of unauthorized use of the private key.
Store the file carefully.

1. Install tools:
   - [sequoia-sq](https://gitlab.com/sequoia-pgp/sequoia-sq), Sequoia PGP.

2. Generate a new key pair. Be sure to update the name and email to real
values.

```sh
sq key generate \
  --own-key \
  --name "Your Name" \
  --email "you@example.com" \
  --expiration never \
  --without-password \
  --output private-key.asc \
  --rev-cert revocation-cert.asc
```

3. Export the public key to a file. Note that despite the name, this doesn't
   actually delete the private key, it just extracts the public key.

```sh
sq key delete \
  --cert-file private-key.asc \
  --output public-key.asc
```

4. Test encrypting a file to the public key:

```sh
echo "test message" > test.txt
sq encrypt \
  --for-file public-key.asc \
  --without-signature \
  --output test.txt.asc \
  test.txt
```

5. Test decrypting the file with the private key:

```sh
sq decrypt --recipient-file private-key.asc test.txt.asc
```

Confirm the output matches the original file contents, then delete the test
files.

6. Save the revocation, public key, and private key files in a secure location.

## Configure Hashi backups

Every node config must provide `backup-pgp-cert` (a certificate file path or inline
armored text) and `backup-dir`:

```toml
backup-pgp-cert = "/path/to/hashi-backup-cert.asc"
backup-dir = "/var/lib/hashi/backups"
```

The `backup-pgp-cert` file is the public key you created in
[Create a backup key](#create-a-backup-key): the `$CARD_FILE`
output from Option 1 (for example, `yubikey-public-0006-26883270.asc`), or
`public-key.asc` from Option 2. It is the public half of the backup key pair.
Restore uses the matching private half, passed as `--backup-pgp-secret-key`
(for example, `private-key.asc` from Option 2) or reached through
`--use-gpg-agent` for YubiKey-backed keys.

Use a persistent, node-specific backup directory outside the database directory,
with write access restricted to the node's user.

### Automatic cleanup

On epoch housekeeping, before the save, Hashi applies these rules in `backup-dir`:

1. Archives older than 14 days by filename timestamp are deleted. The newest is
   kept while the node is still attempting saves; a node with no role attempts
   none, so its last archive expires at 30 days. Archives placed in `backup-dir`
   by manual backups follow the same policy.
2. Abandoned `.hashi-backup-*` files and `.hashi-restore-*` directories older
   than 14 days by modification time are removed, without retaining the newest
   staging entry.
3. Recent staging entries, symlinks, and unrelated files are left alone.
4. Entry errors do not stop the sweep, and a cleanup failure does not prevent
   the backup attempt.

Each sweep logs its epoch, directory, whether a backup was requested, and `removed`/`failed`
counts; expiring the newest archive also warns.

Archives are staged in `backup-dir`, finalized and synced to disk before publication;
the directory is synced afterward on a best-effort basis. A directory sync failure
is logged at error level without failing the already-published backup. Failed saves
remove their temporary files and never overwrite existing archives.

### What operators must clean up

Automatic cleanup does not cover the following; handle them yourself:

- A powered-off node sweeps nothing, so delete a decommissioned host's archives
  yourself, and copy them elsewhere before restarting a long-offline node.
- Manual backups do not trigger cleanup. Keep longer-term copies elsewhere.
- Restore staging and completed restore output contain decrypted keys and
  database data; use a private restore output directory. Completed restores,
  `.hashi-db-restore-*` staging directories beside the destination database, and
  restore output elsewhere are not swept by automatic backup cleanup. Remove
  these plaintext copies when no longer needed.

## Restore from a backup

`hashi backup restore` decrypts an archive and extracts it into a directory you
choose. It installs nothing. The full procedure, from choosing a backup to
restarting the node, is in the
[operator runbook](node-operator-runbook.mdx#102-restoring-a-node).
For S3 restore commands and an on-page recovery checklist, see
[Restore and infrastructure limits](#restore-and-infrastructure-limits) and
[Machine-loss recovery](#machine-loss-recovery) below.

## Back up to S3

Enable S3 uploads with this optional node-config table; both values are required.
Use a bucket name, not an S3 URI. Omit the table for local-only backups.

```toml
[backup-s3]
bucket = "my-hashi-backups"
region = "us-east-1"
```

Uploads and restores use the AWS default credential chain (environment, profiles,
or IAM roles), not credentials in the node config. The secure Mainnet baseline
requires operators to configure:

- A private bucket with S3 Versioning and [Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
  with **bucket-default retention**; Hashi does not set retention per object.
- A bucket policy explicitly denying object-creation `s3:PutObject` requests
  without `If-None-Match: *` (`s3:if-none-match`), rather than relying on the
  client's header alone.
- A node role restricted to `s3:PutObject` within its prefix, without object
  read/delete, bucket/retention administration, or governance-retention bypass.
  Restrict reads to approved recovery roles and keep their credentials off-node.
- CloudTrail **read and write object data events** scoped to the backup bucket,
  retained in an independent audit store outside backup writers' permissions.
  Use per-node credentials for attribution: events identify the credential
  principal, not a trusted archive creator.
- A **14-day remote retention target**, using [lifecycle expiration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-expire-general-considerations.html)
  for current **and noncurrent** versions, coordinated with Object Lock.
  Expiring only current objects can leave historical versions behind. This is
  an operational default, not guaranteed deletion on day 14 or a guaranteed
  recovery window: Object Lock sets a minimum protected period, expiration is
  asynchronous, and recovery depends on epoch-limited certificate history.

Hashi neither provisions nor preflights these controls. Mysten Testnet's Pulumi
configuration defines the bucket and audit safeguards, but leaves read access
unchanged. Recovery-only reads remain Mainnet rollout work; node credential
provisioning is separate.

The destination is derived from the node identity, with no custom prefix:

```text
s3://<bucket>/<sui-chain-id>/<hashi-object-id>/<validator-address>/hashi-backup-<timestamp>.tar.asc
```

Scheduled backups upload the completed encrypted local archive once, without
retries or a queue. Failures preserve local backups and retention, and log the
local path and S3 URI.

### Manual backups

Stop the node before opening its database for a manual backup:

```bash
hashi backup save /path/to/validator.toml --output-dir /var/lib/hashi/backups
```

Replace `/path/to/validator.toml` with the path to your node config, and
`/var/lib/hashi/backups` with the directory to write the archive to (for
example, your configured `backup-dir`).

This saves locally, then uploads if configured. Add `--local-only` to skip S3.
Upload failure returns a nonzero exit status while preserving the local archive.
With S3 configured, a `--backup-pgp-cert` override with different usable encryption recipients requires `--local-only` or updating the configured certificate.

### Restore and infrastructure limits

Restore from a full S3 URI without the original node configuration:

```bash
hashi backup restore s3://my-bucket/<namespace>/hashi-backup-<timestamp>.tar.asc \
  --region us-east-1 --backup-pgp-secret-key /secure/secret-key.asc \
  --output-dir /private/restore
```

Here `<namespace>` is the `<sui-chain-id>/<hashi-object-id>/<validator-address>`
path from the destination template above, and `<timestamp>` is the timestamp in
the archive's filename. Take the full URI from your backup URI/version receipts.

Use `--version-id '<version-id>'` to select an exact object version. Keys are
literal object keys, not URL-decoded paths. Recovery credentials need
`s3:GetObject` for the current object or `s3:GetObjectVersion` for a pinned version;
inspecting version history also requires `s3:ListBucketVersions`.

S3 restore accepts only encrypted `.tar.asc` archives. Choose
`--backup-pgp-secret-key` or `--use-gpg-agent` (with optional `--gpg-homedir`).
Local restores also accept plaintext `.tar` archives, which need neither decryptor.
`--region` is required for S3; it and `--version-id` are invalid for local restores.

Downloads use private temporary storage under `--output-dir` and are removed
afterward. Restore publishes a complete extraction, refuses an existing
destination, and does not install files at their original paths.

Keep backup URI/version receipts, the region, and decryption-key access outside
the node. Use independently retained receipts and audit history to select an
exact version, then pin it with `--version-id`. Neither the newest object nor
successful decryption proves its origin: encryption does not authenticate the
creator. Unexpected versions or delete markers warrant investigation, but
lifecycle rules and authorized administrators can also create them.

### Machine-loss recovery

Use this path for accidental machine or disk loss without suspected compromise.
For suspected compromise, use the separate procedure below, not a snapshot restore.

1. Stop or fence the old node. Restore on a trusted replacement host into a
   private directory (`umask 077`); no original config or database is needed.
2. Verify the restored chain, Hashi object, and validator identity against trusted
   records. Install the config and key files at trusted paths, not paths taken
   blindly from the manifest. Put `hashi-db-snapshot` at the configured `db` path;
   never merge it into an existing database.
3. Update config paths and endpoints, restrict permissions to the node user, and
   start the node. Check chain catch-up and committee participation.
4. Remove plaintext recovery output and temporary key copies when finished.
   Keep decryption-key access independent of the replacement host.

### Suspected node compromise

Assume host-held operator, TLS, and MPC private keys are exposed. Even a known
pre-compromise snapshot can contain those same keys; its age does not make them
safe to restore.

For a **single compromised node with sufficient healthy peers**:

1. Fence the old host. From trusted infrastructure, use the validator account
   authority to revoke the old operator delegation and register fresh operator
   and TLS identities in onchain metadata. Follow the runbook's
   [key generation and registration](node-operator-runbook.mdx#22-tls-key-dedicated)
   and [operator revocation](node-operator-runbook.mdx#24-operator-key-day-to-day-signing)
   procedures with the replacement config; do not authorize recovery with the
   compromised operator key.
2. Provision a fresh machine with an **empty database**, not restored key material.
   Startup generates fresh node encryption/signing keys and registers them;
   see [server startup](node-operator-runbook.mdx#54-step-3-start-the-server).
3. Rejoin through [reconfiguration](node-operator-runbook.mdx#9-epoch-changes-reconfiguration)
   with the healthy peers, and confirm the replacement identities and participation.

Suspected quorum-wide or global MPC key compromise requires coordinated incident
response, not this single-node procedure. Resharing preserves the global Bitcoin
key; it does not repair a stolen global private key.
