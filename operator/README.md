# Guardian Operator

## Collect key provisioner public keys

Key provisioners (KPs) provision their YubiKeys on Macs that are not signed in
to corporate accounts. The scripts in `operator/scripts` collect their public
files through an upload-only S3 bucket:

1. `create-kp-upload-bucket.sh` makes the bucket and an access key that can only
   upload into it.
2. Each KP uploads their five public files with
   `key-provisioner/scripts/upload-pubkey.sh`, as described in the
   [KP guide](../key-provisioner/provision.md#provide-the-public-artifacts-to-the-operator).
3. `download-kp-pubkeys.sh` fetches every upload, verifies each certificate and
   its YubiKey attestations exactly as ceremony commands do, and prints a roster.
4. `revoke-kp-upload-key.sh` deletes the upload key once every KP has confirmed
   the roster.

Each script takes a `<name>` that identifies one collection, such as `mainnet`.
It selects the bucket `mysten-hashi-kp-pubkeys-<name>` in `us-west-2` and the
IAM user `hashi-kp-pubkeys-<name>-upload` under the IAM path
`/hashi-kp-pubkeys/`. The scripts never touch any other resource.

### Before the meeting

Run from a hashi checkout at the commit the KPs use, with administrator
credentials for the guardian AWS account, for example:

```sh
aws sso login --profile admin
export AWS_PROFILE=admin
./operator/scripts/create-kp-upload-bucket.sh mainnet
./operator/scripts/download-kp-pubkeys.sh mainnet
```

`create-kp-upload-bucket.sh` prints the AWS account and asks for confirmation.
It then tests the new access key with a real upload and prints the bucket,
access key ID, and secret access key. The secret is not stored anywhere; if you
lose it before sharing it, run `revoke-kp-upload-key.sh`, then
`create-kp-upload-bucket.sh` with a new name.

The first `download-kp-pubkeys.sh` builds `hashi-guardian-init`, which can take
several minutes, and then reports that there are no uploads yet.

### During the meeting

1. Ask each KP whose Mac was set up before today to run
   `git -C ~/hashi pull --ff-only`, then to read out
   `git -C ~/hashi log -1 --oneline`, and compare it with your checkout.
2. Paste the bucket, access key ID, and secret access key in a code block into
   the meeting's private channel.
3. As KPs report their user IDs, run
   `./operator/scripts/download-kp-pubkeys.sh mainnet`. Each run downloads into
   a new directory under `.hashi/kp-pubkeys/` and prints one row per user ID:
   - `VERIFIED`: the certificate, its attestations, and its fingerprint file
     agree.
   - `INCOMPLETE`: files are missing because the upload is still running or
     failed. The KP runs the upload again.
   - `INVALID`: the reason follows the row. Find the cause before anyone
     re-provisions; for example, a Yubico attestation issuer that hashi does not
     pin yet is a code gap, not a KP mistake.
4. When every row is `VERIFIED` and the roster has exactly one row per KP
   present, post the printed roster in a code block. Rows are in fingerprint
   order, the order in which a ceremony with exactly these certificates assigns
   share IDs.
5. Each KP runs `./key-provisioner/scripts/show-fingerprint.sh` and confirms
   their row.

### After the meeting

```sh
./operator/scripts/revoke-kp-upload-key.sh mainnet
./operator/scripts/download-kp-pubkeys.sh mainnet
```

The final download must print the same roster you posted. Keep its directory,
which holds the verified certificates and `roster.txt`. The bucket keeps every
uploaded version.

### Fixing problems

- **An extra row for an abandoned user ID:** remove its files with
  `aws s3 rm --recursive s3://mysten-hashi-kp-pubkeys-<name>/<user-id>/`, then
  download again.
- **An unexpected object:** inspect it, remove it with `aws s3 rm`, then
  download again.
- **A re-upload note:** the latest upload is verified. Confirm with the KP that
  they uploaded again.
- **A failed `create-kp-upload-bucket.sh`:** follow the cleanup commands in its
  error message.
- **An expired AWS session:** run `aws sso login --profile admin` again.

## Publish a guardian packet

Every guardian operation needs each key provisioner (KP) to hold the same
configuration, every roster certificate with its attestation files, and read
access to the guardian's log bucket. The scripts in `operator/scripts` deliver
all of it through one packet bucket, with one access key shared in the meeting:

1. `create-kp-packet-bucket.sh` makes the bucket and an access key that can read
   packets, write submissions, and only read the guardian's log bucket.
2. `publish-kp-packet.sh` checks a rendered bundle, removes any AWS credentials
   from its configuration, verifies every certificate, and publishes it.
3. Each KP runs `key-provisioner/scripts/run-guardian-step.sh`, as described in
   the [KP guide](../key-provisioner/guardian-operations.md).
4. `download-kp-submissions.sh` collects the signed files a KP-set rotation
   produces.
5. `revoke-kp-packet-key.sh` deletes the access key once the operation is over.

Like the pubkey scripts, each one takes a `<name>` that identifies one operation,
such as `mainnet-ceremony`. It selects the bucket `mysten-hashi-kp-packet-<name>`
in `us-west-2` and the IAM user `hashi-kp-packet-<name>-kp` under the IAM path
`/hashi-kp-packet/`.

### The packet

A packet is a rendered `guardian-init.yaml` plus a `certs/` directory holding
every roster certificate and its three attestation files, with
`kp_pgp_cert_paths` written as `certs/`-relative paths. Render it with the same
renderer that produces your own operator configuration, so a KP's `config_hash`
cannot drift from yours. `publish-kp-packet.sh` never changes anything that
`config_hash` covers; it only empties `guardian_s3.access_key` and
`guardian_s3.secret_key` and drops `kp_pgp_cert_path`, which each KP's script
fills in from their connected YubiKey.

`<phase>` tells the KP script which command to run:

| Guardian operation | `<phase>` | Who runs it |
| --- | --- | --- |
| Key ceremony | `ceremony` | every KP |
| First provisioning of a guardian | `provision-genesis` | threshold of KPs |
| Any later provisioning, including a rotation | `provision` | threshold of KPs |
| KP-set rotation, signing round | `rotate-kp-set` | threshold of current KPs |
| KP-set rotation, new holders | `ceremony` | every new KP |
| Replacing one KP's certificate | `rotate-cert` | that KP |

### Before the round

```sh
aws sso login --profile admin
export AWS_PROFILE=admin
./operator/scripts/create-kp-packet-bucket.sh mainnet-ceremony <guardian-bucket>
./operator/scripts/publish-kp-packet.sh mainnet-ceremony ceremony <bundle-dir>
```

`create-kp-packet-bucket.sh` prints the AWS account and asks for confirmation. It
tests the new key against both buckets and proves, with a policy simulation, that
it cannot write to the guardian's log bucket. `publish-kp-packet.sh` refuses a
checkout with uncommitted changes, because the packet pins the commit KPs must
run.

### During the round

1. Paste the bucket, access key ID, secret access key, and packet digest in a
   code block into the meeting's private channel.
2. Each KP runs `./key-provisioner/scripts/run-guardian-step.sh` and confirms the
   packet digest before anything runs.
3. Run your own phase of the operation, and wait for the KPs. `operator ceremony`
   and `operator rotate-kp-set submit` block until every KP confirms.
4. For a KP-set rotation, run `./operator/scripts/download-kp-submissions.sh
   mainnet-ceremony` once the current KPs report success; it prints the
   `--submission` flags for `operator rotate-kp-set submit`.

Publish a new packet for each round. Each publication gets its own packet ID, and
the pointer is written last, so a KP downloading during a publication sees either
the whole old packet or the whole new one.

### After the round

```sh
./operator/scripts/revoke-kp-packet-key.sh mainnet-ceremony
```

The bucket keeps every packet and submission version.

### Fixing problems

- **A KP's packet digest differs:** they downloaded during a publication. Have
  them run the script again.
- **A KP has no certificate in the packet:** they have the wrong YubiKey
  connected, or the bundle's roster is wrong. Check the roster before
  re-publishing.
- **A KP reports `guardian session ... is not live in S3`:** the guardian has not
  written its first heartbeat. The script waits it out; if it gives up, confirm
  the session is running and have them run the script again.
- **A KP reports a `config_hash` mismatch:** stop. The packet and the guardian
  disagree, and provisioning would fail later at `operator activate`.
- **`publish-kp-packet.sh` refuses a certificate:** that certificate would also
  be rejected by the ceremony. Find the cause before anyone re-provisions.
- **Lost secret:** `revoke-kp-packet-key.sh`, then `create-kp-packet-bucket.sh`
  with a new name, then publish the packet again.
