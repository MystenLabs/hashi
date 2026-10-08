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
4. `publish-kp-config.sh` publishes the guardian configuration to the same
   bucket for the KPs' ceremony and provisioning steps.
5. `revoke-kp-upload-key.sh` deletes the access key once the guardian is
   provisioned.

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
./operator/scripts/download-kp-pubkeys.sh mainnet
```

The final download must print the same roster you posted. Keep its directory,
which holds the verified certificates and `roster.txt`. The bucket keeps every
uploaded version.

If the KPs take no further part, revoke the access key now with
`./operator/scripts/revoke-kp-upload-key.sh mainnet`. Otherwise keep it until
the guardian is provisioned: the KPs use it for the steps below.

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

## Publish the guardian configuration

KPs run `key-provisioner ceremony` and `key-provisioner provision` with the same
`deployment`, `hashi`, `kp_roster` and `limiter_config` as the operator.
`publish-kp-config.sh` puts that configuration in the bucket, under `_config/`,
and each KP fetches it with `key-provisioner/scripts/download-config.sh`, as
described in the
[KP guide](../key-provisioner/provision.md#taking-part-in-guardian-operations).

Prepare a directory that holds:

- `guardian-init.yaml`: the configuration the operator commands use, with the
  public proxy URL as `guardian_endpoint` and `relay_endpoint`, without
  `s3_credentials` and `kp_pgp_cert_path`, and with `current_build` listed
  before `prev_builds`. Its `current_build.git_revision` is the full commit the
  guardian runs, which the KPs check out.
- `certs/`: every certificate in `kp_roster` and its three attestation files,
  from the verified download, listed in the configuration as
  `certs/<user-id>-kp-pubkey.asc`.

Then publish it, naming the guardian's log bucket:

```sh
./operator/scripts/publish-kp-config.sh mainnet <config-dir> <guardian-bucket>
```

The script verifies every certificate, refuses a configuration that holds an
AWS access key, and prints the guardian commit and a configuration digest. It
also lets the KPs' access key read `_config/` and the guardian's log bucket,
and stops it writing to `_config/`: the configuration names the guardian build
every KP will trust.

Post the commit and the digest. Each KP compares the digest with the one
`download-config.sh` prints. Publish again after any change to the directory;
the digest changes with the configuration.

Once the guardian is provisioned and activated, revoke the access key:

```sh
./operator/scripts/revoke-kp-upload-key.sh mainnet
```

## Deploy a guardian

[Deploying a Guardian](deploy.md) takes an operator through a first deployment
step by step: measuring the build, deploying the enclave and the proxy, the key
ceremony, and provisioning. Each step is one run of
`operator/scripts/guardian.sh`.
