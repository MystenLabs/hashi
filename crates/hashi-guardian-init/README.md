# hashi-guardian-init

Off-enclave tooling that initializes a guardian. It reads the guardian's S3 logs
via `hashi_guardian::s3_reader`, verifies the attested enclave, and drives the
initialization flows. It also houses guardian helper tooling and dev-only
shortcuts.

## production flow

The production guardian initialization flow is split by actor:

```bash
cargo run -p hashi-guardian-init -- operator ceremony --config guardian-init.sample.yaml
cargo run -p hashi-guardian-init -- key-provisioner ceremony --config guardian-init.sample.yaml
cargo run -p hashi-guardian-init -- operator provision --config guardian-init.sample.yaml
cargo run -p hashi-guardian-init -- key-provisioner provision --config guardian-init.sample.yaml
cargo run -p hashi-guardian-init -- operator activate --config guardian-init.sample.yaml
```

Each KP generates a PGP key on a yubikey and exports the public cert to the
operator; the key ceremony and provisioning flow is then driven through these
commands. All production commands read the same unified config file; see
[`guardian-init.sample.yaml`](guardian-init.sample.yaml).

For a fully-local end-to-end run of this flow (local sui node + a dockerized
guardian, no devnet), see [`docker/hashi-guardian-local`](../../docker/hashi-guardian-local).

The guardian init config may omit `guardian_s3.access_key` and
`guardian_s3.secret_key`; when both are omitted, the commands use the AWS SDK
default credential chain.

## operator ceremony

The production guardian key ceremony — genesis setup, run once by the operator.

One S3 bucket is involved: the guardian's **log bucket** (object-lock enabled).
The guardian writes its `init/` attestation, `ceremony/` audit log, and
`kp-shares/` encrypted-share recovery log here. The operator and key provisioner
ceremony commands both read it.

Drives a fresh **ceremony-mode** guardian through the one-time genesis BTC key
setup (`sharing_seq = 0`). It connects over gRPC and: `operator_init` (ceremony mode, S3-only) →
`setup_new_key` → verifies the response signature and shape → confirms each
encrypted share is addressed only to its labeled KP cert (PKESK recipients,
parsed without decrypting) → cross-checks the guardian's `ceremony/` audit log
and `kp-shares/` recovery log.

Each share is labeled with its recipient cert's `recipient_fingerprint`, so a KP
finds their share by fingerprint (not positional index).

```bash
cargo run -p hashi-guardian-init -- operator ceremony --config guardian-init.sample.yaml
```

Config: see [`guardian-init.sample.yaml`](guardian-init.sample.yaml). This
command uses `guardian_endpoint`, `hashi`, and `kp_roster`.

## key-provisioner ceremony

Confirms a KP can fetch and decrypt their share from the latest setup or
rotation ceremony. Trust is anchored to the guardian's S3 attestation log (no
gRPC to the live guardian): it discovers the latest ceremony and KP-share state
from S3, verifies each record against its writing session's attested signing
pubkey and the expected `n`/`t`, confirms every encrypted share is addressed
only to its labeled KP cert, finds the share labeled for this KP's cert
fingerprint, decrypts via the yubikey (`gpg --decrypt`), and verifies the
decrypted share against its commitment.

The operator `run` command verifies live `/info` signed info and Nitro
attestation against the configured current build before trusting the session
signing key. The KP `verify` command anchors trust to the S3 `init/`
attestation log before verifying the ceremony and share logs under that
attested session key.

Only the share's **ciphertext** is written to disk (a temp file, deleted on
drop); the decrypted scalar lives only in memory.

```bash
cargo run -p hashi-guardian-init -- key-provisioner ceremony --config guardian-init.sample.yaml
```

Config: see [`guardian-init.sample.yaml`](guardian-init.sample.yaml). This
command uses `kp_pgp_cert_path`, `hashi`, and `kp_roster`.

## operator provision

Initializes a fresh **withdraw-mode** guardian with operator-supplied stable
config — the production `OperatorInit` half of provisioning.

It:

1. Fetches and verifies the fresh withdraw-mode guardian's live `GuardianInfo`
   against the configured current build, and confirms it is not already
   operator-initialized.
2. Reads the latest attested ceremony from S3 and verifies its encrypted-share
   recipients against the expected KP roster.
3. Fetches on-chain MPC master `G`, and reads the latest `committee-update/` or
   `genesis/` record if one already exists.
4. Builds the withdraw-mode `InitConfig` from limiter config, on-chain MPC
   master `G`, the KP PCR allowlist, and configured Bitcoin network.
5. Calls withdraw-mode `OperatorInit` with guardian S3 config and `InitConfig`;
   the enclave reads and pins the latest complete ceremony and KP-share state.
6. On first deploy only, writes the on-chain committee to `genesis/record.json`
   through `OperatorWriteGenesis`.
7. Verifies the live and S3-logged `GuardianInfo` match the installed ceremony
   instance and stable config.
8. Prints the `config_hash` that key provisioners must verify before submitting
   shares.

```bash
cargo run -p hashi-guardian-init -- operator provision --config guardian-init.sample.yaml
```

Config: see [`guardian-init.sample.yaml`](guardian-init.sample.yaml). This
command uses `guardian_endpoint`, `guardian_s3`, `bitcoin_network`, `hashi`,
`kp_roster`, and `limiter_config`.

## key-provisioner provision

A one-shot flow run by a key provisioner when a new guardian instance is
brought up to replace one that went down. Each KP decrypts through their
yubikey-backed gpg setup; plaintext never touches disk, but the raw share scalar
is held in this process' memory long enough to verify and re-encrypt it. It:

1. Fetches and verifies the relay/standby endpoint's signed `GuardianInfo`
   (attestation-anchored), pinning the standby session.
2. Fetches the same session's signed `GuardianInfo` from S3 and requires it to
   match the endpoint response, then checks the enclave's config against expected
   values — S3 bucket, limiter config, `mpc_master_g`, and that the guardian is
   not already provisioner-initialized or activated.
3. Scrapes the authoritative `ceremony/` log for the secret-sharing instance
   (commitments + N + T + sharing_seq) the new guardian was booted with, and
   confirms it matches.
4. Recomputes the stable `InitConfig` from limiter config, on-chain MPC master
   `G`, PCR allowlist, and network, then confirms its `config_hash` matches the
   enclave.
5. Reads this KP's encrypted share from the latest `kp-shares/{seq}/` state,
   verifies every share's recipients against the
   roster, finds the one labeled for this KP's cert fingerprint, decrypts it via
   the yubikey (`gpg --decrypt` over a pipe; the plaintext stays in memory and
   never touches disk), and verifies the decrypted share against its commitment.
6. HPKE-encrypts the decrypted share to the new guardian's `encryption_pubkey`
   (from its `GuardianInfo`), binding the verified `config_hash` as AAD — so the
   share only decrypts on a guardian the KP agreed on the stable config with.
7. Submits the share to the configured relay endpoint. The relay rejects if the
   backend session no longer matches the pinned session, otherwise it collects
   T-of-N shares before forwarding them to the guardian in one `ProvisionerInit`
   call.

```bash
cargo run -p hashi-guardian-init -- key-provisioner provision --config guardian-init.sample.yaml
```

See [`guardian-init.sample.yaml`](guardian-init.sample.yaml) for the unified
config. This command uses `kp_pgp_cert_path`, `relay_endpoint`, `hashi`,
`kp_roster`, and `limiter_config`. The MPC committee verifying key `G` is fetched
from on-chain Hashi state.

## operator activate

Activates a provisioner-initialized **withdraw-mode** standby guardian.

It:

1. Fetches and verifies the live standby `GuardianInfo` against the configured
   current build, and confirms `provisioner_init` has completed but activation
   has not.
2. Verifies the standby's S3 `init/` identity/config still matches the live
   guardian.
3. Checks that all other guardian sessions in the configured S3 bucket have
   been quiet long enough.
4. Reads the latest `committee-update/` or `genesis/` record, recovers the
   limiter state from successful withdrawal logs, computes the expected
   `ActivationState` hash, and calls `OperatorActivate`.
5. Verifies the guardian reports the expected active committee epoch and limiter
   state.

```bash
cargo run -p hashi-guardian-init -- operator activate --config guardian-init.sample.yaml
```

Config: see [`guardian-init.sample.yaml`](guardian-init.sample.yaml). This
command uses `guardian_endpoint`, `guardian_s3`, `bitcoin_network`, `hashi`,
`kp_roster`, and `limiter_config`.

## tools

Guardian helper tooling lives under `tools`:

```bash
cargo run -p hashi-guardian-init -- tools fetch-info --endpoint <guardian-endpoint>
```

`fetch-info` prints a deployed guardian's public keys (signing key, or the
enclave BTC pubkey after provisioning), used by deploy to record them on-chain.
It verifies the GuardianInfo signature but does not verify Nitro attestation or
PCRs.
