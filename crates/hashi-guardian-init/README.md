# hashi-guardian-init

Off-enclave tooling that initializes a guardian. It reads the guardian's S3 logs
via `hashi_guardian::s3_reader`, verifies the attested enclave, and drives the
initialization flows. It also houses guardian helper tooling and dev-only
shortcuts.

## production flow

The production guardian initialization flow is split by actor:

```bash
cargo run -p hashi-guardian-init -- operator ceremony --config guardian-init.sample.yaml
cargo run -p hashi-guardian-init -- key-provisioner ceremony --config guardian-init.sample.yaml --encrypted-shares-path /secure/path/kp-shares.json
cargo run -p hashi-guardian-init -- operator provision --config guardian-init.sample.yaml
cargo run -p hashi-guardian-init -- key-provisioner provision --config guardian-init.sample.yaml
cargo run -p hashi-guardian-init -- operator activate --config guardian-init.sample.yaml
cargo run -p hashi-guardian-init -- key-provisioner rotate-cert --config guardian-init.sample.yaml --new-kp-pgp-cert-path /path/to/kp3-new.asc
```

On first deploy, add `--do-genesis` to the `operator provision` command and
every `key-provisioner provision` command. Omit it for replacement deployments.

Each KP generates one PGP key on a YubiKey and exports its public certificate
to the operator; see the
[key provisioner key-creation guide](../../key-provisioner/provision.md).
The key ceremony and provisioning flow is then driven through these commands.
All production commands read the same unified config file; see
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
share's recipient matches its expected KP cert and its PGP-encrypted ciphertext
targets that cert (parsed without decrypting) → cross-checks the guardian's
`ceremony/` audit log and `kp-shares/` recovery log.
It then waits for every KP to confirm successful share recovery.

`kp_roster.kp_pgp_cert_paths` is an ordered list with one certificate path per
KP/share id. Each share has one encrypted ciphertext addressed to that
certificate's fingerprint.

```bash
cargo run -p hashi-guardian-init -- operator ceremony --config guardian-init.sample.yaml
```

Config: see [`guardian-init.sample.yaml`](guardian-init.sample.yaml). This
command uses `guardian_endpoint`, `hashi`, and `kp_roster`.

## key-provisioner ceremony

Confirms a KP can fetch and decrypt their share from the latest setup or
rotation ceremony. Trust is anchored to the guardian's S3 attestation log: it
discovers the latest ceremony and KP-share state from S3, verifies each record
against its writing session's attested signing pubkey and the expected `n`/`t`,
and confirms each share's recipient and PGP-encrypted ciphertext match the
expected KP cert. It then uses `kp_pgp_cert_path` to identify and decrypt this
KP's share and verifies its commitment. After verification it saves the full
ceremony state, including every KP's encrypted share and the public ceremony
data, to the requested path, then
signs and submits a confirmation to the live guardian. The guardian completes
the ceremony only after all KP/share entries have confirmed.
For rotations, the external orchestrator must keep the ceremony guardian
running after `RotateKpSet` returns until its lifecycle reaches `Completed`.

Both ceremony commands verify live guardian info and Nitro attestation against
the configured current build. The KP additionally anchors the ceremony and
share logs to their writing session's S3 `init/` attestation.

The selected ciphertext is piped from memory to `gpg` over stdin. No temporary
ciphertext or plaintext file is written locally; only the verified ceremony
state containing the encrypted shares is persisted.

The selected `kp_pgp_cert_path` must name the certificate configured for this
KP/share in `kp_roster`; a local certificate outside the roster cannot confirm
the ceremony.

```bash
cargo run -p hashi-guardian-init -- key-provisioner ceremony --config guardian-init.sample.yaml --encrypted-shares-path /secure/path/kp-shares.json
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
   master `G`, the KP PCR allowlist, S3 bucket and retention policy, and
   configured Bitcoin network.
5. Requires the observed serving-committee state to agree with the
   `--do-genesis` intent marker. On first deploy, the flag causes it to build an
   optional `GenesisState` from the current on-chain committee; otherwise a
   serving committee must already exist.
6. Calls withdraw-mode `OperatorInit` with guardian S3 config, `InitConfig`, and
   the optional genesis state; the enclave pins all three inputs plus the latest
   complete ceremony and KP-share state.
7. Verifies the live and S3-logged `GuardianInfo` match the installed ceremony
   instance and stable config.
8. Prints the config and optional genesis hashes that key provisioners must
   verify before submitting shares.

```bash
cargo run -p hashi-guardian-init -- operator provision --config guardian-init.sample.yaml
```

On first deploy, add `--do-genesis`. The flag is purely an explicit intent
marker; the committee still comes from on-chain state and requires threshold KP
authorization during PI.

Config: see [`guardian-init.sample.yaml`](guardian-init.sample.yaml). This
command uses `guardian_endpoint`, `guardian_s3`, `bitcoin_network`, `hashi`,
`kp_roster`, and `limiter_config`.

## key-provisioner provision

A one-shot flow run by a key provisioner for a new guardian instance, either on
first deploy or when replacing a guardian that went down. Each KP decrypts
through their yubikey-backed gpg setup; plaintext never touches disk, but the
raw share scalar is held in this process' memory long enough to verify and
re-encrypt it. It:

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
   `G`, PCR allowlist, S3 bucket and retention policy, and network, then confirms
   its `config_hash` matches the enclave.
5. Requires the observed serving-committee state to agree with the
   `--do-genesis` intent marker. With the flag, independently derives the
   current on-chain committee's `genesis_state_hash`; confirms the optional hash
   matches the enclave.
6. Reads this KP's PGP-encrypted share from the latest `kp-shares/{seq}/`
   state, verifies every share's recipient against the roster, then decrypts
   the share selected by `kp_pgp_cert_path` and verifies its commitment
   (`gpg --decrypt` over a pipe; the plaintext stays in memory and never
   touches disk).
7. HPKE-encrypts the decrypted share to the new guardian's `encryption_pubkey`
   from its `GuardianInfo`.
8. Signs the exact `(session, config_hash, optional genesis_state_hash,
   encrypted share)` submission and sends it to the configured relay endpoint.
   The relay pre-verifies and collects T-of-N distinct submissions; the enclave
   then authoritatively re-verifies every signature and request binding before
   completing `ProvisionerInit`. On first deploy, that same threshold authorizes
   writing the committee to `genesis/record.json`.

```bash
cargo run -p hashi-guardian-init -- key-provisioner provision --config guardian-init.sample.yaml
```

On first deploy, each KP adds `--do-genesis`. The flag is purely an intent
marker; the signed optional genesis hash remains the authorization.

See [`guardian-init.sample.yaml`](guardian-init.sample.yaml) for the unified
config. This command uses `kp_pgp_cert_path`, `relay_endpoint`, `hashi`,
`kp_roster`, and `limiter_config`. The MPC committee verifying key `G` is fetched
from on-chain Hashi state.

## key-provisioner rotate-cert

Replaces this KP's sole OpenPGP cert for the active guardian without changing
the BTC key, sharing instance, threshold, or share id. Individual rotation
requires possession of the old private key because its certificate signs the
request and decrypts the current share. If that sole key is lost, it cannot be
recovered through `rotate-cert`; the KPs must authorize a quorum-based
`RotateKpSet` ceremony instead.

It:

1. Loads the old signing cert from `kp_pgp_cert_path`, requires it to be present
   in `kp_roster`, and loads a replacement cert whose fingerprint does not
   collide with the roster.
2. Fetches and verifies the active guardian's `GuardianInfo` through
   `relay_endpoint`, then requires its BTC public key to match the latest
   attested `ceremony/` log and uses that log's sharing instance.
3. Reads and verifies the latest `kp-shares/{sharing_seq}/` state against the
   current roster, decrypts the old cert's ciphertext, and verifies the share
   commitment.
4. HPKE-encrypts the same share to the guardian, signs the request with the old
   cert, binds the observed `cert_seq` to reject stale updates, and calls
   `ProvisionerRotateCert` through the relay.
5. Verifies the guardian-signed response and the next `kp-shares/` snapshot,
   including that only this share's recipient and ciphertext changed.

```bash
cargo run -p hashi-guardian-init -- key-provisioner rotate-cert \
  --config guardian-init.sample.yaml \
  --new-kp-pgp-cert-path /path/to/kp3-new.asc
```

After success, replace this KP's certificate path in `kp_roster` with the new
path and update `kp_pgp_cert_path` to match.

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
