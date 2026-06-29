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
```

This will replace the `tools dev-bootstrap` shortcut used in dev. Each KP
generates a PGP key on a yubikey and exports the public cert to the operator;
the key ceremony and provisioning flow is then driven through these commands.
All production commands read the same unified config file; see
[`guardian-init.sample.yaml`](guardian-init.sample.yaml).

The guardian init production config may omit `guardian_s3.access_key` and
`guardian_s3.secret_key`; when both are omitted, the production commands use the
AWS SDK default credential chain. The `tools dev-bootstrap` shortcut is
unchanged and still reads AWS credentials from its required env vars.

## operator ceremony

The production guardian key ceremony — genesis setup, run once by the operator.

One S3 bucket is involved: the guardian's **log bucket** (object-lock enabled).
The guardian writes its `init/` attestation, `ceremony/` audit log, and
`shares/` encrypted-share recovery log here. The operator and key provisioner
ceremony commands both read it.

Drives a fresh **ceremony-mode** guardian through the one-time genesis BTC key
setup (`sharing_seq = 0`). It connects over gRPC and: `operator_init` (ceremony mode, S3-only) →
`setup_new_key` → verifies the response signature and shape → confirms each
encrypted share is addressed only to its labeled KP cert (PKESK recipients,
parsed without decrypting) → cross-checks the guardian's `ceremony/` audit log
and `shares/` recovery log.

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
gRPC to the live guardian): it discovers the latest ceremony session from S3,
loads that session's attested signing pubkey, verifies its `ceremony/` audit log
and `shares/` recovery log against the expected `n`/`t`, confirms every
encrypted share is addressed only to its labeled KP cert, finds the share labeled
for this KP's cert fingerprint, decrypts via the yubikey (`gpg --decrypt`), and
verifies the decrypted share against its commitment.

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

Initializes a fresh **withdraw-mode** guardian with operator-supplied state.
This is the missing production replacement for the withdraw-mode `OperatorInit`
part currently covered by `tools dev-bootstrap`.

This command is currently a stub and exits non-zero.

Eventually it will:

1. Read operator provision config.
2. Fetch and verify the withdraw-mode guardian's `GetGuardianInfo`.
3. Build the `WithdrawModeConfig` from guardian S3 config, limiter config,
   current committee or genesis committee, MPC master `G`, secret-sharing
   instance, Bitcoin network, and limiter state.
4. Recover limiter state from prior guardian withdrawal logs, or use genesis
   state for first deployment.
5. Call withdraw-mode `OperatorInit`.
6. Print the state hash that key provisioners must verify before submitting
   shares.

```bash
cargo run -p hashi-guardian-init -- operator provision --config guardian-init.sample.yaml
```

Config: see [`guardian-init.sample.yaml`](guardian-init.sample.yaml).

## key-provisioner provision

A one-shot flow run by a key provisioner when a new guardian instance is
brought up to replace one that went down. Each KP decrypts through their
yubikey-backed gpg setup; plaintext never touches disk, but the raw share scalar
is held in this process' memory long enough to verify and re-encrypt it. It:

1. Audits `heartbeat/` logs to select the single live enclave session (check A).
2. Fetches and verifies that session's signed `GuardianInfo` (attestation-
   anchored) and checks the enclave's config against expected values — S3 bucket,
   limiter config, `mpc_master_g`, and that `enclave_btc_pubkey` is unset (the
   guardian is not already provisioner-initialized) (check B).
3. Scrapes the authoritative `ceremony/` log for the secret-sharing instance
   (commitments + N + T + sharing_seq) the new guardian was booted with, and
   confirms it matches.
4. Sources the initial `LimiterState` — recovered from the prior enclave's
   max-seq `Success` withdrawal log on rotation, or genesis on first deployment —
   and confirms it matches the enclave's (check C).
5. Sources the committee (latest signed `committee-update/` log, or on-chain
   Hashi state before any update exists), recomputes the `state_hash` the operator
   booted the enclave with, and fails fast on mismatch (check D).
6. Reads this KP's encrypted share from `shares/{seq}-{session}.json` (the
   ceremony's recovery log), verifies every share's recipients against the
   roster, finds the one labeled for this KP's cert fingerprint, decrypts it via
   the yubikey (`gpg --decrypt` over a pipe; the plaintext stays in memory and
   never touches disk), and verifies the decrypted share against its commitment
   (check E).
7. HPKE-encrypts the decrypted share to the new guardian's `encryption_pubkey`
   (from its `GuardianInfo`), binding the verified `state_hash` as AAD — so the
   share only decrypts on a guardian the KP agreed on the operator-supplied
   state with.
8. Submits the share to the configured relay endpoint, which runs the same
   pre-checks before forwarding it. The relay collects T-of-N shares before
   forwarding them to the guardian in one `ProvisionerInit` call; submission
   itself awaits the relay's `single_provisioner_init` RPC.

```bash
cargo run -p hashi-guardian-init -- key-provisioner provision --config guardian-init.sample.yaml
```

See [`guardian-init.sample.yaml`](guardian-init.sample.yaml) for the unified
config. This command uses `kp_pgp_cert_path`, `relay_endpoint`, `hashi`,
`kp_roster`, and `limiter_config`. The committee and MPC committee verifying key
`G` are fetched from on-chain Hashi state.

## tools

Guardian helper tooling lives under `tools`:

```bash
cargo run -p hashi-guardian-init -- tools dev-bootstrap --config <node-config.toml> ...
cargo run -p hashi-guardian-init -- tools fetch-info --endpoint <guardian-endpoint>
cargo run -p hashi-guardian-init -- tools generate-master-key
```

`dev-bootstrap` is a centralized dev shortcut for driving a guardian through
bootstrap. `fetch-info` prints deployed guardian public keys for the legacy
bootstrap path; it verifies the GuardianInfo signature but does not verify Nitro
attestation or PCRs. `generate-master-key` creates the BTC master keypair used
by the dev bootstrap flow.
