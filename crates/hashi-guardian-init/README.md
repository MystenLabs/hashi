# hashi-guardian-init

Off-enclave tooling that initializes a guardian. It reads the guardian's S3 logs
via `hashi_guardian::s3_reader`, verifies the attested enclave, and emits the
artifacts that drive initialization. It also houses guardian helper tooling and
dev-only shortcuts.

## ceremony

The production guardian key ceremony — initial setup (`run`, run once by the
operator) and per-KP verification (`verify`, run by each key provisioner).

This replaces the `tools dev-bootstrap` shortcut used in dev. Each KP generates
a PGP key on a yubikey and exports the public cert to the operator; the rest of
the flow is these two commands.

**Two S3 buckets are involved:**
- the guardian's **log bucket** (object-lock enabled) — the guardian writes its
  `init/` attestation + `ceremony/` audit log here; both commands read it.
- a **ceremony artifacts bucket** (object-lock *disabled*, so artifacts can be
  deleted if ever needed) — `run` uploads the signed ceremony artifact here;
  `verify` downloads it. Artifact integrity comes from the guardian's signature,
  not S3 immutability.

### ceremony run (operator)

Drives a fresh **ceremony-mode** guardian through the one-time BTC key setup and
uploads the encrypted key shares. It connects over gRPC and: `operator_init`
(ceremony mode, S3-only) → `setup_new_key` → verifies the response signature and
shape → confirms each encrypted share is addressed only to its labeled KP cert
(PKESK recipients, parsed without decrypting) → cross-checks the guardian's
`ceremony/` audit log → uploads the guardian-signed `SetupNewKeyResponse` (the
ceremony artifact) to the artifacts bucket → round-trip verifies the upload.

Each share is labeled with its recipient cert's `recipient_fingerprint`, so a KP
finds their share by fingerprint (not positional index).

```bash
cargo run -p hashi-guardian-init -- ceremony run --config ceremony-run.sample.yaml
```

Config: see [`ceremony-run.sample.yaml`](ceremony-run.sample.yaml) — the guardian
endpoint, `n`/`t`, both S3 configs, and the KP cert paths.

### ceremony verify (each KP)

Confirms a KP can fetch and decrypt their ceremony share. Trust is anchored
entirely to the guardian's S3 attestation log (no gRPC to the live guardian): it
loads the session's attested signing pubkey, downloads the latest artifact,
verifies its signature, cross-checks its commitments against the `ceremony/`
audit log, finds the share labeled for this KP's cert fingerprint, confirms the
ciphertext is genuinely encrypted to that cert, then decrypts via the yubikey
(`gpg --decrypt`) and verifies the decrypted share against its commitment.

Only the share's **ciphertext** is written to disk (a temp file, deleted on
drop); the decrypted scalar lives only in memory.

```bash
cargo run -p hashi-guardian-init -- ceremony verify --config ceremony-verify.sample.yaml
```

Config: see [`ceremony-verify.sample.yaml`](ceremony-verify.sample.yaml) — the
KP's cert path, both S3 configs, and an optional gpg homedir.

## provision

A one-shot flow run by a key provisioner (IOP-225 checks A–E). It:

1. Audits `heartbeat/` logs to select the single live enclave session.
2. Fetches and verifies that session's signed `GuardianInfo` (attestation-
   anchored) and checks the enclave's config against expected values — S3 bucket,
   limiter config, and the secret-sharing instance (scraped from the authoritative
   `ceremony/` log, not config) — and that it isn't already provisioner-initialized.
3. Sources the initial `LimiterState` — recovered from the prior enclave's
   max-seq `Success` withdrawal log on rotation, or genesis on first deployment —
   and confirms it matches the enclave's.
4. Sources the committee (latest signed `committee-update/` log, or the genesis
   config before any update exists), recomputes the `state_hash` the operator
   booted the enclave with, and fails fast on mismatch (check D).
5. Builds this KP's encrypted share (bound to `state_hash` as AAD) and, if a
   relay endpoint is configured, submits it. The relay collects T-of-N shares
   before forwarding them to the guardian in one `ProvisionerInit` call.

### Usage

```bash
cargo run -p hashi-guardian-init -- provision --config provisioner-init.sample.yaml
```

### Config

See [`provisioner-init.sample.yaml`](provisioner-init.sample.yaml) for a complete
`ProvisionerConfig` example: the KP's secret share, S3 config, limiter config, and
the MPC committee verifying key `G` (`hashi_btc_master_pubkey_hex`). The
secret-sharing instance and (post-genesis) the committee are scraped from S3,
not configured.
`hashi_committee_genesis` is needed only at genesis; omit it once a
`committee-update/` log exists. Omit `relay_endpoint` for a dry run.

## tools

Guardian helper tooling lives under `tools`:

```bash
cargo run -p hashi-guardian-init -- tools dev-bootstrap --config <node-config.toml> ...
cargo run -p hashi-guardian-init -- tools fetch-info --endpoint <guardian-endpoint>
cargo run -p hashi-guardian-init -- tools generate-master-key
```

`dev-bootstrap` is a centralized dev shortcut for driving a guardian through
bootstrap. `fetch-info` prints deployed guardian public keys. `generate-master-key`
creates the BTC master keypair used by the dev bootstrap flow.
