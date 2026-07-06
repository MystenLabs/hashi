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

Initializes a fresh **withdraw-mode** standby guardian with operator-supplied
stable config. This is the production replacement for the withdraw-mode
`OperatorInit` part currently covered by `tools dev-bootstrap`.

It:

1. Fetches and verifies the fresh withdraw-mode guardian's live `GuardianInfo`
   against the configured current build, and confirms it is not already
   operator-initialized.
2. Reads the latest attested ceremony from S3 and verifies its encrypted-share
   recipients against the expected KP roster.
3. Checks whether a committee already exists in S3 (`committee-update/` or
   `genesis/`). If none exists, it reads the current committee from on-chain
   Hashi state and will write it as the operator-trusted genesis bootstrap after
   `OperatorInit`.
4. Fetches the on-chain MPC master `G` and builds the stable `InitConfig` from
   guardian S3 bucket info, limiter config, master G, PCR allowlist, and the
   configured Bitcoin network.
5. Calls withdraw-mode `OperatorInit`; the enclave reads the latest ceremony
   instance from S3, installs the stable config, and exposes the resulting
   `config_hash` in `GuardianInfo`.
6. If this is the first deploy, calls `write_genesis_untrusted` once to seed the
   `genesis/` committee log.
7. Verifies the live and S3-logged `GuardianInfo` match the submitted
   `InitConfig`, then prints the `config_hash` that key provisioners verify
   before submitting shares.

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
   (attestation-anchored), pinning the standby session that KPs will provision.
2. Fetches the same session's S3 `init/` log and requires it to match the
   endpoint `GuardianInfo`, then checks the enclave's config against expected
   values: S3 bucket, limiter config, `mpc_master_g`, and that the
   provisioner-init/operator-activation fields are unset.
3. Scrapes the authoritative `ceremony/` log for the secret-sharing instance
   (commitments + N + T + sharing_seq) the new guardian was booted with, and
   confirms it matches.
4. Recomputes the stable `config_hash` from S3 bucket, limiter config, master G,
   PCR allowlist, and network, then confirms it matches the enclave.
5. Reads this KP's encrypted share from `shares/{seq}-{session}.json` (the
   ceremony's recovery log), verifies every share's recipients against the
   roster, finds the one labeled for this KP's cert fingerprint, decrypts it via
   the yubikey (`gpg --decrypt` over a pipe; the plaintext stays in memory and
   never touches disk), and verifies the decrypted share against its commitment
   (check D).
6. HPKE-encrypts the decrypted share to the new guardian's `encryption_pubkey`
   (from its `GuardianInfo`), binding the verified `config_hash` as AAD, so the
   share only decrypts on a guardian the KP agreed was operator-initialized with
   the expected stable config.
7. Submits the share to the configured relay endpoint. The relay rejects the
   share if the backend session no longer matches the pinned session, otherwise
   it collects T-of-N shares before forwarding them to the guardian in one
   `ProvisionerInit` call; submission itself awaits the relay's
   `single_provisioner_init` RPC.

```bash
cargo run -p hashi-guardian-init -- key-provisioner provision --config guardian-init.sample.yaml
```

See [`guardian-init.sample.yaml`](guardian-init.sample.yaml) for the unified
config. This command uses `kp_pgp_cert_path`, `relay_endpoint`, `hashi`,
`kp_roster`, and `limiter_config`. The relay endpoint is also the source of the
standby session identity. The MPC committee verifying key `G` is fetched from
on-chain Hashi state.

After enough KPs have submitted shares and `ProvisionerInit` completes, the
operator activates the standby with the guardian `OperatorActivate` RPC. That
activation derives live state from S3: it checks other sessions are quiet,
requires the latest ceremony instance to match the armed instance, reads the
latest committee from `committee-update/` or `genesis/`, recovers limiter state
from withdrawal logs, and verifies the operator-supplied `ActivationState`
digest before the guardian starts serving withdrawals.

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
