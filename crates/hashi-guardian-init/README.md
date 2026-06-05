# hashi-guardian-init

Off-enclave tooling that initializes a guardian. It reads the guardian's S3 logs
via `hashi_guardian::s3_reader`, verifies the attested enclave, and emits the
artifacts that drive initialization. Today it houses the key-provisioner flow;
the operator init flow will move here too.

## provisioner-init

A one-shot flow run by a key provisioner (IOP-225 checks A–E). It:

1. Audits `heartbeat/` logs to select the single live enclave session.
2. Fetches that session's `GuardianInfo`, verifies the attestation, and checks
   the enclave's S3 bucket and share commitments — the latter scraped from the
   authoritative `ceremony/` log, not config.
3. Sources the initial `LimiterState` — recovered from the prior enclave's
   max-seq `Success` withdrawal log on rotation, or genesis on first deployment.
4. Sources the committee (latest signed `committee-update/` log, or the genesis
   config before any update exists), recomputes the `state_hash` the operator
   booted the enclave with, and fails fast on mismatch (check D).
5. Builds this KP's encrypted share (bound to `state_hash` as AAD) and, if a
   relay endpoint is configured, submits it. The relay collects T-of-N shares
   before forwarding them to the guardian in one `ProvisionerInit` call.

### Usage

```bash
cargo run -p hashi-guardian-init -- provisioner --config provisioner-init.sample.yaml
```

### Config

See [`provisioner-init.sample.yaml`](provisioner-init.sample.yaml) for a complete
`ProvisionerConfig` example: the KP's secret share, S3 config, limiter config, and
the MPC committee verifying key `G` (`hashi_btc_master_pubkey_hex`). Share
commitments and (post-genesis) the committee are scraped from S3, not configured.
`hashi_committee_genesis` is needed only at genesis; omit it once a
`committee-update/` log exists. Omit `relay_endpoint` for a dry run.
