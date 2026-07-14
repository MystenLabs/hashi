# hashi-guardian

Guardian enclave service that emits immutable S3 logs for audit/state-restart workflows.

The S3 bucket operator is untrusted. Log signatures bind the intent, schema
version, session ID, timestamp, intended object key, and event. Readers compare
the signed key in JSON with the actual S3 key and reject relocated or
non-canonical records. Random failure suffixes are sampled once before signing.
Unsigned OI attestations bind placement through their Nitro-authenticated
signing key and derived session ID.

## S3 log key format

Canonical key layout:

- `init/{session_id}/01-oi-attestation-unsigned.json`
- `init/{session_id}/02-oi-guardian-info.json`
- `init/{session_id}/03-pi-enclave-fully-initialized.json`
- `init/{session_id}/04-oa-activated.json`
- `heartbeat/{yyyy}/{mm}/{dd}/{hh}/{session_id}-{counter:020}.json`
- `withdraw/{yyyy}/{mm}/{dd}/{hh}/success-{seq:020}-{session_id}-wid{wid}.json`
- `withdraw/{yyyy}/{mm}/{dd}/{hh}/failure-{session_id}-wid{wid}-{rand8}.json`
- `ceremony/{sharing_seq:020}-{session_id}.json`
- `kp-shares/{sharing_seq:020}/{cert_seq:020}-{session_id}.json`
- `genesis/record.json`
- `committee-update/{new_epoch:020}-{session_id}.json`
- `committee-update/failure-{proposed_epoch:020}-{session_id}-{rand8}.json`

Where:

- `session_id` is the first 16 hex chars of the enclave ephemeral signing pubkey (lowercase). Acts as a short per-session tag in keys; full pubkey verification still happens via the signed log payload (`SessionID::HEX_LEN` in `hashi-types`).
- `counter` is a zero-padded decimal sequence number (used in heartbeats only).
- `seq` (in `withdraw/`) is the zero-padded limiter sequence number consumed by the withdrawal.
- `sharing_seq` (in `ceremony/`) is a zero-padded rotation counter — `setup_new_key` writes `0`; each `rotate_kps` appends `prev+1`.
- `cert_seq` (in `kp-shares/`) is a zero-padded recipient-cert state counter within one `sharing_seq`. Setup/rotation write `0`; future individual KP cert rotations append higher values.
- `new_epoch` / `proposed_epoch` (in `committee-update/`) are the zero-padded committee epoch numbers — `new_epoch` is the just-applied epoch for successes; `proposed_epoch` is the requested epoch for failures. Hashi reconfig is sparse, so neither is guaranteed to be `from_epoch + 1`.
- `rand8` is a random 8-hex suffix to avoid key collisions (failures only — successes are uniquely keyed by seq).

## Stream semantics

- `init` logs are grouped per session and numerically ordered by lifecycle step.
- `heartbeat` logs are hour-partitioned and strictly ordered per session.
- `withdraw` logs are hour-partitioned. Successes are seq-sorted within a bucket so the KP rotating in the next enclave can recover limiter state by reading the lexicographically last success key.
- `ceremony` logs are flat (not date-partitioned). Each entry is a `CeremonyLogMessage` — `NewKey { instance }` written by `setup_new_key` (genesis, `sharing_seq=0`) or `Rotate { old_instance, new_instance }` written by `rotate_kps` (each rotation, `sharing_seq=prev+1`). A rotation records the `old_instance` it consumed so the chain is auditable from the log alone (each entry's `old_instance` should match the prior entry's instance). KPs read the lexicographically last entry to learn the current authoritative instance (commitments + N + T). The log does not carry encrypted shares or a separate recipient roster.
- `kp-shares` logs carry the current encrypted KP share state for a `sharing_seq`. Written by `setup_new_key` (`sharing_seq=0, cert_seq=0`) and each `rotate_kps` (`cert_seq=0` for the new instance). Future cert rotations can append higher `cert_seq` entries under the same `sharing_seq`; readers take the lexicographically last entry under `kp-shares/{sharing_seq:020}/`. The recipient roster is derived from the share labels (`recipient_fingerprint` ordered by share id). Integrity is the enclave signature, not S3 immutability, so these get only a short object lock (a fetch-window guarantee) and stay readable until purged.
- `genesis` is a fixed singleton record carrying the operator-trusted bootstrap committee before any `committee-update/` success exists.
- `committee-update` logs are flat (not date-partitioned). Successes are epoch-sorted; failures lead with `failure-` so all successes sort first — the lex-last non-`failure-` key is the latest successfully-applied epoch.

## Why this layout

- `init/{session_id}-...` keeps init logs session-addressable.
- `heartbeat/...` and `withdraw/...` date partitions support efficient hour-based polling.
- `ceremony/` and `committee-update/` are flat because the consumer always wants "latest"; a lex sort over the whole prefix is cheap and gives that directly. `kp-shares/` is nested by `sharing_seq` because readers want the latest cert state within one current sharing instance. `genesis/record.json` is fixed because there is at most one bootstrap committee.
- Zero-padding (`{seq:020}` in `withdraw/`, `{sharing_seq:020}` in `ceremony/`, `{cert_seq:020}` in `kp-shares/`, `{new_epoch:020}` in `committee-update/`) makes lexicographic order over the keys equal seq/epoch order. The signed log payload embeds the same value, so a fetched object's filename and content can be cross-checked.
- Prefixes (`init`, `heartbeat`, `withdraw`, `ceremony`, `kp-shares`, `genesis`, `committee-update`) allow independent S3 deletion policies.
