# hashi-guardian

Guardian enclave service that emits immutable S3 logs for audit/state-restart workflows.

## S3 log key format

Canonical key layout:

- `init/{session_id}-{init_suffix}.json`
- `heartbeat/{yyyy}/{mm}/{dd}/{hh}/{session_id}-{counter:020}.json`
- `withdraw/{yyyy}/{mm}/{dd}/{hh}/success-{seq:020}-{session_id}-wid{wid}.json`
- `withdraw/{yyyy}/{mm}/{dd}/{hh}/failure-{session_id}-wid{wid}-{rand8}.json`
- `ceremony/{sharing_seq:020}-{session_id}.json`
- `committee-update/{new_epoch:020}-{session_id}.json`
- `committee-update/failure-{proposed_epoch:020}-{session_id}-{rand8}.json`

Where:

- `session_id` is the first 16 hex chars of the enclave ephemeral signing pubkey (lowercase). Acts as a short per-session tag in keys; full pubkey verification still happens via the signed log payload (`SESSION_ID_HEX_LEN` in `hashi-types`).
- `init_suffix` is a semantic label (`oi-attestation-unsigned`, `oi-guardian-info`, `pi-success-share-{share_id}`, `pi-enclave-fully-initialized`).
- `counter` is a zero-padded decimal sequence number (used in heartbeats only).
- `seq` (in `withdraw/`) is the zero-padded limiter sequence number consumed by the withdrawal.
- `sharing_seq` (in `ceremony/`) is a zero-padded rotation counter — `setup_new_key` writes `0`; each `rotate_kps` appends `prev+1`.
- `new_epoch` / `proposed_epoch` (in `committee-update/`) are the zero-padded committee epoch numbers — `new_epoch` is the just-applied epoch for successes; `proposed_epoch` is the requested epoch for failures. Hashi reconfig is sparse, so neither is guaranteed to be `from_epoch + 1`.
- `rand8` is a random 8-hex suffix to avoid key collisions (failures only — successes are uniquely keyed by seq).

## Stream semantics

- `init` logs are per-session and deterministic by semantic message kind.
- `heartbeat` logs are hour-partitioned and strictly ordered per session.
- `withdraw` logs are hour-partitioned. Successes are seq-sorted within a bucket so the KP rotating in the next enclave can recover limiter state by reading the lexicographically last success key.
- `ceremony` logs are flat (not date-partitioned). Each entry is a `CeremonyLogMessage { secret_sharing_instance }` written by `setup_new_key` (genesis, `sharing_seq=0`) or `rotate_kps` (each rotation, `sharing_seq=prev+1`). KPs read the lexicographically last entry to learn the current authoritative instance (commitments + N + T). The log does not carry the encrypted shares; KPs fetch their ciphertexts from the `setup_new_key` / `rotate_kps` response or from `get_guardian_info`, decrypt them, and verify the result against the instance's per-share commitments.
- `committee-update` logs are flat (not date-partitioned). Successes are epoch-sorted; failures lead with `failure-` so all successes sort first — the lex-last non-`failure-` key is the latest successfully-applied epoch.

## Why this layout

- `init/{session_id}-...` keeps init logs session-addressable.
- `heartbeat/...` and `withdraw/...` date partitions support efficient hour-based polling.
- `ceremony/` and `committee-update/` are flat because the consumer always wants "latest"; a lex sort over the whole prefix is cheap and gives that directly.
- Zero-padding (`{seq:020}` in `withdraw/`, `{sharing_seq:020}` in `ceremony/`, `{new_epoch:020}` in `committee-update/`) makes lexicographic order over the keys equal seq/epoch order. The signed log payload embeds the same value, so a fetched object's filename and content can be cross-checked.
- Prefixes (`init`, `heartbeat`, `withdraw`, `ceremony`, `committee-update`) allow independent S3 deletion policies.
