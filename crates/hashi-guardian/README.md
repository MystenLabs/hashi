# hashi-guardian

Guardian enclave service that emits immutable S3 logs for audit/state-restart workflows.

## S3 log key format

Canonical key layout:

- `init/{session_id}-{init_suffix}.json`
- `heartbeat/{yyyy}/{mm}/{dd}/{hh}/{session_id}-{counter:020}.json`
- `withdraw/{yyyy}/{mm}/{dd}/{hh}/success-{seq:020}-{session_id}-wid{wid}.json`
- `withdraw/{yyyy}/{mm}/{dd}/{hh}/failure-{session_id}-wid{wid}-{rand8}.json`
- `ceremony/{sharing_seq:020}-{session_id}.json`

Where:

- `session_id` is the first 16 hex chars of the enclave ephemeral signing pubkey (lowercase). Acts as a short per-session tag in keys; full pubkey verification still happens via the signed log payload (`SESSION_ID_HEX_LEN` in `hashi-types`).
- `init_suffix` is a semantic label (`oi-attestation-unsigned`, `oi-guardian-info`, `pi-success-share-{share_id}`, `pi-enclave-fully-initialized`).
- `counter` is a zero-padded decimal sequence number (used in heartbeats only).
- `seq` (in `withdraw/`) is the zero-padded limiter sequence number consumed by the withdrawal.
- `sharing_seq` (in `ceremony/`) is a zero-padded rotation counter — `setup_new_key` writes `0`; each `rotate_kps` appends `prev+1`.
- `rand8` is a random 8-hex suffix to avoid key collisions (failures only — successes are uniquely keyed by seq).

## Stream semantics

- `init` logs are per-session and deterministic by semantic message kind.
- `heartbeat` logs are hour-partitioned and strictly ordered per session.
- `withdraw` logs are hour-partitioned. Successes are seq-sorted within a bucket so the KP rotating in the next enclave can recover limiter state by reading the lexicographically last success key.
- `ceremony` logs are flat (not date-partitioned). Each entry is a `CeremonyLogMessage { encrypted_shares, secret_sharing_instance }` written by `setup_new_key` (genesis, `sharing_seq=0`) or `rotate_kps` (each rotation, `sharing_seq=prev+1`). KPs read the lexicographically last entry to learn the current authoritative instance (commitments + N + T) and to fetch their encrypted shares.

## Why this layout

- `init/{session_id}-...` keeps init logs session-addressable.
- `heartbeat/...` and `withdraw/...` date partitions support efficient hour-based polling.
- `ceremony/` is flat because the consumer always wants "latest"; a lex sort over the whole prefix is cheap and gives that directly.
- Zero-padding (`{seq:020}` in `withdraw/`, `{sharing_seq:020}` in `ceremony/`) makes lexicographic order over the keys equal seq order. The signed log payload embeds the same value, so a fetched object's filename and content can be cross-checked.
- Prefixes (`init`, `heartbeat`, `withdraw`, `ceremony`) allow independent S3 deletion policies.
