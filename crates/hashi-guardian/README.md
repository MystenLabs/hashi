# hashi-guardian

Guardian enclave service that emits immutable S3 logs for audit/state-restart workflows.

## S3 log key format

Canonical key layout:

- `init/{session_id}-{init_suffix}.json`
- `heartbeat/{yyyy}/{mm}/{dd}/{hh}/{session_id}-{counter:020}.json`
- `withdraw/{yyyy}/{mm}/{dd}/{hh}/success-{seq:020}-{session_id}-wid{wid}.json`
- `withdraw/{yyyy}/{mm}/{dd}/{hh}/failure-{session_id}-wid{wid}-{rand8}.json`

Where:

- `session_id` is the enclave ephemeral signing pubkey bytes encoded as lowercase hex.
- `init_suffix` is a semantic label (`oi-attestation-unsigned`, `oi-guardian-info`, `setup-new-key-success`, `pi-success-share-{share_id}`, `pi-enclave-fully-initialized`).
- `counter` is a zero-padded decimal sequence number (used in heartbeats only).
- `seq` is the limiter sequence number consumed by this withdrawal; zero-padded so lexicographic order within an hour bucket equals seq order.
- `rand8` is a random 8-hex suffix to avoid key collisions (failures only — successes are uniquely keyed by seq).

## Stream semantics

- `init` logs are per-session and deterministic by semantic message kind.
- `heartbeat` logs are hour-partitioned and strictly ordered per session.
- `withdraw` logs are hour-partitioned. Successes are seq-sorted within a bucket so the KP rotating in the next enclave can recover limiter state by reading the lexicographically last success key.

## Why this layout

- `init/{session_id}-...` keeps init logs session-addressable.
- `heartbeat/...` and `withdraw/...` date partitions support efficient hour-based polling.
- Prefixes (`init`, `heartbeat`, `withdraw`) allow independent S3 deletion policies.
