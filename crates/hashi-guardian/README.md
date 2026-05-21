# hashi-guardian

Guardian enclave service that emits immutable S3 logs for audit/state-restart workflows.

## S3 log key format

Canonical key layout:

- `init/{session_id}-{init_suffix}.json`
- `heartbeat/{yyyy}/{mm}/{dd}/{hh}/{session_id}-{counter:020}.json`
- `withdraw/{yyyy}/{mm}/{dd}/{hh}/success-{seq:020}-{session_id}-wid{wid}.json`
- `withdraw/{yyyy}/{mm}/{dd}/{hh}/failure-{session_id}-wid{wid}-{rand8}.json`
- `key_state/{seq:020}-{session_id}.json`

Where:

- `session_id` is the enclave ephemeral signing pubkey bytes encoded as lowercase hex.
- `init_suffix` is a semantic label (`oi-attestation-unsigned`, `oi-guardian-info`, `pi-success-share-{share_id}`, `pi-enclave-fully-initialized`).
- `counter` is a zero-padded decimal sequence number (used in heartbeats only).
- `seq` is a zero-padded sequence number, scoped to its stream:
  - In `withdraw/`, it's the limiter sequence number consumed by the withdrawal.
  - In `key_state/`, it's the rotation counter — genesis writes `seq=0`; future key-provisioner rotations will append `seq=prev+1`.
- `rand8` is a random 8-hex suffix to avoid key collisions (failures only — successes are uniquely keyed by seq).

## Stream semantics

- `init` logs are per-session and deterministic by semantic message kind.
- `heartbeat` logs are hour-partitioned and strictly ordered per session.
- `withdraw` logs are hour-partitioned. Successes are seq-sorted within a bucket so the KP rotating in the next enclave can recover limiter state by reading the lexicographically last success key.
- `key_state` logs are flat (not date-partitioned). Each entry is a `CurrentKeyState { seq, encrypted_shares, share_commitments }` written by `setup_new_key` (genesis, `seq=0`). KPs read the lexicographically last entry to learn the current authoritative commitments and to fetch their encrypted shares.

## Why this layout

- `init/{session_id}-...` keeps init logs session-addressable.
- `heartbeat/...` and `withdraw/...` date partitions support efficient hour-based polling.
- `key_state/` is flat because the consumer always wants "latest"; a lex sort over the whole prefix is cheap and gives that directly.
- The `{seq:020}` zero-padding everywhere it appears (`withdraw/`, `key_state/`) is the same trick: lexicographic order over the keys equals seq order. The signed log payload embeds the same seq, so a fetched object's filename and content can be cross-checked.
- Prefixes (`init`, `heartbeat`, `withdraw`, `key_state`) allow independent S3 deletion policies.
