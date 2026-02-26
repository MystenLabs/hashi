# hashi-guardian-enclave

Guardian enclave service that emits immutable S3 logs for audit/state-restart workflows.

## S3 log key format

Canonical key layout:

- `init/{session_id}-{init_suffix}.json`
- `heartbeat/{yyyy}/{mm}/{dd}/{hh}/{session_id}-{counter:020}.json`
- `withdraw/{yyyy}/{mm}/{dd}/{hh}/{session_id}-wid{wid}-{status}-{rand8}.json`

Where:

- `session_id` is the enclave ephemeral signing pubkey bytes encoded as lowercase hex.
- `init_suffix` is a semantic label (`oi-attestation-unsigned`, `oi-guardian-info`, `setup-new-key-success`, `pi-success-share-{share_id}`, `pi-enclave-fully-initialized`).
- `counter` is a zero-padded decimal sequence number (used in heartbeats only).
- `status` is `success` or `failure`.
- `rand8` is a random 8-hex suffix to avoid key collisions.

## Stream semantics

- `init` logs are per-session and deterministic by semantic message kind.
- `heartbeat` logs are hour-partitioned and strictly ordered per session.
- `withdraw` logs are hour-partitioned and keyed by wid+status with random de-dup suffix.

## Why this layout

- `init/{session_id}-...` keeps init logs session-addressable.
- `heartbeat/...` and `withdraw/...` date partitions support efficient hour-based polling.
- Prefixes (`init`, `heartbeat`, `withdraw`) allow independent S3 deletion policies.
