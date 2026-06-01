# hashi-monitor
Hashi monitoring library and CLI tool.

## What it does?
Audits the cross-system bridge flow on two parallel tracks.

### Withdrawals (Sui → BTC)
- **E1**: Hashi approval event on Sui (`WithdrawalPickedForProcessingEvent`).
- **E2**: Guardian approval event (success record logged to S3).
- **E3**: BTC transaction confirmed on Bitcoin.

### Deposits (BTC → Sui)
- **E1**: Deposit confirmed on Bitcoin.
- **E2**: `DepositConfirmedEvent` on Sui.

### Checks
- **Predecessor existence**: every successor event has a matching predecessor with consistent txid / wid.
- **Successor existence**: for each non-terminal event, the configured next-event delay bound must hold.

### Modes
1. **Batch**: one-time audit over a guardian time range `[start, end]`.
2. **Continuous**: long-running monitor that polls Sui, Guardian S3, and BTC RPC on fixed intervals and reports findings as they appear.
3. **Provisioner-init**: one-shot provisioner-init flow run by the key provisioner — audits heartbeats for the latest enclave session, verifies attestation and expected config, auto-detects whether this is a fresh deployment or a rotation (based on whether any prior session's init logs exist in S3) and sources the initial `LimiterState` accordingly (genesis defaults vs. recovered from the prior enclave's withdrawal logs), then builds a `ProvisionerInitRequest` and optionally submits it to a guardian endpoint.

### Timeline semantics (withdrawals)
- User-provided `start` / `end` are interpreted on the **guardian (E2)** timeline.
- Sui events are polled in a relaxed range to validate E2 predecessor constraints.
- Orphan E1 findings are currently still reported when E1 falls in the user window.
- Deposits are not gated by the audit window — there is no false-positive risk.

## Usage

### Batch audit
```bash
cargo run -p hashi-monitor -- batch --config audit.sample.yaml --start 1700000000 --end 1700003600
```
`--end` defaults to the current time if omitted.

### Continuous monitoring
```bash
cargo run -p hashi-monitor -- continuous --config audit.sample.yaml --start 1700000000
```

### Provisioner-init
```bash
cargo run -p hashi-monitor -- provisioner-init --config provisioner-init.sample.yaml
```

## Config
See `audit.sample.yaml` for a complete batch/continuous example:

```yaml
# Liveness delay bounds (seconds)
next_event_delays:
  - [E1HashiApproved, 300] # E1 (Hashi approval) -> E2 (Guardian signing)
  - [E2GuardianApproved, 300] # E2 (Guardian signing) -> E3 (BTC confirmed)

# Optional: clock skew tolerance (default: 300s)
# clock_skew: 300

guardian:
  s3_bucket: "hashi-guardian-logs"

sui:
  rpc_url: "https://fullnode.testnet.sui.io:443"

btc:
  rpc_url: "http://localhost:8332"
  rpc_auth:
    type: none
```

The `provisioner-init` subcommand takes a separate YAML (`ProvisionerConfig`, see `provisioner-init.sample.yaml`) with the key-provisioner share, expected share commitments, S3 config, Hashi committee, withdrawal config, and Hashi BTC master pubkey; if `guardian_endpoint` is set, the request is submitted after local checks pass.

## Status
- Implemented:
  - Domain model and withdrawal / deposit state-machine checks.
  - Batch and continuous auditor loops (cursor advancement, BTC fetch, violation detection, GC, progress watermarks).
  - Guardian S3 withdrawal log polling with attestation and signature verification.
  - BTC confirmation lookup via Bitcoin Core RPC.
  - Provisioner-init flow (heartbeat audit, attestation/config check, optional submission).
  - Limiter state recovery: each successful withdrawal log embeds the post-consume `LimiterState`; on rotation, provisioner-init walks back hour buckets to find the max-seq Success log and uses its embedded state as the new enclave's initial state. Genesis path (no prior session in S3) seeds the limiter from `LimiterConfig` instead.
- Not yet implemented:
  - Sui event polling — `AuditorCore::poll_sui` is a stub that returns `CursorUnmoved`, so E1 (withdrawal) and the deposit pipeline currently see no Sui input.
