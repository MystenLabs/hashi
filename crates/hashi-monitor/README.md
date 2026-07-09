# hashi-monitor
Hashi monitoring library and CLI tool.

## What it does?
Audits the cross-system bridge flow on two parallel tracks.

### Withdrawals (Sui → BTC)
- **E1**: Hashi approval event on Sui (`WithdrawalPickedForProcessing`).
- **E2**: Guardian approval event (success record logged to S3).
- **E3**: BTC transaction confirmed on Bitcoin.

### Deposits (BTC → Sui)
- **E1**: Deposit confirmed on Bitcoin.
- **E2**: `DepositConfirmed` on Sui.

### Checks
- **Predecessor existence**: every successor event has a matching predecessor with consistent txid / wid.
- **Successor existence**: for each non-terminal event, the configured next-event delay bound must hold.

### Modes
1. **Batch**: one-time audit over a guardian time range `[start, end]`.
2. **Continuous**: long-running monitor that polls Sui, Guardian S3, and BTC RPC on fixed intervals and reports findings as they appear.

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

## Status
- Implemented:
  - Domain model and withdrawal / deposit state-machine checks.
  - Batch and continuous auditor loops (cursor advancement, BTC fetch, violation detection, GC, progress watermarks).
  - Guardian S3 withdrawal log polling with attestation and signature verification.
  - BTC confirmation lookup via Bitcoin Core RPC.
- Not yet implemented:
  - Sui event polling — `AuditorCore::poll_sui` is a stub that returns `CursorUnmoved`, so E1 (withdrawal) and the deposit pipeline currently see no Sui input.
