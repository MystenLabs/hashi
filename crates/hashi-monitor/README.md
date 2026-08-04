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
- **E2**: `DepositApproved` on Sui.

### Checks
- **Predecessor existence**: every successor event has a matching predecessor with consistent txid / wid.
- **Successor existence**: for each non-terminal event, the configured next-event delay bound must hold.

Findings are tagged as:
- **liveness** when a successor is late or still missing after its deadline;
- **safety** for a contradictory event, a late predecessor, or a predecessor
  still missing after its source cursor passes the deadline.

For withdrawals, a predecessor lookback that is too short can produce a false
safety finding for a missing E1. Reconcile older Sui history before treating
such a finding as conclusive.

### Modes
1. **Batch**: one-time audit over a guardian time range `[start, end]`.
2. **Continuous**: long-running monitor that polls Sui, Guardian S3, and BTC RPC on fixed intervals and reports findings as they appear.

### Timeline semantics (withdrawals)
- User-provided `start` / `end` are interpreted on the **guardian (E2)** timeline.
- Sui withdrawal events are polled from `withdrawal_predecessor_lookback`
  seconds before the guardian window to validate E2 predecessor constraints.
- Orphan E1 findings are currently still reported when E1 falls in the user window.
- Deposits are audited over the derived Sui range rather than gated by the
  withdrawal audit-window logic.

## Usage

### Active testnet

`audit.testnet.yaml` contains the active Hashi Guardian testnet deployment
identifiers and PCR allowlist. Supply AWS credentials through the default
credential chain and keep the Signet provider URI in the environment:

```bash
export AWS_PROFILE=guardian-s3-testnet
export HASHI_SKIP_S3_OBJECT_LOCK_CHECK=1
export HASHI_BITCOIN_RPC_URL="https://your-signet-json-rpc-endpoint"

cargo run -p hashi-monitor -- continuous \
  --config audit.testnet.yaml \
  --start 2026-08-04T19:00:00Z
```

Run this from `crates/hashi-monitor`, or prefix the configuration path with
`crates/hashi-monitor/` when running from the repository root. The object-lock
bypass is temporary and is described below.

### Batch audit
```bash
cargo run -p hashi-monitor -- batch \
  --config audit.sample.yaml \
  --start 2026-08-04T18:00:00Z \
  --end 2026-08-04T19:00:00Z
```
CLI timestamps use whole-second UTC RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`). `--end`
defaults to the current time if omitted.

### Continuous monitoring
```bash
cargo run -p hashi-monitor -- continuous \
  --config audit.sample.yaml \
  --start 2026-08-04T19:00:00Z
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

# Optional: Sui withdrawal history before the guardian window (default: 1 hour)
# withdrawal_predecessor_lookback: 3600

guardian_s3:
  bucket: "hashi-guardian-logs"
  region: "us-east-1"
  # Omit both keys to use the AWS default credential chain.
  # access_key: "..."
  # secret_key: "..."
  retention_environment: "testnet"

sui:
  rpc_url: "https://fullnode.testnet.sui.io:443"
  package_id: "0x0000000000000000000000000000000000000000000000000000000000000000"

btc:
  rpc_url: "env:BITCOIN_RPC_URL"
  # http_headers:
  #   Origin: "https://example.com"
```

## Status
- Implemented:
  - Domain model and withdrawal / deposit state-machine checks.
  - Batch and continuous auditor loops (cursor advancement, BTC fetch, violation detection, GC, progress watermarks).
  - Guardian S3 withdrawal log polling with attestation and signature verification.
  - Checkpoint-bounded, resumable Sui polling for withdrawal and deposit events.
  - Batched BTC confirmation lookup over HTTP JSON-RPC.

## Temporary testnet object-lock bypass

Setting `HASHI_SKIP_S3_OBJECT_LOCK_CHECK` disables S3 object-lock metadata
validation for the process. Signature, PCR, signed object-key, and S3 version
history checks remain enabled. This escape hatch exists only for legacy testnet
logs written before long-lived retention was configured and should be removed
after the planned testnet wipe.
