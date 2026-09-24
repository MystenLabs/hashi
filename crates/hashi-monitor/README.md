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
- **E2**: `DepositConfirmed` on Sui. Because its Move payload has no timestamp,
  the monitor uses the timestamp of its containing checkpoint returned by Sui
  gRPC.

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

Start from `audit.sample.yaml` and fill in your deployment's identifiers and
PCR allowlist. Supply AWS credentials through the default credential chain or
the optional `s3_credentials` block, and set `BITCOIN_RPC_URL` to your Bitcoin
JSON-RPC endpoint.

Run the examples below from `crates/hashi-monitor`, or prefix the configuration
path with `crates/hashi-monitor/` when running from the repository root.

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
Without `--start`, the audit resumes from the earliest time whose checks can
still be pending, which is what a restarted service wants.

## Config
See `audit.sample.yaml` for a complete batch/continuous example:

The required `deployment` block contains the expected Bitcoin network, S3
bucket/region, retention environment, and PCR allowlist. Every Guardian writing
session must match that deployment. Historical builds remain accepted through
`deployment.pcr_allowlist.prev_builds`. Omit `s3_credentials` to use the AWS default
credential chain; explicit credentials require both keys and may include a session token.

```yaml
# Liveness delay bounds (seconds)
next_event_delays:
  - [E1HashiApproved, 300] # E1 (Hashi approval) -> E2 (Guardian signing)
  - [E2GuardianApproved, 300] # E2 (Guardian signing) -> E3 (BTC confirmed)

# Optional: clock skew tolerance (default: 300s)
# clock_skew: 300

# Optional: Sui withdrawal history before the guardian window (default: 1 hour)
# withdrawal_predecessor_lookback: 3600

# Deployment identity and builds accepted when auditing Guardian logs.
deployment:
  bucket_info:
    name: "hashi-guardian-logs"
    region: "us-east-1"
  retention_environment: "testnet"
  bitcoin_network: "signet"
  pcr_allowlist:
    # Expected enclave build: git revision + PCR0 (hex). The live guardian must
    # report this revision, and its attestation PCR0 must match it.
    current_build:
      git_revision: "0000000000000000000000000000000000000000"
      pcr0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

    # Older still-trusted builds accepted only for historical S3 logs during an
    # upgrade window. Omit or leave empty outside an upgrade.
    prev_builds: []
    # prev_builds:
    #   - git_revision: "1111111111111111111111111111111111111111"
    #     pcr0: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"

# Optional explicit credentials; omit this block to use AWS's default credential chain.
# s3_credentials:
#   access_key: "..."
#   secret_key: "..."
#   session_token: "..." # Only for temporary credentials.

# Expected enclave build: git revision + PCR0 (hex).
current_build:
  git_revision: "0000000000000000000000000000000000000000"
  pcr0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

sui:
  rpc_url: "https://fullnode.testnet.sui.io:443"
  package_id: "0x0000000000000000000000000000000000000000000000000000000000000000"

btc:
  rpc_url: "env:BITCOIN_RPC_URL"
  # http_headers:
  #   Origin: "https://example.com"
  #   Authorization: "env:BITCOIN_RPC_AUTHORIZATION"
```

## Status
- Implemented:
  - Domain model and withdrawal / deposit state-machine checks.
  - Batch and continuous auditor loops (cursor advancement, BTC fetch, violation detection, GC, progress watermarks).
  - Guardian S3 withdrawal log polling with attestation and signature verification.
  - Checkpoint-bounded, resumable Sui polling for withdrawal and deposit events.
  - Batched BTC confirmation lookup over HTTP JSON-RPC.
