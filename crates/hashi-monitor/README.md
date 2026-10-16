# hashi-monitor
Hashi monitoring library and CLI tool.

## What it does?
Audits the cross-system bridge flow on two parallel tracks.

### Withdrawals (Sui → BTC)
- **E1**: Hashi approval event on Sui (`WithdrawalPickedForProcessing`).
- **E2**: Guardian approval event (success record logged to S3).
- **E3**: BTC transaction confirmed on Bitcoin, timed by the block that gave it
  six confirmations.

### Deposits (BTC → Sui)
- **E1**: Deposit confirmed on Bitcoin, timed by the block that gave it six
  confirmations.
- **E2**: `DepositConfirmed` on Sui. Because its Move payload has no timestamp,
  the monitor uses the timestamp of its containing checkpoint returned by Sui
  gRPC.

### Checks
- **Predecessor existence**: every successor event has a matching predecessor with consistent txid / wid.
- **Successor existence**: for each non-terminal event, the configured next-event delay bound must hold.

Findings are tagged as:
- **liveness** when a successor is late or still missing after its deadline;
- **safety** for a contradictory event, a late predecessor, a predecessor
  still missing after its source cursor passes the deadline, an event the
  Sui scan covered but never returned, a Hashi approval whose txid does not
  match its inputs and outputs or whose inputs and outputs differ from the
  guardian's, a confirmed deposit
  whose Bitcoin output does not match the Sui request, or a guardian
  withdrawal log whose signed time differs from its S3 `LastModified` time
  by more than 30 seconds (`MAX_EXPECTED_LOG_CLOCK_SKEW` in `hashi-guardian`).

Move does not validate a Hashi approval's txid or change outputs. The monitor
rebuilds the Bitcoin transaction from the approval and checks that the txid
matches; an approval that fails is reported at once and not ingested. Each
withdrawal event carries the inputs, user payouts and change in Move's shape.
The guardian's log, which labels every output it signs as a user payout or
as change to a derivation path, is converted into that shape with the change
addresses the paths derive. Sui's and the guardian's statements must be
equal, in either ingestion order; otherwise a committee can label a payout to
itself as change. The monitor assumes no fixed change path. The bridge keys
that derive the change addresses are read once at startup from the
guardian's genesis and ceremony records.

Move does not see Bitcoin, so the monitor compares a confirmed deposit's
output with the Sui request: the same amount, and the same script as the bridge
address of the claimed derivation path. Without this, a compromised committee
can mint hBTC against any confirmed transaction.

Before reporting a missing withdrawal E1, the monitor reads the withdrawal's
`WithdrawalTransaction` object from Sui, so an E1 older than the predecessor
lookback still matches. An E1 found this way inside the range the Sui scan
already covered also raises `SuiScanMissedEvent`.

### Modes
1. **Batch**: one-time audit over a guardian time range `[start, end]`.
2. **Continuous**: long-running monitor that polls Sui, Guardian S3, and BTC RPC on fixed intervals and reports findings as they appear.

### Timeline semantics (withdrawals)
- User-provided `start` / `end` are interpreted on the **guardian (E2)** timeline.
- Sui withdrawal events are polled from one E1 delay before the guardian
  window, since an E1 older than that is a late E2 in its own right. An E1
  outside the scan is still read from Sui by its withdrawal id.
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
defaults to the current time if omitted. A batch audit fails if the Sui node has
pruned the start of its Sui range.

### Continuous monitoring
```bash
cargo run -p hashi-monitor -- continuous \
  --config audit.sample.yaml \
  --start 2026-08-04T19:00:00Z
```
Without `--start`, the audit starts far enough back to cover a monitor outage of
up to a week, including checks that were still pending when it began. Findings
from that period are reported again after a restart. If the Sui node has pruned
part of that range (the public testnet fullnode keeps under six days), the Sui
scan starts near its oldest checkpoint: withdrawal approvals from before it are
still read by withdrawal id if the guardian signed them, but deposits and
unsigned approvals from before it are not audited.

## Config
The config file holds the identity of one deployment. See `audit.sample.yaml`
for a complete batch/continuous example. The deployment in sui-operations
stores that shape verbatim.

- The required `deployment` block contains the expected Bitcoin network, S3
  bucket/region, retention environment, and PCR allowlist. Every Guardian
  writing session must match that deployment. Historical builds remain
  accepted through `deployment.pcr_allowlist.prev_builds`.
- Omit `s3_credentials` to use the AWS default credential chain; explicit
  credentials require both keys and may include a session token.
- Any string value may be `env:NAME`. The monitor replaces it with the
  environment variable `NAME` at startup. Use it for bucket names, endpoints
  and credentials.
- Unknown keys are an error, so a typo cannot be ignored.

The timing bounds of the withdrawal and deposit flows are not configuration.
They describe the protocol and are the same in every environment, so they
are constants in `src/timing.rs`, each with its reason:

| Bound | Value | Meaning |
|---|---|---|
| E1 -> E2 delay | 1 h | the guardian must sign within this of a Hashi approval |
| E2 -> E3 delay | 1 d | the signed transaction must get six confirmations on Bitcoin within this |
| E1 after E2 skew | 5 min | the guardian's request clock tolerance |
| E2 after E3 skew | 2 h | a block time may lag real time by this |
| deposit confirmation skew | 2 h | a deposit's confirmation time may be after its Hashi confirmation by this; a miner may date a block two hours ahead |

```yaml
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

    # Older still-trusted builds accepted only for historical S3 logs. Keep a
    # replaced build until a restart no longer re-audits its records: a week and
    # 2.5 hours plus the longest next-event delay and clock skew.
    prev_builds: []
    # prev_builds:
    #   - git_revision: "1111111111111111111111111111111111111111"
    #     pcr0: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"

# Optional explicit credentials; omit this block to use AWS's default credential chain.
# s3_credentials:
#   access_key: "..."
#   secret_key: "..."
#   session_token: "..." # Only for temporary credentials.

sui:
  rpc_url: "https://fullnode.testnet.sui.io:443"
  package_id: "0x0000000000000000000000000000000000000000000000000000000000000000"

btc:
  rpc_url: "env:BITCOIN_RPC_URL"
  # Optional headers for hosted JSON-RPC providers:
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
