# hashi-monitor
Hashi monitoring library and CLI tool.

## What it does?
Audits the cross-system withdrawal flow:
- **E1**: Hashi approval event on Sui (PendingWithdrawal creation)
- **E2**: Guardian approval event (logged to S3)
- **E3**: BTC transaction confirmed on Bitcoin

### Checks
- **Predecessor existence**: For every E2, there exists a corresponding E1. For every E3, there exists a corresponding E2 with matching txid.
- **Successor existence**: For every source event, the configured successor delay bound must hold.

### Two modes
1. **Batch**: One-time audit over a guardian time range `[start, end]`.
2. **Continuous**: Intended long-running monitor over guardian timeline.

### Timeline semantics
- User-provided `start` / `end` are interpreted on the **guardian (E2)** timeline.
- Sui events are still polled in a relaxed range to validate E2 predecessor constraints.
- Orphan E1 findings are currently still reported when E1 falls in the user window.

## Usage

### Batch audit
```bash
cargo run -p hashi-monitor -- batch --config config.sample.yaml --start 1700000000 --end 1700003600
```

### Continuous monitoring
```bash
cargo run -p hashi-monitor -- continuous --config config.sample.yaml --start 1700000000
```

## Config
See `config.sample.yaml` for a complete example:

```yaml
# Next event delay bounds (seconds)
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
```

## Status
This crate is currently a scaffold for a future full audit implementation.

- Implemented now:
  - Domain model and withdrawal state-machine checks.
  - Batch/continuous auditor structure and CLI wiring.
- Deferred to a follow-up PR:
  - Sui event download/polling.
  - Guardian S3 event download/polling.
  - BTC confirmation lookup.
  - `batch` and `continuous` are wired through the CLI but currently stop at deferred `todo!` implementation points.
