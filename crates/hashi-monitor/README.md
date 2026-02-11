# hashi-monitor
Hashi monitoring library and CLI tool.

## What it does?
- Cursorless batch auditor over a time range `[t1, t2]`.
- Downloads Guardian logs (E2) and Sui events (E1/E3) with derived lookback/lookahead windows based on delay bounds.
- Checks:
  - Safety (predecessors):
    - For every E2 in `[t1, t2]`, there exists an E1.
    - For every E3 in `[t1, t2]`, there exists an E2 (and txid matches).
  - Liveness (successors, when the corresponding horizon covers the deadline):
    - For every E1 in `[t1, t2]`, there exists an E2 by `E1.ts + e1_e2_delay_secs`.
    - For every E2 in `[t1, t2]`, there exists an E3 by `E2.ts + e2_e3_delay_secs`.
    - For every E3 in `[t1, t2]`, the BTC txid exists on Bitcoin by `E3.ts + e3_e4_delay_secs`.

## Usage
Provide a YAML config plus `t1`/`t2` unix seconds:

```bash
cargo run -p hashi-monitor -- --config config.sample.yaml --t1 1700000000 --t2 1700003600
```

On success, outputs `verified_up_to` and `next_t1` for chaining invocations.

## Config
See `config.sample.yaml` for a complete example:

```yaml
# Liveness delay bounds (seconds)
e1_e2_delay_secs: 300   # E1 (Sui init) -> E2 (Guardian approval)
e2_e3_delay_secs: 300   # E2 (Guardian approval) -> E3 (Sui approval)
e3_e4_delay_secs: 600   # E3 (Sui approval) -> BTC broadcast

# Optional: extra slack for clock skew and ingestion jitter (default: 60s)
# slack_secs: 60

guardian:
  s3_bucket: "hashi-guardian-logs"

sui:
  rpc_url: "https://fullnode.testnet.sui.io:443"

btc:
  rpc_url: "http://localhost:8332"
```

## Status
The CLI flow and checks are wired up. TODOs:
- `download_e2_guardian` - S3 download implementation
- `download_e1_e3_sui` - Sui RPC implementation
- `check_if_btc_txid_exists` - BTC RPC implementation
