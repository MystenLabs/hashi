# hashi-monitor
Hashi monitoring library and CLI tool.

## What it does
Audits the cross-system bridge flow on two parallel tracks.

### Withdrawals (Sui → BTC)
- **E1**: Hashi approval event on Sui (`WithdrawalPickedForProcessing`).
- **E2**: Guardian approval event (success record logged to S3).
- **E3**: BTC transaction confirmed on Bitcoin, timed by the block that gave it
  six confirmations.

### Deposits (BTC → Sui)
- **Request**: `DepositRequested` on Sui, the user's claim. The monitor asks
  Bitcoin about its transaction, and the UTXO pool takes a valid output.
- **Approval**: `DepositApproved` on Sui, the committee's claim that the
  deposit is paid. Move mints hBTC at `DepositConfirmed`, which needs an
  approval at least `bitcoin_deposit_time_delay_ms` earlier. The delay lets
  operators pause Hashi before a bad mint, so the monitor judges the
  approval, not the mint. The approval carries its own timestamp.

### Checks
- **Predecessor existence**: every successor event has a matching predecessor with consistent txid / wid.
- **Successor existence**: for each non-terminal event, the next-event delay bound must hold.

Every finding needs an operator action, so all findings have one level.
The monitor reports a finding for:
- a successor that is late or still missing after its deadline;
- a contradictory event, a late predecessor, or a predecessor
  still missing after its source cursor passes the deadline;
- a Hashi approval or a guardian log
  whose txid does not match its inputs and outputs, a Hashi approval whose
  inputs and outputs differ from the guardian's, an approved deposit
  Bitcoin does not back, or a guardian
  withdrawal log whose signed time differs from its S3 `LastModified` time
  by more than 30 seconds (`MAX_EXPECTED_LOG_CLOCK_SKEW` in `hashi-guardian`);
- a break in the guardian's seq order (`GuardianInconsistency`): two
  withdrawal logs with the same `seq`, a `seq` without a log by the end of
  the hour after a higher seq appeared, or a skip of more than 10 seqs. The
  guardian's limiter takes each seq once, in order, so two logs for one seq
  mean that two guardian sessions signed from one limiter state;
- a source the monitor last checked longer ago than its limit
  (`SourceStale`: three hours for each source),
  or no successful snapshot save for 12 hours (`SnapshotStale`);
- an hBTC supply on Sui that has exceeded the value of the UTXO pool for
  three hours (`HbtcSupplyExceedsPool`). In an honest bridge the supply never
  exceeds the pool: the pool takes a deposit before Move mints it, and Move
  burns a withdrawal before Bitcoin spends its inputs.

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

Move does not see Bitcoin, so the monitor checks every `DepositApproved`
against what Bitcoin paid: the request's own answer if its lookup is still
open, otherwise the UTXO pool. The UTXO must exist, or the pool must have spent
it, as a deposit (`DepositUnbacked`), with the same amount and the same script
as the bridge address of the claimed derivation path (`DepositMismatch`). Its
block must be no later than the approval plus the skew (`DepositLate`): a late
block means Hashi approved before Bitcoin confirmed, or the skew is too tight.
Without this,
a compromised committee can mint hBTC against any confirmed transaction. An
approval that arrives while its request's lookup is still open is judged
when Bitcoin answers or the request lapses. Before that, if two Bitcoin lookups
after the approval find the transaction not yet confirmed, the approval is
reported as `DepositUnbacked`, and again at every later empty lookup. The honest committee approves only at
the confirmation depth, so one lookup may race it by seconds; the second
lookup is one tick later. A request is approved again after a
committee change; the monitor judges only the first approval, since every
approval names the same UTXO and the first has the earliest deadline.

The monitor also follows every `DepositRequested`, the user's own claim that a
Bitcoin output pays the bridge. The committee cannot suppress it. Bitcoin is
asked about the transaction for the watch period of two days. Assumption: an
honest deposit confirms on Bitcoin within it. Move marks a request expired
after a day and an honest leader deletes it, so a slow deposit is requested
again. Move does not refuse to approve an older request, though. A UTXO that
confirms after the watch never enters the monitor's UTXO pool, so an approval
of it is judged against the pool and reported as `DepositUnbacked`.
An output that pays the bridge script of a
claimed derivation path is bridge money, whatever Move does with the request
later; the monitor's UTXO pool takes it (IOP-747). A UTXO Move never confirms,
whether the committee withholds it or a member's sanctions screening rejected
it, shows up in the pool's checks. A claim no output matches is the user's
problem and is dropped. Each request has its own lookup, so a corrected
request for the same UTXO is followed on its own.

### UTXO pool
Each bridge UTXO is a 2-of-2 between the MPC committee and the guardian, plus
a recovery leaf that lets the committee spend alone 60 days after the UTXO
confirms. A compromised committee can mark a UTXO spent on Move without
spending it on Bitcoin, or keep a deposit out of Move, then wait for that day.
So the monitor keeps its own pool of the UTXOs the bridge holds, and only a
Bitcoin fact changes it:

- A UTXO enters when Bitcoin confirms a deposit request's output at the
  bridge script of the claimed path. The committee is not needed.
- When a withdrawal flow is complete, E1, E2 and E3 seen, its change
  outputs enter and its inputs leave. The inputs and amounts come from the
  confirmed Bitcoin transaction.
  Which outputs are change comes from E2: the guardian labels each output
  from paths it derives itself. A withdrawal that never completes never
  touches the pool.
- The pool is fed right after the Bitcoin lookups, before any other poll.
  Bitcoin confirms a withdrawal only after the deposits and withdrawals that
  made its inputs, and one round of lookups answers them all, so a
  withdrawal's inputs enter the pool before the withdrawal spends them. The
  Sui scan can deliver a deposit request and the withdrawal that spends it in
  one poll; the pool waits for the lookups that follow.

Every operation is strict. A second add of a held UTXO is a repeat and is
skipped. One that contradicts
the pool is a finding: `BtcRpcInconsistency` `UtxoMismatch` when
Bitcoin confirms a held outpoint with a second amount or script, since
Bitcoin cannot produce it; `UtxoUnknownInputSpent` when a
confirmed withdrawal spends a UTXO the pool does not hold, since the bridge
spent a UTXO that no verified deposit or change brought in; the pool records
nothing for that spend. In one Bitcoin pass
every add comes before every spend, so a pass
that answers a deposit and the withdrawal that spends it is right in any
order.

Move's records are never read for the pool. The pool starts empty on the
first run, which starts at the bridge's genesis on a fullnode that still
serves the history, so every UTXO is seen enter. The pool keeps no record
of spent UTXOs. It does not need one: the monitor reads each event once, and
Move refuses a deposit request or approval for a UTXO it holds or spent.
The pool is kept between runs in
the monitor's snapshot, so a restart resumes with the pool the last run
built. See "Running the monitor" below.

The monitor asks Bitcoin about every held UTXO at the first pool maintenance tick.
It repeats successful checks once a day. The monitor reports:

- `UtxoTooOld` when a UTXO has sat unspent past `UTXO_MAX_AGE` (40 days).
  The committee can spend it alone at 60 days, so this leaves 20 days to act;
- `UtxoUnexpectedSpend` when a UTXO was spent by a transaction that is not a
  confirmed Hashi withdrawal. This one is not reported at once: a withdrawal
  committed since the last Sui poll can be mined already. The spend waits,
  and a state check reports it once the Sui cursor is past the time Bitcoin
  was asked and still no withdrawal explains it: none the monitor follows
  names the UTXO, and the pool took none that spent it;
- `BtcRpcInconsistency` for `UtxoVanished` when a UTXO Bitcoin
  confirmed does not exist on Bitcoin. Every UTXO held was confirmed when it
  entered, so a missing answer is a reorg, a node without the transaction
  index, or a monitor bug.

A UTXO that a withdrawal the monitor follows spends is not checked. Bitcoin
spends it about an hour before the flow completes, and an incomplete flow
has its own finding.

A UTXO paid to a bridge address with no `DepositRequested`, or with a wrong
derivation path, is invisible to the monitor and out of scope. A paid deposit
that Move never approves stays in the pool and is reported at `UTXO_MAX_AGE`.

### Timeline semantics (withdrawals)
The monitor polls Sui, Guardian S3, and BTC RPC on fixed intervals and reports
findings as they appear.

- The first run reads Sui and the guardian log from the bridge's genesis,
  so the monitor sees every flow from its first event.
- The monitor reads the guardian's current hour directory every five
  minutes, while it fills, so an E2 arrives within about five minutes of
  its log.
- A restart resumes each source exactly where the last run stopped, with
  the open flows the last run held.

## Usage

Start from `audit.sample.yaml` and fill in your deployment's identifiers and
PCR allowlist. Supply AWS credentials through the default credential chain or
the optional `s3_credentials` block, and set `BITCOIN_RPC_URL` to your Bitcoin
JSON-RPC endpoint.

Run the examples below from `crates/hashi-monitor`, or prefix the configuration
path with `crates/hashi-monitor/` when running from the repository root.

### Running the monitor
```bash
cargo run -p hashi-monitor -- \
  --config audit.sample.yaml \
  --snapshot-bucket my-hashi-monitor-snapshot
```
The monitor keeps a snapshot in the bucket and saves it after every state
check: the deployment it audits, the next Sui checkpoint, the guardian hourly
directory with the logs and the seqs read so far, every open flow, the
spends the last pool check has not judged yet, and the UTXO pool, all in
`snapshot.json`. The monitor needs
read and write access to the bucket, through `GOOGLE_APPLICATION_CREDENTIALS`
or, on GKE, its workload identity, and fails to start without it. It must be
the bucket's only writer.

The first run has no snapshot. It starts at the bridge's genesis on Sui, the
checkpoint time of the transaction that published the Hashi package in the
config, with an empty pool, so every UTXO is seen enter. That needs a Sui
node that keeps the history from genesis; the public testnet fullnode keeps
about ten days, and `archive.<network>.sui.io` keeps everything. The monitor
fails to start on a node that has pruned the start, on a first run or a
restart, since a pruned start would leave the pool incomplete for good.

The scan from genesis runs in ranges of 10,000 checkpoints, about an hour of
Sui each, and the state checks wait for it. On a busy network it takes hours.

A restart resumes from the snapshot. It holds the saved flows again and
reads each source from its saved position, so it reads no event twice and
skips none. A restart clears the finding metric. A finding after the last
save comes again: the restart reads Sui and guardian events again and checks
Bitcoin and the pool again. A stale Bitcoin source or a stale snapshot is
reported again only after its limit passes again. A snapshot of another
deployment is ignored and the run is a first run. A snapshot of another
format version or one that does not parse stops the monitor at startup.
Delete `snapshot.json` to start over from genesis.

A flow that never completes stays open in the snapshot, and the monitor
reports its missing event at every state check.

The snapshot is a durable asset, not a cache. Losing it means a new first run
from genesis, on a node that still serves it.

## Config
The config file holds the identity of one deployment. See `audit.sample.yaml`
for a complete example. The deployment in sui-operations
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
| deposit approval skew | 2 h | a deposit's block time may be after its Sui approval by this; a miner may date a block two hours ahead |
| deposit request watch | 2 d | Bitcoin is asked about a deposit request's transaction for this; an honest deposit is assumed to confirm within it |
| UTXO max age | 40 d | an unspent bridge UTXO older than this is a finding; the recovery leaf opens at 60 days |

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
    # replaced build until the guardian cursor, logged at every state check,
    # passes its last record. A first run from genesis reads every record, so
    # it needs every build.
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

### Alerting

The monitor decides what is wrong. An alerting system needs only these rules:

1. `time() - hashi_monitor_last_finding_timestamp_seconds < 3600`: a finding
   in the last hour. The `kind` label names the finding, and each kind
   fires on its own. Its details are in the `monitor finding` ERROR lines.
2. `up < 1`: the monitor cannot be scraped.
3. `absent(up)`: no monitor runs.

### Pool metrics

Every five minutes, pool maintenance updates these gauges:

- `hashi_monitor_pool_utxo_count`: the number of held UTXOs.
- `hashi_monitor_oldest_utxo_timestamp_seconds`: the earliest held UTXO block timestamp.
  An empty pool gives zero.
- `hashi_monitor_pool_value_sats`: the sum of the held UTXO amounts.
- `hashi_monitor_hbtc_supply_sats`: the hBTC supply on Sui, the
  `total_supply` of Hashi's `TreasuryCap<BTC>`.

Use this query to graph how far the hBTC supply is from the pool value. It
is zero or below in an honest bridge. Below zero are coins in flight and
deposits that Move never minted:

```promql
hashi_monitor_hbtc_supply_sats - hashi_monitor_pool_value_sats
```

Use this query to graph the oldest held UTXO age in days:

```promql
((time() - hashi_monitor_oldest_utxo_timestamp_seconds) / 86400)
and (hashi_monitor_pool_utxo_count > 0)
```
