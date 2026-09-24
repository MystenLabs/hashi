# Hashi Antithesis environment

A self-contained hashi deployment for [Antithesis](https://antithesis.com): a
4-validator Sui cluster, a bitcoind regtest, four hashi validators, a test
guardian, and a workload that drives deposits and withdrawals while Antithesis
injects faults.

It follows `sui-operations/docker/sui-antithesis` (a config image carrying
`docker-compose.yaml`, `.env`, and a Sui genesis generated at build time) and
reproduces the boot order of the e2e tests (`crates/e2e-tests`,
`TestNetworksBuilder::build`) with one container per process.

## Topology

| Service         | Image                        | Role |
| --------------- | ---------------------------- | ---- |
| `validator1-4`  | `mysten/sui-node`            | Sui validators |
| `fullnode`      | `mysten/sui-node`            | Sui fullnode; the RPC endpoint for everything below |
| `bitcoind`      | `hashi-antithesis`           | regtest; RPC `:18443`, P2P `:18444` for the nodes' Kyoto light clients |
| `guardian`      | `hashi-antithesis`           | test guardian, gRPC `:3000` |
| `bootstrap`     | `hashi-antithesis`           | one-shot setup (below); exits once `setup_complete` is signaled |
| `hashi1-4`      | `hashi-node` (instrumented)  | `hashi server`, one per Sui validator |
| `workload`      | `hashi-antithesis`           | miner + deposit/withdraw users + SDK assertions |

The bootstrap (`hashi-antithesis bootstrap`):

1. waits for bitcoind, creates the wallet, and mines 101 blocks;
2. waits for Sui, upgrades `SuiSystemState` to v2, and funds the validator accounts;
3. publishes the hashi package (compiled into the image, since Antithesis is offline);
4. writes `shared/hashiN.toml` for each node, staggered; each `hashiN` container waits for its file, then starts and registers itself on-chain;
5. once every node is registered, sends `finish_publish` with the guardian's URL and BTC key, which starts genesis DKG;
6. applies the e2e config overrides through governance, waits for the guardian to activate, then calls `setup_complete`.

The guardian (`hashi-antithesis guardian`) is the e2e `GuardianHarness`, served over gRPC. It
skips the ceremony, the key provisioners, and S3. Its BTC key comes from the config image, and it
activates itself from on-chain DKG output, so after a restart it rejoins with the same key. Only
its rate-limiter state resets.

The workload (`hashi-antithesis workload`) mines a block every 1–10 s and runs
`WORKLOAD_USERS` (default 4) users. Each user loops: deposit BTC and wait for the hBTC credit,
or withdraw hBTC and wait for the BTC payout. Choices come from the Antithesis RNG. Failures and
timeouts are logged and retried. Only the following are asserted:

| Assertion | Kind |
| --- | --- |
| hBTC balance never exceeds the BTC deposited for it | always |
| a withdrawal never pays out more than was requested | always |
| deposit credited hBTC | sometimes |
| withdrawal paid out on bitcoin | sometimes |

Keys come from `genesis/generate.py` when the config image is built. That covers the funded Sui
account, the validator account keys (which double as the hashi operator keys), and the guardian
BTC key. All of them land in `genesis/files/hashi-env.yaml`.

## Build

```sh
docker/antithesis/build.sh           # linux/amd64 + instrumented: the images Antithesis runs
LOCAL=1 docker/antithesis/build.sh   # native arch, uninstrumented: for running locally
```

This produces `hashi-node:<tag>`, `hashi-antithesis:<tag>`, and `hashi-antithesis-config:<tag>`,
where `<tag>` defaults to the short HEAD sha. `SUI_VERSION` selects the `mysten/sui-tools` and
`mysten/sui-node` tag (default `testnet-v1.80.1`). Genesis generation, the Move build, and the Sui
nodes must all use the same Sui version.

## Run locally

```sh
docker/antithesis/run-local.sh -d
cd .hashi/antithesis-local
docker compose logs -f bootstrap workload
```

SDK assertion events land in `.hashi/antithesis-local/sdk/sdk.jsonl`.

## Run in Antithesis

Push the three images plus `mysten/sui-node:<SUI_VERSION>`, and pass
`hashi-antithesis-config:<tag>` as the config image. The image list uses
the same names as `.env`, e.g.
`hashi-node:<tag>;hashi-antithesis:<tag>;docker.io/mysten/sui-node:<SUI_VERSION>`.
Trigger it the way `sui-operations/.github/workflows/run-walrus-antithesis-tests.yaml` does.

## Tuning

| Knob | Where | Default |
| --- | --- | --- |
| Sui epoch length | `SUI_EPOCH_DURATION_MS` build arg (config image) | 10 min |
| hashi/Sui log filters | `HASHI_RUST_LOG`, `SUI_RUST_LOG` build args | `info,hashi=debug`, `info` |
| Users, block interval, timeouts | `WORKLOAD_*` env on `workload` | see `hashi-antithesis workload --help` |
| Withdrawal batching delay, MPC weight divisor | `HASHI_*` env on `bootstrap` | 5 s, 100 |
| Guardian rate limit | `GUARDIAN_LIMITER_*` env on `guardian` | effectively unlimited |
