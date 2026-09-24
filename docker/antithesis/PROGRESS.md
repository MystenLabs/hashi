# Hashi Antithesis environment — implementation progress

Template: `sui-operations/docker/sui-antithesis` (config image + compose + genesis
generation) and `sui-operations/docker/stress-antithesis` (workload image).
Guide: `crates/e2e-tests` (TestNetworksBuilder boot order, deposit/withdraw helpers).

## Decisions
- Guardian: a *test guardian* (in-process `Enclave` from `hashi-guardian` test-utils,
  served over gRPC) with a deterministic BTC key; it finalizes itself from on-chain
  committee state, so restarts are survivable. No ceremony / KP / S3.
- Everything lives in the hashi repo (`docker/antithesis`, `crates/hashi-antithesis`).
  A trigger workflow can live in sui-operations later (walrus pattern).
- Sui nodes: public `mysten/sui-node` image (`sui-tools` only supplies the CLI at build time) (hashi is the system under test).
- Hashi nodes: `hashi server`, built with Antithesis coverage instrumentation.

## Topology (docker network 10.0.0.0/24)
| service       | image               | role |
| ------------- | ------------------- | ---- |
| validator1-4  | mysten/sui-node     | Sui validators (genesis generated at config-image build) |
| fullnode      | mysten/sui-node     | Sui fullnode; RPC for everyone |
| bitcoind      | hashi-antithesis    | regtest, RPC 18443, P2P 18444 (noban for the subnet) |
| guardian      | hashi-antithesis    | test guardian gRPC :3000 |
| bootstrap     | hashi-antithesis    | one-shot: fund, publish, write node configs, launch, overrides, setup_complete |
| hashi1-4      | hashi-node          | hashi validators; wait for their config from bootstrap |
| workload      | hashi-antithesis    | miner + deposit/withdraw users + SDK assertions |

## Status
- [x] Refactor e2e-tests / hashi helpers so they are usable without `TestNetworks`
- [x] `crates/hashi-antithesis`: bootstrap subcommand
- [x] `crates/hashi-antithesis`: guardian subcommand
- [x] `crates/hashi-antithesis`: workload subcommand (+ SDK assertions, restart-safe deposit ledger)
- [x] `docker/antithesis/hashi-node` Dockerfile (instrumented; INSTRUMENT=0 for local arm64)
- [x] `docker/antithesis/tools` Dockerfile (hashi-antithesis, bitcoind 31.1, compiled Move pkg)
- [x] `docker/antithesis/config` Dockerfile, genesis generator, docker-compose.yaml
- [x] build.sh / run-local.sh / README.md
- [ ] End-to-end validation with docker — NOT DONE: the dev mac has no docker or bitcoind.
      Verified so far: crate builds + clippy clean; genesis generator runs against sui 1.77.1;
      offline `sui move build` with a stub client.yaml; key/address formats agree (unit test);
      compose file parses.
- [ ] Trigger workflow (sui-operations, walrus pattern: build images, push, antithesis-trigger-action)

## Unverified assumptions (check on first docker run)
- `mysten/sui-node` ships `/opt/sui/bin/sui-node` (per sui's docker/sui-node/Dockerfile).
- Fullnode serves gRPC (incl. checkpoint subscriptions) on its json-rpc-address :9000.
- libvoidstar-linked hashi binary runs outside Antithesis (as sui-node-antithesis does).
- Kyoto clients recover from bitcoind restarts with noban whitelisting + 2s staggered start.
- Guardian restart: re-finalizing with the then-current committee is accepted by nodes.

## Open questions / follow-ups
- Sui epoch duration for the test (hashi reconfig follows Sui epochs); default 10 min.
- Test Composer (`/opt/antithesis/test/v1/...`) drivers instead of a single long-running workload,
  incl. `eventually_` liveness checks (all deposits credited once faults stop).
- More invariants: on-chain hBTC supply <= BTC in hashi's UTXO pool; no double payout per request.
- Second fullnode so a single fullnode fault doesn't stall all hashi nodes at once.
