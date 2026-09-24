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
- Sui nodes: public `mysten/sui-tools` image (hashi is the system under test).
- Hashi nodes: `hashi server`, built with Antithesis coverage instrumentation.

## Topology (docker network 10.0.0.0/24)
| service       | image               | role |
| ------------- | ------------------- | ---- |
| validator1-4  | sui-tools           | Sui validators (genesis generated at config-image build) |
| fullnode      | sui-tools           | Sui fullnode; RPC for everyone |
| bitcoind      | hashi-antithesis    | regtest, RPC 18443, P2P 18444 (noban for the subnet) |
| guardian      | hashi-antithesis    | test guardian gRPC :3000 |
| bootstrap     | hashi-antithesis    | one-shot: fund, publish, write node configs, launch, overrides, setup_complete |
| hashi1-4      | hashi-node          | hashi validators; wait for their config from bootstrap |
| workload      | hashi-antithesis    | miner + deposit/withdraw users + SDK assertions |

## Status
- [ ] Refactor e2e-tests / hashi helpers so they are usable without `TestNetworks`
- [ ] `crates/hashi-antithesis`: bootstrap subcommand
- [ ] `crates/hashi-antithesis`: guardian subcommand
- [ ] `crates/hashi-antithesis`: workload subcommand (+ SDK assertions)
- [ ] `docker/antithesis/hashi-node` Dockerfile (instrumented)
- [ ] `docker/antithesis/tools` Dockerfile (hashi-antithesis, bitcoind, compiled Move pkg)
- [ ] `docker/antithesis/config` Dockerfile, genesis generator, docker-compose.yaml
- [ ] Local build/run script
- [ ] End-to-end validation with docker (not possible on the dev mac: no docker)
- [ ] Trigger workflow (sui-operations or hashi .github)

## Open questions / follow-ups
- Sui epoch duration for the test (hashi reconfig follows Sui epochs).
- Test Composer (`/opt/antithesis/test/v1/...`) drivers instead of a single long-running workload.
