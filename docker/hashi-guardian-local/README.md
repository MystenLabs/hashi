# hashi-guardian-local

A self-contained, Mac-friendly replica of the guardian's **AWS Nitro Enclave
topology**, wired to a **local sui node** so the *entire* production ceremony →
provision → withdrawal flow runs locally — no devnet. Each `vsock` hop is
replaced by a TCP hop between containers; the on-chain substrate comes from the
native `hashi-localnet` harness (local `sui` + `bitcoind` regtest + a real hashi
committee).

```
  node ──► proxy:3000 ──► host:3000 ──► enclave:3000 (withdraw guardian)
                                            │
   guardian ──► 127.0.0.6x:443 ──► host:810x ──► minio:9000   (S3 audit log)

   provision/ceremony CLI ──► ceremony:3000 (ceremony guardian, direct)
                          ──► proxy:3000 (SingleProvisionerInit relay)
                          ──► host.docker.internal:9000 (native hashi-localnet sui)
```

The pieces map 1:1 to production:

| Replica service | Stands in for | Production source |
| --- | --- | --- |
| `proxy` | the out-of-enclave proxy + relay | `crates/hashi-guardian-proxy` |
| `host` | the EC2 parent host's bridges | `docker/hashi-guardian/scripts/{expose_enclave,user-data}.sh` |
| `enclave` + `run.local.sh` | the withdraw-mode Nitro enclave | `docker/hashi-guardian/run.sh` |
| `ceremony` | the one-time ceremony-mode guardian | a runner-local ceremony container (deploy) |
| `minio` + `bucket-init` | the S3 Object-Lock audit bucket | the guardian's real S3 bucket |
| `init` | the operator + KP running the CLI | `hashi-guardian-init operator/key-provisioner …` |
| native `hashi-localnet` | devnet (sui + committee + published guardian key) | `crates/e2e-tests` |

## Why a local sui node

`operator provision` and `key-provisioner provision` read the on-chain
`current_committee()` and MPC master `G`, so they need a live chain with a formed
committee — which is why the old replica had to point at devnet. `hashi-localnet`
already stands up local sui + bitcoin + a hashi committee (DKG) for the
integration tests; this replica reuses it. The one missing piece — making the
localnet publish **this** dockerized guardian's key instead of a throwaway
in-process one — is the new `hashi-localnet start --guardian-url /
--guardian-btc-pubkey` flags (see `crates/e2e-tests`).

## Prerequisites

- Docker (for the guardian containers + MinIO).
- `sui` and `bitcoind` on your `PATH` (or `SUI_BINARY` set) — the same binaries
  the integration tests use. See `.github/scripts/install-sui.sh` for the sui
  version; `bitcoind` from Homebrew works (`BITCOIND_EXE` if not on PATH).

## Full end-to-end

```sh
# 1. Bring up MinIO + the withdraw guardian + the proxy (no chain needed yet).
make up

# 2. Generate the test KP roster and run the genesis ceremony. The ceremony-mode
#    guardian mints the BTC key in-enclave, writes ceremony/+shares/ to MinIO,
#    and prints its x-only BTC master pubkey (captured for the next step).
make ceremony

# 3. Print the localnet command wired to this guardian's pubkey, and run it
#    NATIVELY in a separate terminal. It publishes the pubkey on-chain, forms the
#    committee via DKG, and stays running.
make localnet-cmd
#   -> cargo run -p e2e-tests --bin hashi-localnet -- start \
#        --guardian-url http://localhost:3000 --guardian-btc-pubkey <hex>

# 4. Once the localnet prints "Localnet started", provision the guardian:
#    operator provision (reads the committee + MPC G from the local sui) then
#    key-provisioner provision x threshold (each KP submits its share to the
#    proxy relay, which batches them into the guardian's ProvisionerInit).
make provision

# 5. Confirm the guardian is fully initialized end to end.
make smoke
```

At this point the deposit/withdraw CLI flows work against the local network
(`hashi-localnet deposit …`), and withdrawals are co-signed by the real
containerized guardian — the whole trust model exercised locally.

`make down` stops everything and drops the volumes.

## Fidelity limits (read this first)

A Mac cannot run real Nitro — no `/dev/nitro_enclaves`, no `nitro-cli`, no
`AF_VSOCK`, no NSM. So this replica:

- runs the **`--features non-enclave-dev`** guardian, which **stubs the NSM
  attestation** (mock document). It is **not** a PCR/attestation test — that only
  exists on real hardware (`docker/hashi-guardian/`, the reproducible EIF). The
  init tooling runs with attestation verification effectively disabled (the
  git-revision + signature + state checks still run).
- substitutes every `vsock` hop with **TCP between containers**. Topology and
  dataflow are faithful; the transport is not.
- talks to MinIO over **http** (`AWS_ENDPOINT_URL_S3` → path-style + plaintext),
  preserving the S3 forwarder chain but not the in-enclave TLS-to-S3.
- uses **software test PGP keys in one shared gnupg home** for the KPs (a real KP
  holds its own yubikey). Same `gpg --decrypt` code path, no hardware.

## Notes

- Only `proxy:3000` is published to the host; the guardian is reachable only
  through the `host` bridge — mirroring the "guardian is not on the internet"
  posture. The KP relay submissions go through the proxy; `operator provision`
  and the ceremony go direct (init RPCs must never be cached).
- `run.local.sh` is the only file that diverges from production
  `docker/hashi-guardian/run.sh`: `VSOCK-*` → `TCP-*`, and it honors
  `CEREMONY_MODE` (as the real enclave does) so one image serves both guardians.
- Roster size defaults to `NUM_SHARES=3`, `THRESHOLD=2` (override via env).
