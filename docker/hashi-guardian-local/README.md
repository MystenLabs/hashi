# hashi-guardian-local

A self-contained, Mac-friendly Docker replica of the guardian's **AWS Nitro
Enclave topology**. It runs the full request path the production fleet uses —
node → proxy → host → enclave → guardian, plus the guardian's S3 audit writes —
with each `vsock` hop replaced by a TCP hop between containers.

```
  client ──► proxy:3000 ──► host:3000 ──► enclave:3000 (guardian)
                                              │
   guardian ──► 127.0.0.6x:443 ──► host:810x ──► minio:9000   (S3 audit log)

  real AWS                          this replica
  ────────                          ────────────
  internet → host socat → vsock  →  proxy → host socat (TCP)
  enclave socat → vsock → vsock-proxy → S3   →   enclave socat (TCP) → host socat → MinIO
```

The pieces map 1:1 to the production assets:

| Replica service | Stands in for | Production source |
| --- | --- | --- |
| `proxy` | the out-of-enclave proxy | `crates/hashi-guardian-proxy` |
| `host` | the EC2 parent host's bridges | `docker/hashi-guardian/scripts/{expose_enclave,user-data}.sh` |
| `enclave` + `run.local.sh` | the Nitro enclave | `docker/hashi-guardian/run.sh` |
| `minio` + `bucket-init` | S3 (Object-Lock audit bucket) | the guardian's real S3 bucket |
| `bootstrap` | the operator bootstrap | `hashi-guardian-init tools dev-bootstrap` |

## Fidelity limits (read this first)

A Mac cannot run real Nitro — no `/dev/nitro_enclaves`, no `nitro-cli`, no
`AF_VSOCK`, no NSM. So this replica:

- runs the **`--features non-enclave-dev`** guardian binary, which **stubs the
  NSM attestation** (mock document). It is **not** a PCR/attestation test — that
  only exists on real hardware (`docker/hashi-guardian/`, the reproducible EIF).
- substitutes every `vsock` hop with **TCP between the `host` and `enclave`
  containers**. The topology and dataflow are faithful; the transport is not.
- talks to MinIO over **http** (the guardian's `AWS_ENDPOINT_URL_S3` points at
  `http://s3.us-east-1.amazonaws.com:443`, which `s3_client.rs` turns into
  path-style + plaintext). The S3 forwarder chain is preserved; the real
  in-enclave TLS-to-S3 is not.

## Usage

```sh
# 1. Bring up MinIO + host + enclave + proxy (builds the image on first run).
make up

# 2. Smoke-test the full path (works with NO chain — health + a gRPC round-trip).
make smoke
```

`make smoke` proves `proxy → host → enclave → guardian` end to end: the gRPC
call reaches the guardian (pre-bootstrap it returns a "not initialized" gRPC
error, which still confirms the whole path is wired).

### Bootstrapping (needs a deployed devnet)

`dev-bootstrap` scrapes the **on-chain committee** and `mpc_public_key`, so it
cannot run against a purely-local chain — point it at a deployed hashi
(devnet):

```sh
# Fill in node.local.toml with the live devnet sui-rpc + hashi package/object ids.
$EDITOR node.local.toml

# If that devnet pinned guardian_btc_public_key, you also need the matching
# secret. Generate a fresh pair (then the pinned pubkey must be this one):
make gen-master-key            # prints HASHI_MASTER_SECRET_HEX=… / _PUBKEY_HEX=…
#   -> put HASHI_MASTER_SECRET_HEX into .env

make bootstrap                 # OperatorInit -> GetGuardianInfo -> ProvisionerInit
make get-info                  # GetGuardianInfo through the proxy -> real guardian info
```

After bootstrap, the guardian writes its attestation + heartbeat objects to
MinIO — confirm the **outbound** S3 chain carried traffic:

```sh
docker compose exec bucket-init mc ls -r local/hashi-guardian-dev
```

### Teardown

```sh
make down      # stops everything and drops the MinIO volume
```

## Notes

- Only `proxy:3000` is published to the host; the guardian is reachable only
  through the `host` bridge — mirroring the production "guardian is not on the
  internet" posture.
- The `bootstrap` service deliberately targets `http://host:3000` (the guardian
  directly), **not** the proxy: ceremony/init RPCs must never be cached.
- `run.local.sh` is the only file that diverges from production
  `docker/hashi-guardian/run.sh`; the diff is just `VSOCK-*` → `TCP-*` and
  dropping the in-enclave inbound bridge (the guardian binds TCP natively).
