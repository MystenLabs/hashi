# Releases

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> Where to find Hashi releases, how to verify the binary and container image, and how Mysten rolls its Testnet nodes.

Releases live at [github.com/MystenLabs/hashi/releases](https://github.com/MystenLabs/hashi/releases). Each release carries the label `Hashi <network> X.Y` and the tag `<network>-X.Y` (for example `testnet-1.0` and `mainnet-1.0`); its notes give the source commit, the binary SHA-256, and the image digest. Use the releases tagged for your network: `mainnet-X.Y` on Mainnet, `testnet-X.Y` on Testnet. Testnet releases before the numbered scheme are tagged `testnet-<full-sha>`.

A Mainnet release is a promoted Testnet release. The release process cuts `mainnet-X.Y` at the commit `testnet-X.Y` points to, and the release run fails if its rebuilt binary differs from the Testnet release's checksum, so the two carry the same version, commit, and binary. `mainnet-1.0` and `testnet-1.0` are the same binary.

## Binary

Download `hashi-linux-amd64` and `SHA256SUMS` from the same release into one directory. Verify that the binary's SHA-256 matches the checksum published with the release:

```bash
sha256sum --check SHA256SUMS
```

The command must print `hashi-linux-amd64: OK`. Do not run the binary if the check fails. You can also inspect the computed hash directly and compare it with the binary SHA-256 shown in the release notes:

```bash
sha256sum hashi-linux-amd64
```

After the hash matches, verify that GitHub Actions produced the binary and make it executable:

```bash
gh attestation verify hashi-linux-amd64 --repo MystenLabs/hashi
chmod +x hashi-linux-amd64
```

## Container image

The matching public image uses the same release tag:

```bash
docker pull mysten/hashi:<network>-X.Y   # for example mysten/hashi:mainnet-1.0
```

The release notes include the image's immutable OCI digest. Pin that digest when a deployment must remain on the exact image regardless of tags:

```text
mysten/hashi@sha256:<digest>
```

## Rolling the Mysten Testnet nodes

The six Mysten validators (`mysten1` through `mysten6`) are single-replica Deployments in namespace `hashi-testnet` on `workloads-secondary-use4`, managed by the `mysten/testnet` stack of `pulumi/services/hashi-server` in sui-operations. Each mounts a ReadWriteOnce PVC, which is why the Deployments use the `Recreate` strategy. Never switch them back to `RollingUpdate`; a surge pod would double-mount the DB volume.

Set `hashi-server:image.image_ref` to the release sha in `pulumi/services/hashi-server/Pulumi.testnet.yaml` (land it as a PR), then roll **one node at a time**:

```bash
cd pulumi/services/hashi-server && pulumi stack select mysten/testnet

# For each N in 1..6, in order:
pulumi up --yes --target "urn:pulumi:testnet::hashi-server::kubernetes:apps/v1:Deployment::mysten<N>"
kubectl -n hashi-testnet rollout status deploy/mysten<N> --timeout=600s
kubectl -n hashi-testnet logs deploy/mysten<N> | grep -m1 "Guardian bootstrap complete"
```

Proceed to the next node only after all three checks pass. If a node does not come back healthy, stop and investigate before touching the next. Every additional node down eats into the committee's 2/3 signing margin (see [Epoch Changes](../validators/epoch-changes.mdx)).

Rollout gotchas:

- **Serialize the updates.** Wait for each `pulumi up` to exit before starting the next; concurrent targeted ups conflict on the stack lock (409).
- **Don't trust the pod label for readiness.** `kubectl wait --for=condition=Ready pod -l hashi-node=mysten<N>` also matches the still-terminating old pod.
- **Unhealthy fleet, different gates.** Mid-incident (for example a reconfiguration stall, see [Stuck reconfigurations](../validators/epoch-changes.mdx#stuck-reconfigurations)) no pod turns Ready, so `rollout status` never completes and pulumi's readiness await reports the Deployment as errored even though the image update applied. Gate on the pod reaching `Running` with no restarts plus the guardian bootstrap log line, and re-run the targeted `pulumi up` after recovery to reconcile state.
