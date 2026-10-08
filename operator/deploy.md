# Deploying a Guardian

This guide takes an operator through a guardian's first deployment: a new
enclave, a new guardian key, and a guardian serving withdrawals. Every operator
step is one run of `operator/scripts/guardian.sh`.

A deployment has three kinds of participant:

- The **operator** runs this guide.
- The **key provisioners** (KPs) each hold one share of the guardian key on a
  YubiKey. They follow the [KP guide](../key-provisioner/provision.md). All of
  them take part in the key ceremony; a threshold of them provisions a guardian.
- The **publisher** holds the Hashi package's `UpgradeCap` and runs
  `hashi launch`.

Two steps cannot be undone. `hashi launch` writes the guardian's Bitcoin key on
chain, where it can never change. Destroying or restarting a guardian instance
loses the key in its memory, so that guardian must be provisioned again by the
KPs.

## Before you start

You need:

- This repository checked out at the commit the guardian will run. The scripts
  build `hashi-guardian-init` from it, and every step that runs it refuses a
  checkout whose `crates/` differ from that commit. If `operator/` has changed
  since that commit, bring the current scripts over with
  `git checkout origin/main -- operator`.
- A sui-operations worktree on a branch of your own, for the guardian's stack
  configuration: `pulumi/services/hashi-guardian-enclave/Pulumi.<stack>.yaml`
  and `pulumi/services/hashi-guardian-proxy/Pulumi.<stack>.yaml`.
- The Pulumi CLI at the version sui-operations' deploy workflows pin, first on
  your `PATH`, and access to the guardian stacks.
- Go, which builds the enclave stack's Pulumi program.
- The AWS CLI with the Session Manager plugin, logged in as an administrator of
  the guardian's AWS account: `aws sso login --profile admin`, then
  `export AWS_PROFILE=admin`. The session lasts some hours; log in again when
  a step reports an expired token.
- The GitHub CLI at version 2.87 or later, which reports the run a dispatch
  starts, able to dispatch workflows in hashi and sui-operations.
- `cargo`, `jq` and `curl`.
- The package ID and Hashi object ID of the published Hashi package, from the
  publisher.

Copy `operator/guardian.env.sample`, fill it in, and pass its path to every
step:

```sh
./operator/scripts/guardian.sh guardian.env <step>
```

Plan the day around the KPs and the chain. The key ceremony needs every KP, so
one missing KP stops it. Hashi forms a new committee at each Sui epoch change;
keep `hashi launch`, provisioning and activation inside one Sui epoch.

## 1. Configure the stack

In your sui-operations worktree, set in the enclave stack's
`Pulumi.<stack>.yaml`:

- `hashi-commit`: the full commit the guardian runs. The proxy, your checkout
  and every KP's checkout use the same one.
- `s3-bucket-name`: a bucket no key ceremony has completed on. The bucket holds
  the guardian's key shares and its log, so each guardian key gets its own.
- `refill-rate-sats-per-sec` and `max-bucket-capacity-sats`: the withdrawal
  limit. It is fixed when the guardian is provisioned; changing it later takes
  a new guardian and a KP quorum.

In the proxy stack's `Pulumi.<stack>.yaml`, set `proxy-image-tag` to the same
commit. Commit both files, push the branch, and open a pull request.

## 2. Collect the KPs' public keys

Follow [Collect key provisioner public keys](README.md#collect-key-provisioner-public-keys).
When every KP has confirmed their roster row, set `KP_ROSTER_DIR` in your
environment file to the directory the final `download-kp-pubkeys.sh` printed,
and `KP_THRESHOLD` to the number of KPs that provision a guardian. Keep the
access key: the KPs use it again below.

## 3. Measure the build

```sh
./operator/scripts/guardian.sh guardian.env measure
```

This builds the enclave image for `hashi-commit` on two GitHub runners, which
takes about 15 minutes, and prints the PCR0 they agree on. PCR0 identifies the
enclave image; the KPs' tools refuse a guardian that does not prove it runs
exactly that image.

The step ends by asking you to set `eif-pcr0` in the enclave stack's
`Pulumi.<stack>.yaml` to the PCR0 it printed. Do that, commit it, then confirm
with the run number from the URL the step printed:

```sh
./operator/scripts/guardian.sh guardian.env measure <run-id>
```

It must end with `It is the eif-pcr0 stack <stack> configures.` Never take
PCR0 from the guardian's own host. If the build fails while pulling an image,
run the step again. If the two runners disagree, stop: the image is not
reproducible at that commit.

## 4. Deploy the enclave

```sh
./operator/scripts/guardian.sh guardian.env deploy
```

The step prints the stack's plan and asks before it applies it. On a stack
with no guardian yet, it asks for `y`. On a stack that already has a guardian,
it asks you to type that instance's ID, because the plan can destroy it and
does not always say so: a new `s3-bucket-name` or `hashi-commit` replaces the
instance. Type the ID only when ending that guardian is what you intend.

It prints the stack's new outputs and ends with `Deployed.` Then follow the
host, which builds the enclave image itself when it boots:

```sh
./operator/scripts/guardian.sh guardian.env host
```

This prints the end of the host's boot log, whether the boot has finished, the
enclave's state and the state of its five services. Run it again until it
shows a `hashi-guardian user-data complete` line, the enclave's `State` is
`RUNNING`, and all five services are `active`. Until then it says
`The boot has not finished.`, the enclave list is `[]` and the services are
`inactive`. A `hashi-guardian user-data FAILED` line means the build failed;
the boot log above it says where.

## 5. Deploy the proxy

The proxy is the guardian's public address. KPs and nodes only ever reach the
guardian through it.

```sh
./operator/scripts/guardian.sh guardian.env proxy
```

This dispatches sui-operations' `hashi-guardian-proxy-deploy.yaml`, which
builds the proxy at `hashi-commit` and applies the proxy stack's configuration
from the sui-operations branch named by `SUI_OPERATIONS_REF`. That workflow
only runs from `main` or a `workflows-testing*` branch, so until your pull
request merges, push your branch under such a name and set
`SUI_OPERATIONS_REF` to it in your environment file. The step prints the
branch it uses, waits for the workflow and ends with
`The proxy answers at <url>.`

## 6. Reach the guardian

In a second terminal, open the tunnel that operator steps use, and leave it
running:

```sh
./operator/scripts/guardian.sh guardian.env tunnel
```

The tunnel closes after 20 minutes without traffic. When a step says it could
not reach the guardian, run the tunnel step again and repeat the step.

Then check the guardian answers:

```sh
./operator/scripts/guardian.sh guardian.env info
```

A new guardian shows a signing key, no BTC key, and `Serving: no`. The step
also checks that the proxy fronts this guardian, and stops if it fronts
another: KPs and nodes reach whichever one the proxy does.

## 7. Publish the configuration to the KPs

```sh
./operator/scripts/guardian.sh guardian.env render
./operator/scripts/guardian.sh guardian.env publish
```

`render` reads the stack and writes three things under
`.hashi/guardian/<stack>/`: `guardian-init.yaml` for the KPs, `operator.yaml`
for you, and `certs/`. `operator.yaml` holds the guardian's S3 key; never share
it. `publish` uploads the KPs' copy and prints a guardian commit and a
configuration digest.

Read `guardian-init.yaml` before you publish it. The Bitcoin network and the
retention class in it come from your environment file, and they are fixed for
the life of the guardian's key.

Post the commit and the digest to the KPs. Each KP checks the commit out and
runs `download-config.sh`, which asks for the digest and refuses a download
that does not have it. Wait until every KP reports that the download finished.
If you render again, publish again and have every KP download again: the
digest covers the configuration and every certificate.

## 8. Run the key ceremony

```sh
./operator/scripts/guardian.sh guardian.env ceremony
```

The guardian generates its Bitcoin key and deals one encrypted share to each
KP. The step then waits, printing a line each minute. Ask every KP to run the
key ceremony command from their guide. Each one decrypts their share and
confirms it to the guardian; the ceremony completes when the last KP confirms.
A KP who runs the command before this step is waiting sees
`not a ceremony guardian`, and runs it again once it is.

The step ends by printing `GUARDIAN_BTC_PUBKEY=<hex>`. Ask one KP to read
`btc_master_pubkey` from the `kp-shares.json` their command saved, and check
it is the same key. The publisher needs it for `hashi launch`.

A KP whose command fails can run it again. If it fails with
`Inappropriate ioctl for device`, GnuPG has no terminal to ask for the PIN on:
they run `export GPG_TTY=$(tty)` first. If your own step is interrupted, the
ceremony still completes when the last KP confirms; take the key from a KP's
`kp-shares.json`.

If the ceremony cannot complete, for example because a KP cannot take part,
nothing has been committed. Start again from section 1 with the new roster and
a new `s3-bucket-name`; section 3 needs no new build while `hashi-commit` is
unchanged.

## 9. Start a fresh guardian session

A guardian that ran a ceremony never serves withdrawals, so restart it:

```sh
./operator/scripts/guardian.sh guardian.env new-session
./operator/scripts/guardian.sh guardian.env info
```

`new-session` refuses unless the bucket holds a completed ceremony, and asks
you to type the instance's ID: a restart also wipes the key of a guardian that
is already provisioned. Afterwards `info` shows a different signing key and no
BTC key.

## 10. Launch Hashi

The publisher runs `hashi launch`, as described in the
[node operator runbook](../design/docs/node-operator-runbook.mdx#55-step-4-launch-admin).
Give them three values:

- `--guardian-url` and `--guardian-node-url`: the `proxy_url` and `node_url`
  outputs of the proxy stack.
- `--guardian-btc-public-key`: the key the ceremony printed.

They run it with `--dry-run` first and read every value back: the key can never
be changed.

The committee then generates its own key. Go on once that has finished.

## 11. Provision the guardian

```sh
./operator/scripts/guardian.sh guardian.env provision --do-genesis
```

This gives the guardian its limit, the ceremony's shares to expect and the
first committee, read from chain. It prints
`Guardian operator provision complete.` If it stops with
`MPC public key not yet available on-chain`, the committee has not finished
generating its key: wait and run it again.

Wait a minute for the guardian's first heartbeat, then ask `KP_THRESHOLD` KPs
to run the provisioning command from their guide with `--do-genesis`. Each one
sends their share to the guardian through the proxy. Once they all have, the
guardian rebuilds its key:

```sh
./operator/scripts/guardian.sh guardian.env info
```

The BTC key it shows must be the ceremony's key.

The guardian is pinned to the committee this step read from chain. If the Sui
epoch turns before the KPs have provisioned, their command refuses the
guardian: start a fresh session (section 9) and run this section again.

## 12. Activate the guardian

```sh
./operator/scripts/guardian.sh guardian.env activate
```

It prints `Guardian operator activate complete.` and the guardian starts
serving withdrawals. Within a minute the `info` step shows
`Serving: committee epoch <n>`, the epoch of the committee it was provisioned
for.

If you provisioned an earlier session and then started a fresh one, the step
first waits until the earlier session has been silent for ten minutes.

## 13. Finish

- Revoke the KPs' access key:
  `./operator/scripts/revoke-kp-upload-key.sh <name>`.
- Delete `.hashi/guardian/<stack>/operator.yaml`, which holds the guardian's
  S3 key. `render` writes it again when a step needs it.
- Merge the sui-operations pull request, so the next deploy from `main` does
  not roll the guardian back.
- Point whatever else pins the guardian's bucket or build, such as monitoring,
  at the new ones.

From here on, the guardian's key exists only in the enclave's memory and in the
KPs' shares. Restarting or replacing the instance means provisioning it again
with a threshold of KPs.
