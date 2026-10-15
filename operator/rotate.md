# Rotating a Guardian

This guide moves a serving guardian's key to a fresh guardian on the stack's
other slot. Use it to replace or resize the host or, with a KP-set rotation
(section 5), to re-deal the key to a new set of key provisioners (KPs). The
serving guardian signs until the switchover. A threshold of KPs provisions the
new one from their shares, so the key never leaves the enclaves and the shares.
Every operator step is one run of `operator/scripts/guardian.sh`, naming the
slot it acts on.

The enclave stack has two slots, `a` and `b`:
- The **active** slot is the one the proxy sends nodes to.
- During a rotation, the other slot is the **standby**. The proxy's relay sends
  KPs to it.

The examples arm slot `b` next to an active slot `a`. Swap the letters when `b`
is active.

Two steps cannot be undone: the switchover stopping the old guardian, and the
teardown of its host. Until the old guardian stops, a rotation is abandoned by
tearing the standby down.

## Before you start

You need:

- Everything [Deploying a Guardian](deploy.md#before-you-start) lists. The
  checkout must be at the commit the serving guardian runs: a rotation keeps
  its build. Use the Pulumi CLI that last wrote the stacks; the rotation steps
  refuse any other.
- `SUI_GRAPHQL_URL` in your environment file.
- `KP_THRESHOLD` KPs available from provisioning until the switchover has
  finished. A KP-set rotation also needs every KP of the new set.

Stop anyone else changing the guardian stacks until the rotation is over. The
steps refuse to run while sui-operations' `hashi-guardian-proxy-deploy.yaml` or
`hashi-guardian-rotate.yaml` has a run queued or in progress.

`sui-operations` `main` must keep matching the stack. Merge each change to
`Pulumi.<stack>.yaml` right after the step that applies it: `arm`, `switchover`
and `teardown`. An `up` from a `main` that still says slot `a` alone deletes
slot `b`, and once slot `b` serves, its key goes with it.

The switchover refuses to start within 30 minutes after a Sui epoch turns, or
within an hour before the next turn. An epoch that turns before activation
leaves the new guardian a committee behind until the following one. Log in to
AWS again just before it: the stop and the activation must not outlive the
session.

## 1. Configure the standby

In your sui-operations worktree, set in the enclave stack's
`Pulumi.<stack>.yaml`:

- `slot-b-enabled: "true"`.
- `hashi-commit-b` and `eif-pcr0-b`: the same values as `hashi-commit` and
  `eif-pcr0`.
- `enclave-instance-type-b`: the size slot `b` keeps while it serves. Resizing
  it later stops the host, which loses the key.
- `enclave-logs-b: "true"`, to send the standby's logs to Loki. Decide now:
  changing it later replaces the host.

Commit the file.

## 2. Arm the standby

```sh
./operator/scripts/guardian.sh guardian.env arm b
```

The step prints the stack's plan for slot `b` and refuses unless the plan only
creates its host. It ends with `Armed slot b on <instance>`. Merge the change to
`Pulumi.<stack>.yaml` into `main` now. Follow the host's boot as the
[deploy guide](deploy.md#4-deploy-the-enclave) describes, with `host b`.

## 3. Point the relay at the standby

```sh
./operator/scripts/guardian.sh guardian.env proxy-update
```

This applies the proxy stack from your sui-operations worktree, so the proxy's
relay reaches slot `b`. It builds no image. It restarts the proxy, which leaves
the guardian's address down for some minutes while nodes retry. It refuses while
KPs are in a round.

## 4. Reach the standby

In another terminal, open slot `b`'s tunnel. It uses the port after slot `a`'s,
3001 by default.

```sh
./operator/scripts/guardian.sh guardian.env tunnel b
```

Then:

```sh
./operator/scripts/guardian.sh guardian.env info b
```

It shows `Slot: b, standby`, a signing key, no BTC key, lifecycle `none`, and
that the relay sends KPs to this guardian.

## 5. Re-deal the key to a new KP set

Skip this section unless the rotation changes who holds the key's shares. It
re-deals the key on slot `b` while slot `a` keeps serving, and section 6 then
provisions slot `b` with the new set.

Collect the new set's public keys as in
[Collect key provisioner public keys](README.md#collect-key-provisioner-public-keys):
KPs who stay keep their keys, and new KPs upload theirs to the same bucket.
`download-kp-pubkeys.sh` takes everyone who has uploaded, so check its roster
lists exactly the new set. When every KP of the new set has confirmed their row,
set in your environment file:

- `NEW_KP_ROSTER_DIR`: the directory the final `download-kp-pubkeys.sh` printed.
- `NEW_KP_THRESHOLD`: how many KPs of the new set provision a guardian.

`KP_ROSTER_DIR` and `KP_THRESHOLD` stay the current set's. Render, and publish
what the current KPs sign:

```sh
./operator/scripts/guardian.sh guardian.env render b
./operator/scripts/guardian.sh guardian.env publish b rotate-kp-set
```

Post the commit, the digest and every fingerprint of the new roster. Then:

```sh
./operator/scripts/guardian.sh guardian.env rotate-kp-set b init
```

It asks before it makes slot `b`'s guardian a ceremony guardian, then prints the
session and the new set. Ask `KP_THRESHOLD` current KPs to sign, as their guide
describes, and to send you the files they write. Then:

```sh
./operator/scripts/guardian.sh guardian.env rotate-kp-set b submit <file> <file>
```

Once it logs `ceremony proposal published`, it waits, with no timeout, for every
KP of the new set. Leave it running, and in another terminal publish what they
confirm with:

```sh
./operator/scripts/guardian.sh guardian.env publish b
```

Post the commit and the digest, and ask every KP of the new set, including those
who were in the current one, to confirm their share as their guide describes.
`submit` ends with `KP-set rotation complete.` If it stops before that, run
`rotate-kp-set b wait` to wait again.

A ceremony guardian never serves, so start a fresh session on slot `b`:

```sh
./operator/scripts/guardian.sh guardian.env new-session b
./operator/scripts/guardian.sh guardian.env info b
```

From now on only `NEW_KP_THRESHOLD` KPs of the new set can provision a
guardian. Once the rotation is over, set `KP_ROSTER_DIR` and `KP_THRESHOLD` to
the new set's, and remove the two `NEW_` lines.

## 6. Provision the standby

```sh
./operator/scripts/guardian.sh guardian.env render b
./operator/scripts/guardian.sh guardian.env publish b
```

After a re-deal, the KPs already have this configuration: skip both commands.
Otherwise post the commit and the digest to the KPs, and wait until every KP
that will provision has confirmed the digest, as for a
[first deployment](deploy.md#7-publish-the-configuration-to-the-kps). Then:

```sh
./operator/scripts/guardian.sh guardian.env provision b
```

It prints `Guardian operator provision complete.` Wait a minute for the
standby's first heartbeat, then ask `KP_THRESHOLD` KPs to run the provisioning
command from their guide, without `--do-genesis`. Once they have:

```sh
./operator/scripts/guardian.sh guardian.env info b
```

The BTC key must be the serving guardian's. Don't run `proxy-update` between
asking KPs to provision and seeing that key: it drops the shares they sent.

## 7. Switch over

In the enclave stack's `Pulumi.<stack>.yaml`, set `active-slot: "b"` and commit
it. With slot `b`'s tunnel open:

```sh
./operator/scripts/guardian.sh guardian.env switchover b
```

The step:

1. Checks that slot `b` is provisioned with the serving guardian's BTC key and
   configuration hash, and that the epoch allows it.
2. Asks to make `b` the active slot.
3. Updates the proxy, which asks again.
4. Asks you to type slot `a`'s instance ID, then stops that guardian for good.
5. Activates slot `b`. Activation waits until every other session has been quiet
   for ten minutes, and prints little until then.
6. Checks that the proxy serves slot `b`'s activated guardian.

From step 2 until activation, nodes' new withdrawals fail and are retried;
already-signed ones keep replaying from the proxy's cache. If the step stops
partway, run it again: it resumes where it stopped.

As soon as the step has made `b` the active slot, merge `active-slot: "b"` into
`main`, for example while it asks about the proxy.
Until the teardown below, the proxy's relay points at the stopped guardian, so
no KP round can run.

## 8. Tear down the old slot

Once slot `b` has served for a while, set `slot-a-enabled: "false"` in the
enclave stack's `Pulumi.<stack>.yaml` and commit it. Then:

```sh
./operator/scripts/guardian.sh guardian.env teardown a
./operator/scripts/guardian.sh guardian.env proxy-update
```

`teardown` refuses unless its plan only deletes slot `a`'s host, and asks you to
type the instance ID. Then merge `slot-a-enabled: "false"` into `main`.

## If something goes wrong

- **The standby's boot fails.** Read `host b`. Then, in the enclave program's
  directory, replace only slot `b`'s host, using the URN `arm` printed its plan
  for: `pulumi up --stack <stack> --replace <urn> --target <urn> --target-dependents`.
- **You give up before the switchover.** Set `slot-b-enabled: "false"`, run
  `teardown b`, then `proxy-update`. The serving guardian is untouched.
- **The re-deal stalls**, for example because a KP of the new set cannot
  confirm. Nothing has committed: the current set still holds the key. Run
  `new-session b --abandon`. Then either start the re-deal again from
  `publish b rotate-kp-set`, or provision slot `b` with the current set: remove
  the two `NEW_` lines and go on with section 6.
- **Activation fails after the stop.** Run `switchover b` again. If slot `b`'s
  guardian lost its session, start a fresh one and provision it again:
  `new-session b`, `provision b` and the KPs, then `switchover b`.
- **The new guardian is a committee behind.** A Sui epoch turned before
  activation, so the guardian's `Serving:` epoch trails the chain's. Restart
  hashi's leader pod, which hands the guardian the committees it missed.
