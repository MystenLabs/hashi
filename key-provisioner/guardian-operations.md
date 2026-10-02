# Guardian Operations

Once your YubiKey is provisioned and the operator has verified your public files,
you take part in guardian operations: the key ceremony, provisioning a guardian,
rotating a guardian, and rotating the key provisioner set.

Each one is a short round. The operator publishes a packet, every key provisioner
runs one command, and everyone reports back. You never edit a configuration file.

## Before a round

Keep your YubiKey connected and no other YubiKey or smart card plugged in. Check
that your Mac is on Wi-Fi.

## Run your step

The operator shares a bucket name, an access key ID, and a secret access key over
a private channel, along with a packet digest.

```sh
./key-provisioner/scripts/run-guardian-step.sh
```

The script downloads the packet, prints the step it contains and the packet
digest, finds your certificate from the connected YubiKey, and shows the exact
command before running anything. Compare the packet digest with the one the
operator posted.

If the repository is not at the commit the guardian runs, the script stops and
prints the `git` command that fixes it. Run that, then run the script again.

Your YubiKey asks for its PIN and a touch, usually twice: once to decrypt your
share and once to sign. The first run of a round compiles the guardian tools,
which takes a few minutes.

When the step finishes, tell the operator and post the summary lines it printed.

## Replacing your certificate

If the operator publishes a certificate replacement, provision the new YubiKey
first, then pass the new `.asc` file:

```sh
./key-provisioner/scripts/run-guardian-step.sh ./jdoe-kp-pubkey.asc
```

Sign with the YubiKey the guardian already knows, not the new one.

## Your files

Everything lands in `.hashi/guardian/<packet id>/` in this repository. After a key
ceremony, keep `kp-shares.json`: it holds every key provisioner's encrypted share
and is the recovery record. It is never an input to a later step.

## Stop and tell the operator

- The packet digest differs from the one the operator posted.
- The script says no certificate in the packet belongs to your YubiKey.
- The script reports a mismatch in `config_hash`, `session_id`, or the guardian's
  build.
- Any step fails twice with the same error.

Never work around a refusal. Each one means the packet, the guardian, or your
YubiKey is not what the round expects.
