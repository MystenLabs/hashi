# Guardian EIF — Nitro boot investigation

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> Why the reproducible eif_build EIF does not boot in a real Nitro enclave, how it was diagnosed, and the interim workaround.

The reproducible enclave image (`docker/hashi-guardian/Containerfile`, built with
stagex `eif_build`) **does not boot in a real AWS Nitro enclave**. This was found
the first time the EIF was run in Nitro (2026-07-09) — until then it had only
been exercised as the Mac-local docker replica (`docker/hashi-guardian-local`,
which uses TCP instead of vsock and never runs a real enclave), and the
`hashi-guardian-enclave` pulumi deploy had never completed a full enclave
bring-up.

## Symptom

`nitro-cli run-enclave --eif-path out/nitro.eif` allocates CPU + memory
("Started enclave with enclave-cid: N, memory: 1024 MiB") but the guest never
signals ready:

```
[ E36 ] Enclave boot failure ... Waiting on enclave to boot failed with error
VsockTimeoutError
```

`nitro-cli describe-enclaves` never lists the enclave, and a `--debug-mode
--attach-console` run produces **zero console output** (not even the early kernel
banner).

## Diagnosis — it is the stagex kernel / eif_build path, not the guardian

Three checks isolate the fault away from the guardian and the host:

1. **The guardian binary is fine.** Extracted from the EIF's `rootfs.cpio` and run
   on the host, it starts normally: `Withdraw mode ... gRPC server listening on
   0.0.0.0:3000`.
2. **The host + Nitro + console capture are fine.** A hello EIF built with
   **`nitro-cli build-enclave`** boots to `RUNNING` with a full kernel console
   (captured via `--debug-mode --attach-console` inside a `tmux` pty — SSM has no
   tty, so this is the only capture that works). A `nitro-cli build-enclave` EIF
   wrapping the *same guardian binary* + a nitro run.sh also boots and serves.
3. **The stagex EIF's guest never executes.** Running the stagex EIF and probing
   `:3000` through the host vsock bridge across the whole ~90 s boot window gets
   **no response at any point** — so the failure is before the kernel starts
   run.sh (not a missing heartbeat with an otherwise-live guardian).

Two cmdline theories were tested against the live enclave and **ruled out**:

- Correcting the stale hardcoded `initrd=0x2000000,3228672` to the real ramdisk
  size (16738802) — still no boot, still empty console.
- Dropping `initrd=…,SIZE root=/dev/ram0` entirely so the kernel auto-unpacks the
  initramfs (matching how `nitro-cli` EIFs boot, which bake no `initrd=`/`root=`)
  — still no boot.

`nitro-cli run-enclave` **appends** the `console=ttyS0 … virtio_mmio.device=…`
console/vsock devices at launch for every EIF (they are not baked, in either the
working or the broken EIF), so a missing virtio device is not the difference.

**Conclusion:** the reproducible `stagex/user-linux-nitro` `bzImage` (or the way
`eif_build` packages it) does not execute in this Nitro version. This is the
remaining blocker; it is not a `Containerfile` cmdline/size change.

## Recommendation

- Bisect the stagex EIF against a known-good `nitro-cli build-enclave` reference:
  compare the kernel + kernel_config, confirm `eif_build` sets the boot-protocol
  ramdisk and entry point the running Nitro version expects, and verify the
  stagex kernel config has the virtio-mmio console + vsock drivers Nitro presents.
- Consider pinning a newer `stagex/user-linux-nitro`, or validating the whole
  EIF against a minimal stagex enclave that just prints + heartbeats, before
  layering the guardian on top.

The affected code is `docker/hashi-guardian/Containerfile` (the `eif_build`
invocation + the stagex `FROM` pins). The `initrd` size is now computed from the
ramdisk (a latent correctness bug fixed alongside this doc) but that alone does
not boot the EIF.

## Interim workaround (dev/testing only)

For dev/testing enclaves (built `--features non-enclave-dev`, so PCR0 provenance
does not matter), a bootable enclave can be produced with `nitro-cli
build-enclave` from a small image that COPYs the guardian binary + a nitro run.sh
(loopback + the S3 `socat → VSOCK-CONNECT:3:810x` forwarders + `VSOCK-LISTEN:3000
→ 127.0.0.1:3000`, `CMD /run.sh`), run at the fixed CID the host gRPC bridge
expects. This boots, seeds entropy from the NSM, and serves the guardian. It is
**not reproducible and has no PCR provenance**, so it is unsuitable for the real
attestation build — that path needs the stagex kernel issue above resolved.
