# Move upgrade-compatibility snapshots

These directories hold the **compiled bytecode of the deployed Hashi Move
package**, checked into the repo so the upgrade-compatibility CI gate runs
**hermetically — with no network call**.

The gate (`crates/hashi/tests/move_upgrade_compat.rs`,
`current_source_is_compatible_upgrade_of_deployed`) builds the current
`packages/hashi` source and asserts it is a *compatible upgrade* of the
snapshot here — the same per-module check a Sui validator runs when it processes
an `Upgrade` command under the default (`Compatible`) `UpgradeCap` policy. The
snapshot IS the "deployed package" side of that comparison.

## Layout

```
move_upgrade_snapshots/
  <network>/
    v<version>/
      <module>.mv        # raw compiled module bytecode, one file per module,
      ...                #   self-addressed at the package's runtime id
      manifest.json      # metadata: network, version, package_id, module list
  README.md
```

Which `<network>/v<version>/` directories the gate checks is **derived from
`packages/hashi/Published.toml`**: every `[published.<network>]` entry must
have a snapshot at its recorded version, and the snapshot's manifest and
bytecode ids are cross-validated against that entry (`package_id` ↔
`published-at`, bytecode self-address ↔ `original-id`). Bumping
`Published.toml` without capturing a matching snapshot fails the gate — so a
mainnet deployment is picked up automatically once its entry lands. The
`HASHI_COMPAT_SNAPSHOT_DIR` environment variable is a dev escape hatch that
checks exactly one directory instead.

## When to regenerate

Regenerate whenever a **new package version is deployed on chain** (i.e. an
`Upgrade` is executed). The deployment bumps `version` (and `published-at`) in
`packages/hashi/Published.toml`, and the gate follows that file — so all that
is needed here is capturing the snapshot it now expects:

1. Create the `<network>/v<N>/` directory matching the new `Published.toml`
   version (keep the old `v<N-1>/` — the history of deployed bytecode is
   preserved, it just stops being checked).
2. Fetch the deployed modules into it (recipe below) and write a
   `manifest.json` that matches the `Published.toml` entry (`network`,
   `version`, `package_id` = `published-at`).

Until the snapshot exists, the gate fails with a "snapshot is missing or
invalid" error pointing here — it cannot silently keep checking the old
version.

## How to regenerate

The `.mv` files are exactly the bytes in the deployed package's on-chain
`moduleMap`. Fetch them with a single JSON-RPC `sui_getObject` call for the
package object (`showBcs: true`), which returns `moduleMap` as a
`name -> base64(bytecode)` map, then base64-decode each entry to `<name>.mv`.

Copy-pasteable recipe (requires `curl`, `jq`, and `base64`):

```bash
# --- edit these two lines for the version you are capturing ---
PACKAGE_ID="0xfcea10cadbb553c4874201584abf68771592678952efd957b2e82c010c7f4360"
OUT_DIR="crates/hashi/tests/move_upgrade_snapshots/testnet/v1"
RPC_URL="https://fullnode.testnet.sui.io:443"
# --------------------------------------------------------------

mkdir -p "$OUT_DIR"

# Fetch the package object with its BCS-encoded module map.
curl -s -X POST "$RPC_URL" \
  -H 'Content-Type: application/json' \
  -d "{
        \"jsonrpc\": \"2.0\",
        \"id\": 1,
        \"method\": \"sui_getObject\",
        \"params\": [\"$PACKAGE_ID\", { \"showBcs\": true }]
      }" > /tmp/hashi_pkg.json

# .result.data.bcs.moduleMap is { "<module>": "<base64 bytecode>", ... }.
# Base64-decode each entry to <module>.mv.
jq -r '.result.data.bcs.moduleMap | to_entries[] | "\(.key)\t\(.value)"' /tmp/hashi_pkg.json \
| while IFS=$'\t' read -r name b64; do
    printf '%s' "$b64" | base64 -d > "$OUT_DIR/$name.mv"
    echo "wrote $OUT_DIR/$name.mv"
  done
```

Then refresh `manifest.json` (network, version, `package_id`, `module_count`,
and the module list) to match what you just wrote. The gate validates the
manifest **strictly**: `module_count` must equal the list length, and the list
must match the `.mv` filenames — and each file's deserialized module self-name
— exactly, in both directions. An incomplete capture (a listed module with no
file) fails loudly rather than silently skipping that module's compatibility
check. Verify the capture is well formed by running the gate:

```bash
cargo test -p hashi --test move_upgrade_compat -- --nocapture
```

The test deserializes every `.mv` file with
`CompiledModule::deserialize_with_defaults`, so a corrupt or truncated capture
fails loudly.
