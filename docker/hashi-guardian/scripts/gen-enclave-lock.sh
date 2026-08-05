#!/usr/bin/env bash
# Regenerate docker/hashi-guardian/enclave-Cargo.lock.
#
# The enclave build compiles only hashi-guardian, but cargo resolves every
# workspace member (dev-dependencies included), so the Containerfile prunes the
# test-only crates before building. That pruned workspace resolves to a smaller
# lock than the root one, and the build passes --locked, so the pruned lock has
# to be committed.
#
# The root lock is copied in first and used as the seed: cargo then only REMOVES
# entries that nothing needs any more, and never re-resolves a version. The
# result must stay a strict subset of the root lock; CI asserts that.
#
# The prune below must mirror the one in the Containerfile. If the two drift,
# the enclave build fails on --locked rather than building something unexpected.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
OUT="$REPO_ROOT/docker/hashi-guardian/enclave-Cargo.lock"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp -R "$REPO_ROOT/crates" "$WORK/crates"
cp "$REPO_ROOT/Cargo.toml" "$WORK/Cargo.toml"
cp "$REPO_ROOT/Cargo.lock" "$WORK/Cargo.lock"
[ -f "$REPO_ROOT/rust-toolchain.toml" ] && cp "$REPO_ROOT/rust-toolchain.toml" "$WORK/"

# --- prune: keep in sync with docker/hashi-guardian/Containerfile ---
rm -rf "$WORK/crates/e2e-tests" "$WORK/crates/hashi-monitor"
grep -vE '^(move-binary-format|move-core-types)\.workspace' \
  "$WORK/crates/hashi/Cargo.toml" > "$WORK/hashi-Cargo.toml"
mv "$WORK/hashi-Cargo.toml" "$WORK/crates/hashi/Cargo.toml"
# --- end prune ---

(cd "$WORK" && cargo metadata --format-version 1 >/dev/null)

# The whole design rests on this: the pruned lock must be a strict subset of the
# root lock. If a version or checksum ever differs, the enclave would compile
# something other than what the workspace resolves to, and the seeding above has
# stopped working.
python3 - "$REPO_ROOT/Cargo.lock" "$WORK/Cargo.lock" <<'PY'
import re, sys

def parse(path):
    out = {}
    for block in open(path).read().split("[[package]]")[1:]:
        f = {}
        for line in block.strip().splitlines():
            m = re.match(r'^(name|version|source|checksum) = "(.*)"$', line.strip())
            if m:
                f[m.group(1)] = m.group(2)
            elif line.strip().startswith("["):
                break
        out[(f.get("name"), f.get("version"), f.get("source"))] = f.get("checksum")
    return out

root, enc = parse(sys.argv[1]), parse(sys.argv[2])
new = [k for k in enc if k not in root]
bad = [k for k in enc if k in root and enc[k] != root[k]]
if new or bad:
    for k in new:
        print(f"  not in root lock: {k}", file=sys.stderr)
    for k in bad:
        print(f"  checksum differs: {k}", file=sys.stderr)
    sys.exit("enclave lock is not a subset of the root lock")
print(f"subset OK: {len(enc)} of {len(root)} entries kept")
PY

cp "$WORK/Cargo.lock" "$OUT"
echo "wrote $OUT"
