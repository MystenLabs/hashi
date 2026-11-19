#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Translate the Guardian rate limiter from Rust to Lean.
# The output is `HashiTypes.lean` in this directory. Do not edit that file.
#
# Requirements: `charon` and `aeneas` from the Aeneas release in `README.md`.
# Set `CHARON` and `AENEAS` if the tools are not on `PATH`.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
charon="${CHARON:-charon}"
aeneas="${AENEAS:-aeneas}"
# Charon uses its own Rust compiler. A separate directory keeps the usual build cache valid.
target="${CHARON_TARGET_DIR:-$repo/target/charon}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

(
  cd "$repo/crates/hashi-types"
  CARGO_TARGET_DIR="$target" "$charon" cargo --preset=aeneas \
    --start-from 'crate::guardian::limiter::RateLimiter::consume_at' \
    --dest-file "$work/hashi_types.llbc" -- -p hashi-types
)
"$aeneas" -backend lean -dest "$work/lean" -no-progress-bar "$work/hashi_types.llbc"
cp "$work/lean/HashiTypes.lean" "$here/HashiTypes.lean"
echo "Wrote $here/HashiTypes.lean"
