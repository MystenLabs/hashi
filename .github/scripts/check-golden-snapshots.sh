#!/usr/bin/env bash
# Flags any change to an existing golden snapshot file since the merge base; new files pass.
# Without an argument the base is HEAD^1, so HEAD must be the PR merge commit (as in CI).
# CI also passes PR_HEAD_SHA, so a checkout of the PR head itself is rejected.
# Violations only warn until GOLDEN_GATE_ENFORCE=true.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

dir=crates/hashi/src/mpc/golden_snapshots
if [ $# -gt 0 ]; then
	base=$1
elif git rev-parse --verify --quiet "HEAD^2^{commit}" >/dev/null &&
	[ "$(git rev-parse HEAD)" != "${PR_HEAD_SHA:-}" ]; then
	base=HEAD^1
else
	echo "::error::HEAD is not the PR merge commit with both parents fetched; in CI check out the merge ref with fetch-depth 2, locally pass the target branch"
	exit 1
fi

if ! git rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
	echo "::error::cannot resolve the base $base; fetch it first"
	exit 1
fi
if ! merge_base=$(git merge-base "$base" HEAD); then
	echo "::error::no merge base between $base and HEAD; fetch more history"
	exit 1
fi

level=warning
if [ "${GOLDEN_GATE_ENFORCE:-false}" = true ]; then
	level=error
fi
changes=$(git diff --no-renames --name-status "$merge_base" HEAD -- "$dir")
echo "Checking $dir against $(git rev-parse --short "$merge_base")"
violations=0
while IFS=$'\t' read -r status path; do
	if [ -z "$status" ] || [ "$status" = A ]; then
		continue
	fi
	echo "::$level file=$path::golden snapshot $status since the merge base; goldens are append-only"
	violations=$((violations + 1))
done <<<"$changes"

if [ "$violations" -gt 0 ] && [ "$level" = error ]; then
	exit 1
fi
