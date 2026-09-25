#!/usr/bin/env bash
# Golden snapshots are append-only against the base (the PR's target branch).
# A signing version's files (`*_v<N>_*`, `*_v<N>.*`) may go only with the
# version itself. Violations only warn until GOLDEN_GATE_ENFORCE=true.
set -euo pipefail

base="${1:-HEAD^1}"
dir=crates/hashi/src/mpc/golden_snapshots
constants=crates/hashi/src/constants.rs
pattern='^pub const SUPPORTED_SIGNING_VERSIONS: &\[u64\] = &\[\([0-9, ]*\)\];$'

if ! git rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
	echo "::error::cannot resolve the base $base; fetch it first (in CI, check out with fetch-depth 2)"
	exit 1
fi

supported_versions() {
	git show "$1:$constants" 2>/dev/null | sed -n "s/$pattern/\1/p" | tr ',' '\n' | tr -d ' ' | sed '/^$/d' | sort -u
}

if [ -z "$(git show "HEAD:$constants" | sed -n "s/$pattern/x/p")" ]; then
	echo "::error file=$constants::cannot parse SUPPORTED_SIGNING_VERSIONS"
	exit 1
fi
dropped=$(comm -23 <(supported_versions "$base") <(supported_versions HEAD))

level=warning
if [ "${GOLDEN_GATE_ENFORCE:-false}" = true ]; then
	level=error
fi
changes=$(git diff --no-renames --name-status "$base" HEAD -- "$dir")
echo "Checking $dir against $(git rev-parse --short "$base")"
violations=0
while IFS=$'\t' read -r status path; do
	if [ -z "$status" ] || [ "$status" = A ]; then
		continue
	fi
	version=$(basename "$path" | sed -n 's/^[^0-9]*_v\([0-9][0-9]*\)[_.].*/\1/p')
	if [ "$status" = D ] && [ -n "$version" ] && grep -qx "$version" <<<"$dropped"; then
		echo "$path: deleted with retired signing version $version"
		continue
	fi
	echo "::$level file=$path::golden snapshot $status against the base; goldens are append-only, so add a new version instead"
	violations=$((violations + 1))
done <<<"$changes"

if [ "$violations" -gt 0 ] && [ "$level" = error ]; then
	exit 1
fi
