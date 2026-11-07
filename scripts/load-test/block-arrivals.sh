#!/usr/bin/env bash
# Read-only: log when the local node first sees each new block, since signet header
# timestamps can trail wall time by 10+ minutes.
# TSV: height  hash  header_time  seen_utc  seen_unix
set -u
# shellcheck source=scripts/load-test/lib.sh
. "$(dirname "$0")/lib.sh"
OUT="$D/block-arrivals.tsv"
[ -e "$OUT" ] || printf 'height\thash\theader_time\tseen_utc\tseen_unix\n' > "$OUT"
last=$(bc getblockcount) || exit 1
while :; do
  height=$(bc getblockcount 2> /dev/null) || {
    sleep 5
    continue
  }
  while [ "$height" -gt "$last" ]; do
    last=$((last + 1))
    hash=$(bc getblockhash "$last")
    header_time=$(bc getblockheader "$hash" | jq -r '.time | todate')
    printf '%s\t%s\t%s\t%s\t%s\n' "$last" "$hash" "$header_time" "$(date -u +%FT%TZ)" "$(date +%s)" >> "$OUT"
  done
  sleep 5
done
