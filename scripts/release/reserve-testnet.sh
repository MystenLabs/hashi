#!/usr/bin/env bash
# Reserve one immutable testnet release tag for a GitHub workflow run.
set -Eeuo pipefail

fail() {
  printf 'reserve-testnet: %s\n' "$*" >&2
  exit 1
}
trap 'printf "reserve-testnet: command failed at line %s\n" "$LINENO" >&2' ERR

ref=''
run_id=''
bump=''
while (($#)); do
  case "$1" in
    --ref | --run-id | --bump-contract-version)
      (($# >= 2)) || fail "missing value for $1"
      option=$1
      value=$2
      shift 2
      ;;
    --ref=* | --run-id=* | --bump-contract-version=*)
      option=${1%%=*}
      value=${1#*=}
      shift
      ;;
    -h | --help)
      printf 'Usage: %s [--ref REF] --run-id ID --bump-contract-version true|false\n' "$0"
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
  case "$option" in
    --ref) ref=$value ;;
    --run-id) run_id=$value ;;
    --bump-contract-version) bump=$value ;;
  esac
done
[[ -n $run_id ]] || fail 'workflow run ID must not be empty'
[[ $bump == true || $bump == false ]] || fail 'bump_contract_version must be true or false'

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

# Only fetched remote refs establish durability. A failed push must not leave
# a local tag that a retry could mistake for a successful reservation. A
# wildcard fetch fails on an empty remote, so check absence explicitly first.
git ls-remote --refs origin 'refs/tags/testnet-*' >"$tmp/remote"
: >"$tmp/records"
if [[ -s $tmp/remote ]]; then
  git fetch --depth=1 --no-tags --prune origin \
    '+refs/tags/testnet-*:refs/hashi-release-reservations/testnet-*' >&2
  git for-each-ref \
    '--format=%(refname:strip=2)%00%(objecttype)%00%(*objecttype)%00%(*objectname)%00%(contents)%00' \
    refs/hashi-release-reservations/ >"$tmp/records"
fi

# NUL delimiters preserve annotated messages, including embedded newlines.
# Lightweight numbered tags count for numbering but cannot own a workflow run.
jq -n --rawfile records "$tmp/records" '
  ($records | if . == "" then [""] else split("\u0000") end) as $fields
  | if (($fields | length) - 1) % 5 != 0
       or ($fields[-1] | test("\\A\\s*\\z") | not)
    then error("invalid release tag records") else . end
  | reduce range(0; ($fields | length) - 1; 5) as $offset
      ({versions: [], by_run: {}};
       ($fields[$offset] | sub("\\A\\n*"; "")) as $name
       | if ($name | test("\\Atestnet-(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\z") | not)
         then .
         else .versions += [$name | ltrimstr("testnet-")]
         | if $fields[$offset + 1] != "tag" then .
           else $fields[$offset + 4] as $message
           | (try {metadata: ($message | fromjson)} catch {}) as $parsed
           | if ($parsed | has("metadata") | not) then
               if ($message | contains("hashi_release"))
               then error("malformed Hashi reservation metadata on " + $name)
               else . end
             elif ($parsed.metadata | type) != "object" then .
             elif ($parsed.metadata | has("hashi_release") | not) then .
             else $parsed.metadata as $metadata
             | if $metadata.hashi_release != "testnet"
                  or ($metadata.workflow_run_id | type) != "string"
                  or $metadata.workflow_run_id == ""
                  or ($metadata.source_sha | type) != "string"
                  or ($metadata.source_sha | tostring | test("\\A(?:[0-9a-f]{40}|[0-9a-f]{64})\\z") | not)
                  or ($metadata.bump_contract_version | type) != "boolean"
                  or $fields[$offset + 2] != "commit"
                  or $fields[$offset + 3] != $metadata.source_sha
               then error("invalid Hashi reservation metadata or target on " + $name)
               elif (.by_run | has($metadata.workflow_run_id))
               then error("multiple Hashi reservations for workflow run " + $metadata.workflow_run_id)
               else .by_run[$metadata.workflow_run_id] = {
                 release_tag: $name,
                 sha: $metadata.source_sha,
                 bump_contract_version: $metadata.bump_contract_version
               } end
             end
           end
         end)
' >"$tmp/reservations"

# Consult durable ownership before resolving the source: main may have moved
# since the original allocation, and a retry must retain its original commit.
reservation=$(jq -c --arg run_id "$run_id" '.by_run[$run_id]' "$tmp/reservations")
if [[ $reservation != null ]]; then
  jq -c --arg run_id "$run_id" --argjson bump "$bump" '
    .by_run[$run_id]
    | if .bump_contract_version != $bump
      then error("bump_contract_version differs from this run\u0027s reservation")
      else {sha, release_tag} end
  ' "$tmp/reservations"
  exit 0
fi

ref=${ref:-main}
# Accept a ref, not an option, refspec, revision expression, or wildcard.
[[ $ref != -* && $ref != +* && $ref != @ ]] || fail 'invalid source ref'
git check-ref-format --allow-onelevel "$ref"
git fetch --depth=1 --no-tags origin "$ref" >&2
sha=$(git rev-parse --verify 'FETCH_HEAD^{commit}')
[[ $sha =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || fail 'source ref did not resolve to a commit SHA'

# Version components are unbounded decimal strings, not Bash integers. Only
# individual digits enter arithmetic, so incrementing cannot silently overflow.
increment_decimal() {
  local value=$1 suffix='' digit
  while [[ $value == *9 ]]; do
    suffix="0$suffix"
    value=${value%?}
  done
  if [[ -z $value ]]; then
    printf '1%s' "$suffix"
  else
    digit=${value: -1}
    printf '%s%s%s' "${value%?}" "$((digit + 1))" "$suffix"
  fi
}

jq -r '.versions[]' "$tmp/reservations" | LC_ALL=C sort -V >"$tmp/versions"
maximum=''
while IFS= read -r version; do
  maximum=$version
done <"$tmp/versions"
if [[ -z $maximum ]]; then
  version=0.1
elif [[ $bump == true ]]; then
  version="$(increment_decimal "${maximum%%.*}").0"
else
  version="${maximum%%.*}.$(increment_decimal "${maximum#*.}")"
fi
tag="testnet-$version"
((${#tag} <= 128)) || fail 'release version exceeds the Docker tag length limit'
metadata=$(jq -cn --arg run_id "$run_id" --arg sha "$sha" --argjson bump "$bump" \
  '{hashi_release: "testnet", workflow_run_id: $run_id, source_sha: $sha, bump_contract_version: $bump}')
identity=$(GIT_COMMITTER_NAME='github-actions[bot]' \
  GIT_COMMITTER_EMAIL='41898282+github-actions[bot]@users.noreply.github.com' \
  git var GIT_COMMITTER_IDENT)
# Create the annotated object without a local release ref. The remote's
# create-only ref update is the atomic allocation operation.
object_id=$(printf 'object %s\ntype commit\ntag %s\ntagger %s\n\n%s\n' \
  "$sha" "$tag" "$identity" "$metadata" | git mktag)
git push --no-force --no-follow-tags origin "$object_id:refs/tags/$tag" >&2
jq -cn --arg sha "$sha" --arg tag "$tag" '{sha: $sha, release_tag: $tag}'
