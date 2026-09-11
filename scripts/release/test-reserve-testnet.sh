#!/usr/bin/env bash
# Black-box reservation invariants using disposable, local Git repositories.
set -Eeuo pipefail
shopt -s inherit_errexit

allocator="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/reserve-testnet.sh"
root=$(mktemp -d "${TMPDIR:-/tmp}/testnet-reservation.XXXXXXXX")
log="$root/commands.log"
pids=()
cleanup() {
  local status=$? pid
  trap - EXIT INT TERM
  for pid in "${pids[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  if ((status != 0)); then
    cat "$log" >&2
  fi
  rm -rf -- "$root"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'printf "FAIL at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
: >"$log"

# Do not inherit the invoking checkout, credentials, signing, or user config.
for variable in "${!GIT_@}"; do
  unset "$variable"
done
export HOME="$root/home" XDG_CONFIG_HOME="$root/config"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_AUTHOR_NAME='Reservation Test Bot' GIT_COMMITTER_NAME='Reservation Test Bot'
export GIT_AUTHOR_EMAIL=reservation-test@example.invalid GIT_COMMITTER_EMAIL=reservation-test@example.invalid
export GIT_TERMINAL_PROMPT=0
mkdir -p "$HOME" "$XDG_CONFIG_HOME"

git_at() {
  git -C "$1" "${@:2}" 2>>"$log"
}

clone() {
  git_at "$scenario" clone "$origin" "$1" >>"$log"
}

commit() {
  printf '%s\n' "$1" >"$work/source.txt"
  git_at "$work" add source.txt
  git_at "$work" commit -m "$1" >>"$log"
  git_at "$work" push origin main >>"$log"
  git_at "$work" rev-parse HEAD
}

setup() {
  scenario="$root/$1"
  origin="$scenario/origin.git"
  work="$scenario/work"
  mkdir "$scenario"
  git_at "$scenario" init --bare --initial-branch=main "$origin" >>"$log"
  clone "$work"
  initial_sha=$(commit initial)
  # Historical SHA-named releases must not initialize the numeric counter.
  git_at "$work" tag "testnet-$initial_sha"
  git_at "$work" push origin --tags >>"$log"
}

reserve() (
  cd -- "$1"
  exec timeout --kill-after=2s 30s bash "$allocator" \
    --ref "$3" --run-id "$2" --bump-contract-version "$4" 2>>"$log"
)

assert_equal() {
  if [[ $1 != "$2" ]]; then
    printf 'Expected <%s>, got <%s>\n' "$2" "$1" >&2
    return 1
  fi
}

assert_reservation() {
  jq -es --arg tag "$2" --arg sha "$3" \
    'length == 1 and (.[0] | .release_tag == $tag and .sha == $sha)' <<<"$1" >/dev/null
  assert_equal "$(git_at "$origin" cat-file -t "refs/tags/$2")" tag
  assert_equal "$(git_at "$origin" rev-parse "refs/tags/$2^{}")" "$3"
}

remote_refs() {
  git_at "$work" ls-remote origin
}

setup numeric
assert_reservation "$(reserve "$work" initial '' false)" testnet-0.1 "$initial_sha"
# Carry 0.9 to 0.10, then choose 0.10 over 0.9 rather than sorting lexically.
# Lightweight numbered tags count for the initial boundary too.
git_at "$work" tag testnet-0.9
git_at "$work" push origin refs/tags/testnet-0.9 >>"$log"
assert_reservation "$(reserve "$work" decimal-carry main false)" testnet-0.10 "$initial_sha"
assert_reservation "$(reserve "$work" after-numeric-boundary main false)" testnet-0.11 "$initial_sha"
assert_reservation "$(reserve "$work" contract-bump main true)" testnet-1.0 "$initial_sha"
assert_reservation "$(reserve "$work" after-bump main false)" testnet-1.1 "$initial_sha"
printf 'ok 1 - historical tags, numeric ordering, and contract bump\n'

setup resume
assert_reservation "$(reserve "$work" original-run main false)" testnet-0.1 "$initial_sha"
assert_reservation "$(reserve "$work" different-run "$initial_sha" false)" testnet-0.2 "$initial_sha"
moved_sha=$(commit 'main moved')
assert_reservation "$(reserve "$work" newer-run main false)" testnet-0.3 "$moved_sha"
before=$(remote_refs)
clone "$scenario/retry"
assert_reservation "$(reserve "$scenario/retry" original-run main false)" testnet-0.1 "$initial_sha"
assert_equal "$(remote_refs)" "$before"
printf 'ok 2 - distinct runs and fresh-clone retry after branch movement\n'

setup conflict
assert_reservation "$(reserve "$work" conflicted-run main false)" testnet-0.1 "$initial_sha"
other_sha=$(commit 'different source')
# Keep the real annotation, but change its target so source metadata conflicts.
git_at "$work" fetch origin refs/tags/testnet-0.1 >>"$log"
annotation=$(git_at "$work" cat-file tag FETCH_HEAD)
conflicting_object=$(
  printf 'object %s\n%s\n' "$other_sha" "${annotation#*$'\n'}" |
    git_at "$work" hash-object -t tag -w --stdin
)
git_at "$work" push --force origin "$conflicting_object:refs/tags/testnet-0.1" >>"$log"
before=$(remote_refs)
clone "$scenario/conflict-retry"
if reserve "$scenario/conflict-retry" conflicted-run main false >"$scenario/rejected.json"; then
  printf 'Conflicting source metadata was accepted\n' >&2
  exit 1
fi
assert_equal "$(remote_refs)" "$before"
assert_equal "$(git_at "$origin" rev-parse 'refs/tags/testnet-0.1^{}')" "$other_sha"
printf 'ok 3 - source conflict rejected without changing remote refs\n'

setup race
git_at "$work" push origin ":refs/tags/testnet-$initial_sha" >>"$log"
assert_equal "$(git_at "$work" ls-remote --refs origin 'refs/tags/*')" ''
checkouts=("$scenario/race-left" "$scenario/race-right")
clone "${checkouts[0]}"
clone "${checkouts[1]}"
mkdir "$origin/barrier"
hook="$origin/hooks/pre-receive"
# Both pushes reach the hook before either creates its ref. Git decides the
# winner; the allocator sees an actual rejected concurrent create, not a mock.
{
  printf '#!%s\n' "$BASH"
  cat <<'HOOK'
set -euo pipefail
barrier="$PWD/barrier"
touch "$barrier/$$"
deadline=$((SECONDS + 10))
while :; do
  arrivals=("$barrier"/*)
  (( ${#arrivals[@]} >= 2 )) && break
  if (( SECONDS >= deadline )); then
    printf 'Timed out waiting for both reservation pushes\n' >&2
    touch "$barrier/timed-out"
    exit 1
  fi
  sleep 0.01
done
HOOK
} >"$hook"
chmod +x "$hook"
for index in 0 1; do
  (
    if reserve "${checkouts[index]}" "race-$index" main false; then
      exit 0
    else
      exit "$?"
    fi
  ) >"$scenario/result-$index.json" &
  pids+=("$!")
done
statuses=()
for index in 0 1; do
  if wait "${pids[index]}"; then
    statuses+=(0)
  else
    statuses+=("$?")
  fi
done
pids=()
rm -- "$hook"
[[ ! -e "$origin/barrier/timed-out" ]]
winners=0
for index in 0 1; do
  if ((statuses[index] == 0)); then
    winner=$index
    winners=$((winners + 1))
  fi
done
assert_equal "$winners" 1
assert_reservation "$(cat "$scenario/result-$winner.json")" testnet-0.1 "$initial_sha"
first_tag=$(git_at "$origin" rev-parse refs/tags/testnet-0.1)
loser=$((1 - winner))
assert_reservation "$(reserve "${checkouts[loser]}" "race-$loser" main false)" testnet-0.2 "$initial_sha"
assert_equal "$(git_at "$origin" rev-parse refs/tags/testnet-0.1)" "$first_tag"
printf 'ok 4 - tagless remote, concurrent winner, and safe loser retry\n'
