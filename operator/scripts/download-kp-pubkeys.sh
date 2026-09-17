#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C
export AWS_PAGER=""
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
KP_FILE_SUFFIXES=(
  kp-pubkey.asc
  kp-fingerprint.txt
  kp-pubkey.attestation-device.pem
  kp-pubkey.attestation-sig.pem
  kp-pubkey.attestation-dec.pem
)
WORK_DIR=""

say() {
  printf '\n== %s ==\n' "$1"
}

die() {
  printf '\nERROR: %s\n' "$1" >&2
  exit 1
}

run_or_die() {
  local failure_message="$1"
  shift

  if ! "$@"; then
    die "$failure_message"
  fi
}

format_fingerprint() {
  local fingerprint="$1"
  printf '%s %s %s %s %s  %s %s %s %s %s' \
    "${fingerprint:0:4}" "${fingerprint:4:4}" "${fingerprint:8:4}" "${fingerprint:12:4}" "${fingerprint:16:4}" \
    "${fingerprint:20:4}" "${fingerprint:24:4}" "${fingerprint:28:4}" "${fingerprint:32:4}" "${fingerprint:36:4}"
}

cleanup() {
  if [[ -n "$WORK_DIR" ]]; then
    rm -rf -- "$WORK_DIR"
  fi
}

command_package() {
  case "$1" in
    aws) printf '%s' "AWS CLI v2" ;;
    cargo) printf '%s' "Rust toolchain (rustup)" ;;
    jq) printf '%s' "jq" ;;
  esac
}

USAGE="Usage: $0 <name> [output-dir]"
NAME=""
OUT_DIR=""
for argument in "$@"; do
  case "$argument" in
    -h | --help)
      printf '%s\n' "$USAGE" \
        "Downloads and verifies every key provisioner upload in s3://mysten-hashi-kp-pubkeys-<name>, then prints the roster." \
        "The output directory must not exist; it defaults to .hashi/kp-pubkeys/<name>-<UTC time> in this repository."
      exit 0
      ;;
    *)
      if [[ -z "$NAME" ]]; then
        NAME="$argument"
      elif [[ -z "$OUT_DIR" ]]; then
        OUT_DIR="$argument"
      else
        die "Unexpected argument: $argument. $USAGE"
      fi
      ;;
  esac
done
name_pattern='^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
if [[ ! "$NAME" =~ $name_pattern ]] || ((${#NAME} > 39)); then
  die "$USAGE, where <name> has at most 39 lowercase letters, digits, and inner hyphens."
fi
BUCKET="mysten-hashi-kp-pubkeys-$NAME"
if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$REPO_ROOT/.hashi/kp-pubkeys/$NAME-$(date -u +%Y%m%dT%H%M%SZ)"
elif [[ "$OUT_DIR" != /* ]]; then
  OUT_DIR="$PWD/$OUT_DIR"
fi

required_commands=(aws cargo jq)
missing_commands=()
for required_command in "${required_commands[@]}"; do
  if ! command -v "$required_command" > /dev/null 2>&1; then
    missing_commands+=("$required_command")
  fi
done

if ((${#missing_commands[@]} > 0)); then
  printf 'The following required CLI tools are not installed or not on PATH:\n' >&2
  for missing_command in "${missing_commands[@]}"; do
    printf '  - %s (%s)\n' "$missing_command" "$(command_package "$missing_command")" >&2
  done
  printf '\nInstall the listed tools, then run this script again.\n' >&2
  exit 1
fi

trap cleanup EXIT
WORK_DIR="$(mktemp -d)"
cd "$REPO_ROOT"

say "Key provisioner upload download"
printf '%s\n' \
  "This script downloads every key provisioner upload in s3://$BUCKET," \
  "verifies each certificate and its YubiKey attestations as certificate-loading commands do," \
  "and prints the roster once every upload verifies."

say "Check the AWS account"
if ! identity="$(aws sts get-caller-identity --query '[Account, Arn]' --output text)"; then
  die "Could not read the AWS identity. Log in first, for example: aws sso login --profile admin"
fi
read -r ACCOUNT ARN <<< "$identity"
printf 'AWS account:  %s\nAWS identity: %s\n' "$ACCOUNT" "$ARN"

# Always build with default features: non-enclave-dev also trusts software attestation devices.
say "Build the certificate verifier"
run_or_die "Could not build hashi-guardian-init." \
  cargo build --release --locked -p hashi-guardian-init

say "List the uploads"
if ! listing="$(aws s3api list-object-versions --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" --output json)"; then
  die "Could not list s3://$BUCKET."
fi
jq -r '(.Versions // [])[] | [.Key, .VersionId, (.IsLatest | tostring)] | @tsv' <<< "$listing" \
  > "$WORK_DIR/versions" || die "Could not parse the listing of s3://$BUCKET."

: > "$WORK_DIR/latest"
: > "$WORK_DIR/all-kp-keys"
: > "$WORK_DIR/unexpected"
while IFS=$'\t' read -r key version_id is_latest; do
  id="${key%%/*}"
  file="${key#*/}"
  valid=false
  if [[ "$key" == */* && "$id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    for suffix in "${KP_FILE_SUFFIXES[@]}"; do
      if [[ "$file" == "$id-$suffix" ]]; then
        valid=true
      fi
    done
  fi
  if [[ "$valid" == true ]]; then
    printf '%s\n' "$key" >> "$WORK_DIR/all-kp-keys"
    if [[ "$is_latest" == true ]]; then
      printf '%s\t%s\t%s\n' "$id" "$key" "$version_id" >> "$WORK_DIR/latest"
    fi
  elif [[ "$is_latest" == true ]]; then
    printf '%s\n' "$key" >> "$WORK_DIR/unexpected"
  fi
done < "$WORK_DIR/versions"

cut -f 1 "$WORK_DIR/latest" | sort -u > "$WORK_DIR/ids"
if [[ ! -s "$WORK_DIR/ids" && ! -s "$WORK_DIR/unexpected" ]]; then
  die "No uploads in s3://$BUCKET yet."
fi
printf 'User IDs: %s\n' "$(wc -l < "$WORK_DIR/ids" | tr -d ' ')"

width=2
: > "$WORK_DIR/case-collisions"
if [[ -s "$WORK_DIR/ids" ]]; then
  say "Download the uploads"
  mkdir -p "$(dirname "$OUT_DIR")"
  run_or_die "Could not create a new output directory at $OUT_DIR." mkdir "$OUT_DIR"
  while IFS=$'\t' read -r id key version_id; do
    mkdir -p "$OUT_DIR/$id"
    run_or_die "Could not download s3://$BUCKET/$key." \
      aws s3api get-object --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
      --key "$key" --version-id "$version_id" "$OUT_DIR/$key" < /dev/null > /dev/null
  done < "$WORK_DIR/latest"
  printf 'Downloaded %s files into %s\n' "$(wc -l < "$WORK_DIR/latest" | tr -d ' ')" "$OUT_DIR"

  # Downloads land on a case-insensitive filesystem, and each ID must name one key provisioner.
  tr '[:upper:]' '[:lower:]' < "$WORK_DIR/ids" | sort | uniq -d > "$WORK_DIR/case-collisions"
  while IFS= read -r id; do
    if ((${#id} > width)); then
      width=${#id}
    fi
  done < "$WORK_DIR/ids"
fi

say "Verify each key provisioner"
: > "$WORK_DIR/status"
while IFS= read -r id; do
  missing=""
  for suffix in "${KP_FILE_SUFFIXES[@]}"; do
    if [[ ! -f "$OUT_DIR/$id/$id-$suffix" ]]; then
      missing+=" $id-$suffix"
    fi
  done
  lower_id="$(printf '%s' "$id" | tr '[:upper:]' '[:lower:]')"
  if [[ -n "$missing" ]]; then
    status=INCOMPLETE
    detail="missing$missing"
  elif grep -qxF -- "$lower_id" "$WORK_DIR/case-collisions"; then
    status=INVALID
    detail="another user ID differs only by letter case"
  elif ! fingerprint="$(cargo run --release --locked --quiet -p hashi-guardian-init -- \
    tools verify-kp-cert --kp-pgp-cert-path "$OUT_DIR/$id/$id-kp-pubkey.asc" < /dev/null 2> "$WORK_DIR/$id.err")"; then
    status=INVALID
    detail="certificate verification failed:"
  elif [[ ! "$fingerprint" =~ ^[0-9A-F]{40}$ ]]; then
    status=INVALID
    detail="unexpected fingerprint: $fingerprint"
  else
    recorded_fingerprint="$(head -n 1 "$OUT_DIR/$id/$id-kp-fingerprint.txt")"
    if [[ "$recorded_fingerprint" != "$fingerprint" ]]; then
      status=INVALID
      detail="$id-kp-fingerprint.txt ($recorded_fingerprint) does not match the certificate ($fingerprint)"
    else
      status=VERIFIED
      detail="$fingerprint"
    fi
  fi
  printf '%s\t%s\t%s\n' "$id" "$status" "$detail" >> "$WORK_DIR/status"
done < "$WORK_DIR/ids"

awk -F '\t' '$2 == "VERIFIED" { print $3 }' "$WORK_DIR/status" | sort | uniq -d > "$WORK_DIR/duplicates"
all_verified=true
: > "$WORK_DIR/verified"
while IFS=$'\t' read -r id status detail; do
  if [[ "$status" == VERIFIED ]] && grep -qxF -- "$detail" "$WORK_DIR/duplicates"; then
    status=INVALID
    detail="same certificate as another user ID ($detail)"
  fi
  if [[ "$status" == VERIFIED ]]; then
    printf '%-*s  %-10s  %s\n' "$width" "$id" "$status" "$(format_fingerprint "$detail")"
    printf '%s\t%s\n' "$detail" "$id" >> "$WORK_DIR/verified"
  else
    all_verified=false
    printf '%-*s  %-10s  %s\n' "$width" "$id" "$status" "$detail"
    if [[ "$detail" == "certificate verification failed:" ]]; then
      sed 's/^/    /' "$WORK_DIR/$id.err"
    fi
  fi
done < "$WORK_DIR/status"

cut -f 2 "$WORK_DIR/latest" > "$WORK_DIR/latest-keys"
sort "$WORK_DIR/all-kp-keys" | uniq -d > "$WORK_DIR/multiple-versions"
: > "$WORK_DIR/reuploads"
while IFS= read -r key; do
  if grep -qxF -- "$key" "$WORK_DIR/latest-keys"; then
    printf '%s\n' "${key%%/*}" >> "$WORK_DIR/reuploads"
  fi
done < "$WORK_DIR/multiple-versions"
if [[ -s "$WORK_DIR/reuploads" ]]; then
  printf '\nNotes:\n'
  sort -u "$WORK_DIR/reuploads" \
    | sed 's/.*/  & uploaded some files more than once; the latest upload of each file is used./'
fi
if [[ -s "$WORK_DIR/unexpected" ]]; then
  all_verified=false
  printf '\nUnexpected objects (inspect them, remove them with aws s3 rm, then download again):\n'
  sed "s|^|  s3://$BUCKET/|" "$WORK_DIR/unexpected"
fi

id_count="$(wc -l < "$WORK_DIR/ids" | tr -d ' ')"
verified_count="$(wc -l < "$WORK_DIR/verified" | tr -d ' ')"
if [[ "$all_verified" != true || "$verified_count" == 0 || "$verified_count" != "$id_count" ]]; then
  if [[ -d "$OUT_DIR" ]]; then
    printf '\nDownloaded files: %s\n' "$OUT_DIR"
  fi
  die "Not every upload verified, so no roster was written. Fix the problems above and download again."
fi

# Share IDs follow the ascending fingerprint order in which a ceremony deals these certificates.
say "Roster"
index=0
sort "$WORK_DIR/verified" > "$WORK_DIR/roster"
while IFS=$'\t' read -r fingerprint id; do
  index=$((index + 1))
  printf '%d  %-*s  %s\n' "$index" "$width" "$id" "$(format_fingerprint "$fingerprint")"
done < "$WORK_DIR/roster" > "$OUT_DIR/roster.txt"
cat "$OUT_DIR/roster.txt"
printf '\nKey provisioners: %d\nRoster and files: %s\n' "$index" "$OUT_DIR"
printf '\nRoster verified successfully! Post it in a code block and have each key provisioner confirm their row.\n'
