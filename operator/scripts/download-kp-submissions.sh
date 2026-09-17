#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C
export AWS_PAGER=""
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
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

cleanup() {
  if [[ -n "$WORK_DIR" ]]; then
    rm -rf -- "$WORK_DIR"
  fi
}

command_package() {
  case "$1" in
    aws) printf '%s' "AWS CLI v2" ;;
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
        "Downloads every key provisioner's signed rotate-kp-set submission from s3://mysten-hashi-kp-packet-<name>," \
        "then prints the --submission flags for operator rotate-kp-set submit." \
        "The output directory must not exist; it defaults to .hashi/kp-submissions/<name>-<UTC time>."
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
BUCKET="mysten-hashi-kp-packet-$NAME"
if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$REPO_ROOT/.hashi/kp-submissions/$NAME-$(date -u +%Y%m%dT%H%M%SZ)"
elif [[ "$OUT_DIR" != /* ]]; then
  OUT_DIR="$PWD/$OUT_DIR"
fi

required_commands=(aws jq)
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

say "Key provisioner submission download"
printf '%s\n' \
  "This script downloads every signed rotate-kp-set submission in s3://$BUCKET" \
  "and prints the command that submits them as one batch."

say "Check the AWS account"
if ! identity="$(aws sts get-caller-identity --query '[Account, Arn]' --output text)"; then
  die "Could not read the AWS identity. Log in first, for example: aws sso login --profile admin"
fi
read -r ACCOUNT ARN <<< "$identity"
printf 'AWS account:  %s\nAWS identity: %s\n' "$ACCOUNT" "$ARN"

say "List the submissions"
if ! listing="$(aws s3api list-object-versions --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
  --prefix submissions/ --output json)"; then
  die "Could not list s3://$BUCKET."
fi
jq -r '(.Versions // [])[] | select(.IsLatest) | [.Key, .VersionId] | @tsv' <<< "$listing" \
  > "$WORK_DIR/versions" || die "Could not parse the listing of s3://$BUCKET."

: > "$WORK_DIR/latest"
: > "$WORK_DIR/unexpected"
while IFS=$'\t' read -r key version_id; do
  id="${key#submissions/}"
  id="${id%%/*}"
  if [[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ && "$key" == "submissions/$id/$id.rotation" ]]; then
    printf '%s\t%s\t%s\n' "$id" "$key" "$version_id" >> "$WORK_DIR/latest"
  else
    printf '%s\n' "$key" >> "$WORK_DIR/unexpected"
  fi
done < "$WORK_DIR/versions"
[[ -s "$WORK_DIR/latest" ]] || die "No submissions in s3://$BUCKET yet."

say "Download the submissions"
mkdir -p "$(dirname "$OUT_DIR")"
run_or_die "Could not create a new output directory at $OUT_DIR." mkdir "$OUT_DIR"
while IFS=$'\t' read -r id key version_id; do
  run_or_die "Could not download s3://$BUCKET/$key." \
    aws s3api get-object --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
    --key "$key" --version-id "$version_id" "$OUT_DIR/$id.rotation" < /dev/null > /dev/null
  printf '%s\n' "$id"
done < "$WORK_DIR/latest"

if [[ -s "$WORK_DIR/unexpected" ]]; then
  printf '\nUnexpected objects (inspect them, remove them with aws s3 rm, then download again):\n'
  sed "s|^|  s3://$BUCKET/|" "$WORK_DIR/unexpected"
fi

say "Submit the batch"
printf '%s\n' \
  "Check that these are exactly the key provisioners who reported success, then run:" \
  ""
printf 'cargo run -p hashi-guardian-init -- operator rotate-kp-set submit --config <operator config>'
while IFS=$'\t' read -r id _ _; do
  printf ' \\\n  --submission %s' "$OUT_DIR/$id.rotation"
done < "$WORK_DIR/latest"
printf '\n\nSubmissions downloaded successfully! Key provisioners: %s\n' \
  "$(wc -l < "$WORK_DIR/latest" | tr -d ' ')"
