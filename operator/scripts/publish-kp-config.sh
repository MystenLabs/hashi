#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C
export AWS_PAGER=""
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true

REGION=us-west-2
IAM_PATH=/hashi-kp-pubkeys/
# Uploads go under a user ID, which never starts with an underscore.
CONFIG_PREFIX=_config
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
ATTESTATION_SUFFIXES=(attestation-device.pem attestation-sig.pem attestation-dec.pem)
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

group_by_four() {
  local value="$1" grouped=""
  while ((${#value} > 4)); do
    grouped+="${value:0:4} "
    value="${value:4}"
  done
  printf '%s' "$grouped$value"
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
    mktemp | shasum) printf '%s' "standard system utilities" ;;
  esac
}

USAGE="Usage: $0 <name> <config-dir> <guardian-bucket>"
NAME=""
CONFIG_DIR=""
GUARDIAN_BUCKET=""
for argument in "$@"; do
  case "$argument" in
    -h | --help)
      printf '%s\n' "$USAGE" \
        "Publishes <config-dir>/guardian-init.yaml and its certs/ directory to s3://mysten-hashi-kp-pubkeys-<name>/$CONFIG_PREFIX/," \
        "and lets the key provisioners' access key read it and the guardian's log bucket." \
        "See operator/README.md."
      exit 0
      ;;
    *)
      if [[ -z "$NAME" ]]; then
        NAME="$argument"
      elif [[ -z "$CONFIG_DIR" ]]; then
        CONFIG_DIR="$argument"
      elif [[ -z "$GUARDIAN_BUCKET" ]]; then
        GUARDIAN_BUCKET="$argument"
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
bucket_pattern='^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'
[[ "$GUARDIAN_BUCKET" =~ $bucket_pattern ]] || die "$USAGE"
[[ -d "$CONFIG_DIR" ]] || die "No configuration directory at $CONFIG_DIR. $USAGE"
if [[ "$CONFIG_DIR" != /* ]]; then
  CONFIG_DIR="$PWD/$CONFIG_DIR"
fi
BUCKET="mysten-hashi-kp-pubkeys-$NAME"
IAM_USER="hashi-kp-pubkeys-$NAME-upload"
CONFIG_FILE="$CONFIG_DIR/guardian-init.yaml"

required_commands=(aws cargo mktemp shasum)
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

if [[ ! -t 0 || ! -t 1 ]]; then
  die "This publication is interactive and must run in a terminal."
fi

trap cleanup EXIT
WORK_DIR="$(mktemp -d)"
cd "$REPO_ROOT"

say "Key provisioner configuration publication"
printf '%s\n' \
  "This script publishes $CONFIG_FILE and its certificates to s3://$BUCKET/$CONFIG_PREFIX/," \
  "and lets the key provisioners' access key read them and s3://$GUARDIAN_BUCKET." \
  "Key provisioners fetch them with key-provisioner/scripts/download-config.sh."

say "Check the configuration"
[[ -s "$CONFIG_FILE" ]] || die "Missing or empty file: $CONFIG_FILE"
# Each key provisioner's copy gets its own certificate path and the shared access key.
if grep -qE '^(kp_pgp_cert_path|s3_credentials):' "$CONFIG_FILE"; then
  die "$CONFIG_FILE sets kp_pgp_cert_path or s3_credentials. Publish a copy without them."
fi
grep -qF -- "$GUARDIAN_BUCKET" "$CONFIG_FILE" \
  || die "$CONFIG_FILE does not name the guardian bucket $GUARDIAN_BUCKET."
HASHI_COMMIT=""
commit_pattern='^[[:space:]]*git_revision:[[:space:]]*"?([0-9a-f]{40})"?[[:space:]]*$'
while IFS= read -r line; do
  if [[ "$line" =~ $commit_pattern ]]; then
    HASHI_COMMIT="${BASH_REMATCH[1]}"
    break
  fi
done < "$CONFIG_FILE"
[[ -n "$HASHI_COMMIT" ]] \
  || die "$CONFIG_FILE must list current_build before prev_builds, with a full commit as its git_revision."

# Always build with default features: non-enclave-dev also trusts software attestation devices.
say "Verify the key provisioner certificates"
run_or_die "Could not build hashi-guardian-init." \
  cargo build --release --locked -p hashi-guardian-init
PUBLISH_DIR="$WORK_DIR/$CONFIG_PREFIX"
mkdir -p "$PUBLISH_DIR/certs"
cp -- "$CONFIG_FILE" "$PUBLISH_DIR/guardian-init.yaml"
cert_count=0
for cert in "$CONFIG_DIR"/certs/*.asc; do
  [[ -f "$cert" ]] || die "No certificates in $CONFIG_DIR/certs."
  cert_name="${cert##*/}"
  grep -qF -- "certs/$cert_name" "$CONFIG_FILE" \
    || die "$CONFIG_FILE does not list certs/$cert_name. Remove the file, or list it."
  if ! fingerprint="$(cargo run --release --locked --quiet -p hashi-guardian-init -- \
    tools verify-kp-cert --kp-pgp-cert-path "$cert" < /dev/null)"; then
    die "Certificate $cert did not verify, so nothing was published."
  fi
  cp -- "$cert" "${ATTESTATION_SUFFIXES[@]/#/${cert%.asc}.}" "$PUBLISH_DIR/certs/"
  printf '%s  %s\n' "$(format_fingerprint "$fingerprint")" "${cert_name%-kp-pubkey.asc}"
  cert_count=$((cert_count + 1))
done
while IFS= read -r listed_cert; do
  [[ -f "$PUBLISH_DIR/$listed_cert" ]] \
    || die "$CONFIG_FILE lists $listed_cert, which is not in $CONFIG_DIR. Add the file, or stop listing it."
done < <(grep -oE 'certs/[A-Za-z0-9._-]+\.asc' "$CONFIG_FILE")
leak_status=0
leaked="$(grep -rlE 'AKIA[A-Z0-9]{16}' "$PUBLISH_DIR")" || leak_status=$?
((leak_status == 1)) \
  || die "Found an AWS access key ID, or could not check for one, so nothing was published: $leaked"
DIGEST="$(shasum -a 256 "$PUBLISH_DIR/guardian-init.yaml")"
DIGEST="${DIGEST:0:16}"
printf '\nGuardian commit:      %s\nKey provisioners:     %d\nConfiguration digest: %s\n' \
  "$HASHI_COMMIT" "$cert_count" "$(group_by_four "$DIGEST")"

say "Check the AWS account"
if ! identity="$(aws sts get-caller-identity --query '[Account, Arn]' --output text)"; then
  die "Could not read the AWS identity. Log in first, for example: aws sso login --profile admin"
fi
read -r ACCOUNT ARN <<< "$identity"
printf 'AWS account:  %s\nAWS identity: %s\n' "$ACCOUNT" "$ARN"
run_or_die "No bucket s3://$BUCKET in account $ACCOUNT. Create it with: $(dirname "$0")/create-kp-upload-bucket.sh $NAME" \
  aws s3api head-bucket --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" > /dev/null
run_or_die "No guardian log bucket s3://$GUARDIAN_BUCKET in account $ACCOUNT." \
  aws s3api head-bucket --bucket "$GUARDIAN_BUCKET" --expected-bucket-owner "$ACCOUNT" > /dev/null
if ! user_path="$(aws iam get-user --user-name "$IAM_USER" --query User.Path --output text 2>&1)"; then
  die "Could not read IAM user $IAM_USER: $user_path"
fi
[[ "$user_path" == "$IAM_PATH" ]] || die "IAM user $IAM_USER has path $user_path, not $IAM_PATH."
if ! IFS= read -r -p "Publish this configuration to s3://$BUCKET/$CONFIG_PREFIX/? Type y/yes to continue: " publish_confirmation; then
  die "No input received; nothing was published."
fi
case "$publish_confirmation" in
  y | yes) ;;
  *) die "Publication not confirmed; nothing was published." ;;
esac

# The access key may write anywhere else in the bucket, so deny it this prefix before filling it:
# the configuration tells every key provisioner which guardian build to trust.
say "Let the access key read the configuration"
run_or_die "Could not add the read policy to $IAM_USER. Nothing was published." \
  aws iam put-user-policy --user-name "$IAM_USER" --policy-name read-guardian-config \
  --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[\
{\"Effect\":\"Deny\",\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/$CONFIG_PREFIX/*\"},\
{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/$CONFIG_PREFIX/*\"},\
{\"Effect\":\"Allow\",\"Action\":\"s3:ListBucket\",\"Resource\":\"arn:aws:s3:::$BUCKET\",\
\"Condition\":{\"StringLike\":{\"s3:prefix\":\"$CONFIG_PREFIX/*\"}}},\
{\"Effect\":\"Allow\",\"Action\":[\"s3:GetBucketObjectLockConfiguration\",\"s3:GetObject\",\"s3:GetObjectRetention\",\
\"s3:ListBucket\",\"s3:ListBucketVersions\"],\
\"Resource\":[\"arn:aws:s3:::$GUARDIAN_BUCKET\",\"arn:aws:s3:::$GUARDIAN_BUCKET/*\"]}]}"
printf 'IAM user %s can read s3://%s/%s/ and s3://%s.\n' "$IAM_USER" "$BUCKET" "$CONFIG_PREFIX" "$GUARDIAN_BUCKET"

say "Publish the configuration"
run_or_die "Could not clear s3://$BUCKET/$CONFIG_PREFIX/. Publish again." \
  aws s3 rm --recursive --only-show-errors --region "$REGION" "s3://$BUCKET/$CONFIG_PREFIX/"
run_or_die "Could not upload the configuration to s3://$BUCKET/$CONFIG_PREFIX/. Publish again." \
  aws s3 cp --recursive --only-show-errors --region "$REGION" "$PUBLISH_DIR/" "s3://$BUCKET/$CONFIG_PREFIX/"
printf 'Published guardian-init.yaml and %d certificates.\n' "$cert_count"

say "Publication complete"
printf '%s\n' \
  "Post the commit and the digest, so each key provisioner can compare them:" \
  "  Guardian commit:      $HASHI_COMMIT" \
  "  Configuration digest: $(group_by_four "$DIGEST")" \
  "Every key provisioner runs, from a hashi checkout at that commit:" \
  "  ./key-provisioner/scripts/download-config.sh"
printf '\nConfiguration published successfully! It lists %d key provisioners.\n' "$cert_count"
