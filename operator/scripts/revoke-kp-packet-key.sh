#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C
export AWS_PAGER=""
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true

IAM_PATH=/hashi-kp-packet/

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

command_package() {
  case "$1" in
    aws) printf '%s' "AWS CLI v2" ;;
  esac
}

USAGE="Usage: $0 <name>, where <name> is the name the bucket was created with (for example mainnet)"
NAME=""
for argument in "$@"; do
  case "$argument" in
    -h | --help)
      printf '%s\n' "$USAGE" \
        "Deletes the key provisioner IAM user for s3://mysten-hashi-kp-packet-<name> and its access keys." \
        "The bucket and its files are kept."
      exit 0
      ;;
    *)
      [[ -z "$NAME" ]] || die "Unexpected argument: $argument. $USAGE"
      NAME="$argument"
      ;;
  esac
done
name_pattern='^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
if [[ ! "$NAME" =~ $name_pattern ]] || ((${#NAME} > 39)); then
  die "$USAGE"
fi
BUCKET="mysten-hashi-kp-packet-$NAME"
IAM_USER="hashi-kp-packet-$NAME-kp"

# Fail before prompting the operator or deleting anything.
required_commands=(aws)
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
  die "This script is interactive and must run in a terminal."
fi

say "Key provisioner packet key revocation"
printf '%s\n' \
  "This script deletes IAM user $IAM_PATH$IAM_USER and its access keys," \
  "so key provisioners can no longer read packets or the guardian log bucket." \
  "The bucket and its files are kept."

say "Check the AWS account"
if ! identity="$(aws sts get-caller-identity --query '[Account, Arn]' --output text)"; then
  die "Could not read the AWS identity. Log in first, for example: aws sso login --profile admin"
fi
read -r ACCOUNT ARN <<< "$identity"
printf 'AWS account:  %s\nAWS identity: %s\n' "$ACCOUNT" "$ARN"
if ! user_path="$(aws iam get-user --user-name "$IAM_USER" --query User.Path --output text 2>&1)"; then
  if [[ "$user_path" == *"(NoSuchEntity)"* ]]; then
    printf '\nIAM user %s does not exist; nothing to revoke.\n' "$IAM_USER"
    exit 0
  fi
  die "Could not read IAM user $IAM_USER: $user_path"
fi
# The fixed path marks users this tooling created; never delete anything else.
[[ "$user_path" == "$IAM_PATH" ]] \
  || die "IAM user $IAM_USER has path $user_path, not $IAM_PATH; refusing to delete it."
if ! attached_policies="$(aws iam list-attached-user-policies --user-name "$IAM_USER" \
  --query 'AttachedPolicies[].PolicyArn' --output text)"; then
  die "Could not list the policies attached to $IAM_USER."
fi
[[ -z "$attached_policies" ]] \
  || die "IAM user $IAM_USER has attached policies ($attached_policies), which this tooling never adds; refusing to delete it."
if ! IFS= read -r -p "Delete IAM user $IAM_USER in AWS account $ACCOUNT? Type y/yes to continue: " revoke_confirmation; then
  die "No input received; nothing was deleted."
fi
case "$revoke_confirmation" in
  y | yes) ;;
  *) die "Revocation not confirmed; nothing was deleted." ;;
esac

say "Delete the access key and user"
if ! access_keys="$(aws iam list-access-keys --user-name "$IAM_USER" \
  --query 'AccessKeyMetadata[].AccessKeyId' --output text)"; then
  die "Could not list the access keys of $IAM_USER."
fi
for access_key_id in $access_keys; do
  run_or_die "Could not delete access key $access_key_id." \
    aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "$access_key_id"
  printf 'Deleted access key %s\n' "$access_key_id"
done
if ! inline_policies="$(aws iam list-user-policies --user-name "$IAM_USER" --query PolicyNames --output text)"; then
  die "Could not list the inline policies of $IAM_USER."
fi
for policy_name in $inline_policies; do
  run_or_die "Could not delete inline policy $policy_name." \
    aws iam delete-user-policy --user-name "$IAM_USER" --policy-name "$policy_name"
done
run_or_die "Could not delete IAM user $IAM_USER." aws iam delete-user --user-name "$IAM_USER"
printf 'Deleted IAM user %s%s\n' "$IAM_PATH" "$IAM_USER"

say "Revocation complete"
printf 'Access key revoked successfully! The packets and submissions remain in s3://%s.\n' "$BUCKET"
