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
SELF_TEST_FILE=""

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

group_by_four() {
  local value="$1" grouped=""
  while ((${#value} > 4)); do
    grouped+="${value:0:4} "
    value="${value:4}"
  done
  printf '%s' "$grouped$value"
}

cleanup() {
  if [[ -n "$SELF_TEST_FILE" ]]; then
    rm -f -- "$SELF_TEST_FILE" "$SELF_TEST_FILE.err"
  fi
}

command_package() {
  case "$1" in
    aws) printf '%s' "AWS CLI v2" ;;
    mktemp | rm) printf '%s' "standard system utilities" ;;
  esac
}

USAGE="Usage: $0 <name>, where <name> (for example mainnet) has at most 39 lowercase letters, digits, and inner hyphens"
NAME=""
for argument in "$@"; do
  case "$argument" in
    -h | --help)
      printf '%s\n' "$USAGE" \
        "Creates the bucket mysten-hashi-kp-pubkeys-<name> and an access key that can only upload into it." \
        "See operator/README.md."
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
BUCKET="mysten-hashi-kp-pubkeys-$NAME"
IAM_USER="hashi-kp-pubkeys-$NAME-upload"
REVOKE_COMMAND="$(dirname "$0")/revoke-kp-upload-key.sh $NAME"

# Fail before prompting the operator or creating anything.
required_commands=(aws mktemp rm)
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
  die "This setup is interactive and must run in a terminal."
fi

trap cleanup EXIT

say "Key provisioner upload bucket setup"
printf '%s\n' \
  "This script creates, in $REGION:" \
  "  S3 bucket s3://$BUCKET, versioned, with public access blocked" \
  "  IAM user $IAM_PATH$IAM_USER, allowed only s3:PutObject into that bucket" \
  "  one access key for that user, tested with a real upload" \
  "Key provisioners enter the bucket and access key into key-provisioner/scripts/upload-pubkey.sh."

say "Check the AWS account"
if ! identity="$(aws sts get-caller-identity --query '[Account, Arn]' --output text)"; then
  die "Could not read the AWS identity. Log in first, for example: aws sso login --profile admin"
fi
read -r ACCOUNT ARN <<< "$identity"
printf 'AWS account:  %s\nAWS identity: %s\n' "$ACCOUNT" "$ARN"
if user_error="$(aws iam get-user --user-name "$IAM_USER" 2>&1 > /dev/null)"; then
  die "IAM user $IAM_USER already exists. Choose another name, or revoke it with: $REVOKE_COMMAND"
fi
[[ "$user_error" == *"(NoSuchEntity)"* ]] || die "Could not check IAM user $IAM_USER: $user_error"
if ! IFS= read -r -p "Create these resources in AWS account $ACCOUNT? Type y/yes to continue: " create_confirmation; then
  die "No input received; nothing was created."
fi
case "$create_confirmation" in
  y | yes) ;;
  *) die "Creation not confirmed; nothing was created." ;;
esac

say "Create the bucket"
run_or_die "Could not create s3://$BUCKET. Nothing was created." \
  aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
  --create-bucket-configuration "LocationConstraint=$REGION" > /dev/null
run_or_die "Could not block public access to s3://$BUCKET. Delete the empty bucket with: aws s3 rb s3://$BUCKET" \
  aws s3api put-public-access-block --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
run_or_die "Could not enable versioning on s3://$BUCKET. Delete the empty bucket with: aws s3 rb s3://$BUCKET" \
  aws s3api put-bucket-versioning --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
  --versioning-configuration Status=Enabled
printf 'Created s3://%s.\n' "$BUCKET"

say "Create the upload user and access key"
run_or_die "Could not create IAM user $IAM_USER. Delete the empty bucket with: aws s3 rb s3://$BUCKET" \
  aws iam create-user --user-name "$IAM_USER" --path "$IAM_PATH" > /dev/null
run_or_die "Could not add the upload policy to $IAM_USER. Remove the user with $REVOKE_COMMAND, then delete the empty bucket with: aws s3 rb s3://$BUCKET" \
  aws iam put-user-policy --user-name "$IAM_USER" --policy-name put-kp-pubkeys \
  --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/*\"}]}"
if ! access_key="$(aws iam create-access-key --user-name "$IAM_USER" \
  --query 'AccessKey.[AccessKeyId, SecretAccessKey]' --output text)"; then
  die "Could not create an access key for $IAM_USER. Remove the user with $REVOKE_COMMAND, then delete the empty bucket with: aws s3 rb s3://$BUCKET"
fi
read -r ACCESS_KEY_ID SECRET_ACCESS_KEY <<< "$access_key"
printf 'Created IAM user %s%s and its access key.\n' "$IAM_PATH" "$IAM_USER"

# New IAM keys and policies take a few seconds to reach S3, so retry only those errors.
say "Test the upload key"
printf 'Uploading a test object exactly as upload-pubkey.sh does. This can take up to 2 minutes.\n'
SELF_TEST_FILE="$(mktemp)"
printf 'self-test\n' > "$SELF_TEST_FILE"
deadline=$((SECONDS + 120))
until version_id="$(
  env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
    AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    AWS_ACCESS_KEY_ID="$ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$SECRET_ACCESS_KEY" \
    aws s3api put-object --region "$REGION" --bucket "$BUCKET" --key self-test --body "$SELF_TEST_FILE" \
    --query VersionId --output text 2> "$SELF_TEST_FILE.err"
)"; do
  self_test_error="$(< "$SELF_TEST_FILE.err")"
  if [[ "$self_test_error" != *"(InvalidAccessKeyId)"* && "$self_test_error" != *"(AccessDenied)"* ]] \
    || ((SECONDS >= deadline)); then
    printf '%s\n' "$self_test_error" >&2
    die "The new access key could not upload. Remove the user with $REVOKE_COMMAND, then delete the bucket with: aws s3 rb s3://$BUCKET"
  fi
  sleep 5
done
run_or_die "Could not delete version $version_id of the test object. Delete it before key provisioners upload: aws s3api delete-object --bucket $BUCKET --key self-test --version-id $version_id" \
  aws s3api delete-object --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
  --key self-test --version-id "$version_id" > /dev/null
printf 'The access key can upload.\n'

say "Setup complete"
printf '%s\n' "Share these values in a code block over a private channel. Spaces are optional." ""
printf '  Bucket:            %s\n' "$BUCKET"
printf '  Access key ID:     %s\n' "$(group_by_four "$ACCESS_KEY_ID")"
printf '  Secret access key: %s\n' "$(group_by_four "$SECRET_ACCESS_KEY")"
printf '\nUpload bucket created successfully! Once every key provisioner confirms the roster, revoke the key with:\n  %s\n' \
  "$REVOKE_COMMAND"
