#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C
export AWS_PAGER=""
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true

REGION=us-west-2
IAM_PATH=/hashi-kp-packet/
GUARDIAN_READ_ACTIONS='"s3:GetObject","s3:GetObjectVersion","s3:ListBucket","s3:ListBucketVersions","s3:GetBucketObjectLockConfiguration","s3:GetObjectRetention"'
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
    rm -f -- "$SELF_TEST_FILE" "$SELF_TEST_FILE.err" "$SELF_TEST_FILE.out"
  fi
}

command_package() {
  case "$1" in
    aws) printf '%s' "AWS CLI v2" ;;
    jq) printf '%s' "jq" ;;
    mktemp | rm) printf '%s' "standard system utilities" ;;
  esac
}

USAGE="Usage: $0 <name> <guardian-bucket>"
NAME=""
GUARDIAN_BUCKET=""
for argument in "$@"; do
  case "$argument" in
    -h | --help)
      printf '%s\n' "$USAGE" \
        "Creates the bucket mysten-hashi-kp-packet-<name> and one access key that key provisioners use to" \
        "read guardian packets, write their submissions, and read the guardian's log bucket." \
        "See operator/README.md."
      exit 0
      ;;
    *)
      if [[ -z "$NAME" ]]; then
        NAME="$argument"
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
  die "$USAGE, where <name> (for example mainnet) has at most 39 lowercase letters, digits, and inner hyphens."
fi
if [[ ! "$GUARDIAN_BUCKET" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]]; then
  die "$USAGE, where <guardian-bucket> is the guardian's existing S3 log bucket."
fi
BUCKET="mysten-hashi-kp-packet-$NAME"
IAM_USER="hashi-kp-packet-$NAME-kp"
REVOKE_COMMAND="$(dirname "$0")/revoke-kp-packet-key.sh $NAME"
[[ "$GUARDIAN_BUCKET" != "$BUCKET" ]] || die "The guardian log bucket cannot be the packet bucket."

# Fail before prompting the operator or creating anything.
required_commands=(aws jq mktemp rm)
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

say "Key provisioner packet bucket setup"
printf '%s\n' \
  "This script creates, in $REGION:" \
  "  S3 bucket s3://$BUCKET, versioned, with public access blocked" \
  "  IAM user $IAM_PATH$IAM_USER, allowed only to" \
  "    read s3://$BUCKET/packet/, write s3://$BUCKET/submissions/," \
  "    and read s3://$GUARDIAN_BUCKET" \
  "  one access key for that user, tested against both buckets" \
  "Key provisioners enter the bucket and access key into key-provisioner/scripts/run-guardian-step.sh."

say "Check the AWS account"
if ! identity="$(aws sts get-caller-identity --query '[Account, Arn]' --output text)"; then
  die "Could not read the AWS identity. Log in first, for example: aws sso login --profile admin"
fi
read -r ACCOUNT ARN <<< "$identity"
printf 'AWS account:  %s\nAWS identity: %s\n' "$ACCOUNT" "$ARN"
run_or_die "No guardian log bucket s3://$GUARDIAN_BUCKET in account $ACCOUNT. Check the name against the enclave stack." \
  aws s3api head-bucket --bucket "$GUARDIAN_BUCKET" --expected-bucket-owner "$ACCOUNT" > /dev/null
printf 'Guardian log bucket: s3://%s\n' "$GUARDIAN_BUCKET"
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

say "Create the key provisioner user and access key"
run_or_die "Could not create IAM user $IAM_USER. Delete the empty bucket with: aws s3 rb s3://$BUCKET" \
  aws iam create-user --user-name "$IAM_USER" --path "$IAM_PATH" > /dev/null
run_or_die "Could not add the packet policy to $IAM_USER. Remove the user with $REVOKE_COMMAND, then delete the empty bucket with: aws s3 rb s3://$BUCKET" \
  aws iam put-user-policy --user-name "$IAM_USER" --policy-name kp-packet-access \
  --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[\
{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/packet/*\"},\
{\"Effect\":\"Allow\",\"Action\":\"s3:ListBucket\",\"Resource\":\"arn:aws:s3:::$BUCKET\"},\
{\"Effect\":\"Allow\",\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/submissions/*\"},\
{\"Effect\":\"Allow\",\"Action\":[$GUARDIAN_READ_ACTIONS],\"Resource\":[\"arn:aws:s3:::$GUARDIAN_BUCKET\",\"arn:aws:s3:::$GUARDIAN_BUCKET/*\"]}]}"
if ! access_key="$(aws iam create-access-key --user-name "$IAM_USER" \
  --query 'AccessKey.[AccessKeyId, SecretAccessKey]' --output text)"; then
  die "Could not create an access key for $IAM_USER. Remove the user with $REVOKE_COMMAND, then delete the empty bucket with: aws s3 rb s3://$BUCKET"
fi
read -r ACCESS_KEY_ID SECRET_ACCESS_KEY <<< "$access_key"
printf 'Created IAM user %s%s and its access key.\n' "$IAM_PATH" "$IAM_USER"

say "Test the access key"
printf 'Reading a test packet object, writing a test submission, and listing the guardian log bucket.\n'
printf 'This can take up to 2 minutes.\n'
SELF_TEST_FILE="$(mktemp)"
printf 'self-test\n' > "$SELF_TEST_FILE"
run_or_die "Could not write the test packet object. Remove the user with $REVOKE_COMMAND, then delete the bucket with: aws s3 rb s3://$BUCKET" \
  aws s3api put-object --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
  --key packet/self-test --body "$SELF_TEST_FILE" > /dev/null

# Run every check the key provisioners' script needs, exactly as it runs them.
kp_aws() {
  env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
    AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    AWS_ACCESS_KEY_ID="$ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$SECRET_ACCESS_KEY" \
    aws "$@"
}

self_test() {
  kp_aws s3api get-object --region "$REGION" --bucket "$BUCKET" --key packet/self-test "$SELF_TEST_FILE.out" \
    && kp_aws s3api put-object --region "$REGION" --bucket "$BUCKET" --key submissions/self-test \
      --body "$SELF_TEST_FILE" \
    && kp_aws s3api list-objects-v2 --bucket "$GUARDIAN_BUCKET" --max-items 1
}

# New IAM keys and policies take a few seconds to reach S3, so retry only those errors.
deadline=$((SECONDS + 120))
until self_test > /dev/null 2> "$SELF_TEST_FILE.err"; do
  self_test_error="$(< "$SELF_TEST_FILE.err")"
  if [[ "$self_test_error" != *"(InvalidAccessKeyId)"* && "$self_test_error" != *"(AccessDenied)"* ]] \
    || ((SECONDS >= deadline)); then
    printf '%s\n' "$self_test_error" >&2
    die "The new access key failed its test. Remove the user with $REVOKE_COMMAND, then delete the bucket with: aws s3 rb s3://$BUCKET"
  fi
  sleep 5
done

# The guardian log bucket is key custody, so prove the key cannot write to it. Simulating the
# policy answers that without sending a request that would succeed if the policy were wrong.
if ! simulation="$(aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::$ACCOUNT:user$IAM_PATH$IAM_USER" \
  --action-names s3:PutObject s3:PutObjectRetention s3:DeleteObject s3:DeleteObjectVersion \
  --resource-arns "arn:aws:s3:::$GUARDIAN_BUCKET/*" --output json)"; then
  die "Could not simulate the policy of $IAM_USER. Remove the user with $REVOKE_COMMAND, then delete the bucket with: aws s3 rb s3://$BUCKET"
fi
if allowed="$(jq -r '[.EvaluationResults[] | select(.EvalDecision == "allowed") | .EvalActionName] | join(", ")' \
  <<< "$simulation")" && [[ -n "$allowed" ]]; then
  die "The access key can write to the guardian log bucket ($allowed). Remove the user immediately with: $REVOKE_COMMAND"
fi
printf 'The access key can read packets, write submissions, and only read s3://%s.\n' "$GUARDIAN_BUCKET"

for key in packet/self-test submissions/self-test; do
  versions="$(aws s3api list-object-versions --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
    --prefix "$key" --query 'Versions[].VersionId' --output text)"
  for version_id in $versions; do
    run_or_die "Could not delete version $version_id of $key. Delete it before key provisioners download: aws s3api delete-object --bucket $BUCKET --key $key --version-id $version_id" \
      aws s3api delete-object --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
      --key "$key" --version-id "$version_id" > /dev/null
  done
done

say "Setup complete"
printf '%s\n' "Share these values in a code block over a private channel. Spaces are optional." ""
printf '  Bucket:            %s\n' "$BUCKET"
printf '  Access key ID:     %s\n' "$(group_by_four "$ACCESS_KEY_ID")"
printf '  Secret access key: %s\n' "$(group_by_four "$SECRET_ACCESS_KEY")"
printf '\nPacket bucket created successfully! Publish a packet with:\n  %s %s <bundle-dir>\n' \
  "$(dirname "$0")/publish-kp-packet.sh" "$NAME"
printf 'Once the guardian operation is over, revoke the key with:\n  %s\n' "$REVOKE_COMMAND"
