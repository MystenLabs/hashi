#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
export LC_ALL=C
export AWS_PAGER=""

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
REGION=us-west-2
IAM_PATH=/hashi-kp-pubkeys/
KP_FILE_SUFFIXES=(
  kp-pubkey.asc
  kp-fingerprint.txt
  kp-pubkey.attestation-device.pem
  kp-pubkey.attestation-sig.pem
  kp-pubkey.attestation-dec.pem
)

WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$WORK_DIR"' EXIT

say() {
  printf '\n== %s ==\n' "$1"
}

die() {
  printf '\nERROR: %s\n' "$1" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    "Usage: $0 create <name>" \
    "       $0 download <name> [output-dir]" \
    "       $0 revoke <name>" \
    "" \
    "<name> (for example mainnet) selects the bucket mysten-hashi-kp-pubkeys-<name>" \
    "and its upload-only IAM user. See operator/README.md."
}

require_commands() {
  local command
  for command in "$@"; do
    command -v "$command" > /dev/null 2>&1 || die "$command is not installed or not on PATH."
  done
}

set_names() {
  local name_pattern='^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
  NAME="$1"
  if [[ ! "$NAME" =~ $name_pattern ]] || ((${#NAME} > 39)); then
    die "Invalid name '$NAME': use at most 39 lowercase letters, digits, and inner hyphens."
  fi
  BUCKET="mysten-hashi-kp-pubkeys-$NAME"
  IAM_USER="hashi-kp-pubkeys-$NAME-upload"
}

show_identity() {
  local identity
  identity="$(aws sts get-caller-identity --query '[Account, Arn]' --output text)" \
    || die "Could not read the AWS identity. Log in first, for example: aws sso login --profile admin"
  read -r ACCOUNT ARN <<< "$identity"
  printf 'AWS account:  %s\nAWS identity: %s\n' "$ACCOUNT" "$ARN"
}

confirm_name() {
  local answer
  if ! IFS= read -r -p "Type the name ($NAME) to continue: " answer; then
    die "No input received; nothing was changed."
  fi
  [[ "$answer" == "$NAME" ]] || die "The name did not match; nothing was changed."
}

group_by_four() {
  local value="$1" grouped=""
  while ((${#value} > 4)); do
    grouped+="${value:0:4} "
    value="${value:4}"
  done
  printf '%s' "$grouped$value"
}

format_fingerprint() {
  local fpr="$1"
  printf '%s %s %s %s %s  %s %s %s %s %s' \
    "${fpr:0:4}" "${fpr:4:4}" "${fpr:8:4}" "${fpr:12:4}" "${fpr:16:4}" \
    "${fpr:20:4}" "${fpr:24:4}" "${fpr:28:4}" "${fpr:32:4}" "${fpr:36:4}"
}

# Uploads with a KP's credentials exactly as key-provisioner/scripts/upload-pubkey.sh does,
# ignoring the operator's own AWS configuration.
upload_as_kp() {
  env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
    AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" \
    aws s3api put-object --region "$REGION" --bucket "$BUCKET" --key "$3" --body "$4" \
    --query VersionId --output text
}

create_failed() {
  printf '\nERROR: %s\n' "$1" >&2
  if [[ "$CREATED_USER" == true ]]; then
    printf 'Remove the IAM user with: %s revoke %s\n' "$0" "$NAME" >&2
  fi
  printf 'Remove the bucket, if it is empty, with: aws s3 rb s3://%s\n' "$BUCKET" >&2
  exit 1
}

cmd_create() {
  require_commands aws
  set_names "$1"
  say "Create the key provisioner upload bucket"
  show_identity

  local error
  if error="$(aws iam get-user --user-name "$IAM_USER" 2>&1 > /dev/null)"; then
    die "IAM user $IAM_USER already exists. Choose another name, or run: $0 revoke $NAME"
  fi
  [[ "$error" == *"(NoSuchEntity)"* ]] || die "Could not check IAM user $IAM_USER: $error"

  printf '%s\n' \
    "This creates, in $REGION:" \
    "  S3 bucket s3://$BUCKET, versioned, with public access blocked" \
    "  IAM user $IAM_PATH$IAM_USER, allowed only s3:PutObject into that bucket, and one access key"
  confirm_name

  CREATED_USER=false
  aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
    --create-bucket-configuration "LocationConstraint=$REGION" > /dev/null \
    || die "Could not create s3://$BUCKET. Nothing was created."
  aws s3api put-public-access-block --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
    || create_failed "Could not block public access to s3://$BUCKET."
  aws s3api put-bucket-versioning --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
    --versioning-configuration Status=Enabled \
    || create_failed "Could not enable versioning on s3://$BUCKET."

  aws iam create-user --user-name "$IAM_USER" --path "$IAM_PATH" > /dev/null \
    || create_failed "Could not create IAM user $IAM_USER."
  CREATED_USER=true
  aws iam put-user-policy --user-name "$IAM_USER" --policy-name put-kp-pubkeys \
    --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/*\"}]}" \
    || create_failed "Could not add the upload policy to $IAM_USER."
  local access_key access_key_id secret_access_key
  access_key="$(aws iam create-access-key --user-name "$IAM_USER" \
    --query 'AccessKey.[AccessKeyId, SecretAccessKey]' --output text)" \
    || create_failed "Could not create an access key for $IAM_USER."
  read -r access_key_id secret_access_key <<< "$access_key"

  # New IAM keys and policies take a few seconds to reach S3; retry only those errors.
  say "Test the upload key"
  printf 'self-test\n' > "$WORK_DIR/self-test"
  local version_id deadline=$((SECONDS + 120))
  until version_id="$(upload_as_kp "$access_key_id" "$secret_access_key" self-test "$WORK_DIR/self-test" \
    2> "$WORK_DIR/self-test.err")"; do
    error="$(< "$WORK_DIR/self-test.err")"
    if [[ "$error" != *"(InvalidAccessKeyId)"* && "$error" != *"(AccessDenied)"* ]] || ((SECONDS >= deadline)); then
      create_failed "The new access key could not upload: $error"
    fi
    sleep 5
  done
  aws s3api delete-object --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
    --key self-test --version-id "$version_id" > /dev/null \
    || create_failed "Could not delete version $version_id of the self-test object."
  printf 'The access key can upload.\n'

  say "Upload values for the key provisioners"
  printf '%s\n' "Share these in a code block over a private channel. Spaces are optional." ""
  printf '  Bucket:            %s\n' "$BUCKET"
  printf '  Access key ID:     %s\n' "$(group_by_four "$access_key_id")"
  printf '  Secret access key: %s\n' "$(group_by_four "$secret_access_key")"
  printf '\n%s\n  %s\n' "Revoke the key once every key provisioner has confirmed the roster:" "$0 revoke $NAME"
}

verify_kp_cert() {
  (cd "$REPO_ROOT" && cargo run --release --locked --quiet -p hashi-guardian-init -- \
    tools verify-kp-cert --kp-pgp-cert-path "$1" < /dev/null)
}

cmd_download() {
  require_commands aws cargo jq
  set_names "$1"
  local out_dir="${2:-$REPO_ROOT/.hashi/kp-pubkeys/$NAME-$(date -u +%Y%m%dT%H%M%SZ)}"
  if [[ "$out_dir" != /* ]]; then
    out_dir="$PWD/$out_dir"
  fi
  say "Download key provisioner uploads"
  show_identity

  # Always build with default features: non-enclave-dev also trusts software attestation devices.
  say "Build the certificate verifier"
  (cd "$REPO_ROOT" && cargo build --release --locked -p hashi-guardian-init) \
    || die "Could not build hashi-guardian-init."

  say "Check s3://$BUCKET"
  local listing
  listing="$(aws s3api list-object-versions --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" --output json)" \
    || die "Could not list s3://$BUCKET."
  jq -r '(.Versions // [])[] | [.Key, .VersionId, (.IsLatest | tostring)] | @tsv' <<< "$listing" \
    > "$WORK_DIR/versions" || die "Could not parse the listing of s3://$BUCKET."

  local key version_id is_latest id file suffix valid
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

  local width=2
  : > "$WORK_DIR/case-collisions"
  if [[ -s "$WORK_DIR/ids" ]]; then
    mkdir -p "$(dirname "$out_dir")"
    mkdir "$out_dir" || die "Could not create a new output directory at $out_dir."
    while IFS=$'\t' read -r id key version_id; do
      mkdir -p "$out_dir/$id"
      aws s3api get-object --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
        --key "$key" --version-id "$version_id" "$out_dir/$key" < /dev/null > /dev/null \
        || die "Could not download s3://$BUCKET/$key."
    done < "$WORK_DIR/latest"
    printf 'Downloaded %s files into %s\n' "$(wc -l < "$WORK_DIR/latest" | tr -d ' ')" "$out_dir"

    # Downloads land on a case-insensitive filesystem, and each ID must name one key provisioner.
    tr '[:upper:]' '[:lower:]' < "$WORK_DIR/ids" | sort | uniq -d > "$WORK_DIR/case-collisions"
    while IFS= read -r id; do
      if ((${#id} > width)); then
        width=${#id}
      fi
    done < "$WORK_DIR/ids"
  fi

  say "Verify each key provisioner"
  local missing lower_id fingerprint recorded status detail
  : > "$WORK_DIR/status"
  while IFS= read -r id; do
    missing=""
    for suffix in "${KP_FILE_SUFFIXES[@]}"; do
      if [[ ! -f "$out_dir/$id/$id-$suffix" ]]; then
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
    elif ! fingerprint="$(verify_kp_cert "$out_dir/$id/$id-kp-pubkey.asc" 2> "$WORK_DIR/$id.err")"; then
      status=INVALID
      detail="certificate verification failed:"
    elif [[ ! "$fingerprint" =~ ^[0-9A-F]{40}$ ]]; then
      status=INVALID
      detail="unexpected fingerprint: $fingerprint"
    else
      recorded="$(head -n 1 "$out_dir/$id/$id-kp-fingerprint.txt")"
      if [[ "$recorded" != "$fingerprint" ]]; then
        status=INVALID
        detail="$id-kp-fingerprint.txt ($recorded) does not match the certificate ($fingerprint)"
      else
        status=VERIFIED
        detail="$fingerprint"
      fi
    fi
    printf '%s\t%s\t%s\n' "$id" "$status" "$detail" >> "$WORK_DIR/status"
  done < "$WORK_DIR/ids"

  awk -F '\t' '$2 == "VERIFIED" { print $3 }' "$WORK_DIR/status" | sort | uniq -d > "$WORK_DIR/duplicates"
  local all_verified=true
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
    sort -u "$WORK_DIR/reuploads" | sed 's/.*/  & uploaded some files more than once; the latest upload of each file is used./'
  fi
  if [[ -s "$WORK_DIR/unexpected" ]]; then
    all_verified=false
    printf '\nUnexpected objects (inspect them, remove them with aws s3 rm, then download again):\n'
    sed "s|^|  s3://$BUCKET/|" "$WORK_DIR/unexpected"
  fi

  local id_count verified_count
  id_count="$(wc -l < "$WORK_DIR/ids" | tr -d ' ')"
  verified_count="$(wc -l < "$WORK_DIR/verified" | tr -d ' ')"
  if [[ "$all_verified" != true || "$verified_count" == 0 || "$verified_count" != "$id_count" ]]; then
    if [[ -d "$out_dir" ]]; then
      printf '\nDownloaded files: %s\n' "$out_dir"
    fi
    die "Not every upload verified, so no roster was written. Fix the problems above and download again."
  fi

  # Share IDs follow the ascending fingerprint order in which a ceremony deals these certificates.
  say "Roster"
  local index=0
  sort "$WORK_DIR/verified" > "$WORK_DIR/roster"
  while IFS=$'\t' read -r fingerprint id; do
    index=$((index + 1))
    printf '%d  %-*s  %s\n' "$index" "$width" "$id" "$(format_fingerprint "$fingerprint")"
  done < "$WORK_DIR/roster" > "$out_dir/roster.txt"
  cat "$out_dir/roster.txt"
  printf '\nKey provisioners: %d\nRoster and files: %s\n' "$index" "$out_dir"
}

cmd_revoke() {
  require_commands aws
  set_names "$1"
  say "Revoke the key provisioner upload key"
  show_identity

  local path error
  if ! path="$(aws iam get-user --user-name "$IAM_USER" --query User.Path --output text 2> "$WORK_DIR/get-user.err")"; then
    error="$(< "$WORK_DIR/get-user.err")"
    if [[ "$error" == *"(NoSuchEntity)"* ]]; then
      printf 'IAM user %s does not exist; nothing to revoke.\n' "$IAM_USER"
      return
    fi
    die "Could not read IAM user $IAM_USER: $error"
  fi
  [[ "$path" == "$IAM_PATH" ]] || die "IAM user $IAM_USER has path $path, not $IAM_PATH; refusing to delete it."

  local attached_policies access_keys inline_policies item
  attached_policies="$(aws iam list-attached-user-policies --user-name "$IAM_USER" \
    --query 'AttachedPolicies[].PolicyArn' --output text)" || die "Could not list policies attached to $IAM_USER."
  [[ -z "$attached_policies" ]] \
    || die "IAM user $IAM_USER has attached policies ($attached_policies), which this script never adds; refusing to delete it."

  printf 'This deletes IAM user %s and its access keys. s3://%s and its files are kept.\n' "$IAM_USER" "$BUCKET"
  confirm_name

  access_keys="$(aws iam list-access-keys --user-name "$IAM_USER" \
    --query 'AccessKeyMetadata[].AccessKeyId' --output text)" || die "Could not list the access keys of $IAM_USER."
  for item in $access_keys; do
    aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "$item" \
      || die "Could not delete access key $item."
  done
  inline_policies="$(aws iam list-user-policies --user-name "$IAM_USER" \
    --query 'PolicyNames' --output text)" || die "Could not list the inline policies of $IAM_USER."
  for item in $inline_policies; do
    aws iam delete-user-policy --user-name "$IAM_USER" --policy-name "$item" \
      || die "Could not delete inline policy $item."
  done
  aws iam delete-user --user-name "$IAM_USER" || die "Could not delete IAM user $IAM_USER."
  printf 'Revoked. The uploaded files remain in s3://%s.\n' "$BUCKET"
}

case "${1:-}" in
  create)
    (($# == 2)) || { usage >&2; exit 1; }
    cmd_create "$2"
    ;;
  download)
    (($# == 2 || $# == 3)) || { usage >&2; exit 1; }
    cmd_download "$2" "${3:-}"
    ;;
  revoke)
    (($# == 2)) || { usage >&2; exit 1; }
    cmd_revoke "$2"
    ;;
  -h | --help)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
