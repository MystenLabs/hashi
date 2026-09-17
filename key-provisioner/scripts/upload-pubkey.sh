#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C

REGION=us-west-2

say() {
  printf '\n== %s ==\n' "$1"
}

warn() {
  printf '\nWARNING: %s\n' "$1" >&2
}

die() {
  printf '\nERROR: %s\n' "$1" >&2
  exit 1
}

# Sets VALUE from the terminal with whitespace removed; pressing Enter keeps the current value.
read_value() {
  local label="$1" current="$2" input
  if [[ -n "$current" ]]; then
    label="$label [$current]"
  fi
  if ! IFS= read -e -r -p "$label: " input; then
    die "No input received. Run this script from an interactive terminal."
  fi
  VALUE="${input//[[:space:]]/}"
  VALUE="${VALUE:-$current}"
}

format_fingerprint() {
  local fingerprint="$1"
  printf '%s %s %s %s %s  %s %s %s %s %s' \
    "${fingerprint:0:4}" "${fingerprint:4:4}" "${fingerprint:8:4}" "${fingerprint:12:4}" "${fingerprint:16:4}" \
    "${fingerprint:20:4}" "${fingerprint:24:4}" "${fingerprint:28:4}" "${fingerprint:32:4}" "${fingerprint:36:4}"
}

cleanup() {
  gpgconf --kill scdaemon > /dev/null 2>&1 || true
}

command_package() {
  case "$1" in
    aws) printf '%s' "AWS CLI v2" ;;
    gpg | gpgconf) printf '%s' "GnuPG" ;;
  esac
}

USAGE="Usage: $0 <user-id>-kp-pubkey.asc"
CERT_FILE=""
for argument in "$@"; do
  case "$argument" in
    -h | --help)
      printf '%s\n' "$USAGE" \
        "Uploads the five public files written by provision-yubikey.sh to the guardian operator's bucket."
      exit 0
      ;;
    *)
      [[ -z "$CERT_FILE" ]] || die "Unexpected argument: $argument. $USAGE"
      CERT_FILE="$argument"
      ;;
  esac
done
[[ -n "$CERT_FILE" ]] || die "$USAGE"

# Fail before prompting the user.
required_commands=(aws gpg gpgconf)
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
  die "This upload is interactive and must run in a terminal."
fi

trap cleanup EXIT

say "Guardian key provisioner public key upload"
printf '%s\n' \
  "This script checks the five public files from provision-yubikey.sh against the connected YubiKey," \
  "then uploads them to the guardian operator's bucket." \
  "It uses only the bucket and access key the operator shares, never other AWS configuration on this Mac."

say "Check the public files"
cert_name="${CERT_FILE##*/}"
[[ "$cert_name" == *-kp-pubkey.asc ]] \
  || die "Expected the <user-id>-kp-pubkey.asc file written by provision-yubikey.sh, not: $CERT_FILE"
USER_ID="${cert_name%-kp-pubkey.asc}"
[[ "$USER_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "Unexpected user ID in the file name: $USER_ID"
case "$CERT_FILE" in
  */*) CERT_DIR="${CERT_FILE%/*}" ;;
  *) CERT_DIR=. ;;
esac
FINGERPRINT_FILE="$CERT_DIR/$USER_ID-kp-fingerprint.txt"
FILES=(
  "$CERT_FILE"
  "$FINGERPRINT_FILE"
  "$CERT_DIR/$USER_ID-kp-pubkey.attestation-device.pem"
  "$CERT_DIR/$USER_ID-kp-pubkey.attestation-sig.pem"
  "$CERT_DIR/$USER_ID-kp-pubkey.attestation-dec.pem"
)
for file in "${FILES[@]}"; do
  [[ -f "$file" && -s "$file" ]] || die "Missing or empty file: $file"
done

if ! public_key_data="$(gpg --batch --show-keys --with-colons -- "$CERT_FILE")"; then
  die "GnuPG could not read $CERT_FILE."
fi
certificates=0
FINGERPRINT=""
while IFS=: read -r record _ _ _ _ _ _ _ _ value _; do
  case "$record" in
    pub) certificates=$((certificates + 1)) ;;
    fpr) [[ -n "$FINGERPRINT" ]] || FINGERPRINT="$value" ;;
  esac
done <<< "$public_key_data"
((certificates == 1)) || die "$CERT_FILE must contain exactly one certificate; found $certificates."
[[ "$FINGERPRINT" =~ ^[0-9A-F]{40}$ ]] || die "Unexpected primary-key fingerprint in $CERT_FILE: $FINGERPRINT"
recorded_fingerprint="$(head -n 1 "$FINGERPRINT_FILE")"
[[ "$recorded_fingerprint" == "$FINGERPRINT" ]] \
  || die "$FINGERPRINT_FILE ($recorded_fingerprint) does not match $CERT_FILE ($FINGERPRINT)."

# A long-running scdaemon can miss a replugged YubiKey and holds the card exclusively,
# so read the card with a fresh one; cleanup releases it on exit.
gpgconf --kill scdaemon > /dev/null 2>&1 || true
if ! card_data="$(gpg --card-status --with-colons)"; then
  die "GnuPG could not read a YubiKey. Connect only the YubiKey you provisioned, then run this script again."
fi
SERIAL=""
card_fingerprint=""
while IFS=: read -r record value _; do
  case "$record" in
    serial) SERIAL="$value" ;;
    fpr) card_fingerprint="$value" ;;
  esac
done <<< "$card_data"
[[ "$card_fingerprint" == "$FINGERPRINT" ]] \
  || die "The connected YubiKey (serial ${SERIAL:-unknown}) holds signing key ${card_fingerprint:-none}, not $FINGERPRINT from $CERT_FILE. Connect the YubiKey that generated these files."

printf 'User ID:        %s\nYubiKey serial: %s\nFingerprint:    %s\n' \
  "$USER_ID" "$SERIAL" "$(format_fingerprint "$FINGERPRINT")"

say "Enter the upload values from the guardian operator"
printf '%s\n' \
  "The operator shares a bucket name, an access key ID, and a secret access key." \
  "Spaces in the values are optional."
BUCKET=""
ACCESS_KEY_ID=""
SECRET_ACCESS_KEY=""
while true; do
  while true; do
    read_value "Bucket" "$BUCKET"
    if [[ "$VALUE" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]]; then
      BUCKET="$VALUE"
      break
    fi
    printf 'A bucket name has 3 to 63 lowercase letters, digits, dots, or hyphens.\n' >&2
  done
  while true; do
    read_value "Access key ID" "$ACCESS_KEY_ID"
    VALUE="$(printf '%s' "$VALUE" | tr '[:lower:]' '[:upper:]')"
    if [[ "$VALUE" =~ ^AKIA[A-Z0-9]{16}$ ]]; then
      ACCESS_KEY_ID="$VALUE"
      break
    fi
    printf 'An access key ID is AKIA followed by 16 letters or digits: 20 characters, and you entered %d.\n' \
      "${#VALUE}" >&2
  done
  while true; do
    read_value "Secret access key" "$SECRET_ACCESS_KEY"
    if [[ "$VALUE" =~ ^[A-Za-z0-9/+]{40}$ ]]; then
      SECRET_ACCESS_KEY="$VALUE"
      break
    fi
    printf 'A secret access key has 40 letters, digits, slashes, or plus signs, and you entered %d characters.\n' \
      "${#VALUE}" >&2
  done

  say "Upload the public files"
  upload_failed=false
  for file in "${FILES[@]}"; do
    printf 'Uploading %s\n' "${file##*/}"
    if ! upload_error="$(
      env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
        AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true \
        AWS_ACCESS_KEY_ID="$ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$SECRET_ACCESS_KEY" \
        aws s3api put-object --region "$REGION" --bucket "$BUCKET" --key "$USER_ID/${file##*/}" \
        --body "$file" 2>&1 > /dev/null
    )"; then
      printf '%s\n' "$upload_error" >&2
      case "$upload_error" in
        *"(SignatureDoesNotMatch)"*) warn "The upload failed: the secret access key is wrong." ;;
        *"(InvalidAccessKeyId)"*) warn "The upload failed: the access key ID is wrong, or the operator has revoked it." ;;
        *"(NoSuchBucket)"*) warn "The upload failed: the bucket name is wrong." ;;
        *"(AccessDenied)"*) warn "The upload failed: this access key cannot upload to that bucket. Check the bucket name." ;;
        *"(RequestTimeTooSkewed)"*) warn "The upload failed: this Mac's clock is wrong. Turn on automatic date and time in System Settings." ;;
        *) warn "The upload failed. Check the network connection and the values." ;;
      esac
      upload_failed=true
      break
    fi
  done
  if [[ "$upload_failed" == false ]]; then
    break
  fi

  say "Enter the upload values again"
  printf 'Press Enter to keep a value shown in brackets.\n'
done

say "Upload complete"
printf '%s\n' \
  "Uploaded to: s3://$BUCKET/$USER_ID/" \
  "Tell the guardian operator your user ID: $USER_ID" \
  "When the operator posts the roster, check that it has one row per key provisioner" \
  "and that the row for $USER_ID shows exactly this fingerprint:" \
  "  $(format_fingerprint "$FINGERPRINT")"
printf '\nPublic files uploaded successfully! To show the YubiKey fingerprint again, run:\n  %q\n' \
  "$(dirname "$0")/show-fingerprint.sh"
