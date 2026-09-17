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

format_fingerprint() {
  local fpr="$1"
  printf '%s %s %s %s %s  %s %s %s %s %s' \
    "${fpr:0:4}" "${fpr:4:4}" "${fpr:8:4}" "${fpr:12:4}" "${fpr:16:4}" \
    "${fpr:20:4}" "${fpr:24:4}" "${fpr:28:4}" "${fpr:32:4}" "${fpr:36:4}"
}

usage="Usage: $0 <path to your <user-id>-kp-pubkey.asc>"
if (($# != 1)); then
  die "$usage"
fi
case "$1" in
  -h | --help)
    printf '%s\n' "$usage" \
      "Uploads the five public files written by provision-yubikey.sh to the guardian operator's bucket."
    exit 0
    ;;
esac

for required_command in aws gpg gpgconf; do
  command -v "$required_command" > /dev/null 2>&1 || die "$required_command is not installed or not on PATH."
done

CERT_FILE="$1"
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

say "Check the public files"
for file in "${FILES[@]}"; do
  [[ -f "$file" && -s "$file" ]] || die "Missing or empty file: $file"
done

if ! key_data="$(gpg --batch --show-keys --with-colons -- "$CERT_FILE")"; then
  die "GnuPG could not read $CERT_FILE."
fi
certificates=0
FINGERPRINT=""
while IFS=: read -r record _ _ _ _ _ _ _ _ value _; do
  case "$record" in
    pub) certificates=$((certificates + 1)) ;;
    fpr) [[ -n "$FINGERPRINT" ]] || FINGERPRINT="$value" ;;
  esac
done <<< "$key_data"
((certificates == 1)) || die "$CERT_FILE must contain exactly one certificate; found $certificates."
[[ "$FINGERPRINT" =~ ^[0-9A-F]{40}$ ]] || die "Unexpected primary-key fingerprint in $CERT_FILE: $FINGERPRINT"
recorded_fingerprint="$(head -n 1 "$FINGERPRINT_FILE")"
[[ "$recorded_fingerprint" == "$FINGERPRINT" ]] \
  || die "$FINGERPRINT_FILE ($recorded_fingerprint) does not match $CERT_FILE ($FINGERPRINT)."

# A long-running scdaemon can miss a replugged YubiKey and holds the card exclusively,
# so read the card with a fresh one and release it on exit.
trap 'gpgconf --kill scdaemon > /dev/null 2>&1 || true' EXIT
gpgconf --kill scdaemon > /dev/null 2>&1 || true
if ! card_data="$(gpg --card-status --with-colons)"; then
  die "GnuPG could not read a YubiKey. Connect only the YubiKey you provisioned, then run this script again."
fi
serial=""
card_fingerprint=""
while IFS=: read -r record value _; do
  case "$record" in
    serial) serial="$value" ;;
    fpr) card_fingerprint="$value" ;;
  esac
done <<< "$card_data"
[[ "$card_fingerprint" == "$FINGERPRINT" ]] \
  || die "The connected YubiKey (serial ${serial:-unknown}) holds signing key ${card_fingerprint:-none}, not $FINGERPRINT from $CERT_FILE. Connect the YubiKey that generated these files."

printf 'User ID:        %s\nYubiKey serial: %s\nFingerprint:    %s\n' \
  "$USER_ID" "$serial" "$(format_fingerprint "$FINGERPRINT")"

BUCKET=""
ACCESS_KEY_ID=""
SECRET_ACCESS_KEY=""

# Sets VALUE from the terminal with whitespace removed; Enter keeps the current value.
prompt_value() {
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

read_upload_values() {
  while true; do
    prompt_value "Bucket" "$BUCKET"
    if [[ "$VALUE" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]]; then
      BUCKET="$VALUE"
      break
    fi
    printf 'A bucket name has 3 to 63 lowercase letters, digits, dots, or hyphens.\n' >&2
  done
  while true; do
    prompt_value "Access key ID" "$ACCESS_KEY_ID"
    VALUE="$(printf '%s' "$VALUE" | tr '[:lower:]' '[:upper:]')"
    if [[ "$VALUE" =~ ^AKIA[A-Z0-9]{16}$ ]]; then
      ACCESS_KEY_ID="$VALUE"
      break
    fi
    printf 'An access key ID is AKIA followed by 16 letters or digits: 20 characters, and you entered %d.\n' \
      "${#VALUE}" >&2
  done
  while true; do
    prompt_value "Secret access key" "$SECRET_ACCESS_KEY"
    if [[ "$VALUE" =~ ^[A-Za-z0-9/+]{40}$ ]]; then
      SECRET_ACCESS_KEY="$VALUE"
      break
    fi
    printf 'A secret access key has 40 letters, digits, slashes, or plus signs, and you entered %d characters.\n' \
      "${#VALUE}" >&2
  done
}

# Only the typed credentials and region are used, never other AWS configuration on this Mac.
upload_file() {
  env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
    AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    AWS_ACCESS_KEY_ID="$ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$SECRET_ACCESS_KEY" \
    aws s3api put-object --region "$REGION" --bucket "$BUCKET" --key "$USER_ID/${1##*/}" --body "$1" > /dev/null
}

upload_hint() {
  case "$1" in
    *"(SignatureDoesNotMatch)"*) printf 'The secret access key is wrong.' ;;
    *"(InvalidAccessKeyId)"*) printf 'The access key ID is wrong, or the operator has revoked it.' ;;
    *"(NoSuchBucket)"*) printf 'The bucket name is wrong.' ;;
    *"(AccessDenied)"*) printf 'This access key cannot upload to that bucket. Check the bucket name.' ;;
    *"(RequestTimeTooSkewed)"*) printf "This Mac's clock is wrong. Turn on automatic date and time in System Settings." ;;
    *) printf 'Check the network connection and the values.' ;;
  esac
}

say "Enter the upload values from the guardian operator"
printf 'Spaces are optional.\n'
while true; do
  read_upload_values
  say "Upload"
  uploaded=true
  for file in "${FILES[@]}"; do
    printf 'Uploading %s\n' "${file##*/}"
    if ! error="$(upload_file "$file" 2>&1)"; then
      printf '%s\n' "$error" >&2
      warn "The upload failed. $(upload_hint "$error")"
      uploaded=false
      break
    fi
  done
  if [[ "$uploaded" == true ]]; then
    break
  fi
  say "Enter the upload values again"
  printf 'Press Enter to keep a value shown in brackets.\n'
done

say "Upload complete"
printf '%s\n' \
  "Uploaded the five public files to s3://$BUCKET/$USER_ID/." \
  "Tell the guardian operator your user ID: $USER_ID" \
  "" \
  "When the operator posts the roster, check that it has one row per key provisioner" \
  "and that the row for $USER_ID shows exactly this fingerprint:" \
  "  $(format_fingerprint "$FINGERPRINT")" \
  "" \
  "To show the fingerprint of the connected YubiKey again, run:" \
  "  $(dirname "$0")/show-fingerprint.sh"
