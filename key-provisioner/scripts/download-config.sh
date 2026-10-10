#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C

REGION=us-west-2
# Uploads go under a user ID, which never starts with an underscore.
CONFIG_PREFIX=_config
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
ATTESTATION_SUFFIXES=(attestation-device.pem attestation-sig.pem attestation-dec.pem)
WORK_DIR=""

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

run_or_die() {
  local failure_message="$1"
  shift

  if ! "$@"; then
    die "$failure_message"
  fi
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

# Prints one SHA-256 digest over every file under a directory. publish-kp-config.sh refuses to
# publish unless its copy of this function is the same.
config_digest() {
  local manifest digest
  manifest="$(cd "$1" && find . -type f -exec shasum -a 256 {} + | sort -k 2)" || return 1
  digest="$(printf '%s\n' "$manifest" | shasum -a 256)" || return 1
  printf '%s' "${digest:0:64}"
}

guardian_init() {
  cargo run --release --locked --quiet --manifest-path "$REPO_ROOT/Cargo.toml" -p hashi-guardian-init -- "$@"
}

cleanup() {
  gpgconf --kill scdaemon > /dev/null 2>&1 || true
  if [[ -n "$WORK_DIR" ]]; then
    rm -rf -- "$WORK_DIR"
  fi
}

command_package() {
  case "$1" in
    aws) printf '%s' "AWS CLI v2" ;;
    cargo) printf '%s' "Rust toolchain" ;;
    git) printf '%s' "git" ;;
    gpg | gpgconf) printf '%s' "GnuPG" ;;
    mktemp | shasum) printf '%s' "standard system utilities" ;;
  esac
}

USAGE="Usage: $0"
for argument in "$@"; do
  case "$argument" in
    -h | --help)
      printf '%s\n' "$USAGE" \
        "Downloads the guardian operator's configuration from the operator's bucket and prepares it" \
        "for the key provisioner whose YubiKey is connected."
      exit 0
      ;;
    *) die "Unknown argument: $argument. $USAGE" ;;
  esac
done

# Fail before prompting the user.
required_commands=(aws cargo git gpg gpgconf mktemp shasum)
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
  die "This download is interactive and must run in a terminal."
fi

trap cleanup EXIT
WORK_DIR="$(mktemp -d)"

say "Guardian configuration download"
printf '%s\n' \
  "This script downloads the configuration the guardian operator published, checks it against the" \
  "digest the operator posted, verifies every key provisioner certificate in it, and prepares it" \
  "for the connected YubiKey." \
  "It uses only the bucket and access key the operator shares, never other AWS configuration on this Mac."

# A long-running scdaemon can miss a replugged YubiKey and holds the card exclusively,
# so read the card with a fresh one; cleanup releases it on exit.
say "Check the YubiKey"
gpgconf --kill scdaemon > /dev/null 2>&1 || true
if ! card_data="$(gpg --card-status --with-colons)"; then
  die "GnuPG could not read a YubiKey. Connect only your YubiKey, then run this script again."
fi
SERIAL=""
CARD_FINGERPRINT=""
while IFS=: read -r record value _; do
  case "$record" in
    serial) SERIAL="$value" ;;
    fpr) CARD_FINGERPRINT="$value" ;;
  esac
done <<< "$card_data"
[[ "$CARD_FINGERPRINT" =~ ^[0-9A-F]{40}$ ]] \
  || die "The connected YubiKey (serial ${SERIAL:-unknown}) has no signing key."
printf 'YubiKey serial: %s\nFingerprint:    %s\n' "$SERIAL" "$(format_fingerprint "$CARD_FINGERPRINT")"

say "Enter the values from the guardian operator"
printf '%s\n' \
  "The operator shares a bucket name, an access key ID, and a secret access key." \
  "They are the values you entered to upload your public files. Spaces in the values are optional."
BUCKET=""
ACCESS_KEY_ID=""
SECRET_ACCESS_KEY=""
DOWNLOAD_DIR="$WORK_DIR/config"
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

  say "Download the configuration"
  rm -rf -- "$DOWNLOAD_DIR"
  if download_error="$(
    env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
      AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true \
      AWS_ACCESS_KEY_ID="$ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$SECRET_ACCESS_KEY" \
      aws s3 cp --recursive --only-show-errors --region "$REGION" "s3://$BUCKET/$CONFIG_PREFIX/" "$DOWNLOAD_DIR/" 2>&1
  )"; then
    break
  fi
  printf '%s\n' "$download_error" >&2
  case "$download_error" in
    *"(SignatureDoesNotMatch)"*) warn "The download failed: the secret access key is wrong." ;;
    *"(InvalidAccessKeyId)"*) warn "The download failed: the access key ID is wrong, or the operator has revoked it." ;;
    *"(NoSuchBucket)"*) warn "The download failed: the bucket name is wrong." ;;
    *"(AccessDenied)"*) warn "The download failed: the operator has not published the configuration yet, or the bucket name is wrong." ;;
    *"(RequestTimeTooSkewed)"*) warn "The download failed: this Mac's clock is wrong. Turn on automatic date and time in System Settings." ;;
    *) warn "The download failed. Check the network connection and the values." ;;
  esac

  say "Enter the values again"
  printf 'Press Enter to keep a value shown in brackets.\n'
done

PUBLISHED_CONFIG="$DOWNLOAD_DIR/guardian-init.yaml"
[[ -s "$PUBLISHED_CONFIG" ]] \
  || die "s3://$BUCKET/$CONFIG_PREFIX/ holds no configuration. Ask the operator to publish it."

# The download names the commit to build, the guardian build to trust and the certificates the key
# is shared between, so nothing in it is used before it has the digest the operator posted.
say "Enter the configuration digest"
printf 'The operator posts it with the guardian commit. Spaces in it are optional.\n'
DIGEST="$(config_digest "$DOWNLOAD_DIR")" || die "Could not read the downloaded configuration."
while true; do
  read_value "Configuration digest" ""
  VALUE="$(printf '%s' "$VALUE" | tr '[:upper:]' '[:lower:]')"
  if [[ "$VALUE" == "$DIGEST" ]]; then
    break
  fi
  if [[ "$VALUE" =~ ^[0-9a-f]{64}$ ]]; then
    printf '%s\n' \
      "The published configuration does not have that digest. Check it against the operator's post." \
      "If you entered it as posted, stop and tell the operator: the bucket holds another configuration." >&2
  else
    printf 'A configuration digest has 64 characters, each a digit or a letter from a to f, and you entered %d.\n' \
      "${#VALUE}" >&2
  fi
done
printf 'The configuration is the one the operator posted.\n'

# This script writes both keys below; a published copy would make them ambiguous.
if grep -qE '^(kp_pgp_cert_path|s3_credentials):' "$PUBLISHED_CONFIG"; then
  die "The published configuration sets kp_pgp_cert_path or s3_credentials. Ask the operator to publish it again."
fi
# The first build listed is current_build: the commit the guardian runs, which these tools must match.
HASHI_COMMIT=""
commit_pattern='^[[:space:]]*git_revision:[[:space:]]*"?([0-9a-f]{40})"?[[:space:]]*$'
while IFS= read -r line; do
  if [[ "$line" =~ $commit_pattern ]]; then
    HASHI_COMMIT="${BASH_REMATCH[1]}"
    break
  fi
done < "$PUBLISHED_CONFIG"
[[ -n "$HASHI_COMMIT" ]] \
  || die "The published configuration names no guardian commit. Ask the operator to publish it again."
printf 'Guardian commit: %s\n' "$HASHI_COMMIT"

if ! checkout_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"; then
  die "Could not read the commit of $REPO_ROOT."
fi
if [[ "$checkout_commit" != "$HASHI_COMMIT" ]]; then
  die "This checkout is at $checkout_commit, but the guardian runs $HASHI_COMMIT. Update it, then run this script again:
  git -C $REPO_ROOT fetch origin
  git -C $REPO_ROOT checkout $HASHI_COMMIT"
fi

say "Build the guardian tools"
printf 'The first build can take several minutes.\n'
run_or_die "Could not build hashi-guardian-init." \
  cargo build --release --locked --manifest-path "$REPO_ROOT/Cargo.toml" -p hashi-guardian-init

say "Verify the key provisioner certificates"
MY_CERT=""
cert_count=0
for cert in "$DOWNLOAD_DIR"/certs/*.asc; do
  [[ -f "$cert" ]] || die "The published configuration has no certificates. Tell the operator."
  cert_name="${cert##*/}"
  for suffix in "${ATTESTATION_SUFFIXES[@]}"; do
    [[ -s "${cert%.asc}.$suffix" ]] \
      || die "The published configuration is missing ${cert_name%.asc}.$suffix. Tell the operator."
  done
  if ! fingerprint="$(guardian_init tools verify-kp-cert --kp-pgp-cert-path "$cert" < /dev/null)"; then
    die "Certificate $cert_name did not verify. Tell the operator."
  fi
  [[ "$fingerprint" =~ ^[0-9A-F]{40}$ ]] || die "Unexpected fingerprint for $cert_name: $fingerprint"
  printf '%s  %s\n' "$(format_fingerprint "$fingerprint")" "${cert_name%-kp-pubkey.asc}"
  cert_count=$((cert_count + 1))
  if [[ "$fingerprint" == "$CARD_FINGERPRINT" ]]; then
    MY_CERT="$cert_name"
  fi
done
[[ -n "$MY_CERT" ]] \
  || die "None of the $cert_count certificates belongs to the connected YubiKey (serial $SERIAL). Connect your own YubiKey, or tell the operator that you are missing from the roster."

# Keep everything else in the directory: a ceremony saves its recovery record there.
CONFIG_DIR="$REPO_ROOT/.hashi/guardian-config/$BUCKET"
mkdir -p "$CONFIG_DIR"
rm -rf -- "$CONFIG_DIR/certs"
cp -R "$DOWNLOAD_DIR/certs" "$CONFIG_DIR/certs"
CONFIG_FILE="$CONFIG_DIR/guardian-init.yaml"
(
  umask 077
  rm -f -- "$CONFIG_FILE"
  {
    printf '# Written by key-provisioner/scripts/download-config.sh from s3://%s/%s/.\n' "$BUCKET" "$CONFIG_PREFIX"
    printf 'kp_pgp_cert_path: "certs/%s"\n' "$MY_CERT"
    printf 's3_credentials:\n  access_key: "%s"\n  secret_key: "%s"\n\n' "$ACCESS_KEY_ID" "$SECRET_ACCESS_KEY"
    cat "$PUBLISHED_CONFIG"
  } > "$CONFIG_FILE"
) || die "Could not write $CONFIG_FILE."

say "Download complete"
printf 'Configuration:    %s\n' "$CONFIG_FILE"
printf 'Your certificate: certs/%s\n' "$MY_CERT"
printf 'Key provisioners: %d\n' "$cert_count"
printf '%s\n' \
  "" \
  "The configuration holds the access key, so do not share it." \
  "When the operator asks for a step, run it from the configuration directory, as described in" \
  "key-provisioner/provision.md:"
printf '  cd %q\n' "$CONFIG_DIR"
printf '\nConfiguration downloaded successfully!\n'
