#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C
export AWS_PAGER=""
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true
# GnuPG needs a terminal of its own to ask for the YubiKey PIN.
GPG_TTY="$(tty || true)"
export GPG_TTY

REGION=us-west-2
# The guardian writes its first heartbeat about a minute after the operator starts a session.
SESSION_WAIT_SECONDS=240
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
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

group_by_four() {
  local value="$1" grouped=""
  while ((${#value} > 4)); do
    grouped+="${value:0:4} "
    value="${value:4}"
  done
  printf '%s' "$grouped$value"
}

# Prints the primary-key fingerprint of an armored OpenPGP certificate holding exactly one key.
cert_fingerprint() {
  local certificates=0 fingerprint="" record value key_data
  key_data="$(gpg --batch --show-keys --with-colons -- "$1")" || return 1
  while IFS=: read -r record _ _ _ _ _ _ _ _ value _; do
    case "$record" in
      pub) certificates=$((certificates + 1)) ;;
      fpr) [[ -n "$fingerprint" ]] || fingerprint="$value" ;;
    esac
  done <<< "$key_data"
  ((certificates == 1)) && [[ "$fingerprint" =~ ^[0-9A-F]{40}$ ]] || return 1
  printf '%s' "$fingerprint"
}

# Runs the guardian tools with only the operator's access key, never other AWS configuration on this Mac.
guardian_init() {
  env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
    -u AWS_ENDPOINT_URL -u AWS_ENDPOINT_URL_S3 \
    AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    AWS_ACCESS_KEY_ID="$ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$SECRET_ACCESS_KEY" \
    cargo run --release --locked --quiet --manifest-path "$REPO_ROOT/Cargo.toml" \
    -p hashi-guardian-init ${BUILD_FEATURES[@]+"${BUILD_FEATURES[@]}"} -- key-provisioner "$@"
}

packet_aws() {
  local operation="$1"
  shift

  env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE -u AWS_SESSION_TOKEN -u AWS_SECURITY_TOKEN \
    AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    AWS_ACCESS_KEY_ID="$ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$SECRET_ACCESS_KEY" \
    aws s3api "$operation" --region "$REGION" --bucket "$BUCKET" "$@"
}

explain_aws_error() {
  printf '%s\n' "$1" >&2
  case "$1" in
    *"(SignatureDoesNotMatch)"*) warn "The secret access key is wrong." ;;
    *"(InvalidAccessKeyId)"*) warn "The access key ID is wrong, or the operator has revoked it." ;;
    *"(NoSuchBucket)"*) warn "The bucket name is wrong." ;;
    *"(NoSuchKey)"*) warn "The operator has not published a packet to this bucket yet." ;;
    *"(AccessDenied)"*) warn "This access key cannot read that bucket. Check the bucket name." ;;
    *"(RequestTimeTooSkewed)"*) warn "This Mac's clock is wrong. Turn on automatic date and time in System Settings." ;;
    *) warn "Check the network connection and the values." ;;
  esac
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
    shasum) printf '%s' "standard system utilities" ;;
  esac
}

USAGE="Usage: $0 [<replacement>-kp-pubkey.asc]"
NEW_CERT_FILE=""
for argument in "$@"; do
  case "$argument" in
    -h | --help)
      printf '%s\n' "$USAGE" \
        "Downloads the guardian operator's packet and runs this key provisioner's part of the step it names." \
        "The .asc argument is needed only for a certificate replacement." \
        "See key-provisioner/guardian-operations.md."
      exit 0
      ;;
    *)
      [[ -z "$NEW_CERT_FILE" ]] || die "Unexpected argument: $argument. $USAGE"
      [[ -f "$argument" ]] || die "No replacement certificate at $argument. $USAGE"
      # The step runs from the packet directory, so hold the path from here.
      NEW_CERT_FILE="$(cd "$(dirname "$argument")" && pwd -P)/$(basename "$argument")"
      ;;
  esac
done

# Fail before prompting the user.
required_commands=(aws cargo git gpg gpgconf shasum)
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
  die "This step is interactive and must run in a terminal."
fi

trap cleanup EXIT
WORK_DIR="$(mktemp -d)"

say "Guardian key provisioner step"
printf '%s\n' \
  "This script downloads the guardian operator's packet, checks it against your YubiKey," \
  "and runs your part of the guardian step the packet names." \
  "It uses only the bucket and access key the operator shares, never other AWS configuration on this Mac."

say "Enter the packet values from the guardian operator"
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

  if download_error="$(packet_aws get-object --key packet/current "$WORK_DIR/current" 2>&1 > /dev/null)"; then
    break
  fi
  explain_aws_error "$download_error"
  say "Enter the packet values again"
  printf 'Press Enter to keep a value shown in brackets.\n'
done

say "Download the packet"
PACKET_ID="$(head -n 1 "$WORK_DIR/current")"
[[ "$PACKET_ID" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "Unexpected packet ID in s3://$BUCKET/packet/current: $PACKET_ID"
PACKET_DIR="$REPO_ROOT/.hashi/guardian/$PACKET_ID"
mkdir -p "$PACKET_DIR"
run_or_die "Could not download the packet manifest from s3://$BUCKET/packet/$PACKET_ID/." \
  packet_aws get-object --key "packet/$PACKET_ID/MANIFEST" "$PACKET_DIR/MANIFEST" > /dev/null

PHASE=""
ATTESTATION=real
HASHI_COMMIT=""
GUARDIAN_BUCKET=""
NUM_SHARES=""
THRESHOLD=""
: > "$WORK_DIR/files"
while read -r field value extra; do
  case "$field" in
    phase) PHASE="$value" ;;
    attestation) ATTESTATION="$value" ;;
    hashi_commit) HASHI_COMMIT="$value" ;;
    guardian_bucket) GUARDIAN_BUCKET="$value" ;;
    num_shares) NUM_SHARES="$value" ;;
    threshold) THRESHOLD="$value" ;;
    file) printf '%s  %s\n' "$value" "$extra" >> "$WORK_DIR/files" ;;
    packet_id) [[ "$value" == "$PACKET_ID" ]] || die "The manifest names packet $value, not $PACKET_ID." ;;
  esac
done < "$PACKET_DIR/MANIFEST"
[[ -n "$PHASE" && "$HASHI_COMMIT" =~ ^[0-9a-f]{40}$ && -n "$GUARDIAN_BUCKET" ]] \
  || die "s3://$BUCKET/packet/$PACKET_ID/MANIFEST is incomplete. Ask the operator to publish the packet again."
[[ -s "$WORK_DIR/files" ]] || die "The manifest lists no files. Ask the operator to publish the packet again."

while read -r _ file; do
  [[ "$file" == certs/* || "$file" == guardian-init.yaml ]] \
    || die "The manifest lists an unexpected file: $file"
  mkdir -p "$PACKET_DIR/$(dirname "$file")"
  run_or_die "Could not download s3://$BUCKET/packet/$PACKET_ID/$file. If the operator has already revoked the access key, ask for a new one." \
    packet_aws get-object --key "packet/$PACKET_ID/$file" "$PACKET_DIR/$file" > /dev/null
done < "$WORK_DIR/files"
if ! (cd "$PACKET_DIR" && shasum -a 256 -c --status "$WORK_DIR/files"); then
  die "The packet does not match its manifest. Ask the operator to publish it again."
fi
DIGEST="$(shasum -a 256 "$PACKET_DIR/MANIFEST" | cut -c 1-16)"
printf 'Step:          %s\nAttestation:   %s\nPacket digest: %s\nFiles:         %s\n' \
  "$PHASE" "$ATTESTATION" "$(group_by_four "$DIGEST")" "$PACKET_DIR"
printf '\nCheck that the packet digest is the one the operator posted. Stop if it differs.\n'

CHECKOUT_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
if [[ "$CHECKOUT_COMMIT" != "$HASHI_COMMIT" ]]; then
  die "This checkout is at $CHECKOUT_COMMIT, but the guardian runs $HASHI_COMMIT. Update it with:
  git -C $REPO_ROOT fetch origin && git -C $REPO_ROOT checkout $HASHI_COMMIT"
fi

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

# The certificate is chosen by the connected YubiKey, so no path is ever edited by hand.
MY_CERT=""
while read -r _ file; do
  if [[ "$file" != certs/*.asc ]]; then
    continue
  fi
  if ! fingerprint="$(cert_fingerprint "$PACKET_DIR/$file")"; then
    die "GnuPG could not read $file from the packet, so this Mac cannot tell which certificate is yours."
  fi
  if [[ "$fingerprint" == "$CARD_FINGERPRINT" ]]; then
    [[ -z "$MY_CERT" ]] || die "The packet holds more than one certificate for $CARD_FINGERPRINT. Tell the operator."
    MY_CERT="$file"
  fi
done < "$WORK_DIR/files"
[[ -n "$MY_CERT" ]] \
  || die "No certificate in this packet belongs to the connected YubiKey (serial $SERIAL, signing key $CARD_FINGERPRINT). Connect your own YubiKey, or tell the operator that you are missing from the roster."
USER_ID="$(basename "$MY_CERT" .asc)"
USER_ID="${USER_ID%-kp-pubkey}"
[[ "$USER_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "Unexpected user ID in the certificate name: $MY_CERT"
printf 'YubiKey serial: %s\nUser ID:        %s\nFingerprint:    %s\n' \
  "$SERIAL" "$USER_ID" "$(format_fingerprint "$CARD_FINGERPRINT")"

CONFIG_FILE="guardian-init.kp.yaml"
{
  printf 'kp_pgp_cert_path: "%s"\n' "$MY_CERT"
  cat "$PACKET_DIR/guardian-init.yaml"
} > "$PACKET_DIR/$CONFIG_FILE"

# A guardian built with non-enclave-dev signs mock attestations, which only a
# CLI built the same way accepts. The packet says which, and says it loudly:
# nothing production ever runs this way.
say "Build the guardian tools"
BUILD_FEATURES=()
if [[ "$ATTESTATION" == mock ]]; then
  warn "This packet is for a guardian with mock attestation. That is a rehearsal, never production."
  BUILD_FEATURES=(--features non-enclave-dev)
elif [[ "$ATTESTATION" != real ]]; then
  die "The packet names an attestation kind this script does not know: $ATTESTATION"
fi
run_or_die "Could not build hashi-guardian-init." \
  cargo build --release --locked --manifest-path "$REPO_ROOT/Cargo.toml" -p hashi-guardian-init \
  ${BUILD_FEATURES[@]+"${BUILD_FEATURES[@]}"}

SHARES_FILE="kp-shares.json"
SUBMISSION_FILE="$USER_ID.rotation"
case "$PHASE" in
  ceremony)
    STEP_ARGS=(ceremony --config "$CONFIG_FILE" --encrypted-shares-path "$SHARES_FILE")
    STEP_SUMMARY="Decrypt your share of the new guardian key and confirm it to the guardian."
    ;;
  provision)
    STEP_ARGS=(provision --config "$CONFIG_FILE")
    STEP_SUMMARY="Submit your share to the standby guardian through the relay."
    ;;
  provision-genesis)
    STEP_ARGS=(provision --config "$CONFIG_FILE" --do-genesis)
    STEP_SUMMARY="Submit your share to the first guardian through the relay, authorizing its genesis committee."
    ;;
  rotate-kp-set)
    STEP_ARGS=(rotate-kp-set --config "$CONFIG_FILE" --submission-path "$SUBMISSION_FILE")
    STEP_SUMMARY="Sign the proposed new key provisioner set, then upload the signed submission to the operator."
    ;;
  rotate-cert)
    [[ -n "$NEW_CERT_FILE" ]] \
      || die "This packet replaces a certificate, so run this script with the path of your new .asc file. $USAGE"
    STEP_ARGS=(rotate-cert --config "$CONFIG_FILE" --new-kp-pgp-cert-path "$NEW_CERT_FILE")
    STEP_SUMMARY="Replace your certificate on the serving guardian, signing with the one it already knows."
    ;;
  *) die "This packet names the step $PHASE, which this script does not know. Update the repository, or tell the operator." ;;
esac

say "Confirm the step"
printf '%s\n' \
  "$STEP_SUMMARY" \
  "Sharing: $THRESHOLD-of-$NUM_SHARES    Guardian log bucket: s3://$GUARDIAN_BUCKET" \
  "Your YubiKey asks for its PIN and a touch, usually twice." \
  "" \
  "  hashi-guardian-init key-provisioner ${STEP_ARGS[*]}" \
  ""
if ! IFS= read -r -p "Run this step now? Type y/yes to continue: " step_confirmation; then
  die "No input received; the step was not run."
fi
case "$step_confirmation" in
  y | yes) ;;
  *) die "The step was not confirmed and was not run." ;;
esac

# The guardian's session is only live once it has written a heartbeat, about a minute
# after the operator starts it, so wait that refusal out instead of failing the round.
say "Run the step"
cd "$PACKET_DIR"
deadline=$((SECONDS + SESSION_WAIT_SECONDS))
while true; do
  if guardian_init "${STEP_ARGS[@]}" 2>&1 | tee "$WORK_DIR/step.log"; then
    break
  fi
  if ! grep -q "is not live in S3" "$WORK_DIR/step.log" || ((SECONDS >= deadline)); then
    die "The step did not complete. Send the operator the last lines above."
  fi
  warn "The guardian has not started its session yet. Trying again in 15 seconds."
  sleep 15
done

if [[ "$PHASE" == rotate-kp-set ]]; then
  say "Upload the submission"
  run_or_die "Could not upload $SUBMISSION_FILE. Send it to the operator another way; it holds nothing secret." \
    packet_aws put-object --key "submissions/$USER_ID/$SUBMISSION_FILE" --body "$PACKET_DIR/$SUBMISSION_FILE" > /dev/null
  printf 'Uploaded to: s3://%s/submissions/%s/%s\n' "$BUCKET" "$USER_ID" "$SUBMISSION_FILE"
fi

say "Step complete"
printf '%s\n' \
  "Tell the guardian operator that $USER_ID finished, and post the summary lines above." \
  "Files: $PACKET_DIR"
if [[ "$PHASE" == ceremony ]]; then
  printf '%s\n' \
    "Keep $SHARES_FILE. It holds every key provisioner's encrypted share and is the recovery record," \
    "not an input to any later step."
fi
printf '\nGuardian step completed successfully!\n'
