#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C
export AWS_PAGER=""
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
ATTESTATION_SUFFIXES=(attestation-device.pem attestation-sig.pem attestation-dec.pem)
PHASES=(ceremony provision provision-genesis rotate-kp-set rotate-cert)
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

group_by_four() {
  local value="$1" grouped=""
  while ((${#value} > 4)); do
    grouped+="${value:0:4} "
    value="${value:4}"
  done
  printf '%s' "$grouped$value"
}

# Prints the indented body of a top-level YAML block, without its key line.
yaml_block() {
  awk -v key="$1" '
    $0 == key ":" { inside = 1; next }
    inside && /^[^[:space:]#]/ { inside = 0 }
    inside { print }
  ' "$2"
}

# Prints the value of a key two spaces deep, with surrounding quotes removed.
yaml_value() {
  sed -n "s/^  $1: *//p" <<< "$2" | head -n 1 | sed -e 's/^"//' -e 's/"$//'
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
    git) printf '%s' "git" ;;
    shasum) printf '%s' "standard system utilities" ;;
  esac
}

USAGE="Usage: $0 <name> <phase> <bundle-dir>, where <phase> is one of: ${PHASES[*]}"
NAME=""
PHASE=""
BUNDLE_DIR=""
for argument in "$@"; do
  case "$argument" in
    -h | --help)
      printf '%s\n' "$USAGE" \
        "Publishes a guardian packet to s3://mysten-hashi-kp-packet-<name> for key provisioners to download." \
        "The bundle directory holds the rendered guardian-init.yaml and a certs/ directory with every" \
        "roster certificate and its attestation files. See operator/README.md."
      exit 0
      ;;
    *)
      if [[ -z "$NAME" ]]; then
        NAME="$argument"
      elif [[ -z "$PHASE" ]]; then
        PHASE="$argument"
      elif [[ -z "$BUNDLE_DIR" ]]; then
        BUNDLE_DIR="$argument"
      else
        die "Unexpected argument: $argument. $USAGE"
      fi
      ;;
  esac
done
name_pattern='^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
if [[ ! "$NAME" =~ $name_pattern ]] || ((${#NAME} > 39)); then
  die "$USAGE"
fi
phase_known=false
for known_phase in "${PHASES[@]}"; do
  if [[ "$PHASE" == "$known_phase" ]]; then
    phase_known=true
  fi
done
[[ "$phase_known" == true ]] || die "Unknown phase: ${PHASE:-none}. $USAGE"
[[ -d "$BUNDLE_DIR" ]] || die "No bundle directory at ${BUNDLE_DIR:-none}. $USAGE"
BUCKET="mysten-hashi-kp-packet-$NAME"

required_commands=(aws cargo git shasum)
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
PACKET_DIR="$WORK_DIR/packet"
mkdir -p "$PACKET_DIR/certs"

say "Guardian packet publication"
printf '%s\n' \
  "This script checks the $PHASE bundle in $BUNDLE_DIR," \
  "removes any AWS credentials from its configuration, verifies every certificate," \
  "and publishes it to s3://$BUCKET for key provisioners to download."

say "Check the bundle"
CONFIG_FILE=""
for candidate in "$BUNDLE_DIR/guardian-init.yaml" "$BUNDLE_DIR/guardian-init.yml"; do
  if [[ -f "$candidate" ]]; then
    [[ -z "$CONFIG_FILE" ]] || die "$BUNDLE_DIR holds both guardian-init.yaml and guardian-init.yml; keep one."
    CONFIG_FILE="$candidate"
  fi
done
[[ -n "$CONFIG_FILE" ]] || die "No guardian-init.yaml in $BUNDLE_DIR."

# The guardian's own access key must never reach a key provisioner: the CLI reads
# AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from the environment when the file omits them.
awk '
  /^[^[:space:]#]/ { inside_s3 = ($0 == "guardian_s3:") }
  inside_s3 && /^  access_key:/ { print "  access_key:"; next }
  inside_s3 && /^  secret_key:/ { print "  secret_key:"; next }
  /^kp_pgp_cert_path:/ { next }
  { print }
' "$CONFIG_FILE" > "$PACKET_DIR/guardian-init.yaml"

S3_BLOCK="$(yaml_block guardian_s3 "$PACKET_DIR/guardian-init.yaml")"
GUARDIAN_BUCKET="$(yaml_value bucket "$S3_BLOCK")"
[[ -n "$GUARDIAN_BUCKET" ]] || die "$CONFIG_FILE has no guardian_s3.bucket."
[[ -z "$(yaml_value access_key "$S3_BLOCK")$(yaml_value secret_key "$S3_BLOCK")" ]] \
  || die "Could not remove guardian_s3.access_key and guardian_s3.secret_key from $CONFIG_FILE."

ROSTER_BLOCK="$(yaml_block kp_roster "$PACKET_DIR/guardian-init.yaml")"
NUM_SHARES="$(yaml_value num_shares "$ROSTER_BLOCK")"
THRESHOLD="$(yaml_value threshold "$ROSTER_BLOCK")"
[[ "$NUM_SHARES" =~ ^[0-9]+$ && "$THRESHOLD" =~ ^[0-9]+$ ]] \
  || die "$CONFIG_FILE has no kp_roster.num_shares and kp_roster.threshold."
awk '
  /^  [a-z_]+:/ { collecting = ($0 == "  kp_pgp_cert_paths:") }
  collecting && /^    - / { sub(/^    - /, ""); gsub(/"/, ""); print }
' <<< "$ROSTER_BLOCK" > "$WORK_DIR/cert-paths"
if [[ "$PHASE" == rotate-kp-set ]]; then
  awk '
    /^  [a-z_]+:/ { collecting = ($0 == "  kp_pgp_cert_paths:") }
    collecting && /^    - / { sub(/^    - /, ""); gsub(/"/, ""); print }
  ' <<< "$(yaml_block new_kp_roster "$PACKET_DIR/guardian-init.yaml")" >> "$WORK_DIR/cert-paths"
  [[ "$(wc -l < "$WORK_DIR/cert-paths")" -gt "$NUM_SHARES" ]] \
    || die "$CONFIG_FILE has no new_kp_roster.kp_pgp_cert_paths, which rotate-kp-set needs."
fi
sort -u "$WORK_DIR/cert-paths" > "$WORK_DIR/certs"
roster_count="$(grep -c . < "$WORK_DIR/cert-paths" || true)"
[[ "$PHASE" == rotate-kp-set ]] || ((roster_count == NUM_SHARES)) \
  || die "$CONFIG_FILE lists $roster_count certificate paths but sets num_shares to $NUM_SHARES."

while IFS= read -r cert_path; do
  [[ "$cert_path" == certs/*.asc ]] \
    || die "Certificate path $cert_path is not relative to the bundle's certs/ directory."
  stem="${cert_path%.asc}"
  for file in "$cert_path" "${ATTESTATION_SUFFIXES[@]/#/$stem.}"; do
    [[ -f "$BUNDLE_DIR/$file" && -s "$BUNDLE_DIR/$file" ]] || die "Missing or empty file: $BUNDLE_DIR/$file"
    cp -- "$BUNDLE_DIR/$file" "$PACKET_DIR/$file"
  done
done < "$WORK_DIR/certs"
printf 'Phase:           %s\nCertificates:    %s\nSharing:         %s-of-%s\nGuardian bucket: s3://%s\n' \
  "$PHASE" "$(grep -c . < "$WORK_DIR/certs" || true)" "$THRESHOLD" "$NUM_SHARES" "$GUARDIAN_BUCKET"

if leaked="$(grep -rlE 'AKIA[A-Z0-9]{16}' "$PACKET_DIR" || true)" && [[ -n "$leaked" ]]; then
  printf '%s\n' "$leaked" >&2
  die "The packet still contains an AWS access key ID. Remove it from the bundle and publish again."
fi

# Always build with default features: non-enclave-dev also trusts software attestation devices.
say "Verify the certificates"
cd "$REPO_ROOT"
run_or_die "Could not build hashi-guardian-init." \
  cargo build --release --locked -p hashi-guardian-init
invalid=false
while IFS= read -r cert_path; do
  if ! fingerprint="$(cargo run --release --locked --quiet -p hashi-guardian-init -- \
    tools verify-kp-cert --kp-pgp-cert-path "$PACKET_DIR/$cert_path" < /dev/null 2> "$WORK_DIR/verify.err")"; then
    invalid=true
    printf '%s  INVALID\n' "${cert_path#certs/}"
    sed 's/^/    /' "$WORK_DIR/verify.err"
    continue
  fi
  printf '%s  %s\n' "${cert_path#certs/}" "$(group_by_four "$fingerprint")"
done < "$WORK_DIR/certs"
[[ "$invalid" == false ]] \
  || die "The bundle holds a certificate the guardian would reject, so nothing was published."

say "Check the AWS account"
if ! identity="$(aws sts get-caller-identity --query '[Account, Arn]' --output text)"; then
  die "Could not read the AWS identity. Log in first, for example: aws sso login --profile admin"
fi
read -r ACCOUNT ARN <<< "$identity"
printf 'AWS account:  %s\nAWS identity: %s\n' "$ACCOUNT" "$ARN"
run_or_die "No packet bucket s3://$BUCKET. Create it with: $(dirname "$0")/create-kp-packet-bucket.sh $NAME $GUARDIAN_BUCKET" \
  aws s3api head-bucket --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" > /dev/null

say "Write the manifest"
HASHI_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]; then
  die "This checkout has uncommitted changes, so key provisioners could not reproduce it at $HASHI_COMMIT."
fi
PACKET_ID="$(date -u +%Y%m%dT%H%M%SZ)"
MANIFEST="$PACKET_DIR/MANIFEST"
{
  printf 'phase %s\n' "$PHASE"
  printf 'packet_id %s\n' "$PACKET_ID"
  printf 'hashi_commit %s\n' "$HASHI_COMMIT"
  printf 'guardian_bucket %s\n' "$GUARDIAN_BUCKET"
  printf 'num_shares %s\n' "$NUM_SHARES"
  printf 'threshold %s\n' "$THRESHOLD"
} > "$MANIFEST"
(cd "$PACKET_DIR" && find . -type f ! -name MANIFEST | sed 's|^\./||' | sort \
  | while IFS= read -r file; do
    printf 'file %s %s\n' "$(shasum -a 256 "$file" | cut -d ' ' -f 1)" "$file"
  done) >> "$MANIFEST"
DIGEST="$(shasum -a 256 "$MANIFEST" | cut -c 1-16)"
printf 'Packet ID:      %s\nHashi commit:   %s\nPacket digest:  %s\n' \
  "$PACKET_ID" "$HASHI_COMMIT" "$(group_by_four "$DIGEST")"

# Upload the files first and the pointer last, so a download either sees the whole
# new packet or the whole previous one.
say "Publish the packet"
while IFS= read -r file; do
  run_or_die "Could not upload $file to s3://$BUCKET." \
    aws s3api put-object --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
    --key "packet/$PACKET_ID/$file" --body "$PACKET_DIR/$file" > /dev/null
  printf 'Published %s\n' "$file"
done < <(cd "$PACKET_DIR" && find . -type f | sed 's|^\./||' | sort)
printf '%s\n' "$PACKET_ID" > "$WORK_DIR/current"
run_or_die "Could not update the packet pointer in s3://$BUCKET. Publish again." \
  aws s3api put-object --bucket "$BUCKET" --expected-bucket-owner "$ACCOUNT" \
  --key packet/current --body "$WORK_DIR/current" > /dev/null

say "Publication complete"
printf '%s\n' \
  "Post the packet digest with the bucket and access key, so each key provisioner can compare it:" \
  "  Packet digest: $(group_by_four "$DIGEST")" \
  "Every key provisioner runs, from a hashi checkout at $HASHI_COMMIT:" \
  "  ./key-provisioner/scripts/run-guardian-step.sh"
printf '\nPacket published successfully! It is the %s step for %s key provisioners.\n' "$PHASE" "$NUM_SHARES"
