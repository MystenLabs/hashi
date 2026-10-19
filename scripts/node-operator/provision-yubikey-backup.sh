#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
export LC_ALL=C
umask 077

OUTPUT_DIR=.
FORCE_WIPE=false
WORK_DIR=
GPG_HOME=
KEYGEN_STARTED=false
COMPLETE=false
CARD=
SERIAL=

die() {
  printf '\nERROR: %s\n' "$1" >&2
  exit 1
}

run_or_die() {
  local message="$1"
  shift
  if ! "$@"; then
    die "$message"
  fi
}

cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$GPG_HOME" ]]; then
    gpgconf --homedir "$GPG_HOME" --kill all >/dev/null 2>&1 || true
    rm -rf -- "$GPG_HOME"
  fi
  if [[ -n "$WORK_DIR" ]]; then
    # Keep public recovery artifacts, but never throwaway test material.
    rm -f -- "$WORK_DIR/test.txt" "$WORK_DIR/test.asc" "$WORK_DIR/test.decrypted"
    if [[ "$KEYGEN_STARTED" == true && "$COMPLETE" != true ]]; then
      printf '\nProvisioning stopped after key generation was attempted; keys may or may not have been created.\n' >&2
      printf 'Public recovery files are retained in: %s\n' "$WORK_DIR" >&2
      printf '%s\n' \
        'Keep public.asc (even if a later step failed) and any files already published in the output directory.' \
        'Inspect the card with oct status. If no keys were created, rerun using the current PINs.' \
        'If keys were created but no data depends on them, you can restart with --force-wipe.' \
        'If data is encrypted to these keys, do not wipe or regenerate them; recover the public artifacts instead.' \
        'If public.asc is absent or incomplete, recover the existing public certificate with oct pubkey, not oct admin generate.' \
        'Recover ATT with ykman openpgp certificates export --format PEM att FILE and DEC with ykman openpgp keys attest --format PEM dec FILE.' \
        'Never import or generate an ATT key. Check oct pubkey --help for certificate recovery options.' >&2
    else
      rm -rf -- "$WORK_DIR"
    fi
  fi
  exit "$status"
}

usage() {
  printf '%s\n' \
    "Usage: $0 [--output-dir PATH] [--force-wipe] [--help]" \
    'Provision a YubiKey (firmware 5.7+) for node-operator backups; requires empty slots by default.' \
    '--force-wipe resets OpenPGP keys, data, and PINs after typed serial confirmation.' \
    'This permanently destroys existing OpenPGP keys; ATT and other applications are untouched.' \
    'Prompts for an optional User ID, confirmation, and PIN changes.' \
    'Generates curve25519 SIG/DEC keys on-card, no AUT key, and requires fresh DEC touch.' \
    'Writes four public files named yubikey-backup-<FULL ENCRYPTION SUBKEY FINGERPRINT>:' \
    '  .asc, .attestation-device.pem, .attestation-dec.pem, .fingerprints.txt' \
    'Output defaults to the current directory; existing files are never overwritten.' \
    'Dependencies: oct (openpgp-card-tools), gpg/gpgconf (GnuPG), ykman (YubiKey Manager),' \
    'jq, cat, cmp, mkdir, mktemp, rm, tty, and an interactive terminal.'
}

while (($#)); do
  case "$1" in
  --help | -h)
    usage
    exit 0
    ;;
  --output-dir)
    (($# >= 2)) || die '--output-dir requires a path.'
    [[ -n "$2" ]] || die '--output-dir requires a nonempty path.'
    OUTPUT_DIR=$2
    shift 2
    ;;
  --force-wipe)
    FORCE_WIPE=true
    shift
    ;;
  *) die "Unknown argument: $1 (use --help)." ;;
  esac
done

for command_name in oct gpg gpgconf ykman jq cat cmp mkdir mktemp rm tty; do
  command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name (see --help for dependencies)."
done
[[ -t 0 && -t 1 ]] || die 'Run this script from an interactive terminal.'
GPG_TTY=$(tty) || die 'Could not determine the interactive terminal.'
export GPG_TTY
run_or_die 'Could not create the output directory.' mkdir -p -- "$OUTPUT_DIR"
OUTPUT_DIR=$(cd -- "$OUTPUT_DIR" && pwd -P) || die 'Could not resolve the output directory.'
WORK_DIR=$(mktemp -d "$OUTPUT_DIR/.yubikey-backup.XXXXXXXX") || die 'Could not create a private working directory.'
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Use a short absolute path: macOS TMPDIR and output paths can exceed GPG's
# Unix socket path limit. Initialize before any PIN changes or key generation.
GPG_HOME=$(mktemp -d /tmp/hashi-gpg.XXXXXXXX) || die 'Could not create the isolated test keyring.'
run_or_die 'Could not launch the test GnuPG agent.' gpgconf --homedir "$GPG_HOME" --launch gpg-agent

# Both inventories must stay unambiguous. Pin ykman mutations to the serial,
# and oct mutations to the OpenPGP card identifier selected here.
inspect_devices() {
  local output line current_serial current_card expected_card count
  output=$(ykman list --serials) || die 'Could not list YubiKeys.'
  count=0
  current_serial=
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    [[ "$line" =~ ^[0-9]{1,8}$ ]] || die 'Unparseable or unsupported YubiKey serial listing.'
    current_serial=$line
    count=$((count + 1))
  done <<<"$output"
  [[ "$count" == 1 ]] || die 'Connect exactly one YubiKey.'
  output=$(oct list --idents-only) || die 'Could not list OpenPGP cards.'
  count=0
  current_card=
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    current_card=$line
    count=$((count + 1))
  done <<<"$output"
  [[ "$count" == 1 ]] || die 'Connect exactly one OpenPGP card.'
  # oct uses manufacturer:raw-serial hex. Yubico's raw serial is BCD, so
  # its eight displayed digits match the zero-padded decimal ykman serial.
  # Source: yubikit.openpgp.OpenPgpAid.serial; manufacturer 0006 is Yubico.
  printf -v expected_card '0006:%08d' "$((10#${current_serial}))"
  [[ "$current_card" == "$expected_card" ]] || die 'The OpenPGP card does not belong to the selected YubiKey. Enable OpenPGP on that device and disconnect other cards.'
  if [[ -n "$SERIAL" ]]; then
    [[ "$current_serial" == "$SERIAL" && "$current_card" == "$CARD" ]] || die 'Device identity changed. Reconnect the originally selected card; no keys will be generated.'
  else
    SERIAL=$current_serial
    CARD=$current_card
  fi
}

require_empty_slots() {
  local status slots
  status=$(oct --output-format json --output-version 0.11.0 status --card "$CARD") || die 'Could not read OpenPGP card status.'
  slots=$(jq -er '
    [.signature_key, .decryption_key, .authentication_key]
    | if all(.[]; type == "object" and has("fingerprint") and has("status")
        and (.fingerprint == null or (.fingerprint | type == "string"))
        and (.status == "not present" or .status == "generated" or .status == "imported"))
      then if all(.[]; .fingerprint == null and .status == "not present")
        then "empty" else "occupied" end
      else error("Missing or unrecognized slot fingerprints/status") end
  ' <<<"$status") || die 'Cannot prove SIG, DEC, and AUT are empty; refusing to change the card.'
  [[ "$slots" == empty ]] || die 'SIG, DEC, or AUT is populated. Use another card, or --force-wipe only if all existing OpenPGP keys can be permanently destroyed.'
}

printf '%s\n' 'Disconnect every other YubiKey and OpenPGP card before continuing.'
inspect_devices
info=$(ykman --device "$SERIAL" info) || die 'Could not read YubiKey model and firmware version.'
firmware_count=0
firmware_major=0
firmware_minor=0
device_count=0
device_type=
while IFS= read -r line; do
  if [[ "$line" == "Device type: "* ]]; then
    device_count=$((device_count + 1))
    device_type=${line#Device type: }
  fi
  if [[ "$line" =~ ^Firmware[[:space:]]version:[[:space:]]+([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})[[:space:]]*$ ]]; then
    firmware_count=$((firmware_count + 1))
    firmware_major=$((10#${BASH_REMATCH[1]}))
    firmware_minor=$((10#${BASH_REMATCH[2]}))
  fi
done <<<"$info"
[[ "$device_count" == 1 && -n "$device_type" ]] || die 'Could not unambiguously identify the YubiKey model; refusing to change the card.'
[[ "$device_type" != *FIPS* ]] || die 'YubiKey FIPS models are not supported: this script uses X25519 decryption keys. Use a non-FIPS YubiKey; no card data or PINs have been changed.'
[[ "$firmware_count" == 1 ]] || die 'Could not unambiguously parse the firmware version.'
((firmware_major > 5 || (firmware_major == 5 && firmware_minor >= 7))) || die 'YubiKey firmware 5.7 or newer is required.'
if [[ "$FORCE_WIPE" == true ]]; then
  printf '\nWARNING: Permanently erase OpenPGP keys and data on YubiKey serial %s (%s).\n' "$SERIAL" "$CARD" >&2
  printf '%s\n' \
    'Any data encrypted to these keys may become permanently unrecoverable.' \
    'User and Admin PINs will return to factory defaults. ATT and other applications are untouched.' >&2
  IFS= read -r -p "Type the device serial $SERIAL to confirm the OpenPGP wipe: " wipe_confirmation || die 'No wipe confirmation received.'
  [[ "$wipe_confirmation" == "$SERIAL" ]] || die 'Serial did not match; nothing was wiped.'
  inspect_devices
  run_or_die 'OpenPGP reset failed and may have partially changed the card. Inspect its state before retrying.' \
    ykman --device "$SERIAL" openpgp reset --force
  inspect_devices
  require_empty_slots
  printf 'OpenPGP reset complete. User PIN: 123456; Admin PIN: 12345678.\n'
else
  require_empty_slots
fi

IFS= read -r -p 'User ID (optional public label; press Enter to omit): ' USER_ID || die 'No User ID input received.'
printf '\nYubiKey serial: %s\nOpenPGP card: %s\nUser ID: %s\n' "$SERIAL" "$CARD" "$USER_ID"
printf '%s\n' \
  'This changes User/Admin PINs and irreversibly generates on-card SIG and DEC keys (no AUT).' \
  'It requires fresh touch for DEC, exports the existing factory ATT certificate, and creates a DEC attestation.' \
  'The DEC cardholder certificate is replaced; the factory ATT key/certificate are never replaced.' \
  'The User PIN authorizes decryption; the Admin PIN authorizes configuration.' \
  'Factory defaults are User PIN 123456 and Admin PIN 12345678; do not guess if already changed.' \
  'Choose replacement PINs and store them safely in your password manager or another secure offline store.' \
  'Never share the PINs or keep them with public artifacts. oct prompts directly; this script does not capture PINs.'
IFS= read -r -p 'Provision this empty device? Type yes to continue: ' confirmation || die 'No confirmation received.'
[[ "$confirmation" == yes ]] || die 'Provisioning not confirmed.'
# Recheck before any mutation, including PIN changes.
inspect_devices
require_empty_slots
run_or_die 'Changing the User PIN failed. Inspect PIN state before retrying.' oct pin --card "$CARD" set-user
run_or_die 'Changing the Admin PIN failed. The User PIN may already have changed.' oct pin --card "$CARD" set-admin

# No user prompts or other provisioning steps intervene between this check and generation.
inspect_devices
require_empty_slots
KEYGEN_STARTED=true
run_or_die 'Key generation did not complete; inspect the card and follow the recovery guidance below.' \
  oct admin --card "$CARD" generate --userid "$USER_ID" --output "$WORK_DIR/public.asc" --no-aut curve25519
[[ -s "$WORK_DIR/public.asc" ]] || die 'Key generation produced no public certificate.'

# Use the isolated keyring so decryption cannot use a local private key.
key_data=$(gpg --homedir "$GPG_HOME" --batch --with-colons --show-keys -- "$WORK_DIR/public.asc") || die 'Could not parse the public certificate.'
primary_fingerprint=
encryption_fingerprint=
primary_count=0
encryption_count=0
pending=
while IFS=: read -r -a fields; do
  case "${fields[0]:-}" in
  pub)
    primary_count=$((primary_count + 1))
    pending=primary
    ;;
  sub)
    pending=
    if [[ "${fields[11]:-}" == *e* ]]; then
      encryption_count=$((encryption_count + 1))
      pending=encryption
    fi
    ;;
  fpr)
    fingerprint=${fields[9]:-}
    if [[ -n "$pending" ]]; then
      [[ "$fingerprint" =~ ^([0-9A-F]{40}|[0-9A-F]{64})$ ]] || die 'Invalid full key fingerprint in public certificate.'
      case "$pending" in
      primary) primary_fingerprint=$fingerprint ;;
      encryption) encryption_fingerprint=$fingerprint ;;
      esac
      pending=
    fi
    ;;
  esac
done <<<"$key_data"
[[ "$primary_count" == 1 && -n "$primary_fingerprint" && "$encryption_count" == 1 && -n "$encryption_fingerprint" ]] || die 'Expected one primary key and exactly one encryption subkey with full fingerprints.'
BASE="$OUTPUT_DIR/yubikey-backup-$encryption_fingerprint"
for suffix in asc attestation-device.pem attestation-dec.pem fingerprints.txt; do
  [[ ! -e "$BASE.$suffix" && ! -L "$BASE.$suffix" ]] || die "Refusing to overwrite existing output: $BASE.$suffix"
done

inspect_devices
run_or_die 'Could not enable fresh DEC touch.' ykman --device "$SERIAL" openpgp keys set-touch --force dec on
touch_info=$(ykman --device "$SERIAL" openpgp keys info dec) || die 'Could not read DEC touch policy.'
touch_on=false
while IFS= read -r line; do
  [[ "$line" =~ ^Touch[[:space:]]policy:[[:space:]]+On[[:space:]]*$ ]] && touch_on=true
done <<<"$touch_info"
[[ "$touch_on" == true ]] || die 'DEC touch policy is not On (fresh touch required).'
run_or_die 'Could not export the factory ATT certificate.' \
  ykman --device "$SERIAL" openpgp certificates export --format PEM att "$WORK_DIR/attestation-device.pem"
[[ -s "$WORK_DIR/attestation-device.pem" ]] || die 'Factory ATT certificate is empty.'
run_or_die 'Could not create the DEC attestation.' \
  ykman --device "$SERIAL" openpgp keys attest --format PEM dec "$WORK_DIR/attestation-dec.pem"
[[ -s "$WORK_DIR/attestation-dec.pem" ]] || die 'DEC attestation is empty.'
run_or_die 'Could not export the labeled fingerprint listing.' \
  gpg --homedir "$GPG_HOME" --batch --show-keys --with-subkey-fingerprint \
  -- "$WORK_DIR/public.asc" >"$WORK_DIR/fingerprints.txt"

# Noclobber redirection refuses existing files, symlinks, and directories, even
# if a collision appears after preflight. Keep the workspace source on failure.
publish() {
  (
    set -o noclobber
    cat -- "$1" >"$2"
  )
}
run_or_die 'Could not publish public certificate without overwriting a path.' publish "$WORK_DIR/public.asc" "$BASE.asc"
for suffix in attestation-device.pem attestation-dec.pem fingerprints.txt; do
  run_or_die "Could not publish $suffix without overwriting a path." publish "$WORK_DIR/$suffix" "$BASE.$suffix"
done

run_or_die 'Could not import the public certificate for testing.' \
  gpg --homedir "$GPG_HOME" --batch --import "$WORK_DIR/public.asc"
run_or_die 'Could not associate the public certificate with the card.' \
  gpg --homedir "$GPG_HOME" --card-status
printf 'YubiKey backup decryption test: %s\n' "$encryption_fingerprint" >"$WORK_DIR/test.txt"
run_or_die 'Could not encrypt to the exact encryption subkey.' \
  gpg --homedir "$GPG_HOME" --batch --trust-model always --armor --encrypt \
  --recipient "$encryption_fingerprint!" --output "$WORK_DIR/test.asc" "$WORK_DIR/test.txt"
printf '%s\n' 'Enter the User PIN when prompted. Confirm decryption waits for touch, then touch the YubiKey.'
run_or_die 'Card-backed test decryption failed.' \
  gpg --homedir "$GPG_HOME" --output "$WORK_DIR/test.decrypted" --decrypt "$WORK_DIR/test.asc"
run_or_die 'Decrypted plaintext did not match.' cmp -s "$WORK_DIR/test.txt" "$WORK_DIR/test.decrypted"
COMPLETE=true
printf '\nDecryption round-trip succeeded. Public artifacts:\n'
for suffix in asc attestation-device.pem attestation-dec.pem fingerprints.txt; do
  printf '  %s.%s\n' "$BASE" "$suffix"
done
printf '%s\n' \
  'Attestations were collected, NOT cryptographically verified; assemble-cert performs that verification.' \
  'Keep these four public files together. Private keys remain on the YubiKey; store the device and PINs safely.' \
  'Throwaway test files and the isolated test keyring are removed on exit.'
