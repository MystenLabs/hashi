#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C

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

pause() {
  local message="${1:-Press Enter to continue, or Ctrl-C to stop.}"

  if ! IFS= read -r -p "$message" _; then
    die "No input received. Run this script from an interactive terminal."
  fi
  printf '\n'
}

confirm_yes() {
  local message="$1"
  local reply

  if ! IFS= read -r -p "$message [y/N] " reply; then
    die "No input received. Run this script from an interactive terminal."
  fi
  case "$reply" in
    y | Y | yes | YES | Yes) return 0 ;;
    *) die "Confirmation not received; no further changes were made." ;;
  esac
}

run_or_die() {
  local failure_message="$1"
  shift

  if ! "$@"; then
    die "$failure_message"
  fi
}

cleanup() {
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    # Stop the temporary agent before deleting its sockets and keyring.
    gpgconf --kill gpg-agent >/dev/null 2>&1 || true
    rm -rf -- "$WORK_DIR"
  fi
}

command_package() {
  case "$1" in
    oct) printf '%s' "openpgp-card-tools" ;;
    gpg | gpgconf) printf '%s' "GnuPG" ;;
    ykman) printf '%s' "YubiKey Manager CLI" ;;
    cmp | mkdir | mktemp | rm) printf '%s' "standard system utilities (coreutils)" ;;
  esac
}

# Fail before prompting the user or making any changes to the YubiKey.
required_commands=(cmp gpg gpgconf mkdir mktemp oct rm ykman)
missing_commands=()
for required_command in "${required_commands[@]}"; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
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

say "Guardian key provisioner YubiKey setup"
printf '%s\n' \
  "This script changes the OpenPGP PINs, generates new keys on one YubiKey," \
  "requires a physical touch for signing and decryption, and tests both operations."
warn "Generating keys overwrites any keys already in the OpenPGP slots. Overwritten keys cannot be recovered."
warn "Unplug every YubiKey except the new device you are setting up."
pause "After only the target YubiKey is connected, press Enter to inspect it. "

# ykman identifies physical devices; oct independently identifies OpenPGP cards.
# Requiring one result from each prevents an ambiguous hardware selection.
if ! yubikey_output="$(ykman list)"; then
  die "YubiKey Manager could not list connected YubiKeys. Check the USB connection and permissions."
fi
yubikeys=()
while IFS= read -r yubikey; do
  [[ -n "$yubikey" ]] && yubikeys+=("$yubikey")
done <<< "$yubikey_output"

if ((${#yubikeys[@]} != 1)); then
  printf '\nykman detected:\n%s\n' "${yubikey_output:-(no YubiKeys)}" >&2
  die "Expected exactly one connected YubiKey; found ${#yubikeys[@]}."
fi

if ! card_output="$(oct list --idents-only)"; then
  die "oct could not list OpenPGP cards. Check the USB connection and smart-card permissions."
fi
cards=()
while IFS= read -r card; do
  [[ -n "$card" ]] && cards+=("$card")
done <<< "$card_output"

if ((${#cards[@]} != 1)); then
  printf '\noct detected these OpenPGP card identifiers:\n%s\n' "${card_output:-(none)}" >&2
  die "Expected exactly one OpenPGP card; found ${#cards[@]}."
fi

CARD="${cards[0]}"
printf '\nConnected YubiKey: %s\nOpenPGP card identifier: %s\n' "${yubikeys[0]}" "$CARD"
pause "Confirm this is the labeled device you intend to provision, then press Enter. "

# Replace the factory PINs before creating keys. The User PIN authorizes normal
# cryptographic operations; the Admin PIN authorizes card configuration.
say "Change the OpenPGP PINs"
printf '%s\n' \
  "The factory User PIN is 123456." \
  "The factory Admin PIN is 12345678." \
  "Choose replacement PINs and store them in the key provisioner's approved secret store." \
  "oct will ask for the current and replacement PINs; input is hidden when appropriate."
run_or_die "Changing the User PIN failed. The card has not been fully provisioned." \
  oct pin --card "$CARD" set-user
run_or_die "Changing the Admin PIN failed. The card has not been fully provisioned." \
  oct pin --card "$CARD" set-admin

# Show the slots and require a human decision: populated keys may be legitimate,
# and replacing them is irreversible.
say "Confirm the key slots are empty"
run_or_die "oct could not read the OpenPGP card status." oct status --card "$CARD"
warn "The Signature, Decryption, and Authentication slots above must not contain key fingerprints."
warn "Continuing with populated slots will irreversibly overwrite their keys."
if ! IFS= read -r -p "Type EMPTY only after confirming all three slots are empty: " empty_confirmation; then
  die "No input received. Run this script from an interactive terminal."
fi
[[ "$empty_confirmation" == "EMPTY" ]] || die "The empty-slot confirmation did not match; stopping before key generation."

# Collect the certificate identity and a safe destination before key generation.
say "Choose the certificate identity and output file"
USER_ID=""
while [[ -z "$USER_ID" ]]; do
  if ! IFS= read -r -p "Key user ID (real name or assigned guardian identifier): " USER_ID; then
    die "No input received. Run this script from an interactive terminal."
  fi
  [[ -n "$USER_ID" ]] || printf 'The user ID cannot be empty.\n' >&2
done

while true; do
  if ! IFS= read -r -p "Public certificate output path [guardian-kp.asc]: " OUTPUT_FILE; then
    die "No input received. Run this script from an interactive terminal."
  fi
  OUTPUT_FILE="${OUTPUT_FILE:-guardian-kp.asc}"

  if [[ "$OUTPUT_FILE" == */ ]]; then
    printf 'Enter a file path, not a directory.\n' >&2
    continue
  fi
  if [[ -e "$OUTPUT_FILE" || -L "$OUTPUT_FILE" ]]; then
    printf 'Refusing to overwrite existing path: %s\n' "$OUTPUT_FILE" >&2
    continue
  fi

  OUTPUT_DIR="${OUTPUT_FILE%/*}"
  [[ "$OUTPUT_DIR" == "$OUTPUT_FILE" ]] && OUTPUT_DIR="."
  if [[ ! -d "$OUTPUT_DIR" || ! -w "$OUTPUT_DIR" ]]; then
    printf 'The parent directory does not exist or is not writable: %s\n' "$OUTPUT_DIR" >&2
    continue
  fi
  break
done

# oct creates all private key material on the card and exports only the public
# OpenPGP certificate to the requested file.
printf '\nThe script will now generate signing, decryption, and authentication keys on:\n  %s\n' "$CARD"
printf 'The armored public certificate will be written to:\n  %s\n' "$OUTPUT_FILE"
warn "This key generation step cannot be undone."
pause
run_or_die "Key generation failed. Inspect the card status before attempting any recovery." \
  oct admin --card "$CARD" generate --userid "$USER_ID" --output "$OUTPUT_FILE" curve25519
[[ -s "$OUTPUT_FILE" ]] || die "oct reported success but did not create a non-empty public certificate."

# Require a new touch for every signing and decryption operation, then read both
# policies back so a failed or ignored configuration cannot pass silently.
say "Require touch for signing and decryption"
printf '%s\n' \
  "YubiKey Manager will request the Admin PIN." \
  "The 'on' policy requires a fresh physical touch for every operation; it is not cached."
run_or_die "Could not enable the signing-key touch policy." \
  ykman openpgp keys set-touch sig on
run_or_die "Could not enable the decryption-key touch policy." \
  ykman openpgp keys set-touch dec on

if ! signature_key_info="$(ykman openpgp keys info sig 2>&1)"; then
  printf '%s\n' "$signature_key_info" >&2
  die "Could not read the signing-key touch policy."
fi
if ! decryption_key_info="$(ykman openpgp keys info dec 2>&1)"; then
  printf '%s\n' "$decryption_key_info" >&2
  die "Could not read the decryption-key touch policy."
fi
printf '\nSigning key:\n%s\n\nDecryption key:\n%s\n' "$signature_key_info" "$decryption_key_info"
[[ "$signature_key_info" == *"Touch policy: On"* ]] || die "The signing-key touch policy is not On."
[[ "$decryption_key_info" == *"Touch policy: On"* ]] || die "The decryption-key touch policy is not On."

# The first fpr record belongs to the primary key and identifies the certificate
# independently of its user ID or output filename.
if ! public_key_data="$(gpg --batch --show-keys --with-colons -- "$OUTPUT_FILE")"; then
  die "GnuPG could not read the generated public certificate."
fi
FINGERPRINT=""
while IFS=: read -r record _ _ _ _ _ _ _ _ value _; do
  if [[ "$record" == "fpr" ]]; then
    FINGERPRINT="$value"
    break
  fi
done <<< "$public_key_data"
[[ -n "$FINGERPRINT" ]] || die "GnuPG did not report a primary-key fingerprint."
printf '\nGuardian key fingerprint: %s\n' "$FINGERPRINT"

# Isolate testing from the user's normal GnuPG keyring and delete it on exit.
say "Test decryption"
if ! WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hashi-key-provisioner.XXXXXX")"; then
  die "Could not create a temporary directory for the key tests."
fi
export GNUPGHOME="$WORK_DIR/gnupg"
run_or_die "Could not create a temporary GnuPG home." mkdir -m 700 "$GNUPGHOME"

PLAINTEXT_FILE="$WORK_DIR/guardian-kp-test.txt"
CIPHERTEXT_FILE="$WORK_DIR/guardian-kp-test.txt.asc"
DECRYPTED_FILE="$WORK_DIR/guardian-kp-test.decrypted.txt"
SIGNATURE_FILE="$WORK_DIR/guardian-kp-test.sig.asc"
printf 'guardian key test\n' > "$PLAINTEXT_FILE"

# Import the public certificate and let GnuPG associate it with the private keys
# on the card before exercising the encryption and signing subkeys.
run_or_die "GnuPG could not import the public certificate into the temporary test keyring." \
  gpg --batch --import "$OUTPUT_FILE"
run_or_die "GnuPG could not connect the generated certificate to the YubiKey." \
  gpg --card-status
run_or_die "GnuPG could not encrypt the test file." \
  gpg --batch --yes --encrypt --armor --trust-model always --recipient "$FINGERPRINT" \
  --output "$CIPHERTEXT_FILE" "$PLAINTEXT_FILE"

# Round-trip known plaintext to prove the decryption key works and requires touch.
printf '%s\n' \
  "The next command decrypts the test file." \
  "Do not touch the YubiKey immediately: first confirm that decryption waits for a touch." \
  "When its indicator flashes, touch the YubiKey to finish the operation."
pause "Press Enter to begin the decryption test. "
run_or_die "Test decryption failed." \
  gpg --output "$DECRYPTED_FILE" --decrypt "$CIPHERTEXT_FILE"
run_or_die "The decrypted test content does not match the original." \
  cmp -s "$PLAINTEXT_FILE" "$DECRYPTED_FILE"
confirm_yes "Did decryption wait for a physical touch?"
printf 'Decryption succeeded and the plaintext matched.\n'

# Create and verify a detached signature to prove the signing key works too.
say "Test signing"
printf '%s\n' \
  "The next command creates a detached signature." \
  "Do not touch the YubiKey immediately: first confirm that signing waits for a touch." \
  "When its indicator flashes, touch the YubiKey to finish the operation."
pause "Press Enter to begin the signing test. "
run_or_die "Test signing failed." \
  gpg --armor --detach-sign --local-user "$FINGERPRINT" \
  --output "$SIGNATURE_FILE" "$PLAINTEXT_FILE"
confirm_yes "Did signing wait for a physical touch?"
run_or_die "GnuPG could not verify the test signature." \
  gpg --verify "$SIGNATURE_FILE" "$PLAINTEXT_FILE"
printf 'Signature creation and verification succeeded.\n'

say "Setup complete"
printf 'Public certificate: %s\n' "$OUTPUT_FILE"
printf 'Primary-key fingerprint: %s\n' "$FINGERPRINT"
printf '%s\n' \
  "Give only this public certificate and fingerprint to the guardian operator." \
  "Do not send either PIN or any local GnuPG data." \
  "The temporary plaintext, ciphertext, signature, and test keyring will now be deleted."
