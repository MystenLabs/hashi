#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C

TEST_FILES_STARTED=false

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

run_or_die() {
  local failure_message="$1"
  shift

  if ! "$@"; then
    die "$failure_message"
  fi
}

cleanup() {
  if [[ "$TEST_FILES_STARTED" == true ]]; then
    rm -f -- "$PLAINTEXT_FILE" "$CIPHERTEXT_FILE" "$DECRYPTED_FILE" "$SIGNATURE_FILE"
  fi
}

command_package() {
  case "$1" in
    oct) printf '%s' "openpgp-card-tools" ;;
    gpg | gpgconf) printf '%s' "GnuPG" ;;
    ykman) printf '%s' "YubiKey Manager CLI" ;;
    cmp | mkdir | rm) printf '%s' "standard system utilities (coreutils)" ;;
  esac
}

# Fail before prompting the user or making any changes to the YubiKey.
required_commands=(cmp gpg gpgconf mkdir oct rm ykman)
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

# Use the normal GnuPG home (or the caller's GNUPGHOME) and keep it after exit.
# Check agent startup before making any changes to the YubiKey.
run_or_die "Could not create the GnuPG home." mkdir -p -m 700 "${GNUPGHOME:-$HOME/.gnupg}"
run_or_die "GnuPG could not start the agent. No YubiKey changes were made." \
  gpgconf --launch gpg-agent

say "Guardian key provisioner YubiKey setup"
printf '%s\n' \
  "This script changes the OpenPGP PINs, generates new keys on one YubiKey," \
  "exports public attestation artifacts, requires a physical touch for signing and decryption," \
  "and tests both operations." \
  "Supported provisioning requires YubiKey firmware 5.7 or later and the original" \
  "factory Yubico OpenPGP ATT private key and certificate. Never import or replace ATT."
warn "Generating keys overwrites any keys already in the OpenPGP slots. Overwritten keys cannot be recovered."
warn "Creating attestations overwrites the SIG and DEC cardholder certificate slots, not their private keys."
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
printf '%s\n' "Before continuing, confirm firmware 5.7+ and that the factory Yubico ATT key and certificate are intact."
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

# Use structured status and fail closed if any slot's fingerprint is unreadable.
say "Check the key slots"
if ! slot_status="$(oct --output-format json --output-version 0.11.0 status --card "$CARD")"; then
  die "oct could not read the OpenPGP card status."
fi
if ! occupied_slots="$(jq -er '
  [.signature_key, .decryption_key, .authentication_key]
  | if all(.[];
      type == "object" and has("fingerprint")
      and (.fingerprint == null or (.fingerprint | type == "string")))
    then map(.fingerprint != null) | if any then "occupied" else "empty" end
    else error("Missing or invalid key-slot fingerprints")
    end
' <<< "$slot_status")"; then
  die "Could not determine whether all three key slots are empty; stopping before key generation."
fi
case "$occupied_slots" in
  empty)
    printf 'All three key slots are empty; continuing automatically.\n'
    ;;
  occupied)
    run_or_die "oct could not display the existing keys." oct status --card "$CARD"
    printf '\n%s\n' \
      '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!' \
      '!!! DANGER: THIS YUBIKEY ALREADY CONTAINS PRIVATE KEYS !!!' \
      '!!! CONTINUING WILL PERMANENTLY OVERWRITE THE EXISTING KEYS. !!!' \
      '!!! THEY CANNOT BE RECOVERED. DATA ENCRYPTED TO THEM MAY BE LOST. !!!' \
      '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!' >&2
    if ! IFS= read -r -p "Are you sure you want to overwrite existing keys? Type y/yes to continue: " overwrite_confirmation; then
      die "No input received; stopping before key generation."
    fi
    case "$overwrite_confirmation" in
      y | yes) ;;
      *) die "Overwrite not confirmed; stopping before key generation." ;;
    esac
    ;;
  *) die "Unexpected key-slot status; stopping before key generation." ;;
esac

# The user ID labels output filenames only; it never becomes certificate identity.
say "Choose a filename identifier and output directory"
while true; do
  if ! IFS= read -r -p "User ID (used for outputted file names): " USER_ID; then
    die "No input received. Run this script from an interactive terminal."
  fi
  [[ "$USER_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] && break
  printf 'Use an ASCII letter or digit first, followed only by ASCII letters, digits, dots, underscores, or hyphens.\n' >&2
done

while true; do
  if ! IFS= read -r -p "Output directory [.]: " OUTPUT_DIR; then
    die "No input received. Run this script from an interactive terminal."
  fi
  OUTPUT_DIR="${OUTPUT_DIR:-.}"
  if [[ ! -d "$OUTPUT_DIR" || ! -w "$OUTPUT_DIR" ]]; then
    printf 'The output directory does not exist or is not writable: %s\n' "$OUTPUT_DIR" >&2
    continue
  fi
  if ! OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd -P)"; then
    printf 'Could not resolve the output directory.\n' >&2
    continue
  fi

  OUTPUT_FILE="${OUTPUT_DIR%/}/$USER_ID-kp-pubkey.asc"
  FINGERPRINT_FILE="${OUTPUT_DIR%/}/$USER_ID-kp-fingerprint.txt"
  ATTESTATION_DEVICE_FILE="${OUTPUT_FILE%.asc}.attestation-device.pem"
  ATTESTATION_SIG_FILE="${OUTPUT_FILE%.asc}.attestation-sig.pem"
  ATTESTATION_DEC_FILE="${OUTPUT_FILE%.asc}.attestation-dec.pem"
  PLAINTEXT_FILE="${OUTPUT_DIR%/}/$USER_ID-kp-test.txt"
  CIPHERTEXT_FILE="${OUTPUT_DIR%/}/$USER_ID-kp-test.txt.asc"
  DECRYPTED_FILE="${OUTPUT_DIR%/}/$USER_ID-kp-test.decrypted.txt"
  SIGNATURE_FILE="${OUTPUT_DIR%/}/$USER_ID-kp-test.sig.asc"
  output_paths=(
    "$OUTPUT_FILE" "$FINGERPRINT_FILE"
    "$ATTESTATION_DEVICE_FILE" "$ATTESTATION_SIG_FILE" "$ATTESTATION_DEC_FILE"
    "$PLAINTEXT_FILE" "$CIPHERTEXT_FILE" "$DECRYPTED_FILE" "$SIGNATURE_FILE"
  )
  output_collision=false
  for output_path in "${output_paths[@]}"; do
    if [[ -e "$output_path" || -L "$output_path" ]]; then
      printf 'Refusing to overwrite existing path: %s\n' "$output_path" >&2
      output_collision=true
    fi
  done
  [[ "$output_collision" == false ]] || continue
  break
done

# oct creates all private key material on the card and exports only the public
# OpenPGP certificate to the requested file. oct requires a --userid field;
# an empty value supports GPG import without adding a named certificate identity.
printf '\nThe script will now generate signing, decryption, and authentication keys on:\n  %s\n' "$CARD"
printf 'The armored public certificate will be written to:\n  %s\n' "$OUTPUT_FILE"
printf 'The PEM attestation artifacts will be written to:\n  %s\n  %s\n  %s\n' \
  "$ATTESTATION_DEVICE_FILE" "$ATTESTATION_SIG_FILE" "$ATTESTATION_DEC_FILE"
warn "This key generation step cannot be undone."
pause
printf 'Tap your YubiKey whenever its indicator flashes during key generation and certificate signing.\n'
run_or_die "Key generation failed. Inspect the card status before attempting any recovery." \
  oct admin --card "$CARD" generate --userid '' --output "$OUTPUT_FILE" curve25519
[[ -s "$OUTPUT_FILE" ]] || die "oct reported success but did not create a non-empty public certificate. Inspect the card; do not rerun key generation to recover missing public artifacts."

# Require a new touch for every signing and decryption operation, then read both
# policies back so a failed or ignored configuration cannot pass silently.
say "Require touch for signing and decryption"
printf '%s\n' \
  "YubiKey Manager will request the Admin PIN." \
  "The 'on' policy requires a fresh physical touch for every operation; it is not cached."
run_or_die "Could not enable the signing-key touch policy." \
  ykman openpgp keys set-touch --force sig on
run_or_die "Could not enable the decryption-key touch policy." \
  ykman openpgp keys set-touch --force dec on

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

# Keep the factory ATT identity intact: export its certificate, then attest only
# the on-card signing and decryption keys. All three outputs are public PEM.
# Capture attestations only after configuring and checking the intended touch policies.
say "Export device certificate and create signing and decryption attestations"
printf '%s\n' \
  "Follow YubiKey Manager's PIN prompts and touch the YubiKey when requested." \
  "The existing factory ATT certificate is exported; ATT is never replaced." \
  "SIG and DEC attestations overwrite their cardholder certificates, not private keys."
run_or_die "Exporting the factory ATT certificate failed. Inspect the card and recover the public artifacts with ykman; do not rerun key generation." \
  ykman openpgp certificates export --format PEM att "$ATTESTATION_DEVICE_FILE"
[[ -s "$ATTESTATION_DEVICE_FILE" ]] || die "ykman reported success but the device certificate is empty or missing. Recover the public artifacts with ykman; do not rerun key generation."
run_or_die "Creating the SIG attestation failed. Inspect the card and recover the public artifacts with ykman; do not rerun key generation." \
  ykman openpgp keys attest --format PEM sig "$ATTESTATION_SIG_FILE"
[[ -s "$ATTESTATION_SIG_FILE" ]] || die "ykman reported success but the SIG attestation is empty or missing. Recover the public artifacts with ykman; do not rerun key generation."
run_or_die "Creating the DEC attestation failed. Inspect the card and recover the public artifacts with ykman; do not rerun key generation." \
  ykman openpgp keys attest --format PEM dec "$ATTESTATION_DEC_FILE"
[[ -s "$ATTESTATION_DEC_FILE" ]] || die "ykman reported success but the DEC attestation is empty or missing. Recover the public artifacts with ykman; do not rerun key generation."
printf '%s\n' "These non-empty output checks are not cryptographic attestation verification."

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
if ! (
  set -o noclobber
  printf '%s\n' "$FINGERPRINT" > "$FINGERPRINT_FILE"
); then
  die "Could not write the primary-key fingerprint file."
fi
printf '\nGuardian key fingerprint: %s\n' "$FINGERPRINT"

# Import into the normal keyring and retain the certificate after testing.
say "Test decryption"

# Enable cleanup only after output collision checks, when test creation begins.
TEST_FILES_STARTED=true
printf 'OpenPGP encryption and signing test\n' > "$PLAINTEXT_FILE"

# Import the public certificate and let GnuPG associate it with the private keys
# on the card before exercising the encryption and signing subkeys.
run_or_die "GnuPG could not import the public certificate into your keyring." \
  gpg --batch --import "$OUTPUT_FILE"
printf 'Public certificate imported into your GnuPG keyring.\n'
run_or_die "GnuPG could not connect the generated certificate to the YubiKey." \
  gpg --card-status
run_or_die "GnuPG could not encrypt the test file." \
  gpg --batch --yes --encrypt --armor --trust-model always --recipient "$FINGERPRINT" \
  --output "$CIPHERTEXT_FILE" "$PLAINTEXT_FILE"

# Round-trip known plaintext to prove the decryption key works and requires touch.
printf '%s\n' \
  "The next command decrypts the test file." \
  "Do not touch the YubiKey immediately: first confirm that decryption waits for a touch." \
  "After confirming it waits, tap the YubiKey when its indicator flashes."
pause "Press Enter to begin the decryption test. "
printf 'Tap your YubiKey when its indicator flashes, after confirming decryption waits for touch.\n'
run_or_die "Test decryption failed." \
  gpg --output "$DECRYPTED_FILE" --decrypt "$CIPHERTEXT_FILE"
run_or_die "The decrypted test content does not match the original." \
  cmp -s "$PLAINTEXT_FILE" "$DECRYPTED_FILE"
printf 'Decryption succeeded and the plaintext matched.\n'

# Create and verify a detached signature to prove the signing key works too.
say "Test signing"
printf '%s\n' \
  "The next command creates a detached signature." \
  "Do not touch the YubiKey immediately: first confirm that signing waits for a touch." \
  "After confirming it waits, tap the YubiKey when its indicator flashes."
pause "Press Enter to begin the signing test. "
printf 'Tap your YubiKey when its indicator flashes, after confirming signing waits for touch.\n'
run_or_die "Test signing failed." \
  gpg --armor --detach-sign --local-user "$FINGERPRINT" \
  --output "$SIGNATURE_FILE" "$PLAINTEXT_FILE"
run_or_die "GnuPG could not verify the test signature." \
  gpg --verify "$SIGNATURE_FILE" "$PLAINTEXT_FILE"
printf 'Signature creation and verification succeeded.\n'

say "Setup complete"
printf 'Public certificate: %s\n' "$OUTPUT_FILE"
printf 'Device signer certificate (PEM): %s\n' "$ATTESTATION_DEVICE_FILE"
printf 'SIG attestation (PEM): %s\n' "$ATTESTATION_SIG_FILE"
printf 'DEC attestation (PEM): %s\n' "$ATTESTATION_DEC_FILE"
printf 'Primary-key fingerprint: %s\n' "$FINGERPRINT"
printf 'Fingerprint file: %s\n' "$FINGERPRINT_FILE"
printf '%s\n' \
  "Give these five public files to the guardian operator." \
  "Keep all three PEM sidecars with the armored public certificate for later attestation verification." \
  "This script does not cryptographically verify attestations; guardian/CLI enforcement is not wired in." \
  "Do not send either PIN or any local GnuPG data." \
  "The public certificate, fingerprint file, and attestation PEMs are retained in the selected output directory." \
  "The public certificate remains in your GnuPG keyring; the four test files will now be deleted."
printf '\nYubiKey provisioning completed successfully! Public key outputted to %s\n' "$OUTPUT_FILE"
