#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C

say() {
  printf '\n== %s ==\n' "$1"
}

die() {
  printf '\nERROR: %s\n' "$1" >&2
  exit 1
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
    gpg | gpgconf) printf '%s' "GnuPG" ;;
  esac
}

for argument in "$@"; do
  case "$argument" in
    -h | --help)
      printf '%s\n' \
        "Usage: $0" \
        "Shows the serial number and signing-key fingerprint of the connected YubiKey."
      exit 0
      ;;
    *) die "Unknown argument: $argument. Usage: $0" ;;
  esac
done

required_commands=(gpg gpgconf)
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

# A long-running scdaemon can miss a replugged YubiKey and holds the card exclusively,
# so read the card with a fresh one; cleanup releases it on exit.
gpgconf --kill scdaemon > /dev/null 2>&1 || true
if ! card_data="$(gpg --card-status --with-colons)"; then
  die "GnuPG could not read a YubiKey. Connect only your YubiKey, then run this script again."
fi
serial=""
fingerprint=""
while IFS=: read -r record value _; do
  case "$record" in
    serial) serial="$value" ;;
    fpr) fingerprint="$value" ;;
  esac
done <<< "$card_data"
[[ "$fingerprint" =~ ^[0-9A-F]{40}$ ]] || die "The connected YubiKey (serial ${serial:-unknown}) has no signing key."

say "Connected YubiKey"
printf 'YubiKey serial: %s\nFingerprint:    %s\n' "$serial" "$(format_fingerprint "$fingerprint")"
