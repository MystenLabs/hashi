#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C

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

usage="Usage: $0 (shows the serial number and signing-key fingerprint of the connected YubiKey)"
case "${1:-}" in
  "") (($# == 0)) || die "$usage" ;;
  -h | --help)
    printf '%s\n' "$usage"
    exit 0
    ;;
  *) die "$usage" ;;
esac

for required_command in gpg gpgconf; do
  command -v "$required_command" > /dev/null 2>&1 || die "$required_command is not installed or not on PATH."
done

# A long-running scdaemon can miss a replugged YubiKey and holds the card exclusively,
# so read the card with a fresh one and release it on exit.
trap 'gpgconf --kill scdaemon > /dev/null 2>&1 || true' EXIT
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

printf 'YubiKey serial: %s\nFingerprint:    %s\n' "$serial" "$(format_fingerprint "$fingerprint")"
