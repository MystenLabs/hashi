#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Genesis ceremony against the ceremony-mode guardian (chain-free):
#   1. generate the test KP roster,
#   2. `operator ceremony` -> the guardian generates the BTC key in-enclave,
#      splits it, encrypts shares to the KP certs, writes ceremony/ + shares/
#      to MinIO, and returns the x-only BTC master pubkey,
#   3. capture that pubkey for `hashi-localnet start --guardian-btc-pubkey`.
#
# The ceremony needs NO chain — `hashi.*` config ids can be placeholders here
# (operator ceremony never dials Sui). We still render a full config so the same
# file is reusable; SUI_RPC/ids may be dummy at this stage.
set -euo pipefail
. /scripts/lib.sh

# Ceremony runs before the localnet exists; allow dummy chain ids.
SUI_RPC="${SUI_RPC:-http://127.0.0.1:9000}"
PACKAGE_ID="${PACKAGE_ID:-0x0000000000000000000000000000000000000000000000000000000000000000}"
HASHI_OBJECT_ID="${HASHI_OBJECT_ID:-0x0000000000000000000000000000000000000000000000000000000000000000}"
export SUI_RPC PACKAGE_ID HASHI_OBJECT_ID

gen_kp_keys
write_kp_roster
# `operator ceremony` connects to the ceremony-mode guardian directly.
render_config "${CEREMONY_GUARDIAN_ENDPOINT:-http://ceremony:3000}" ""

echo "Running operator ceremony..."
# Capture stdout so we can extract GUARDIAN_BTC_PUBKEY=... (tracing -> stderr).
out="$(hashi-guardian-init operator ceremony --config "${CONFIG}")"
echo "${out}"

pubkey="$(printf '%s\n' "${out}" | sed -n 's/^GUARDIAN_BTC_PUBKEY=//p' | tail -1)"
if [ -z "${pubkey}" ]; then
  echo "ERROR: operator ceremony did not print GUARDIAN_BTC_PUBKEY" >&2
  exit 1
fi
printf '%s' "${pubkey}" > "${PUBKEY_FILE}"
echo
echo "Ceremony complete. Guardian BTC master pubkey:"
echo "  ${pubkey}"
echo "Saved to ${PUBKEY_FILE} (the Makefile reads it for 'make localnet')."
