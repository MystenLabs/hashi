#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Genesis ceremony against the ceremony-mode guardian (chain-free):
#   1. mint the test KP roster,
#   2. `operator ceremony` -> the guardian generates the BTC key in-enclave,
#      splits it, encrypts shares to the KP certs, writes ceremony/ + kp-shares/
#      to MinIO, and waits for every KP's confirmation,
#   3. every KP runs `key-provisioner ceremony`: verify, decrypt, save, confirm,
#   4. capture the BTC pubkey for `hashi-localnet start --guardian-btc-pubkey`.
#
# The ceremony needs NO chain — `hashi.*` config ids can be placeholders here
# (ceremony commands never dial Sui). We still render a full config so the same
# file is reusable; SUI_RPC/ids may be dummy at this stage.
set -euo pipefail
. /scripts/lib.sh

# Ceremony runs before the localnet exists; allow dummy chain ids.
SUI_RPC="${SUI_RPC:-http://127.0.0.1:9000}"
PACKAGE_ID="${PACKAGE_ID:-0x0000000000000000000000000000000000000000000000000000000000000000}"
HASHI_OBJECT_ID="${HASHI_OBJECT_ID:-0x0000000000000000000000000000000000000000000000000000000000000000}"
export SUI_RPC PACKAGE_ID HASHI_OBJECT_ID

if [ -f "${ROSTER_FILE}" ]; then
  echo "A ceremony already dealt a roster (${ROSTER_FILE}); 'make down' for a fresh key." >&2
  exit 1
fi
load_roster
gen_kp_keys 1 "${NUM_SHARES}"
# Ceremony commands connect to the ceremony-mode guardian directly.
endpoint="${CEREMONY_GUARDIAN_ENDPOINT:-http://ceremony:3000}"
render_config "${endpoint}" ""

echo "== operator ceremony (waits for every KP's confirmation) =="
# stdout carries GUARDIAN_BTC_PUBKEY=...; tracing goes to stderr.
hashi-guardian-init operator ceremony --config "${CONFIG}" \
  > "${WORK}/operator-ceremony.out" 2> "${WORK}/operator-ceremony.log" &
operator=$!
wait_for_line "${WORK}/operator-ceremony.log" "waiting for every key provisioner" 120 "${operator}"

echo "== key-provisioner ceremony x ${NUM_SHARES} =="
confirm_kps "${endpoint}" "${KP_CERTS}"

wait "${operator}" || { cat "${WORK}/operator-ceremony.log" >&2; exit 1; }
cat "${WORK}/operator-ceremony.out"
pubkey="$(sed -n 's/^GUARDIAN_BTC_PUBKEY=//p' "${WORK}/operator-ceremony.out" | tail -1)"
if [ -z "${pubkey}" ]; then
  echo "ERROR: operator ceremony did not print GUARDIAN_BTC_PUBKEY" >&2
  exit 1
fi
printf '%s' "${pubkey}" > "${PUBKEY_FILE}"
save_roster "${NUM_SHARES}" "${THRESHOLD}" "${KP_CERTS}"
echo
echo "Ceremony complete (${THRESHOLD}-of-${NUM_SHARES}). Guardian BTC master pubkey:"
echo "  ${pubkey}"
echo "Saved to ${PUBKEY_FILE} (the Makefile reads it for 'make localnet-cmd')."
