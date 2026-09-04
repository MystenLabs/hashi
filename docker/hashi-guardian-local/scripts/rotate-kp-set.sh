#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# KP-set rotation against a FRESH ceremony-mode guardian (chain-free):
#   1. mint the new KP set (kp<N+1>..; n and t may change),
#   2. `operator rotate-kp-set init`,
#   3. threshold-many current KPs sign submissions (`key-provisioner rotate-kp-set`),
#   4. `operator rotate-kp-set submit` -> RotateKpSet, then waits for the new KPs,
#   5. every new KP runs `key-provisioner ceremony`,
#   6. the new set becomes the dealt roster; `make reprovision` next.
set -euo pipefail
. /scripts/lib.sh

SUI_RPC="${SUI_RPC:-http://127.0.0.1:9000}"
PACKAGE_ID="${PACKAGE_ID:-0x0000000000000000000000000000000000000000000000000000000000000000}"
HASHI_OBJECT_ID="${HASHI_OBJECT_ID:-0x0000000000000000000000000000000000000000000000000000000000000000}"
export SUI_RPC PACKAGE_ID HASHI_OBJECT_ID

if [ ! -f "${ROSTER_FILE}" ]; then
  echo "No dealt roster (${ROSTER_FILE}); run 'make ceremony' first." >&2
  exit 1
fi
load_roster
NEW_NUM_SHARES="${NEW_NUM_SHARES:-3}"
NEW_THRESHOLD="${NEW_THRESHOLD:-2}"
first=$(( $(ls "${CERTS_DIR}"/kp*.asc | wc -l) + 1 ))
last=$(( first + NEW_NUM_SHARES - 1 ))
gen_kp_keys "${first}" "${last}"
NEW_KP_CERTS="$(kp_cert_paths "${first}" "${last}")"
export NEW_NUM_SHARES NEW_THRESHOLD NEW_KP_CERTS
endpoint="${CEREMONY_GUARDIAN_ENDPOINT:-http://ceremony:3000}"

echo "== operator rotate-kp-set init =="
render_config "${endpoint}" ""
hashi-guardian-init operator rotate-kp-set init --config "${CONFIG}"

echo "== key-provisioner rotate-kp-set x ${THRESHOLD} (current set) =="
submissions=()
signed=0
for cert in ${KP_CERTS}; do
  [ "${signed}" -lt "${THRESHOLD}" ] || break
  name="$(basename "${cert}" .asc)"
  echo "-- ${name} --"
  render_config "${endpoint}" "${cert}"
  hashi-guardian-init key-provisioner rotate-kp-set --config "${CONFIG}" \
    --submission-path "${WORK}/${name}.rotation"
  submissions+=(--submission "${WORK}/${name}.rotation")
  signed=$((signed + 1))
done

echo "== operator rotate-kp-set submit (waits for every new KP's confirmation) =="
render_config "${endpoint}" ""
hashi-guardian-init operator rotate-kp-set submit --config "${CONFIG}" "${submissions[@]}" \
  > "${WORK}/operator-rotate.out" 2> "${WORK}/operator-rotate.log" &
operator=$!
wait_for_line "${WORK}/operator-rotate.log" "waiting for every key provisioner" 120 "${operator}"

echo "== key-provisioner ceremony x ${NEW_NUM_SHARES} (new set) =="
NUM_SHARES="${NEW_NUM_SHARES}"
THRESHOLD="${NEW_THRESHOLD}"
KP_CERTS="${NEW_KP_CERTS}"
unset NEW_KP_CERTS
confirm_kps "${endpoint}" "${KP_CERTS}"

wait "${operator}" || { cat "${WORK}/operator-rotate.log" >&2; exit 1; }
cat "${WORK}/operator-rotate.out"
save_roster "${NUM_SHARES}" "${THRESHOLD}" "${KP_CERTS}"
echo
echo "KP-set rotation complete: the dealt set is now kp${first}..kp${last} (${THRESHOLD}-of-${NUM_SHARES})."
echo "Next: 'make reprovision' (a fresh withdraw guardian, provisioned by the new set)."
