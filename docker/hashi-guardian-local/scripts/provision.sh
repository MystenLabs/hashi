#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Provision the withdraw-mode guardian against the running localnet:
#   1. `operator provision` -> boots the guardian into withdraw mode with the
#      on-chain committee + MPC master G (reads them from the localnet Sui RPC),
#   2. `key-provisioner provision` x THRESHOLD -> each KP decrypts its share and
#      submits it to the proxy relay (SingleProvisionerInit); the relay batches a
#      threshold-many into the guardian's ProvisionerInit, bringing it to
#      fully-initialized.
#
# Requires the localnet to be up with DKG complete (current_committee +
# mpc_public_key on-chain), which `hashi-localnet start` guarantees before it
# prints "Localnet started".
set -euo pipefail
. /scripts/lib.sh

: "${SUI_RPC:?}" "${PACKAGE_ID:?}" "${HASHI_OBJECT_ID:?}"

# operator provision talks to the withdraw guardian directly (via the host
# bridge), NOT the proxy — init RPCs must not be cached.
render_config "${WITHDRAW_GUARDIAN_ENDPOINT:-http://host:3000}" ""

echo "== operator provision =="
hashi-guardian-init operator provision --config "${CONFIG}"

# The withdraw guardian only begins heartbeating AFTER OperatorInit above, and
# its first heartbeat lands up to HEARTBEAT_INTERVAL (~60s) later. KP provision's
# heartbeat_audit needs that beat, and fails fast (before submitting any share)
# if it isn't there yet — so retry the FIRST KP on that specific error while we
# wait for it. (In prod the operator/KP steps are minutes apart by human
# coordination, so this wait is purely a local-orchestration concern.) The relay
# dedupes by share id, so a retry is idempotent regardless.
kp_provision() {  # $1 = KP index; waits out the first-heartbeat gap, fails fast otherwise
  local idx="$1" deadline=$(( SECONDS + 180 )) out
  # Each KP uses its own cert; shares are submitted to relay_endpoint (the proxy).
  render_config "${WITHDRAW_GUARDIAN_ENDPOINT:-http://host:3000}" "${CERTS_DIR}/kp${idx}.asc"
  while :; do
    if out="$(hashi-guardian-init key-provisioner provision --config "${CONFIG}" 2>&1)"; then
      printf '%s\n' "${out}"
      return 0
    fi
    printf '%s\n' "${out}" >&2
    if ! grep -q "no heartbeat logs found" <<<"${out}"; then
      return 1  # a real failure, not the first-heartbeat gap
    fi
    if [ "${SECONDS}" -ge "${deadline}" ]; then
      echo "KP ${idx}: guardian still not heartbeating after 180s — aborting." >&2
      return 1
    fi
    echo "KP ${idx}: guardian not heartbeating yet; waiting 10s for its first heartbeat..." >&2
    sleep 10
  done
}

echo
echo "== key-provisioner provision x ${THRESHOLD} (via the proxy relay) =="
for i in $(seq 1 "${THRESHOLD}"); do
  echo "-- KP ${i}/${THRESHOLD} --"
  kp_provision "${i}"
done

echo
echo "Provisioning complete — the guardian should now be fully initialized."
echo "Verify:  hashi-guardian-init tools fetch-info --endpoint http://host:3000 --field enclave-btc-pubkey"
