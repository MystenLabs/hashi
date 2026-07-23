#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Provision the withdraw-mode guardian against the running localnet:
#   1. `operator provision --do-genesis` -> boots the guardian into withdraw
#      mode with the stable config + MPC master G (reads them from the localnet
#      Sui RPC),
#   2. `key-provisioner provision --do-genesis` x THRESHOLD -> each KP decrypts
#      its share and submits it to the proxy relay (SingleProvisionerInit); the
#      relay batches a threshold-many into the guardian's ProvisionerInit,
#   3. `operator activate` -> derives live ActivationState from S3 and activates
#      the fully provisioned standby.
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

echo "== operator provision --do-genesis =="
hashi-guardian-init operator provision --config "${CONFIG}" --do-genesis

echo
echo "== key-provisioner provision x ${THRESHOLD} (via the proxy relay) =="
for i in $(seq 1 "${THRESHOLD}"); do
  echo "-- KP ${i}/${THRESHOLD} --"
  # Each KP uses its own cert; shares are submitted to relay_endpoint (the proxy).
  render_config "${WITHDRAW_GUARDIAN_ENDPOINT:-http://host:3000}" "${CERTS_DIR}/kp${i}.asc"
  hashi-guardian-init key-provisioner provision --config "${CONFIG}" --do-genesis
done

operator_activate() {
  local deadline=$(( SECONDS + 180 )) out
  render_config "${WITHDRAW_GUARDIAN_ENDPOINT:-http://host:3000}" ""
  while :; do
    if out="$(hashi-guardian-init operator activate --config "${CONFIG}" 2>&1)"; then
      printf '%s\n' "${out}"
      return 0
    fi
    printf '%s\n' "${out}" >&2
    if ! grep -q "no heartbeat logs found for session" <<<"${out}"; then
      return 1
    fi
    if [ "${SECONDS}" -ge "${deadline}" ]; then
      echo "guardian still has no heartbeat after 180s — aborting activation." >&2
      return 1
    fi
    echo "guardian has not heartbeated yet; waiting 10s before activation..." >&2
    sleep 10
  done
}

echo
echo "== operator activate =="
operator_activate

echo
echo "Provisioning and activation complete — the guardian should now be serving withdrawals."
echo "Verify:  hashi-guardian-init tools fetch-info --endpoint http://host:3000 --field enclave-btc-pubkey"
