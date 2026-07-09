#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Provision a withdraw-mode guardian against the running localnet.
#
# Usage: provision.sh [full|arm|activate] [guardian_endpoint]
#   full (default)  operator provision + KP shares + operator activate — the
#                   first bring-up, exactly the deploy's bootstrap flow.
#   arm             operator provision + KP shares, NO activation — arming a
#                   standby while the active guardian keeps serving; ends by
#                   verifying the reconstructed BTC pubkey == the ceremony's.
#   activate        operator activate only — the switchover step, run after
#                   the old guardian is stopped and its heartbeats aged past
#                   the quiet window.
#
# The steps:
#   1. `operator provision` -> boots the guardian into withdraw mode with the
#      stable config + MPC master G (reads them from the localnet Sui RPC),
#   2. `key-provisioner provision` x THRESHOLD -> each KP decrypts its share and
#      submits it to the proxy relay (SingleProvisionerInit); the relay batches a
#      threshold-many into the guardian's ProvisionerInit,
#   3. `operator activate` -> derives live ActivationState from S3 and activates
#      the fully provisioned standby.
#
# Requires the localnet to be up with DKG complete (current_committee +
# mpc_public_key on-chain), which `hashi-localnet start` guarantees before it
# prints its state.
set -euo pipefail
. /scripts/lib.sh

MODE="${1:-full}"
GUARDIAN="${2:-${WITHDRAW_GUARDIAN_ENDPOINT:-http://host:3000}}"

operator_provision() {
  render_config "${GUARDIAN}" ""
  echo "== operator provision (${GUARDIAN}) =="
  hashi-guardian-init operator provision --config "${CONFIG}"
}

kp_provision_all() {
  echo
  echo "== key-provisioner provision x ${THRESHOLD} (via the proxy relay) =="
  local i
  for i in $(seq 1 "${THRESHOLD}"); do
    echo "-- KP ${i}/${THRESHOLD} --"
    # Each KP uses its own cert; shares are submitted to relay_endpoint (the proxy).
    render_config "${GUARDIAN}" "${CERTS_DIR}/kp${i}.asc"
    hashi-guardian-init key-provisioner provision --config "${CONFIG}"
  done
}

# The armed standby must hold the SAME key the ceremony minted — the whole
# point of a rotation is that the BTC key never changes.
verify_armed() {
  local expected got
  expected="$(cat "${PUBKEY_FILE}")"
  got="$(hashi-guardian-init tools fetch-info --endpoint "${GUARDIAN}" --field enclave-btc-pubkey)"
  if [ "${expected}" != "${got}" ]; then
    echo "ERROR: standby BTC pubkey ${got} != ceremony pubkey ${expected}" >&2
    exit 1
  fi
  echo "Standby armed: reconstructed BTC pubkey matches the ceremony (${got})."
}

operator_activate() {
  local deadline=$(( SECONDS + ${ACTIVATE_WAIT_SECS:-300} )) out
  render_config "${GUARDIAN}" ""
  echo
  echo "== operator activate (${GUARDIAN}) =="
  while :; do
    if out="$(hashi-guardian-init operator activate --config "${CONFIG}" 2>&1)"; then
      printf '%s\n' "${out}"
      return 0
    fi
    printf '%s\n' "${out}" >&2
    # Retriable fence conditions only: the standby's first heartbeat hasn't
    # landed yet, or another session's heartbeats haven't aged out of the
    # quiet window. Anything else is a real failure.
    if ! grep -qE "no heartbeat logs found for session|sessions are still active" <<<"${out}"; then
      return 1
    fi
    if [ "${SECONDS}" -ge "${deadline}" ]; then
      echo "activation fence still closed after ${ACTIVATE_WAIT_SECS:-300}s — aborting." >&2
      return 1
    fi
    echo "activation fence not open yet; retrying in 10s..." >&2
    sleep 10
  done
}

case "${MODE}" in
  full)
    operator_provision
    kp_provision_all
    operator_activate
    echo
    echo "Provisioning and activation complete — the guardian should now be serving withdrawals."
    echo "Verify:  hashi-guardian-init tools fetch-info --endpoint ${GUARDIAN} --field enclave-btc-pubkey"
    ;;
  arm)
    operator_provision
    kp_provision_all
    verify_armed
    echo
    echo "Standby armed (not activated). Switch over with 'make switchover'."
    ;;
  activate)
    operator_activate
    echo
    echo "Activation complete — the guardian should now be serving withdrawals."
    ;;
  *)
    echo "usage: provision.sh [full|arm|activate] [guardian_endpoint]" >&2
    exit 1
    ;;
esac
