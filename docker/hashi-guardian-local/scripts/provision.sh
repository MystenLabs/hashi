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

echo
echo "== key-provisioner provision x ${THRESHOLD} (via the proxy relay) =="
for i in $(seq 1 "${THRESHOLD}"); do
  echo "-- KP ${i}/${THRESHOLD} --"
  # Each KP uses its own cert; shares are submitted to relay_endpoint (the proxy).
  render_config "${WITHDRAW_GUARDIAN_ENDPOINT:-http://host:3000}" "${CERTS_DIR}/kp${i}.asc"
  hashi-guardian-init key-provisioner provision --config "${CONFIG}"
done

echo
echo "Provisioning complete — the guardian should now be fully initialized."
echo "Verify:  hashi-guardian-init tools fetch-info --endpoint http://host:3000 --field enclave-btc-pubkey"
