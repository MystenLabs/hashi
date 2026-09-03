#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Provision the withdraw-mode guardian against the running localnet:
#   1. `operator provision` -> boots the guardian into withdraw mode with the
#      stable config + MPC master G (reads them from the localnet Sui RPC),
#   2. `key-provisioner provision` x THRESHOLD -> each KP of the dealt set
#      decrypts its share and submits it to the proxy relay
#      (SingleProvisionerInit); the relay batches a threshold-many into the
#      guardian's ProvisionerInit,
#   3. `operator activate` -> derives live ActivationState from S3 and activates
#      the fully provisioned standby.
#
# GENESIS=1 (the first guardian on this bucket) adds --do-genesis to the
# operator's and every KP's command; GENESIS=0 (a replacement, e.g. after a
# KP-set rotation) requires the serving committee already recorded in S3.
#
# Requires the localnet to be up with DKG complete (current_committee +
# mpc_public_key on-chain), which `hashi-localnet start` guarantees before it
# prints "Localnet started".
set -euo pipefail
. /scripts/lib.sh

: "${SUI_RPC:?}" "${PACKAGE_ID:?}" "${HASHI_OBJECT_ID:?}"
genesis_flag=""
[ "${GENESIS:-1}" = "1" ] && genesis_flag="--do-genesis"

if [ ! -f "${ROSTER_FILE}" ]; then
  echo "No dealt roster (${ROSTER_FILE}); run 'make ceremony' first." >&2
  exit 1
fi
load_roster
endpoint="${WITHDRAW_GUARDIAN_ENDPOINT:-http://host:3000}"

# operator provision talks to the withdraw guardian directly (via the host
# bridge), NOT the proxy — init RPCs must not be cached.
render_config "${endpoint}" ""

echo "== operator provision ${genesis_flag} =="
# shellcheck disable=SC2086
hashi-guardian-init operator provision --config "${CONFIG}" ${genesis_flag}

# A KP refuses a guardian session it cannot see heartbeating in S3, and the
# first heartbeat lands on the guardian's own cadence, not at operator
# provision; here nothing else separates the two. Retry that one refusal.
kp_provision() {
  local attempt out
  for attempt in 1 2 3 4 5 6; do
    # shellcheck disable=SC2086
    if out="$(hashi-guardian-init key-provisioner provision --config "${CONFIG}" ${genesis_flag} 2>&1)"; then
      printf '%s\n' "${out}"
      return 0
    fi
    printf '%s\n' "${out}" | tail -3
    grep -q "not live in S3" <<<"${out}" || return 1
    echo "guardian heartbeat not in S3 yet; retrying in 20s (${attempt}/6)"
    sleep 20
  done
  return 1
}

echo
echo "== key-provisioner provision x ${THRESHOLD} (via the proxy relay) =="
submitted=0
for cert in ${KP_CERTS}; do
  [ "${submitted}" -lt "${THRESHOLD}" ] || break
  echo "-- $(basename "${cert}" .asc) --"
  # Each KP uses its own cert; shares are submitted to relay_endpoint (the proxy).
  render_config "${endpoint}" "${cert}"
  kp_provision
  submitted=$((submitted + 1))
done

echo
echo "== operator activate =="
render_config "${endpoint}" ""
hashi-guardian-init operator activate --config "${CONFIG}"

echo
echo "Provisioning and activation complete — the guardian should now be serving withdrawals."
echo "Verify:  hashi-guardian-init tools fetch-info --endpoint http://host:3000 --field enclave-btc-pubkey"
