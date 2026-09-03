#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for the ceremony/provision/rotation scripts, run inside the
# `init` container (has gnupg + hashi-guardian-init). All state lives under
# /work (a named volume) so the KP keys, the dealt roster and the rendered
# config survive across the one-shot runs.

set -euo pipefail

WORK="${WORK:-/work}"
export GNUPGHOME="${WORK}/gnupg"
CERTS_DIR="${WORK}/kp-certs"
CONFIG="${WORK}/guardian-init.local.yaml"
PUBKEY_FILE="${WORK}/guardian-btc-pubkey.hex"
# The dealt KP set: NUM_SHARES, THRESHOLD and KP_CERTS (cert paths in share
# order). Written by the ceremony, replaced by a KP-set rotation.
ROSTER_FILE="${WORK}/roster.env"

# The dealt set from file, else the set the first ceremony deals (compose env).
load_roster() {
  if [ -f "${ROSTER_FILE}" ]; then
    # shellcheck source=/dev/null
    . "${ROSTER_FILE}"
  else
    NUM_SHARES="${NUM_SHARES:-3}"
    THRESHOLD="${THRESHOLD:-2}"
    KP_CERTS="$(kp_cert_paths 1 "${NUM_SHARES}")"
  fi
}

save_roster() { # NUM_SHARES THRESHOLD "cert paths"
  printf 'NUM_SHARES=%s\nTHRESHOLD=%s\nKP_CERTS="%s"\n' "$1" "$2" "$3" > "${ROSTER_FILE}"
}

kp_cert_paths() { # FIRST LAST -> "path path ..."
  local i out=""
  for i in $(seq "$1" "$2"); do
    out="${out}${out:+ }${CERTS_DIR}/kp${i}.asc"
  done
  printf '%s' "${out}"
}

# Mint test KP PGP keypairs kpFIRST..kpLAST in one shared GNUPGHOME (a test
# rig — real KPs each hold their own yubikey). `operator ceremony` encrypts
# each share to the matching public cert; the KP commands decrypt and sign via
# gpg, which selects the right secret key from this same home.
gen_kp_keys() { # FIRST LAST
  mkdir -p "${GNUPGHOME}" "${CERTS_DIR}"
  chmod 700 "${GNUPGHOME}"
  local i fpr
  for i in $(seq "$1" "$2"); do
    [ -s "${CERTS_DIR}/kp${i}.asc" ] && continue
    gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
      "hashi-local-kp${i} <kp${i}@localhost>" default default never >/dev/null 2>&1
    fpr="$(gpg --list-keys --with-colons "kp${i}@localhost" | awk -F: '/^fpr:/{print $10; exit}')"
    gpg --armor --export "${fpr}" > "${CERTS_DIR}/kp${i}.asc"
  done
  echo "KP certs kp$1..kp$2 in ${CERTS_DIR}."
}

yaml_cert_list() { # "path path ..." -> YAML list items under kp_pgp_cert_paths
  local p out=""
  for p in $1; do
    out="${out}    - ${p}"$'\n'
  done
  printf '%s' "${out%$'\n'}"
}

# Render guardian-init.local.yaml from the template + the running localnet.
# Args: $1 = GUARDIAN_ENDPOINT (direct-to-guardian), $2 = KP_PGP_CERT_PATH (this
# KP's cert; may be empty for operator commands). kp_roster comes from
# NUM_SHARES/THRESHOLD/KP_CERTS (load_roster); with NEW_KP_CERTS set, the
# new_kp_roster block comes from NEW_NUM_SHARES/NEW_THRESHOLD/NEW_KP_CERTS.
render_config() {
  local guardian_endpoint="$1"
  local kp_cert_path="${2:-}"

  : "${SUI_RPC:?SUI_RPC must be set (localnet sui RPC)}"
  : "${PACKAGE_ID:?PACKAGE_ID must be set (from hashi-localnet state.json)}"
  : "${HASHI_OBJECT_ID:?HASHI_OBJECT_ID must be set (from hashi-localnet state.json)}"

  local new_kp_roster_yaml=""
  if [ -n "${NEW_KP_CERTS:-}" ]; then
    new_kp_roster_yaml="new_kp_roster:
  num_shares: ${NEW_NUM_SHARES}
  threshold: ${NEW_THRESHOLD}
  kp_pgp_cert_paths:
$(yaml_cert_list "${NEW_KP_CERTS}")"
  fi

  GUARDIAN_ENDPOINT="${guardian_endpoint}" \
  RELAY_ENDPOINT="${RELAY_ENDPOINT:-http://proxy:3000}" \
  KP_PGP_CERT_PATH="${kp_cert_path}" \
  AWS_S3_BUCKET="${AWS_S3_BUCKET}" \
  AWS_REGION="${AWS_REGION}" \
  AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
  AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
  SUI_RPC="${SUI_RPC}" \
  PACKAGE_ID="${PACKAGE_ID}" \
  HASHI_OBJECT_ID="${HASHI_OBJECT_ID}" \
  NUM_SHARES="${NUM_SHARES}" \
  THRESHOLD="${THRESHOLD}" \
  KP_CERT_PATHS_YAML="$(yaml_cert_list "${KP_CERTS}")" \
  NEW_KP_ROSTER_YAML="${new_kp_roster_yaml}" \
  GUARDIAN_GIT_REVISION="${GUARDIAN_GIT_REVISION:-local}" \
    envsubst < /scripts/guardian-init.local.yaml.tmpl > "${CONFIG}"
  echo "Rendered ${CONFIG} (guardian_endpoint=${guardian_endpoint})."
}

# Block until FILE contains PATTERN, for at most TIMEOUT seconds; give up early
# if PID exits.
wait_for_line() { # FILE PATTERN TIMEOUT PID
  local i
  for i in $(seq 1 "$3"); do
    grep -q "$2" "$1" 2>/dev/null && return 0
    if ! kill -0 "$4" 2>/dev/null; then
      echo "process $4 exited before logging '$2':" >&2
      cat "$1" >&2
      return 1
    fi
    sleep 1
  done
  echo "timed out waiting for '$2' in $1" >&2
  return 1
}

# Every KP in "$2" verifies, decrypts, saves and confirms its share to the
# ceremony guardian at $1 (the operator is waiting for exactly these).
confirm_kps() { # ENDPOINT "cert paths"
  local cert name
  for cert in $2; do
    name="$(basename "${cert}" .asc)"
    echo "-- ${name}: key-provisioner ceremony --"
    render_config "$1" "${cert}"
    hashi-guardian-init key-provisioner ceremony --config "${CONFIG}" \
      --encrypted-shares-path "${WORK}/${name}-shares.json"
  done
}
