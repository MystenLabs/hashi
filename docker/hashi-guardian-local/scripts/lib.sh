#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for the ceremony/provision scripts, run inside the `init`
# container (has gnupg + hashi-guardian-init). All state lives under /work
# (a named volume) so the KP keys + rendered config survive across the
# `ceremony` and `provision` one-shot runs.

set -euo pipefail

WORK="${WORK:-/work}"
export GNUPGHOME="${WORK}/gnupg"
CERTS_DIR="${WORK}/kp-certs"
CONFIG="${WORK}/guardian-init.local.yaml"
PUBKEY_FILE="${WORK}/guardian-btc-pubkey.hex"

NUM_SHARES="${NUM_SHARES:-3}"
THRESHOLD="${THRESHOLD:-2}"

kp_bundles_exist() {
  [ -d "${CERTS_DIR}" ] || return 1
  local i
  for i in $(seq 1 "${NUM_SHARES}"); do
    [ -f "${CERTS_DIR}/kp${i}.asc" ] \
      && [ -f "${CERTS_DIR}/kp${i}-device-attestation.pem" ] \
      && [ -f "${CERTS_DIR}/kp${i}-sig-attestation.pem" ] \
      && [ -f "${CERTS_DIR}/kp${i}-dec-attestation.pem" ] \
      || return 1
  done
}

# Generate NUM_SHARES test KP OpenPGP keypairs and mock attestation evidence in
# one shared GNUPGHOME (a test rig — real KPs each hold their own YubiKey).
# `operator ceremony` encrypts each share to the matching public cert;
# `key-provisioner provision` decrypts via `gpg --decrypt`, which auto-selects
# the right secret key from this same home.
gen_kp_keys() {
  if kp_bundles_exist; then
    echo "KP keys already generated (${NUM_SHARES})."
    return 0
  fi
  echo "Generating ${NUM_SHARES} test KP PGP keypairs..."
  rm -rf "${GNUPGHOME}" "${CERTS_DIR}"
  mkdir -p "${GNUPGHOME}" "${CERTS_DIR}"
  chmod 700 "${GNUPGHOME}"
  local i fpr
  for i in $(seq 1 "${NUM_SHARES}"); do
    gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
      "hashi-local-kp${i} <kp${i}@localhost>" default default never >/dev/null 2>&1
    # Export the newest key's armored public cert.
    fpr="$(gpg --list-keys --with-colons "kp${i}@localhost" | awk -F: '/^fpr:/{print $10; exit}')"
    gpg --armor --export "${fpr}" > "${CERTS_DIR}/kp${i}.asc"
    printf 'mock device attestation for local development\n' > "${CERTS_DIR}/kp${i}-device-attestation.pem"
    printf 'mock signature attestation for local development\n' > "${CERTS_DIR}/kp${i}-sig-attestation.pem"
    printf 'mock decryption attestation for local development\n' > "${CERTS_DIR}/kp${i}-dec-attestation.pem"
  done
  echo "Wrote ${NUM_SHARES} KP certificate bundles to ${CERTS_DIR}."
}

# Render guardian-init.local.yaml from the template + the running localnet.
# Args: $1 = GUARDIAN_ENDPOINT (direct-to-guardian), $2 = KP_PGP_CERT_PATH (this
# KP's cert; may be empty for operator commands).
render_config() {
  local guardian_endpoint="$1"
  local kp_cert_path="${2:-}"

  : "${SUI_RPC:?SUI_RPC must be set (localnet sui RPC)}"
  : "${PACKAGE_ID:?PACKAGE_ID must be set (from hashi-localnet state.json)}"
  : "${HASHI_OBJECT_ID:?HASHI_OBJECT_ID must be set (from hashi-localnet state.json)}"

  # Build ordered KP bundle entries. The local key generator creates explicit
  # mock evidence for the non-enclave-dev guardian.
  # `i` must be local — callers (e.g. provision.sh's KP loop) use `i` too, and
  # bash's dynamic scoping would otherwise let this loop clobber theirs.
  local kp_cert_bundles_yaml="" i
  for i in $(seq 1 "${NUM_SHARES}"); do
    kp_cert_bundles_yaml="${kp_cert_bundles_yaml}    - cert_path: ${CERTS_DIR}/kp${i}.asc"$'\n'
    kp_cert_bundles_yaml="${kp_cert_bundles_yaml}      device_attestation_cert_path: ${CERTS_DIR}/kp${i}-device-attestation.pem"$'\n'
    kp_cert_bundles_yaml="${kp_cert_bundles_yaml}      sig_attestation_path: ${CERTS_DIR}/kp${i}-sig-attestation.pem"$'\n'
    kp_cert_bundles_yaml="${kp_cert_bundles_yaml}      dec_attestation_path: ${CERTS_DIR}/kp${i}-dec-attestation.pem"$'\n'
  done

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
  KP_CERT_BUNDLES_YAML="${kp_cert_bundles_yaml%$'\n'}" \
  GUARDIAN_GIT_REVISION="${GUARDIAN_GIT_REVISION:-local}" \
    envsubst < /scripts/guardian-init.local.yaml.tmpl > "${CONFIG}"
  echo "Rendered ${CONFIG} (guardian_endpoint=${guardian_endpoint})."
}
