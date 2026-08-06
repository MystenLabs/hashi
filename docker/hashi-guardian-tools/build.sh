#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Builds the non-enclave-dev guardian binaries the deploy pipeline's CI
# ceremony downloads. Local parity with what mp3 publishes to
# gs://mysten-hashi-binaries/<sha>/.
#
# Usage:
#   bash docker/hashi-guardian-tools/build.sh
#   bash docker/hashi-guardian-tools/build.sh --no-cache

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel)"
IMAGE_NAME="${IMAGE_NAME:-hashi-guardian-tools}"
GIT_REVISION="${GIT_REVISION:-$(git -C "$REPO_ROOT" describe --always --exclude '*' --dirty --abbrev=8)}"
IMAGE_TAG="${IMAGE_TAG:-${GIT_REVISION}}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/out}"

EXTRA_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --no-cache) EXTRA_ARGS+=("--no-cache") ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

mkdir -p "${OUT_DIR}"

echo "Building ${IMAGE_NAME}:${IMAGE_TAG} (revision: ${GIT_REVISION})"

docker build \
    -f "${SCRIPT_DIR}/Containerfile" \
    --platform linux/amd64 \
    --build-arg "GIT_REVISION=${GIT_REVISION}" \
    --provenance=false \
    ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    -t "${IMAGE_NAME}:latest" \
    "${REPO_ROOT}"

echo "Successfully built ${IMAGE_NAME}:${IMAGE_TAG}"

CID=$(docker create "${IMAGE_NAME}:${IMAGE_TAG}")
trap 'docker rm "${CID}" > /dev/null' EXIT
for bin in hashi-guardian-dev hashi-guardian-init-dev; do
    docker cp "${CID}:/opt/hashi/bin/${bin}" "${OUT_DIR}/${bin}"
    echo "${bin}: ${OUT_DIR}/${bin} (SHA-256 $(sha256sum "${OUT_DIR}/${bin}" | awk '{print $1}'))"
done
