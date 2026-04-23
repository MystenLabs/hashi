#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Builds the hashi-guardian binary as a plain Kubernetes (non-enclave) image.
#
# Usage:
#   bash docker/hashi-guardian-k8s/build.sh              # build with cache
#   GIT_REVISION=test bash docker/hashi-guardian-k8s/build.sh --no-cache && sha256sum out/hashi-guardian   # build without cache, useful to check reproducibility

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel)"
IMAGE_NAME="${IMAGE_NAME:-hashi-guardian}"
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
    "${EXTRA_ARGS[@]}" \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    -t "${IMAGE_NAME}:latest" \
    "${REPO_ROOT}"

echo "Successfully built ${IMAGE_NAME}:${IMAGE_TAG}"

# Extract the binary from the image
CID=$(docker create "${IMAGE_NAME}:${IMAGE_TAG}")
docker cp "${CID}:/usr/bin/hashi-guardian" "${OUT_DIR}/hashi-guardian"
docker rm "${CID}" > /dev/null

echo ""
echo "Binary: ${OUT_DIR}/hashi-guardian"
echo "SHA-256: $(sha256sum "${OUT_DIR}/hashi-guardian" | awk '{print $1}')"
