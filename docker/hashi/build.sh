#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel)"
IMAGE_NAME="${IMAGE_NAME:-hashi}"
GIT_REVISION="${GIT_REVISION:-$(git -C "$REPO_ROOT" describe --always --exclude '*' --dirty --abbrev=8)}"
IMAGE_TAG="${IMAGE_TAG:-${GIT_REVISION}}"

echo "Building ${IMAGE_NAME}:${IMAGE_TAG} (revision: ${GIT_REVISION})"

docker build \
    -f "${SCRIPT_DIR}/Containerfile" \
    --platform linux/amd64 \
    --build-arg "GIT_REVISION=${GIT_REVISION}" \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    -t "${IMAGE_NAME}:latest" \
    "${REPO_ROOT}"

echo "Successfully built ${IMAGE_NAME}:${IMAGE_TAG}"
