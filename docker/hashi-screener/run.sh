#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-hashi-screener}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
CONTAINER_NAME="${CONTAINER_NAME:-hashi-screener}"
GRPC_PORT="${GRPC_PORT:-50051}"
METRICS_PORT="${METRICS_PORT:-9184}"

if [ -z "${MERKLE_SCIENCE_API_KEY:-}" ]; then
    echo "Error: MERKLE_SCIENCE_API_KEY is not set" >&2
    exit 1
fi

echo "Starting ${CONTAINER_NAME} (${IMAGE_NAME}:${IMAGE_TAG})"
echo "  gRPC:    http://localhost:${GRPC_PORT}"
echo "  Metrics: http://localhost:${METRICS_PORT}"

exec docker run --rm \
    --name "${CONTAINER_NAME}" \
    --platform linux/amd64 \
    -e "MERKLE_SCIENCE_API_KEY=${MERKLE_SCIENCE_API_KEY}" \
    -e "RUST_LOG=${RUST_LOG:-info}" \
    -p "${GRPC_PORT}:50051" \
    -p "${METRICS_PORT}:9184" \
    "${IMAGE_NAME}:${IMAGE_TAG}"
