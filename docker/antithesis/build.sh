#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Build the images the hashi Antithesis environment needs:
#   hashi-node:<tag>               instrumented `hashi` validator
#   hashi-antithesis:<tag>         bitcoind + guardian/bootstrap/workload + compiled Move package
#   hashi-antithesis-config:<tag>  docker-compose.yaml, .env, and the Sui genesis
#
# Usage:
#   docker/antithesis/build.sh           # linux/amd64, instrumented: what Antithesis runs
#   LOCAL=1 docker/antithesis/build.sh   # native arch, uninstrumented: for run-local.sh
#
# Env: TAG (default: short HEAD sha), SUI_VERSION (mysten/sui-{tools,node} tag).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel)"
TAG="${TAG:-$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)}"
SUI_VERSION="${SUI_VERSION:-testnet-v1.80.1}"

if [ "${LOCAL:-0}" = 1 ]; then
    case "$(uname -m)" in
        arm64 | aarch64) PLATFORM=linux/arm64 SUI_SUFFIX=-arm64 ;;
        *) PLATFORM=linux/amd64 SUI_SUFFIX= ;;
    esac
    INSTRUMENT=0
else
    PLATFORM=linux/amd64 SUI_SUFFIX= INSTRUMENT=1
fi
SUI_TOOLS_IMAGE="mysten/sui-tools:${SUI_VERSION}${SUI_SUFFIX}"
SUI_NODE_IMAGE="mysten/sui-node:${SUI_VERSION}${SUI_SUFFIX}"

echo "Building tag ${TAG} for ${PLATFORM} (instrument=${INSTRUMENT}, sui=${SUI_VERSION}${SUI_SUFFIX})"

docker build --platform "${PLATFORM}" \
    -f "${SCRIPT_DIR}/hashi-node/Dockerfile" \
    --build-arg INSTRUMENT="${INSTRUMENT}" \
    --build-arg GIT_REVISION="${TAG}" \
    -t "hashi-node:${TAG}" \
    "${REPO_ROOT}"

docker build --platform "${PLATFORM}" \
    -f "${SCRIPT_DIR}/tools/Dockerfile" \
    --build-arg SUI_TOOLS_IMAGE="${SUI_TOOLS_IMAGE}" \
    --build-arg GIT_REVISION="${TAG}" \
    -t "hashi-antithesis:${TAG}" \
    "${REPO_ROOT}"

docker build --platform "${PLATFORM}" \
    -f "${SCRIPT_DIR}/config/Dockerfile" \
    --build-arg SUI_TOOLS_IMAGE="${SUI_TOOLS_IMAGE}" \
    --build-arg SUI_NODE_IMAGE="${SUI_NODE_IMAGE}" \
    --build-arg HASHI_NODE_TAG="${TAG}" \
    --build-arg HASHI_ANTITHESIS_TAG="${TAG}" \
    -t "hashi-antithesis-config:${TAG}" \
    "${SCRIPT_DIR}/config"

echo
echo "Built hashi-node:${TAG} hashi-antithesis:${TAG} hashi-antithesis-config:${TAG}"
echo "Sui nodes run ${SUI_NODE_IMAGE}"
