#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Run the environment locally without fault injection, the way Antithesis
# would: unpack the config image and `docker compose up` in it. Build first
# with `LOCAL=1 docker/antithesis/build.sh`.
#
# SDK assertions are written to $WORK/sdk/sdk.jsonl. Setup is complete once the
# bootstrap container exits 0; watch `docker compose logs -f workload` after.
#
# Env: TAG (default: short HEAD sha), WORK (default: .hashi/antithesis-local).
# Extra arguments are passed to `docker compose up`, e.g. `-d`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel)"
TAG="${TAG:-$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)}"
WORK="${WORK:-${REPO_ROOT}/.hashi/antithesis-local}"

if [ -d "${WORK}" ]; then
    (cd "${WORK}" && docker compose down -v --remove-orphans >/dev/null 2>&1) || true
    rm -rf "${WORK}"
fi
mkdir -p "${WORK}"

# The config image is FROM scratch; the container is only created to copy out
# of, never started, so the command is a placeholder.
cid="$(docker create "hashi-antithesis-config:${TAG}" /none)"
trap 'docker rm "${cid}" >/dev/null' EXIT
docker cp "${cid}:/." "${WORK}/"

cd "${WORK}"
export ANTITHESIS_SDK_LOCAL_OUTPUT=/sdk/sdk.jsonl
echo "Running from ${WORK}"
docker compose up "$@"
