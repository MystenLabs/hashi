# syntax=docker/dockerfile:1
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# The Antithesis config image, modeled on sui-operations/docker/sui-antithesis:
# docker-compose.yaml, the `.env` pinning every image tag, and a Sui genesis
# generated at build time (plus the hashi key material in hashi-env.yaml).
# Build from this directory:
#   docker build -f Dockerfile -t hashi-antithesis-config:<tag> \
#     --build-arg HASHI_NODE_TAG=<tag> --build-arg HASHI_ANTITHESIS_TAG=<tag> .

ARG SUI_TOOLS_IMAGE=mysten/sui-tools:testnet-v1.80.1

FROM ${SUI_TOOLS_IMAGE} AS setup

RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-yaml python3-cryptography \
 && rm -rf /var/lib/apt/lists/*

COPY genesis /genesis

ARG SUI_EPOCH_DURATION_MS=600000
RUN python3 /genesis/generate.py --target-directory /genesis/files --epoch-duration-ms "${SUI_EPOCH_DURATION_MS}"

# SUI_NODE_IMAGE must run the same Sui version as SUI_TOOLS_IMAGE, which
# generated the genesis above.
ARG SUI_NODE_IMAGE=mysten/sui-node:testnet-v1.80.1
ARG HASHI_NODE_TAG
ARG HASHI_ANTITHESIS_TAG
ARG SUI_RUST_LOG=info
ARG HASHI_RUST_LOG=info,hashi=debug
RUN test -n "${HASHI_NODE_TAG}" && test -n "${HASHI_ANTITHESIS_TAG}" \
 && { \
      echo "SUI_NODE_IMAGE=${SUI_NODE_IMAGE}"; \
      echo "HASHI_NODE_TAG=${HASHI_NODE_TAG}"; \
      echo "HASHI_ANTITHESIS_TAG=${HASHI_ANTITHESIS_TAG}"; \
      echo "SUI_RUST_LOG=${SUI_RUST_LOG}"; \
      echo "HASHI_RUST_LOG=${HASHI_RUST_LOG}"; \
    } > /.env

COPY docker-compose.yaml /docker-compose.yaml

FROM scratch

COPY --from=setup /docker-compose.yaml /docker-compose.yaml
COPY --from=setup /.env /.env
COPY --from=setup /genesis/files/ /genesis/files/
