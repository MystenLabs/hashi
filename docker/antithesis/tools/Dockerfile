# syntax=docker/dockerfile:1
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Everything in the environment that is not a Sui or hashi node: bitcoind, the
# test guardian, the bootstrap, and the workload (crates/hashi-antithesis), plus
# the hashi Move package compiled ahead of time since Antithesis runs offline.
# Build from the repo root:
#   docker build -f docker/antithesis/tools/Dockerfile -t hashi-antithesis:<tag> .

# Must match the Sui version the cluster runs, so the package links against
# the same framework the network has.
ARG SUI_TOOLS_IMAGE=mysten/sui-tools:testnet-v1.80.1

FROM ${SUI_TOOLS_IMAGE} AS sui

FROM rust:1.96-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
      clang libclang-dev cmake pkg-config libssl-dev libpq5 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
ARG GIT_REVISION=unknown
ENV GIT_REVISION=${GIT_REVISION}
RUN cargo build --locked --release --bin hashi-antithesis

COPY --from=sui /usr/local/bin/sui /usr/local/bin/sui
# `sui move build` offers to create a client config interactively when none
# exists, which corrupts the JSON on stdout. Nothing in it is used offline.
RUN mkdir -p /tmp/sui \
 && echo '[]' > /tmp/sui/sui.keystore \
 && printf 'keystore:\n  File: /tmp/sui/sui.keystore\nenvs:\n  - alias: localnet\n    rpc: "http://127.0.0.1:9000"\n    ws: ~\nactive_env: localnet\nactive_address: ~\n' > /tmp/sui/client.yaml \
 && sui move --client.config /tmp/sui/client.yaml -p packages/hashi build \
      -e testnet --dump-bytecode-as-base64 --no-tree-shaking > /tmp/hashi-package.json

FROM debian:bookworm-slim AS bitcoin
ARG BITCOIN_VERSION=31.1
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
RUN case "${TARGETARCH}" in \
      amd64) triple=x86_64-linux-gnu ;; \
      arm64) triple=aarch64-linux-gnu ;; \
      *) echo "unsupported arch ${TARGETARCH}" && exit 1 ;; \
    esac \
 && tarball="bitcoin-${BITCOIN_VERSION}-${triple}.tar.gz" \
 && cd /tmp \
 && curl -fsSLO "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/${tarball}" \
 && curl -fsSLO "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/SHA256SUMS" \
 && grep " ${tarball}\$" SHA256SUMS | sha256sum -c - \
 && tar -xzf "${tarball}" \
 && install -m 0755 "bitcoin-${BITCOIN_VERSION}/bin/bitcoind" "bitcoin-${BITCOIN_VERSION}/bin/bitcoin-cli" /usr/local/bin/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libssl3 \
 && rm -rf /var/lib/apt/lists/*

# The Antithesis SDK reports assertions through this library when present
# (x86_64 only); elsewhere it falls back to ANTITHESIS_SDK_LOCAL_OUTPUT.
ARG TARGETARCH
RUN if [ "${TARGETARCH}" = amd64 ]; then \
      curl -fsSL -o /usr/lib/libvoidstar.so https://antithesis.com/assets/instrumentation/libvoidstar.so; \
    fi

COPY --from=bitcoin /usr/local/bin/bitcoind /usr/local/bin/bitcoin-cli /usr/local/bin/
COPY --from=builder /src/target/release/hashi-antithesis /usr/local/bin/hashi-antithesis
COPY --from=builder /tmp/hashi-package.json /opt/hashi-antithesis/hashi-package.json
RUN mkdir -p /data
