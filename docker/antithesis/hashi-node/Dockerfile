# syntax=docker/dockerfile:1
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# The hashi validator binary with Antithesis coverage instrumentation, modeled
# on sui-operations/docker/sui-node-antithesis. Build from the repo root:
#   docker build -f docker/antithesis/hashi-node/Dockerfile -t hashi-node:<tag> .
# INSTRUMENT=0 builds without instrumentation, e.g. for a native arm64 image to
# run the environment locally (libvoidstar only exists for x86_64).

FROM rust:1.96-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
      clang libclang-dev cmake pkg-config libssl-dev binutils \
 && rm -rf /var/lib/apt/lists/*

ARG INSTRUMENT=1

# The instrumentation runtime; instrumented binaries link against it and
# Antithesis supplies the real implementation when the image runs there.
RUN mkdir -p /voidstar \
 && if [ "${INSTRUMENT}" = 1 ]; then \
      curl -fsSL -o /voidstar/libvoidstar.so https://antithesis.com/assets/instrumentation/libvoidstar.so; \
    fi

WORKDIR /src
COPY . .
RUN cargo fetch --locked

ARG GIT_REVISION=unknown
ENV GIT_REVISION=${GIT_REVISION}
ENV CARGO_PROFILE_RELEASE_DEBUG=true

# Antithesis symbolizes from /symbols, keyed by build id; the shipped binary
# keeps only a debuglink to them.
RUN --network=none \
    if [ "${INSTRUMENT}" = 1 ]; then \
      export LD_LIBRARY_PATH=/voidstar; \
      export RUSTFLAGS="-C target-feature=-crt-static -C codegen-units=1 -C passes=sancov-module \
        -C llvm-args=-sanitizer-coverage-level=3 \
        -C llvm-args=-sanitizer-coverage-trace-pc-guard \
        -C link-args=-Wl,--build-id \
        -L/voidstar -lvoidstar"; \
    else \
      export RUSTFLAGS="-C link-args=-Wl,--build-id"; \
    fi \
 && cargo build --frozen --release --bin hashi \
 && mkdir -p /opt/hashi/bin /symbols \
 && objcopy --only-keep-debug target/release/hashi /symbols/hashi.debug \
 && cp target/release/hashi /opt/hashi/bin/hashi \
 && objcopy --strip-debug --add-gnu-debuglink=/symbols/hashi.debug /opt/hashi/bin/hashi \
 && build_id="$(readelf -n /opt/hashi/bin/hashi | awk '/Build ID:/ { print $3; exit }')" \
 && test -n "${build_id}" \
 && ln /symbols/hashi.debug "/symbols/${build_id}.build_id.dwarf"

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl libssl3 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /voidstar/ /usr/lib/
COPY --from=builder /opt/hashi/bin/hashi /opt/hashi/bin/hashi
COPY --from=builder /symbols /symbols
RUN mkdir -p /opt/hashi/data
ENTRYPOINT ["/opt/hashi/bin/hashi"]
