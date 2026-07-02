# syntax=docker/dockerfile:1

# Local-only image for the Mac/dev Nitro replica. Builds all three guardian
# binaries for the container's native arch — fidelity here is the network
# TOPOLOGY, not the reproducible musl EIF (that lives in docker/hashi-guardian/
# and cannot run off real Nitro hardware). Bundles socat (the vsock->TCP shims)
# and grpcurl + the proto tree (smoke tests).

FROM rust:1-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang libclang-dev pkg-config libssl-dev nettle-dev git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Baked into the guardian at build time (option_env!) and reported as
# `untrusted_git_revision`; the init config's `current_build.git_revision` must
# match it, so pin a stable local value both sides agree on.
ARG GIT_REVISION=local
ENV GIT_REVISION=${GIT_REVISION}
# hashi-guardian needs `non-enclave-dev` (stubs the Nitro NSM attestation call so
# it runs as a plain container); build it on its own so the feature is
# unambiguous, then the proxy + init tooling.
RUN cargo build --release -p hashi-guardian --features non-enclave-dev
RUN cargo build --release -p hashi-guardian-proxy -p hashi-guardian-init

FROM debian:bookworm-slim
# socat: the vsock->TCP shims. gnupg: the test KP keys (`operator ceremony`
# encrypts shares to them; `key-provisioner provision` decrypts via gpg — the
# same gpg-over-a-pipe path a real KP's yubikey uses). grpcurl: smoke tests.
RUN apt-get update && apt-get install -y --no-install-recommends socat gnupg jq ca-certificates curl \
 && arch="$(dpkg --print-architecture)"; case "$arch" in amd64) ga=x86_64;; arm64) ga=arm64;; *) ga="$arch";; esac; \
    curl -fsSL "https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_${ga}.tar.gz" \
      | tar -xz -C /usr/local/bin grpcurl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/hashi-guardian       /usr/bin/hashi-guardian
COPY --from=builder /src/target/release/hashi-guardian-proxy /usr/bin/hashi-guardian-proxy
COPY --from=builder /src/target/release/hashi-guardian-init  /usr/bin/hashi-guardian-init
COPY crates/hashi-types/proto /proto
