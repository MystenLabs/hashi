#!/bin/sh
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Local replica of docker/hashi-guardian/run.sh with the vsock hops rewritten to
# TCP. Real Nitro bridges the parent host (vsock CID 3) and the enclave over
# AF_VSOCK; a Mac has no vsock, so every `VSOCK-*` hop becomes a `TCP-*` hop to
# the `host` container. The S3 hostname redirect is kept so the guardian's S3
# traffic still traverses the forwarder chain (enclave -> host -> MinIO).
#
# CEREMONY_MODE (env, default unset=false) selects ceremony vs withdraw mode,
# exactly as the real enclave `main.rs` does — so the same image serves the
# ceremony-mode and withdraw-mode guardians in the replica.
set -e
echo "run.local.sh starting (CEREMONY_MODE=${CEREMONY_MODE:-false})"

# Point S3 hostnames at loopback (kept from run.sh). AWS_REGION comes from the
# container env. /etc/hosts is a bind mount, so append (>>) rather than truncate.
echo "127.0.0.64   s3.${AWS_REGION}.amazonaws.com" >> /etc/hosts
echo "127.0.0.65   ${AWS_S3_BUCKET}.s3.${AWS_REGION}.amazonaws.com" >> /etc/hosts
echo "127.0.0.66   s3.amazonaws.com" >> /etc/hosts

# Outbound S3 forwarders: 127.0.0.6x:443 -> host:810x. On real Nitro these
# VSOCK-CONNECT the host's nitro vsock-proxy daemons; here they TCP-connect the
# `host` container, which forwards 810x -> MinIO. (Path-style addressing only
# uses the .64/8101 region endpoint; .65/.66 are kept for topology fidelity.)
socat TCP4-LISTEN:443,bind=127.0.0.64,reuseaddr,fork TCP:host:8101 &
socat TCP4-LISTEN:443,bind=127.0.0.65,reuseaddr,fork TCP:host:8102 &
socat TCP4-LISTEN:443,bind=127.0.0.66,reuseaddr,fork TCP:host:8103 &

# The guardian binds 0.0.0.0:3000 directly, so (unlike real Nitro) there is no
# in-enclave vsock->TCP inbound bridge — the `host`/`proxy` containers connect
# straight to :3000.
exec /usr/bin/hashi-guardian
