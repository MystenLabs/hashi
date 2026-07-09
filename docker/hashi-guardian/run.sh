#!/bin/sh
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Init for the hashi-guardian Nitro enclave; the kernel execs this as PID 1.
# - Mounts the pseudo-filesystems
# - Signals the parent that the enclave booted (Nitro vsock heartbeat)
# - Configures loopback network and /etc/hosts
# - Starts traffic forwarders for S3 endpoints
# - Forwards VSOCK port 3000 to localhost:3000 (gRPC)
# - Launches hashi-guardian

set -e
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/
export LD_LIBRARY_PATH=/lib:$LD_LIBRARY_PATH
echo "run.sh script is running"

# The Nitro loader hands us a bare initramfs root; mount the pseudo-filesystems.
# Tolerate an already-mounted fs (the kernel auto-mounts devtmpfs).
busybox mount -t proc proc /proc 2>/dev/null || :
busybox mount -t sysfs sysfs /sys 2>/dev/null || :
busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null || :
busybox mount -t tmpfs tmpfs /tmp 2>/dev/null || :

# Signal the parent that the enclave booted: connect to the parent (vsock CID 3,
# port 9000) and exchange the 0xB7 heartbeat byte. Without it the parent times
# out (VsockTimeout) and the enclave never reaches the RUNNING state.
n=0
while ! printf '\267' | socat - VSOCK-CONNECT:3:9000; do
	n=$((n + 1))
	[ "$n" -ge 10 ] && break
	sleep 1
done

# Assign an IP address to local loopback
busybox ip addr add 127.0.0.1/32 dev lo
busybox ip link set dev lo up

# Add hosts records, pointing S3 calls to local loopback
# BUCKET_NAME and AWS_REGION are substituted at build time via Containerfile
echo "127.0.0.1   localhost" > /etc/hosts
echo "127.0.0.64   s3.${AWS_REGION}.amazonaws.com" >> /etc/hosts
echo "127.0.0.65   ${BUCKET_NAME}.s3.${AWS_REGION}.amazonaws.com" >> /etc/hosts
echo "127.0.0.66   s3.amazonaws.com" >> /etc/hosts

cat /etc/hosts

# Run traffic forwarders in background.
# Forwards traffic from 127.0.0.x:443 -> VSOCK CID 3 on ports 8101-8103.
# A vsock-proxy on the host forwards these to the actual S3 endpoints
socat TCP4-LISTEN:443,bind=127.0.0.64,reuseaddr,fork VSOCK-CONNECT:3:8101 &
socat TCP4-LISTEN:443,bind=127.0.0.65,reuseaddr,fork VSOCK-CONNECT:3:8102 &
socat TCP4-LISTEN:443,bind=127.0.0.66,reuseaddr,fork VSOCK-CONNECT:3:8103 &

# Forward VSOCK port 3000 to localhost:3000 (gRPC server)
socat VSOCK-LISTEN:3000,reuseaddr,fork TCP:localhost:3000 &

exec /guardian
