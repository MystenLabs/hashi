#!/bin/sh
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Setup script for hashi-guardian that acts as an init script (launched by nit)
# - Sets up Python and library paths
# - Configures loopback network and /etc/hosts
# - Starts traffic forwarders for S3 endpoints
# - Forwards VSOCK port 3000 to localhost:3000 (gRPC)
# - Launches hashi-guardian

set -e
echo "run.sh script is running"
export PYTHONPATH=/lib/python3.11:/usr/local/lib/python3.11/lib-dynload:/usr/local/lib/python3.11/site-packages:/lib
export LD_LIBRARY_PATH=/lib:$LD_LIBRARY_PATH

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

# Run traffic forwarders in background
# Forwards traffic from 127.0.0.x:443 -> VSOCK CID 3 on ports 8101-8103
# A vsock-proxy on the host forwards these to the actual S3 endpoints
python3 /traffic_forwarder.py 127.0.0.64 443 3 8101 &
python3 /traffic_forwarder.py 127.0.0.65 443 3 8102 &
python3 /traffic_forwarder.py 127.0.0.66 443 3 8103 &

# Forward VSOCK port 3000 to localhost:3000 (gRPC server)
socat VSOCK-LISTEN:3000,reuseaddr,fork TCP:localhost:3000 &

/guardian
