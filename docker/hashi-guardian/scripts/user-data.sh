#!/bin/bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# Update the instance and install Nitro Enclaves tools, Docker and other utilities
sudo yum update -y
sudo yum install -y aws-nitro-enclaves-cli-devel aws-nitro-enclaves-cli docker nano socat git make

# Add the current user to the docker group (so you can run docker without sudo)
sudo usermod -aG docker ec2-user

# Start and enable Nitro Enclaves allocator and Docker services
sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service
sudo systemctl start docker && sudo systemctl enable docker
sudo systemctl enable nitro-enclaves-vsock-proxy.service

# == Add your endpoints to vsock-proxy config ==
# Pattern: echo "- {address: <your-endpoint>, port: 443}" | sudo tee -a /etc/nitro_enclaves/vsock-proxy.yaml
# Example:
echo "- {address: s3.@@AWS_REGION@@.amazonaws.com, port: 443}" | sudo tee -a /etc/nitro_enclaves/vsock-proxy.yaml
echo "- {address: @@BUCKET_NAME@@.s3.@@AWS_REGION@@.amazonaws.com, port: 443}" | sudo tee -a /etc/nitro_enclaves/vsock-proxy.yaml
echo "- {address: s3.amazonaws.com, port: 443}" | sudo tee -a /etc/nitro_enclaves/vsock-proxy.yaml
# Stop the allocator so we can modify its configuration
sudo systemctl stop nitro-enclaves-allocator.service

# Adjust the enclave allocator memory (default set to 3072 MiB)
ALLOCATOR_YAML=/etc/nitro_enclaves/allocator.yaml
MEM_KEY=memory_mib
DEFAULT_MEM=3072
sudo sed -r "s/^(\s*${MEM_KEY}\s*:\s*).*/\1${DEFAULT_MEM}/" -i "${ALLOCATOR_YAML}"

# Restart the allocator with the updated memory configuration
sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service

# == Add your vsock-proxy processes ==
# Pattern: vsock-proxy 810Y <your-endpoint> 443 --config /etc/nitro_enclaves/vsock-proxy.yaml &
# Y should match the port numbers from run.sh (8101, 8102, etc.)
# Example:
vsock-proxy 8101 s3.@@AWS_REGION@@.amazonaws.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml &
vsock-proxy 8102 @@BUCKET_NAME@@.s3.@@AWS_REGION@@.amazonaws.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml &
vsock-proxy 8103 s3.amazonaws.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml &
