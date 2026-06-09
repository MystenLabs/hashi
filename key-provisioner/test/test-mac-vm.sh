#!/usr/bin/env bash

set -euo pipefail

vm_name="hashi-key-provisioner-test"
image="ghcr.io/cirruslabs/macos-tahoe-base:latest"
repo_root="$(pwd)"

if [ "$(basename "$repo_root")" != "hashi" ]; then
    echo "Run this script from the hashi repo root"
    exit 1
fi

echo "Regenerating key-provisioner/flake.lock"
nix flake lock --output-lock-file "$repo_root/key-provisioner/flake.lock" "path:$repo_root/key-provisioner"

echo "Deleting any existing VM $vm_name"
tart stop "$vm_name" || true
tart delete "$vm_name" || true

echo "Cloning $image to $vm_name"
tart clone "$image" "$vm_name"

echo "Setting VM memory to 16 GB"
tart set "$vm_name" --memory 16384

echo "Setting VM disk to 75 GB"
tart set "$vm_name" --disk-size 75

echo "Running VM $vm_name"
tart run --dir=hashi:"$repo_root" "$vm_name" &

echo "Waiting for VM $vm_name to start"
until tart exec "$vm_name" true; do
    sleep 1
done

echo "Copying hashi repo to ~/hashi"
tart exec "$vm_name" rsync -a \
    --exclude .git \
    --exclude .jj \
    --exclude target \
    --exclude out \
    "/Volumes/My Shared Files/hashi/" \
    /Users/admin/hashi/

echo "Default VM username: admin"
echo "Default VM password: admin"

boot_time="$(tart exec "$vm_name" sysctl -n kern.boottime)"

echo "Running setup-mac.sh"
tart exec "$vm_name" open /Users/admin/hashi/key-provisioner/test/run-test-setup-mac.command

echo "Waiting for VM $vm_name to restart"
until new_boot_time="$(timeout 2s tart exec "$vm_name" sysctl -n kern.boottime 2>/dev/null)" && [ "$new_boot_time" != "$boot_time" ]; do
    sleep 1
done

echo "VM $vm_name restarted"

echo "Running update-mac.sh"
tart exec "$vm_name" open /Users/admin/hashi/key-provisioner/test/run-test-update-mac.command
