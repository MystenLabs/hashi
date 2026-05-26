#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ "${HASHI_TART_TEST:-}" = "1" ]; then
    echo "Skipping macOS software updates in Tart test VM"
else
    echo "Installing all macOS software updates"
    sudo softwareupdate --install --all --restart
fi

echo "Applying nix-darwin config"
sudo darwin-rebuild switch --flake "$repo_root/key-provisioner#hashi-guardian-key-provisioner"
