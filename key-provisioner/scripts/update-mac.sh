#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

echo "Updating to latest main..."
git checkout main
git pull --ff-only origin main

echo "Recent commits:"
git log --oneline -5

echo "Applying nix-darwin config"
sudo darwin-rebuild switch --flake "$repo_root/key-provisioner#hashi-guardian-key-provisioner"

echo "Installing all macOS software updates"
sudo softwareupdate --install --all --restart
