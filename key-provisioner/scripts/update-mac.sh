#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

branch="$(git symbolic-ref --short HEAD)"
if [[ "$branch" != "main" ]]; then
    if read -r -p "WARNING: main must be used for key provisioner operations. You're on '$branch'. Switch to main? [y/N] " answer &&
        [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]; then
        branch="main"
    fi
fi

echo "Updating to latest $branch..."
git checkout "$branch"
git pull --ff-only origin "$branch"

echo "Recent commits:"
git log --oneline -5

echo "Applying nix-darwin config"
sudo darwin-rebuild switch --flake "$repo_root/key-provisioner#hashi-guardian-key-provisioner"

echo "Installing all macOS software updates"
sudo softwareupdate --install --all

echo "Update complete. Restarting to apply settings..."
sudo shutdown -r now
