#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ -x /nix/var/nix/profiles/default/bin/nix ]; then
    echo "Nix is already installed; skipping Determinate Nix installation"
else
    echo "Installing Determinate Nix"
    curl --proto '=https' --tlsv1.2 -sSf -L \
        -o /tmp/determinate-nix.pkg \
        https://install.determinate.systems/determinate-pkg/stable/Universal
    sudo installer -pkg /tmp/determinate-nix.pkg -target /
fi

. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh

echo "Applying nix-darwin config..."
sudo -H nix run --inputs-from "$repo_root/key-provisioner" nix-darwin#darwin-rebuild -- switch \
    --flake "$repo_root/key-provisioner#hashi-guardian-key-provisioner"

echo "Setup complete. Restarting to apply macOS settings..."
sudo shutdown -r now
