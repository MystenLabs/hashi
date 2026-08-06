#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ "${HASHI_TART_TEST:-}" = "1" ]; then
    echo "Skipping software updates in Tart test VM"
else
    echo "Updating MacOS"
    sudo softwareupdate --install --all --restart
    echo "Installing Xcode Command Line Tools"
    xcode-select --install
fi

echo "Installing Determinate Nix"
curl --proto '=https' --tlsv1.2 -sSf -L \
    -o /tmp/determinate-nix.pkg \
    https://install.determinate.systems/determinate-pkg/stable/Universal
sudo installer -pkg /tmp/determinate-nix.pkg -target /

. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh

echo "Applying nix-darwin config"
sudo nix run nix-darwin/nix-darwin-25.11#darwin-rebuild -- switch \
    --flake "$repo_root/key-provisioner#hashi-guardian-key-provisioner"

if [ "${HASHI_TART_TEST:-}" = "1" ]; then
    echo "Restarting Tart test VM to apply macOS settings"
    sudo shutdown -r now
fi
