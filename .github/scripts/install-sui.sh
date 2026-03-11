#!/usr/bin/env bash
set -euo pipefail

FALLBACK_VERSION="testnet-v1.63.1"

echo "Detecting latest Sui testnet version with ubuntu binary..."
SUI_VERSION=$(curl -s https://api.github.com/repos/MystenLabs/sui/releases |
	jq -r '.[] | select(.tag_name | startswith("testnet-")) |
         select(.assets[].name | contains("ubuntu-x86_64")) |
         .tag_name' | head -n 1)

if [ -z "$SUI_VERSION" ]; then
	echo "Failed to detect testnet version, falling back to $FALLBACK_VERSION"
	SUI_VERSION="$FALLBACK_VERSION"
fi

echo "Installing Sui binary ${SUI_VERSION}..."

wget -q https://sui-releases.s3-accelerate.amazonaws.com/${SUI_VERSION}/sui || {
	echo "Failed to download Sui ${SUI_VERSION}"
	exit 1
}

sudo chmod +x sui
sudo mv sui /usr/local/bin/

sui --version

echo "SUI_BINARY=/usr/local/bin/sui" >>"$GITHUB_ENV"
