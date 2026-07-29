#!/usr/bin/env bash
set -euo pipefail

FALLBACK_VERSION="testnet-v1.63.1"
S3_BASE_URL="https://sui-releases.s3-accelerate.amazonaws.com"

echo "Detecting latest Sui testnet version with a published binary..."

# The GitHub release tag appears before its binaries finish uploading, and
# the release's own assets can lag the S3 bucket we actually download from.
# Probe S3 directly so the readiness check matches the download source.
SUI_VERSION=""
while read -r tag; do
	if curl -fsI "${S3_BASE_URL}/${tag}/sui" >/dev/null; then
		SUI_VERSION="$tag"
		break
	fi
	echo "No binary on S3 yet for ${tag}, trying the previous release..."
done < <(curl -fsSL \
	-H "Authorization: Bearer ${GITHUB_TOKEN}" \
	-H "Accept: application/vnd.github+json" \
	https://api.github.com/repos/MystenLabs/sui/releases |
	jq -r '.[] | select(.tag_name | startswith("testnet-")) | .tag_name')

if [ -z "$SUI_VERSION" ]; then
	echo "Failed to detect testnet version, falling back to $FALLBACK_VERSION"
	SUI_VERSION="$FALLBACK_VERSION"
fi

echo "Installing Sui binary ${SUI_VERSION}..."

wget -q "${S3_BASE_URL}/${SUI_VERSION}/sui" || {
	echo "Failed to download Sui ${SUI_VERSION}"
	exit 1
}

sudo chmod +x sui
sudo mv sui /usr/local/bin/

sui --version

echo "SUI_BINARY=/usr/local/bin/sui" >>"$GITHUB_ENV"
