#!/bin/bash
set -euo pipefail

echo "==> Validating server and shared code..."

# Paths relative to enclave directory
SERVER_PATH="../src/server"
SHARED_PATH="../src/shared"

if [ ! -d "$SERVER_PATH" ]; then
    echo "❌ Error: Server code not found at $SERVER_PATH"
    echo "   Make sure you're running from the enclave directory"
    exit 1
fi

if [ ! -d "$SHARED_PATH" ]; then
    echo "❌ Error: Shared library not found at $SHARED_PATH"
    echo "   Make sure you're running from the enclave directory"
    exit 1
fi

# Check for required files
if [ ! -f "$SERVER_PATH/Cargo.toml" ]; then
    echo "❌ Error: Server Cargo.toml not found at $SERVER_PATH/Cargo.toml"
    exit 1
fi

if [ ! -f "$SHARED_PATH/Cargo.toml" ]; then
    echo "❌ Error: Shared Cargo.toml not found at $SHARED_PATH/Cargo.toml"
    exit 1
fi

echo "✅ Validated server and shared code"

# Create src directory if it doesn't exist
mkdir -p src

# Copy server and shared code
echo "==> Copying server and shared code..."
cp -r "$SERVER_PATH" src/
cp -r "$SHARED_PATH" src/

echo "✅ Build preparation complete!"
