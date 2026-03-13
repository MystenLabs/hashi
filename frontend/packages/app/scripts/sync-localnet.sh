#!/usr/bin/env bash
# Reads hashi-localnet state and writes .env.localnet for Vite
set -euo pipefail

# Resolve hashi repo root (four levels up from frontend/packages/app/scripts)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HASHI_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
STATE_FILE="${HASHI_LOCALNET_DATA_DIR:-$HASHI_ROOT/.hashi/localnet}/state.json"

if [ ! -f "$STATE_FILE" ]; then
  echo "No localnet state found at $STATE_FILE"
  echo "Start localnet first: hashi-localnet start"
  exit 1
fi

SUI_RPC_URL=$(python3 -c "import json; print(json.load(open('$STATE_FILE'))['sui_rpc_url'])")
PACKAGE_ID=$(python3 -c "import json; print(json.load(open('$STATE_FILE'))['package_id'])")
HASHI_OBJECT_ID=$(python3 -c "import json; print(json.load(open('$STATE_FILE'))['hashi_object_id'])")
BTC_RPC_URL=$(python3 -c "import json; print(json.load(open('$STATE_FILE'))['btc_rpc_url'])")
BTC_RPC_USER=$(python3 -c "import json; print(json.load(open('$STATE_FILE'))['btc_rpc_user'])")
BTC_RPC_PASSWORD=$(python3 -c "import json; print(json.load(open('$STATE_FILE'))['btc_rpc_password'])")

ENV_FILE="$(dirname "$0")/../.env.localnet"

cat > "$ENV_FILE" << EOF
VITE_DEFAULT_NETWORK=localnet
VITE_SUI_RPC_URL=$SUI_RPC_URL
VITE_HASHI_PACKAGE_ID=$PACKAGE_ID
VITE_HASHI_OBJECT_ID=$HASHI_OBJECT_ID
VITE_BTC_RPC_URL=$BTC_RPC_URL
VITE_BTC_RPC_USER=$BTC_RPC_USER
VITE_BTC_RPC_PASSWORD=$BTC_RPC_PASSWORD
EOF

echo "Wrote $ENV_FILE:"
cat "$ENV_FILE"
