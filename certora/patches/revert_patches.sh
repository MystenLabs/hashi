#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

git apply -R "$SCRIPT_DIR/upgrade.move.patch"
git apply -R "$SCRIPT_DIR/update_config.move.patch"
git apply -R "$SCRIPT_DIR/emergency_pause.move.patch"
git apply -R "$SCRIPT_DIR/proposal.move.patch"
git apply -R "$SCRIPT_DIR/proposals.move.patch"
git apply -R "$SCRIPT_DIR/reconfig.move.patch"
git apply -R "$SCRIPT_DIR/threshold.move.patch"
git apply -R "$SCRIPT_DIR/committee.move.patch"
git apply -R "$SCRIPT_DIR/deposit.move.patch"
git apply -R "$SCRIPT_DIR/withdraw.move.patch"
git apply -R "$SCRIPT_DIR/withdrawal_queue.move.patch"
git apply -R "$SCRIPT_DIR/bitcoin_state.move.patch"
git apply -R "$SCRIPT_DIR/deposit_queue.move.patch"
git apply -R "$SCRIPT_DIR/utxo_pool.move.patch"
git apply -R "$SCRIPT_DIR/utxo.move.patch"
git apply -R "$SCRIPT_DIR/treasury.move.patch"
git apply -R "$SCRIPT_DIR/config.move.patch"
git apply -R "$SCRIPT_DIR/versioning.move.patch"
git apply -R "$SCRIPT_DIR/committee_set.move.patch"
git apply -R "$SCRIPT_DIR/hashi.move.patch"
git apply -R "$SCRIPT_DIR/Move.toml.patch"
git checkout HEAD -- packages/hashi/Move.lock
