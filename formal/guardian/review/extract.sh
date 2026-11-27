#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Translate the Guardian withdrawal handler and the rate limiter from Rust to Lean.
# The output is `no-review/HashiGuardian.lean`. Do not edit that file.
#
# Steps:
# 1. Copy the workspace.
# 2. Apply `sync-copy.patch` to the copy. The patch makes the handler sync.
# 3. Run Charon and Aeneas.
#
# Requirements: `charon` and `aeneas` from the Aeneas release in `README.md`.
# Set `CHARON` and `AENEAS` if the tools are not on `PATH`.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
charon="${CHARON:-charon}"
aeneas="${AENEAS:-aeneas}"
# Charon uses its own Rust compiler. A separate directory keeps the usual build cache valid.
target="${CHARON_TARGET_DIR:-$repo/target/charon}"
# The work directory has a fixed path, so that Cargo can use its cache again.
work="$target/extract-work"
copy="$work/workspace"

rm -rf "$work"
mkdir -p "$copy"

# 1. Copy the workspace.
rsync -a --exclude /target --exclude /.git --exclude /node_modules --exclude .lake \
  "$repo/" "$copy/"

# 2. Make the handler sync. `--fuzz=0` stops the script if a line of the patch does not match.
patch -p1 --fuzz=0 -d "$copy" <"$here/sync-copy.patch"

# 3. Run Charon and Aeneas.
#    `--sysroot default` uses the standard library files of the Rust toolchain.
#    With the Charon default, the C library of the dependency `crc-fast` does not link.
#    `--include` gives an item outside this crate its real body. A pattern `m::_::f` is each
#    method `f` in module `m`. The list is the path from the wire request to the outflow.
#    `--opaque` gives a function no body. The proof holds for each pure function in its place.
(
  cd "$copy/crates/hashi-guardian"
  CARGO_TARGET_DIR="$target" "$charon" cargo --preset=aeneas --sysroot default \
    --start-from 'crate::withdraw_mode::standard_withdrawal::standard_withdrawal' \
    --include 'hashi_types::guardian::limiter::_' \
    --include 'hashi_types::guardian::lifecycle::_' \
    --include 'hashi_types::guardian::StandardWithdrawalRequest' \
    --include 'hashi_types::guardian::_::utxos' \
    --include 'hashi_types::guardian::_::seq' \
    --include 'hashi_types::guardian::_::timestamp_secs' \
    --include 'hashi_types::guardian::{impl hashi_types::guardian::AddressValidation<_> for _}' \
    --include 'hashi_types::bitcoin::utxo::TxUTXOs' \
    --include 'hashi_types::bitcoin::utxo::OutputUTXO' \
    --include 'hashi_types::bitcoin::utxo::ExternalOutputUTXO' \
    --include 'hashi_types::bitcoin::utxo::check_output_address' \
    --include 'hashi_types::bitcoin::utxo::check_output_addresses' \
    --include 'hashi_types::bitcoin::utxo::_::new' \
    --include 'hashi_types::bitcoin::utxo::_::gross_outflow_amount' \
    --include 'hashi_types::bitcoin::utxo::{impl core::clone::Clone for hashi_types::bitcoin::utxo::InternalOutputUTXO}' \
    --include 'hashi_types::committee::SignedMessage' \
    --include 'hashi_types::committee::_::into_parts' \
    --include 'hashi_types::committee::_::message' \
    --include 'hashi_types::committee::_::new' \
    --include 'bitcoin_units::amount::Amount' \
    --include 'bitcoin_units::amount::_::to_sat' \
    --include 'bitcoin_units::amount::_::from_sat' \
    --include 'bitcoin_units::amount::{impl core::clone::Clone for bitcoin_units::amount::Amount}' \
    --include 'sui_sdk_types::address::{impl core::clone::Clone for sui_sdk_types::address::Address}' \
    --opaque 'crate::withdraw_mode::verify_hashi_cert' \
    --dest-file "$work/hashi_guardian.llbc" -- -p hashi-guardian --lib
)
"$aeneas" -backend lean -dest "$work/lean" -no-progress-bar "$work/hashi_guardian.llbc"
cp "$work/lean/HashiGuardian.lean" "$here/../no-review/HashiGuardian.lean"
echo "Wrote no-review/HashiGuardian.lean"
