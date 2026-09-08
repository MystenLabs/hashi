#!/usr/bin/env bash

set -euo pipefail

cd ~/hashi
HASHI_TART_TEST=1 ./key-provisioner/scripts/update-mac.sh
