#!/usr/bin/env bash

set -euo pipefail

echo "Fetching latest main"
git fetch origin main

echo "Checking out main"
git checkout main

echo "Recent commits:"
git log --oneline -5
