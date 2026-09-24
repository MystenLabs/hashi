#!/usr/bin/env python3
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Generate the Sui genesis and the hashi key material for the Antithesis config image.

Adapted from sui-operations/docker/sui-antithesis/genesis/generate.py. Besides the
Sui validator configs and genesis blob, it writes `hashi-env.yaml`, which the
hashi-antithesis containers read: the genesis-funded account key, each
validator's account key (which doubles as its hashi operator key), and the test
guardian's BTC secret key.
"""

import argparse
import base64
import copy
import hashlib
import os
import re
import secrets
import shutil
import subprocess
import sys

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ED25519_FLAG = b"\x00"
# Far more SUI than the bootstrap and workload will ever hand out.
FUNDED_ACCOUNT_GAS = [750_000_000_000_000_000] * 2
ADDRESS_PATTERN = r"/(?:dns|ip4|ip6)/(?P<host>[^/]*)/(?:udp|tcp)/(?P<port>\d+)"


def deep_merge(base, overlay):
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def new_sui_account():
    """Return (keystore-encoded private key, 0x address) for a fresh Ed25519 key."""
    seed = secrets.token_bytes(32)
    public = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    address = hashlib.blake2b(ED25519_FLAG + public, digest_size=32).hexdigest()
    return base64.b64encode(ED25519_FLAG + seed).decode(), f"0x{address}"


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def write_yaml(path, data):
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)


def main(args):
    target = args.target_directory
    if os.path.exists(os.path.join(target, "genesis.blob")):
        print("configuration already exists, not generating")
        return
    work = os.path.join(target, "work")
    os.makedirs(work, exist_ok=True)

    genesis_config = load_yaml(args.genesis_template)
    funded_key, funded_address = new_sui_account()
    genesis_config["accounts"] = [
        {"address": funded_address, "gas_amounts": FUNDED_ACCOUNT_GAS}
    ]
    genesis_config["parameters"]["epoch_duration_ms"] = args.epoch_duration_ms

    validators = []
    for validator in genesis_config["validator_config_info"]:
        match = re.search(ADDRESS_PATTERN, validator["network_address"])
        validator["name"] = match.group("host")
        validators.append((match.group("host"), f"{match.group('host')}-{match.group('port')}.yaml"))

    genesis_yaml = os.path.join(target, "genesis.yaml")
    write_yaml(genesis_yaml, genesis_config)
    subprocess.run(
        ["sui", "genesis", "--from-config", genesis_yaml, "--working-dir", work, "-f"],
        check=True,
    )

    overlay = load_yaml(os.path.join(BASE_DIR, "overlays", "validator.yaml"))
    hashi_validators = []
    for index, (name, config_file) in enumerate(validators, start=1):
        config = load_yaml(os.path.join(work, config_file))
        write_yaml(os.path.join(target, config_file), deep_merge(config, overlay))
        hashi_validators.append(
            {
                "name": name,
                "hashi-host": f"hashi{index}",
                "account-key": config["account-key-pair"]["value"],
            }
        )

    shutil.move(os.path.join(work, "genesis.blob"), os.path.join(target, "genesis.blob"))
    shutil.copy(os.path.join(BASE_DIR, "static", "fullnode.yaml"), target)
    shutil.rmtree(work)

    write_yaml(
        os.path.join(target, "hashi-env.yaml"),
        {
            "funded-account-key": funded_key,
            "validators": hashi_validators,
            # A uniformly random 32-byte value is a valid secp256k1 secret with
            # overwhelming probability.
            "guardian-btc-secret-key": secrets.token_hex(32),
        },
    )
    print(f"generated genesis in {target} (funded account {funded_address})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--genesis-template",
        default=os.path.join(BASE_DIR, "compose-validators.yaml"),
    )
    parser.add_argument("--target-directory", default=os.path.join(BASE_DIR, "files"))
    parser.add_argument("--epoch-duration-ms", type=int, default=600_000)
    main(parser.parse_args())
    sys.exit(0)
