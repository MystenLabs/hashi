# Overview

This is a high level overview and design doc for `hashi` the Sui native Bitcoin
orchestrator. This is intended to be a living document that should be updated
as new decisions and features are made with the goal of this being a canonical
description for how hashi is designed and operates.

At a high level `hashi` is a protocol for securing and managing BTC for use on
the Sui blockchain leveraging threshold cryptography.

The first feature that hashi supports is the ability to deposit and withdrawal
BTC to a managed pool with ownership represented as a fungible `Coin<BTC>` on
Sui.
