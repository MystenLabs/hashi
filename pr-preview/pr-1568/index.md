# Introduction

*[Documentation index](/hashi/design/llms.txt) · [Full index](/hashi/design/llms-full.txt)*

> High-level overview of Hashi, the Sui native Bitcoin orchestrator that secures and manages BTC for use on Sui through threshold cryptography.

This is a high-level overview and design doc for `hashi`, the Sui native
Bitcoin orchestrator. The document is a living reference, updated as new
decisions and features land, with the goal of being a canonical description
of how Hashi is designed and operates.

## What is Hashi?

At a high level, `hashi` is a protocol for securing and managing BTC for use
on the Sui blockchain using threshold cryptography.

## How does Hashi manage Bitcoin on Sui?

The first feature that Hashi supports is the ability to deposit and withdraw
BTC to a pool managed through multi-party computation (MPC), with ownership
represented as a fungible `Coin<BTC>` (hBTC) on Sui.
