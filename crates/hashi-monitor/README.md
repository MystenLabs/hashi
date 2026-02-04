# hashi-monitor
A small bridge monitoring binary.

## What it does?
- Defines normalized event types (BTC/Sui/Guardian) and emitted findings.
- Provides a minimal `Store` trait plus an `InMemoryStore` implementation.
- Implements safety checks using **exact txid / wid matching** only.
