# hashi-monitor
A small bridge monitoring binary.

## Current scope (PR1)
- Defines normalized event types (BTC/Sui/Guardian) and emitted findings.
- Provides a minimal `Store` trait plus an `InMemoryStore` implementation.
- Implements correlation for BTC spends using **exact txid matching** only.
- Includes unit tests for the 3 mismatch classifications.

## Non-goals (PR1)
- No real collectors (Bitcoin/Sui/AWS S3).
- No persistent database backend.
- No automated remediation actions (halt/plug-off); findings only.

## Open questions
- Persistence backend: fjall vs sqlite (or other) for cursors + forensic queries.
- Join keys: txid vs request_id vs heuristic matching.
- BTC reorg handling and checkpoint semantics.
- Guardian log integrity details (ListObjectVersions, object lock, delete markers, signature verification).