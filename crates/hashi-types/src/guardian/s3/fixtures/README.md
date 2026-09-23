# Guardian log fixtures

`v1/` contains deterministic dummy records for the single log schema introduced
at the testnet wipe. These replace the old deployed V1/V2 compatibility fixtures;
they are not records from a running guardian.

The corpus covers all 16 cases, including both ceremony-proposal variants and
both ceremony/withdraw deployment summaries in OI records. Records use the public test signing key seed `[21u8; 32]`, timestamp
`1700000000000`, and an all-zero suffix wherever a writer would normally choose
a random failure suffix. Every signed record has a
valid Guardian signature. Attestation bytes, encrypted shares, and other nested
mock payloads are dummy data; these fixtures do not establish Nitro attestation
or end-to-end protocol validity.

Generate the JSON files and print their contents with Rust, from the repository
root:

```sh
cargo test -p hashi-types regenerate_log_fixtures -- --ignored --nocapture
```

The ignored generator uses the same dummy messages as the writer round-trip
test. `dummy_log_fixtures_round_trip_and_verify` checks the checked-in JSON
against those messages, round-trips it, and verifies Guardian signatures.
The testnet wipe establishes a fresh V1 baseline: pre-wipe records and signatures
need not remain readable. Regeneration is allowed while establishing this baseline.
After deployment, preserve the existing fixtures and signatures as described below.
Keep files pretty-printed with a final newline, organized by log type under the
corresponding schema-version directory.

## Corpus maintenance policy

Use generated dummy data as the compatibility baseline; do not wait for deployed
records. Cover every supported `VersionedLogMessage` schema, each of its
log-message variants, and every variant of its nested log-message enums,
including success/failure and new-key/rotation cases.

After this baseline is deployed:

1. Preserve existing fixtures and their signatures unchanged. Do not regenerate
   them to accommodate a change that breaks reading or verifying existing records.
2. Add a separate fixture corpus for every new schema version, covering all of
   its log-message variants, while retaining fixtures for supported older versions.
3. Whenever an optional field is added, add fixtures covering both its absence
   and a populated value. An optional field can stay within the same schema only
   if existing records still deserialize and their original signatures verify;
   JSON optionality alone does not establish this compatibility.
4. For changes to fields, variants, or Serde/BCS representations that cannot
   preserve that compatibility, introduce a new schema version and its fixtures.
5. Update the Rust dummy cases and exhaustive variant coverage in the same change.
   Generate new cases at distinct paths and review the diff to ensure existing
   fixtures remain unchanged. Extend the fixture checks to read and verify both
   the retained records and the new cases.

Generation is deliberate: ordinary test runs must only read the corpus, so an
accidental schema change fails instead of silently rewriting the baseline.
