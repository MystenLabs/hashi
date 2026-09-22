# Guardian log fixtures

`v1/` contains deterministic dummy records for the single log schema introduced
at the testnet wipe. These replace the old deployed V1/V2 compatibility fixtures;
they are not records from a running guardian.

The corpus covers all 15 log-message shapes, including both ceremony-proposal
variants. Records use the public test signing key seed `[21u8; 32]`, timestamp
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
Regenerate only for an intentional schema change and review the resulting diff.
Keep files pretty-printed with a final newline, organized by log type under
`v1/`.

## Corpus maintenance policy

Use generated dummy data as the compatibility baseline; do not wait for deployed
records. Cover every supported `VersionedLogMessage` schema, each of its
log-message variants, and every variant of its nested log-message enums,
including success/failure and new-key/rotation cases.

Whenever a log field is added, removed, renamed, or changes type, or its Serde/BCS
representation changes:

1. Update `dummy_log_messages` with representative values for the changed fields
   and add cases for any new variants.
2. Update the exhaustive `fixture_name` matches when variants change.
3. Run the Rust generator and commit the regenerated corpus with the code change.
4. Review the JSON and signature changes as part of the schema change. CI checks
   the corpus against the Rust types and verifies the signed records.

Generation is deliberate: ordinary test runs must only read the corpus, so an
accidental schema change fails instead of silently rewriting the baseline.
