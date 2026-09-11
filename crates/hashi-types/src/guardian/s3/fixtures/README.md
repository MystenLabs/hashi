# Guardian log fixtures

These fixtures are authentic S3 records for deployed Guardian log shapes that
current readers support. The compatibility test deserializes every fixture,
checks its schema version and message shape, round-trips its JSON, and verifies
its Guardian signature when the record is signed.

Organize fixtures by schema version and log type. Add a fixture when a reader
starts supporting a new `(schema version, message shape)` combination.

Keep fixtures unchanged apart from JSON whitespace:

- Pretty-print compact records of at most 5 KiB with `jq .` so they are easy to
  review.
- Store records larger than 5 KiB on one line with `jq -c .` to limit diff size.

The corpus follows the supported reader surface; diagnostic records that no
reader consumes do not require fixtures.
