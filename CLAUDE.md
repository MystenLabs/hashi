# Hashi

## Project Structure

Rust workspace with crates in `crates/`:

- `hashi` — main validator binary and CLI
- `hashi-types` — protobuf types
- `hashi-screener` — transaction screening
- `e2e-tests` — end-to-end test infrastructure + `hashi-localnet` binary

Move packages in `packages/`.

## Pre-commit Checks

Always run before committing:

```sh
make check-fmt   # rustfmt (imports_granularity=Item) + buf format
make clippy       # cargo clippy --all-features --all-targets
```

Full CI (includes tests):

```sh
make ci
```

## Formatting

Rust formatting uses custom config flags:

```sh
cargo fmt -- --config imports_granularity=Item --config format_code_in_doc_comments=true
```

Key rule: **one item per `use` statement** (no `use foo::{A, B};` — use separate `use foo::A; use foo::B;`).

## Git

Never add `Co-Authored-By` lines to commits. Do not credit Claude as a coauthor.

## Testing

```sh
make test         # cargo nextest run + doc tests
make test-move    # Move package tests
```
