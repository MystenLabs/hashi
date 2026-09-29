# Draft: sequence, withdrawal-ID, and date indexes for Guardian withdrawals

Status: design for discussion; this document changes no runtime behavior.

The aim is to make sequence conflicts detectable at commit time, make proxy
lookups by withdrawal ID (`wid`) direct, and preserve efficient time-based
monitoring. This is an alternative to the smaller pre-withdrawal S3 state check
in [PR #1285](https://github.com/MystenLabs/hashi/pull/1285), not a dependency of it.

## Proposed records

Use one authoritative sequence record and two derived indexes per withdrawal.
All three must be durable before a successful RPC response or the next withdrawal.
The exact prefix names and schema version below are provisional.

| Role | Proposed key | Contents |
| --- | --- | --- |
| Authoritative sequence log | `withdraw-v2/seq/{reverse_seq:020}.json` | Full signed withdrawal record, including `wid`, transaction/signatures, timestamp, session, request certificate, and post-withdrawal limiter state |
| Withdrawal-ID index | `withdraw-v2/wid/{wid}.json` | Reference to the authoritative record and its content digest |
| Date index | `withdraw-v2/date/YYYY/MM/DD/HH/{seq:020}.json` | The same reference, under the hour derived from the authoritative record's signed timestamp |

`reverse_seq = u64::MAX - seq`: fixed-width encoding makes ascending S3 listings
return the highest committed sequence first. The sequence key must not include
a session ID, date, or `wid`: competing sessions must address the same key.
Keys live in one fixed, independently approved deployment namespace.

The references are discovery hints, not independent attestations. A reader must
fetch and verify the authoritative record, its exact S3 key and history, and the
expected index key derived from its authenticated contents. A digest alone does
not establish trust. References can be generated deterministically by any
recovering enclave without the original enclave's signing key. In particular,
we cannot just copy today's signed log to a different key: its signature binds
its intended object key, and existing readers reject relocation.

The `wid` index is a singleton because this design makes Guardian withdrawals
idempotent by `wid`. This is a deliberate change from today's Guardian behavior,
which can consume a new sequence for a retry of the same withdrawal ID. The
proxy already attempts to provide idempotency by `wid`.

## Required withdrawal-ID invariant

One `wid` has at most one committed signing result across all sequences,
sessions, and restarts. A matching retry returns the exact stored BTC signatures
without signing again or consuming allowance. A different sequence is not a new
authorization for the same ID. Different transaction contents under the same ID
are rejected.

All three withdrawal logs are long-lived. In particular, retain a durable,
non-reusable `wid` binding and its original signing result for the full lifetime
in which that ID can be submitted; do not expire them while the ID remains valid.
A migration must preserve these bindings and results. Retention is an explicit
design assumption, but does not alone prove that an untrusted operator cannot
hide a record from readers.

Here, "once" means one committed/released signing result. A crash after computing
a signature but before any durable write cannot prove that the cryptographic
operation never happened. Literal at-most-once computation would require a durable
reservation before signing and a policy for a crashed reservation with no result;
that is a separate, stronger requirement to discuss if intended.

## Withdrawal handling

Authenticate the request, then hold the local limiter mutex across lookup,
validation, signing, all three durable writes, and local state publication.

1. Look up the request's `wid` index. If it exists, verify its authoritative
   record and compare the requested transaction and signing context with that
   record. A matching withdrawal returns the stored BTC signatures without
   consuming allowance again, even if the retry supplies a different sequence
   or attempt timestamp. Reusing a `wid` for different transaction contents is
   an error. Do not establish equivalence from the identifier alone.
2. For a new `wid`, require the requested sequence to equal the local next
   sequence, validate request time, and calculate the limiter transition.
   An existing authoritative record for that sequence is a conflict unless it
   is the matching previously committed withdrawal, in which case complete
   recovery/repair rather than consume again.
3. Construct the complete authoritative record and conditionally create its
   sequence key. Exactly one competing record should be able to commit to a
   sequence, subject to the storage requirements below. A pre-read is not the
   exclusion mechanism; the conditional commit is.
4. Create the `wid` reference, then the date reference. Retries write the same
   deterministic bytes. Existing matching references are success; different
   references are conflicts. Do not silently overwrite them.
5. Publish the new local limiter state and return the response. Do not process
   another withdrawal until all indexes for this one are durable.

Once the authoritative record is durable, allowance is consumed, even if an
index write or the RPC response subsequently fails. The record already contains
BTC signatures accessible to a bucket reader; withholding the RPC response does
not mean the transaction cannot be spent. Never roll back the limiter transition
just because index completion failed. A failure after committing the sequence
record must stop further serving until recovery resolves the committed state.

A same-`wid` retry must return the original stored BTC signatures, not compute
new signatures even for an identical transaction. The exact
replay envelope needs to be specified: retain the original BTC signatures and
transaction, while preserving the RPC's session-signature requirements. Reusing
an expired certificate or an old session's outer response as though it were a
fresh response is not part of this proposal.

## Restart and partial-write repair

Keep the existing initialization and activation authorization checks. Before
serving, discover and verify the latest authoritative sequence record; recover
limiter state from it, not from either secondary index. Derive both expected
references from that record, verify any existing references, and create missing
ones idempotently. Only then expose the enclave as active.

| Last completed durable step | Recovery action |
| --- | --- |
| None | No committed withdrawal to recover |
| Sequence record only | Recover its post-state; create both indexes |
| Sequence record and `wid` index | Recover its post-state; create the date index |
| All three records, response lost | Recover its post-state; replay a matching retry by `wid` |
| Write acknowledgment lost | Read the exact record and compare contents; an unknown outcome must not be treated as absence |
| Conflicting index contents or unverifiable canonical record | Refuse activation/serving and report the conflict |

Repairing only the latest sequence is justified only under an explicit invariant:
no writer may advance to the next sequence before all earlier indexes are
complete, and every replacement must repair the preceding committed record
before serving. This must hold across concurrently live sessions, not merely
inside one process. Prove this invariant with the sequence-commit rules before
relying on a one-record repair bound.

If indexes can lag multiple commits, if a migration starts with incomplete
indexes, or if older indexes can be removed after completion, latest-only repair
is insufficient. Recovery then needs a verified checkpoint and replay range, or
a full rebuild. Index retention must therefore match the promised recovery and
lookup window. Restart repair does not prove that every historical index is
present against an operator allowed to delete older entries.

## Reader behavior

- **Guardian recovery:** list the sequence namespace newest first, authenticate
  the candidate and its history, recover state, and repair its indexes. Fetch
  and verify what is actually committed; do not accept a key name alone.
- **Guardian retry:** resolve the `wid` index and validate the transaction before
  replaying signatures. A missing index is not proof of no prior commit until
  the partial-write invariant and recovery rules above establish completeness.
- **Proxy:** directly get `wid/{wid}.json`, fetch its canonical record, and apply
  the existing transaction/signature checks. A missing index during an incomplete
  commit must trigger recovery/reconciliation or an unavailable response, not
  blind forwarding. Define a concrete fallback before replacing today's scan.
- **Monitor:** list date partitions, resolve references, and verify canonical
  records. A committed withdrawal may precede its date index, so the monitor
  must not silently advance a complete-through watermark past an unindexed
  commit. A sequence-log reconciliation pass or a proven index-completion bound
  is required. Date partitions still depend on signed enclave timestamps.

## Storage assumptions that must be resolved

S3's `If-None-Match: *` chooses one winner among concurrent writes to the same
currently occupied key. It is not, by itself, a permanent "this sequence has
never been used" primitive. In a versioned bucket a current delete marker makes
that conditional create eligible again. Object Lock protects retained object
versions; it does not by itself prohibit creating delete markers.

Our bucket operator is untrusted. Before claiming that this design prevents
sequence reuse, specify how sequence keys and `wid` bindings cannot be hidden/replaced/reused,
including after retention expiry. A bucket policy controlled by that same
operator is not an independent guarantee. Existing version-history checks remain
necessary, but a check followed by a write is not atomic. Nor does checking
history after publishing a record necessarily undo the exposure of its BTC
signatures. This is an unresolved security requirement, not something the key
layout alone fixes.

Within a namespace that actually enforces non-reusable sequence commits, the
conditional commit closes the two-enclave same-sequence race left by a pre-read
check. It does not replace request authorization, constrain clock-driven token
refill, or prove every aspect of lifecycle fencing safe.

## Implementation and validation plan

1. Specify authoritative-record and index schemas, canonical key derivation,
   pointer validation, `wid` transaction equivalence, and replay response format.
2. Specify conditional-write conflicts and unknown-outcome handling, including
   hostile versioning operations and signature exposure at the commit boundary.
3. Implement serialized commits and restart repair, then update Guardian,
   proxy, and monitor readers together. Decide how index completeness is exposed
   to live readers before allowing them to infer absence.
4. Add deterministic Rust-generated fixtures covering every new record variant.
   Preserve supported existing fixtures; define a versioned migration/cutover
   rather than silently changing their key/signature semantics.
5. Exercise crashes before and after each write, lost acknowledgments, identical
   retries, conflicting `wid`/sequence records, and two competing enclave sessions.
   Test missing older indexes, delete markers, overwrites, retention expiry,
   and failed or interrupted repair. Assert that committed allowance is never
   refunded and indexes never cause a different transaction to be replayed.

Accepted requirements: one signing result per `wid`, replay of the original
signatures, and long-lived retention of all three withdrawal logs.

Remaining decisions for review: choose reference indexes versus full record
copies; settle non-reusable sequence and `wid` storage and reader completeness;
then decide whether the added write/recovery protocol is preferable to today's
layout. No implementation or rollout is proposed until those decisions are settled.

## References

- [AWS conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- [AWS Object Lock considerations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html)
- [Guardian log schema fixture policy](../crates/hashi-types/src/guardian/s3/fixtures/README.md)
