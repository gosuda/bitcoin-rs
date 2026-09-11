# Chainstate journal writer contract

**Contract:** `chainstate-journal-writer/v1.0.0`

This document is the normative contract for the writer tests in
`crates/node/src/chainstate_journal/writer/tests/`. Test names and comments
refer to the requirement IDs below; implementation details are not part of the
contract.

## Requirements

- **JW-BOOT-1**: opening a new writer uses the configured chainstate-journal
  defaults.
- **JW-REC-1**: on reopen, bytes after the durable head are ignored or
  truncated; an incomplete append can be retried without duplicating a record.
- **JW-ORDER-1**: appends are contiguous and failed or out-of-order appends
  block further apply until the gap is resolved.
- **JW-DUR-1**: the head advances only after the required storage flush and
  filesystem synchronization succeed; failed boundaries are retryable.
- **JW-ROT-1**: rotation preserves cursor invariants and a published head never
  names a missing segment.
- **JW-RET-1**: retention limits prevent apply until checkpoint compaction;
  successful compaction permits apply again.
- **JW-LIFE-1**: freeze, resume, and compaction failures leave the writer in a
  retryable state and successful lifecycle transitions preserve the contract.
- **JW-MARK-1**: clearing the full-revalidation marker is idempotent and a
  failed directory sync is retried.
- **JW-FAIL-1**: documented failpoints fail their named boundary without
  publishing an advanced head.

This is version 1.0.0 of the test contract. Changes to a guarantee require a
new version (or an explicit requirement revision) and corresponding test
review.
