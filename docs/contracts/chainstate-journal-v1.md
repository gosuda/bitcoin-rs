# Chainstate journal writer contract
**Contract:** `chainstate-journal-writer/v1.0.0`; normative for `crates/storage/src/chainstate_journal/writer/tests/` (test names/comments cite IDs below; implementation is not contractual). Guarantee changes require a new version or requirement revision with test review.
## Requirements
**JW-BOOT-1**: new writer uses configured defaults. **JW-REC-1**: on reopen, post-head bytes ignored/truncated; incomplete append retried without duplication. **JW-ORDER-1**: appends contiguous; failed/out-of-order appends block apply and checkpoint compaction until resolved.
**JW-DUR-1**: head advances only after storage flush and filesystem sync succeed; failed boundaries retryable. **JW-ROT-1**: rotation preserves cursor invariants; published head never names a missing segment. **JW-RET-1**: retention limits block apply until checkpoint compaction; success re-permits apply.
**JW-LIFE-1**: freeze/resume/compaction failures leave retryable state; successful transitions preserve contract. **JW-MARK-1**: clearing full-revalidation marker idempotent; failed directory sync retried. **JW-MARK-2**: boot-replay-only compaction preserves marker; only completed recovery or ordinary replacement checkpoint retires it.
**JW-FAIL-1**: documented failpoints fail their named boundary without publishing an advanced head.
