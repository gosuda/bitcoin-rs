# Better tasting and efficient index design and abstractions

Status: ideation complete; intent selection pending.

The useful direction is less duplicated resolution policy and less repeated query work. A new index framework is not justified by this review.

This document contains 19 candidates: 4 survivors and 15 rejections. These are design options, not approved changes. No source code, tests, database contents, measurements, or publication were changed for this brainstorm.

## Grounding

Source: the integrated worktree at `fc179042a55f33a896f397294f1e7948c12f4094`. All source paths below are relative to that worktree. The root listing contains no `STRATEGY.md`.

The brainstorm reused the completed index, snapshot, and storage-memory surveys. Five read-only passes grounded ownership, historical coverage, retained work, storage layout, and recovery. Three generators produced the pool. One critic assessed every candidate. One independent reviewer supplied the final survivor set and rejection reasons.

### Constraints already selected

- Provide eventual complete canonical transaction and script history, including the prefix before the snapshot base.
- Keep mining readiness separate from historical-index readiness.
- Keep one production index mutation owner.
- Limit decoded spent-script anchors to each parallel block-preparation operation. This direction was selected before this brainstorm.
- Preserve consensus, recovery, exact identity checks, and honest query answers.
- Do not infer permission for public-interface removal, format migration, pruning, a database replacement, or a performance regression.

### What the current modules own

| Module or path | Grounded fact | Source |
|---|---|---|
| Index writer | Checks contiguous preparation and publishes rows, format, watermarks, and consumer cursor through a fenced durable write. This module earns its complexity. | `crates/index/src/index/write.rs:385-470`; `crates/index/src/index/state.rs:427-464` |
| Runtime query engine | Owns health checks, coherent snapshots, query budgets, readiness, coverage floors, and before/after state checks. | `crates/index/src/runtime/query.rs:303-397` |
| Alternate reader resolvers | Resolve the same lossy prefix rows but differ from the runtime engine in validation, budgets, incomplete-history handling, and spending composition. No production caller was found in the inspected crates. External consumers remain unknown. | `crates/index/src/index/reader.rs:168-269,292-401`; `crates/index/src/runtime/query/transactions.rs:72-89,200-213` |
| History representation | Watermarks and coverage floors are separate facts. A zero floor alone does not prove readiness. ScriptLive state is not historical event coverage. | `crates/index/src/index/capability.rs:6-34,352-378`; `crates/index/src/runtime/query.rs:348-370` |
| Historical scheduling | The worker follows the applied tip. Historical validation does not dispatch ordinary index follower events. Existing floor anchoring does not by itself meet the selected complete-history target. | `crates/node/src/state/index.rs:117`; `crates/node/src/sync.rs:163-172`; `crates/node/src/snapshot.rs:210-213` |
| Query work | A history query can revisit a block through funding and spending resolution. Position reads reduce work but do not replace exact checks or full-block fallback. | `crates/index/src/runtime/query/scripts.rs:65-168`; `crates/index/src/runtime/query/transactions.rs:28-119` |
| Row ordering | History rows support sorting and deduplication. ScriptLive put/delete order carries meaning and must remain intact. | `crates/index/src/index/rows.rs:53-96,171-182` |
| Retained work | Bodies, decoded anchors, prepared rows, and the admitted batch have different lifetimes. Their individual limits do not establish a total RSS bound. Merged rows and encoded batch bytes can coexist. | `crates/index/src/runtime/catch_up.rs:228-303,454-476`; `crates/index/src/index/prepared.rs`; `crates/index/src/index/write.rs:416-448` |

No query-frequency distribution, peak-memory result, or latency improvement was measured. Large backend constructor cache defaults are not extra live allocations: runtime construction passes configured shares. Frozen backend and performance results remain unchanged.

### Terms

A module has an interface and an implementation. Its interface includes the facts callers must know, not only Rust method declarations. A seam permits substitution where behavior varies. Depth means useful behavior hidden behind a small interface. Removing a trait does not improve depth if its responsibilities merely move into callers.

## Generation axes

| Axis | Frame | Question |
|---|---|---|
| A | Caller knowledge and locality | Which repeated policy can disappear, rather than move behind another trait? |
| B | Useful query work | Which repeated lookup or decode can be removed without changing exactness, budgets, or disk format? |
| C | Lifecycle and resource ownership | Which state or retained work is essential for recovery, and which proposed simplification would duplicate it? |

The pool included opposing structures. Candidates were not guaranteed a place. The final reviewer could reject a proposal even when it contained a useful smaller observation. Rejected proposals were not silently rewritten into new candidates.

## Survivors

### A2 — Give unavailability a typed cause

**Idea.** Replace free-text discrimination inside `TxQueryError::Unavailable` with explicit causes. Keep the human message as rendering. Causes can distinguish uncovered history, exhausted query work, a disabled capability, and unavailable filter history.

**Why it survives.** Those causes already exist in the implementation. A typed vocabulary makes caller handling deliberate and reduces reliance on message text. It does not require new durable state or a disk-format change.

**Evidence.** `crates/index/src/query_api.rs:48-56`; `crates/index/src/runtime/query.rs:276-321`; `crates/index/src/runtime/query/transactions.rs:200-212`; `crates/rpc/src/error.rs:121-137`; `crates/index/src/lib.rs:37-41`.

**Important correction.** An enum cannot enforce the rule that an unproven absence must never return `None`. The query branches still own that rule. The value here is explicit causes, not a new correctness proof.

**Cost and gate.** This changes a public Rust error shape. Message text is also observable. Actual consumers and the desired wire mapping must be identified before approval. A machine-readable wire field is a separate contract decision, not an automatic consequence.

**Intent question.** Do real clients need to distinguish these causes programmatically, or should this wait for such a consumer?

### A7 — Keep one exact-resolution owner, if caller obligations permit

**Idea.** Keep the runtime query engine as the exact-resolution owner. Propose retiring the alternate `Indexer::resolve_*` path only after each real caller obligation is resolved. Do not merge strict and lenient behavior into a policy-driven resolver.

**Why it survives.** The two paths implement different meanings of a complete answer. The reader can skip an unresolved height; the engine reports unavailability. The engine also owns readiness, work bounds, and position validation. Removing the alternate policy would remove duplicated knowledge, not just forwarding methods.

**Evidence.** `crates/index/src/index/reader.rs:168-269,292-401,434-458`; `crates/index/src/runtime/query/transactions.rs:72-89,200-213`; `crates/index/src/runtime/query/scripts.rs:113-168`.

**Cost and gate.** This is a possible public-surface removal. No in-tree caller is not proof that no external caller exists. A real offline or repair consumer may need the bare-reader contract. If that obligation cannot move without weakening the engine, retain the existing path. Do not add a watermark-free engine mode to make retirement appear complete.

Primitive row scans and `BlockSource` remain separate from this proposal. Existing test and benchmark obligations must move to the retained interface or be retired with the behavior they protect. A compatibility wrapper is not the selected structure.

**Intent question.** Is a separate lenient, offline resolution path an intended product capability, or should exact query answers have one owner?

### B1 — Reuse verified full blocks within one query

**Idea.** Use a query-scoped, byte-capped memo keyed by height and block hash. Reuse a verified decoded block when that same query reaches it again.

**Why it survives.** Funding fallbacks and spending lookups can read and decode the same block more than once. Query-local reuse can remove those repeated operations without a durable cache, a new disk format, or a process-wide invalidation protocol.

**Evidence.** `crates/index/src/runtime/query/transactions.rs:28-57`; `crates/index/src/runtime/query/scripts.rs:77-78,104-105,141-147`; `crates/index/src/runtime/query.rs:105-193,303-397`; `crates/index/src/runtime.rs:265-273`.

**Cost and gate.** This exchanges repeated work for retained query memory. The memo needs an explicit byte cap. Hits must preserve the existing query-accounting behavior, including the charges that bound answers. Retain the tip/revision checks and hash-qualified identity. This is not permission to make previously refused oversized queries succeed by bypassing accounting.

No observed workload establishes how often the reuse occurs. Positioned range reads do not automatically benefit from a full-block memo. The proposal remains a resource tradeoff pending evidence, not a speed claim.

**Intent question.** Is bounded query-local reuse worth investigating, or should it wait until a representative query shows repeated full-block decoding?

### B2 — Resolve the block identity once per spending row

**Idea.** Resolve the height's block hash at row scope. Pass that identity through positional reads and full-block fallback instead of resolving it again for each position and again for fallback.

**Why it survives.** The repeated tree lookup is visible in the current control flow. This changes where an existing fact is obtained, not the row format or the meaning of a query result. The full-block fallback and exact checks remain.

**Evidence.** `crates/index/src/runtime/query/transactions.rs:10-26,91-119`; `crates/index/src/runtime/query/scripts.rs:104-105,113-148`; `crates/chain/src/tree.rs:424-440`.

**Cost and gate.** Internal call shapes change. The identity must remain tied to the captured query tip. The proposal removes repeated lookup work by structure, but its latency effect is unmeasured. It does not justify dropping fallback, validation, or query-budget checks.

**Intent question.** Should row-scoped block identity be the preferred query design, with one captured identity used throughout that row's resolution?

## Rejected candidates

| ID | Candidate | Final rejection reason | Evidence |
|---|---|---|---|
| A1 | One QueryReadiness value for queries and progress | The paths do not have the same policy. Progress reports watermark synchronization; queries also enforce floors, capability/filter state, and live-query exclusion. A unified decision would change semantics. Shared facts alone are a smaller, different proposal. | `crates/index/src/runtime/query.rs:290-460` |
| A3 | Split row scans from coverage metadata into another seam | Adds a trait and constructor obligations over the same snapshot without a demonstrated reduction in caller knowledge. The existing snapshot seam already hides coherent reads. | `crates/index/src/index/snapshot.rs:39-93,203-221`; `crates/index/src/runtime/query.rs:348-356` |
| A4 | Parameterize one resolver over strict and lenient policies | Turns different correctness contracts into policy choices at call sites. That moves the burden rather than removing it. The contingent single-owner alternative is clearer. | `crates/index/src/index/reader.rs:168-269,292-401`; `crates/index/src/runtime/query/transactions.rs:72-89,200-213`; `crates/index/src/runtime/query/scripts.rs:113-168` |
| A5 | Replace zero-floor semantics with a coverage enum | Readiness still needs the watermark. The proposed not-applicable state is not used by the two floored capabilities. No current decision disappears. | `crates/index/src/index/capability.rs:26-34,352-378`; `crates/index/src/runtime/query.rs:203-225,348-370` |
| A6 | Merge all body reads into IndexBlockSource | The paths use different identity authorities and error behavior. A mechanical merge could change which block is read during a reorg. Observed error swallowing is a separate issue, not proof that this merge is sound. | `crates/index/src/runtime/query.rs:19-60,96-104,230-302`; `crates/index/src/runtime/query/transactions.rs:40-57,91-119` |
| B3 | Merge history walks to avoid already-walked spender work | The funding transaction does not supply the spending transaction. The claimed avoided lookup is unsupported. Internal walk deduplication remains an ordinary refactor, not the proposed work reduction. | `crates/index/src/runtime/query/scripts.rs:171-254` |
| B4 | Stop ordered spender scans at the first proven height | The implementation already returns on a match and skips repeated heights. Absence at one height does not prove absence at later heights. The proposed extra type does not remove work. | `crates/index/src/runtime/query/scripts.rs:119-148`; `crates/index/src/index/reader.rs:72-76,149-156`; `crates/index/src/types.rs:7-15` |
| B5 | Make position validation canonical in the decoder | A validating borrowed decoder need not allocate, contrary to the critic's claim. Rejection rests on changed corrupt-row behavior and overlap with resolver ownership, not an unavoidable copy. All-or-scan already exists. | `crates/index/src/types.rs:353-383`; `crates/index/src/runtime/query/transactions.rs:72-89`; `crates/index/src/index/reader.rs:328-357` |
| B6 | Carry decoded transactions and avoid partial-position fallback | The decoded transaction is already passed onward. A failed position belongs to the current block, which is what fallback reads. Skipping the full rescan or changing a range-read failure to Unavailable changes the completeness/error contract. | `crates/index/src/runtime/query/scripts.rs:46-63,86-108`; `crates/index/src/types.rs:353-376` |
| C1 | Add durable positive coverage attestation | Duplicates floor and watermark facts. Reset removes the watermark, so a cleared floor does not make the index ready. Adds a format and coherence obligation without a demonstrated missing state. | `crates/index/src/index/capability.rs:26-34,352-378`; `crates/index/src/index/state.rs:561-574`; `crates/index/src/runtime/query.rs:357-370` |
| C2 | Recheck the history lease at each commit | The existing check runs per preparation chunk, not only at pass entry. No wrong committed row was established. Another check changes failure precedence and adds work without a demonstrated need. | `crates/index/src/runtime/catch_up.rs:99-126,223-233,385-391` |
| C3 | Retry missing target-chain nodes as a moved-tip case | The premise is false. Reorgs do not remove tree nodes; traversal uses parent links from the captured tip. Retrying a missing node would hide an inconsistent tree. | `crates/chain/src/tree.rs:424-440,669-676`; `crates/index/src/runtime/catch_up.rs:33-62`; `crates/index/src/runtime/reconciliation.rs:42-51` |
| C4 | Commit a whole bounded rewind under one fence | Enlarges the atomic write and retained work during a reorg. The caller's rebuild cutover and the writer's per-block atomicity have different jobs. No evidence requires combining them. | `crates/index/src/index/write.rs:470-548`; `crates/index/src/runtime/reconciliation.rs:276-290`; `crates/index/src/runtime.rs:293-300`; `crates/index/src/index/rows.rs:171-182` |
| C5 | Replace all retained-work caps with one byte ledger | A total budget is a real alternative, but no measured peak establishes its need. It changes packing policy and constructor obligations. The previously selected per-block anchor change does not authorize this broader design. | `crates/index/src/runtime.rs:300-321`; `crates/index/src/runtime/catch_up.rs:262-292,454-476`; `crates/index/src/index/write.rs:416-469` |
| C6 | Store one durable lifecycle phase | An explicit in-memory reconciliation phase already exists. Persisting it adds a second durable description alongside reset claims, revisions, and watermarks. Recovery should derive the phase from those authoritative facts. | `crates/index/src/runtime/reconciliation.rs:97-148`; `crates/index/src/runtime.rs:115-133`; `crates/index/src/index/state.rs:229-303,561-603` |

## Review corrections and limits

The final reviewer retained the bounded memo proposal after correcting the critic: its raw candidate already required a byte cap and budget charging on hits. The reviewer also rejected claims that a cause enum enforces correct absence handling, that shared validation necessarily loses zero-copy behavior, and that a reorg can remove a captured tree node.

The reviewer's introductory rejection count was a counting error. The complete ID ledger contains 19 unique candidates, with 4 survivors and 15 rejections. The counts in this document follow that ledger.

Some early resource follow-up citations came from the stale root checkout. The corrected grounding uses the integrated worktree. No measured gain is inferred from these source facts. Public-caller discovery and resource acceptance remain future obligations.

## Next step: clarify intent

My preference is to deepen the existing query module, not add an index framework. The single-owner direction offers the clearest reduction in duplicated policy. Row-scoped identity offers the clearest removal of repeated work. Typed refusal causes need a real caller requirement. Query-local memoization needs evidence that its memory tradeoff earns its place.

Which of the four survivors should shape the next design discussion? Choose any combination. Keep the public-removal gate explicit, and decide whether memoization should wait for a representative workload. `askme` can help resolve those tradeoffs. This document does not begin planning or implementation.
