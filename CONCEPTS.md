# Concepts

Shared domain vocabulary for this project: entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then accretes as ce-compound processes learnings; direct edits are fine. Glossary only, not a spec or catch-all.

## Initial Block Download

### Initial Block Download (IBD)
The one-time bulk process of downloading and fully validating the chain from the start point (genesis, or a trusted snapshot) up to the network's current best tip; run when a node first starts or has fallen far behind normal operation. Its dominant cost at high block heights is download bandwidth, not local validation.

### Apply frontier
The greatest height up to which every block has been validated and committed to the UTXO set in one unbroken run — the contiguous tip of *applied* state, distinct from the header tip (how far valid headers are known) and from blocks already downloaded but not yet applied because an earlier block is still missing.

The frontier advances only over a contiguous run: a single missing or late block at the frontier stalls all apply progress even when many later blocks are already in hand. This is why a slow peer assigned the frontier block can freeze sync.

### Download window
The bounded set of blocks permitted to be in flight — requested from peers but not yet received — at any moment during sync. It is capped jointly by a block count and an estimated-bytes budget and is refilled as blocks arrive.

### Staller
A peer that holds up the apply frontier by having been assigned a frontier block it then fails to deliver promptly.

Stalling detection is the mechanism that identifies the staller and, in the reference (Bitcoin Core) design, disconnects it so another peer can supply the blocking block. Without stalling detection, a staller freezes apply progress until a long fixed timeout elapses.

### assumevalid
A validation mode that skips script-signature verification for blocks at or below a configured trusted height while still performing every other consensus check, used to accelerate IBD without abandoning validation; blocks above the height are fully verified.

## Consensus validation

### bitcoinconsensus
Bitcoin Core's script-verification engine, extracted as a C library and linked into bitcoin-rs as the default backend for **non-taproot** script verification; it performs the per-input signature and script checks (for non-taproot inputs) that assumevalid skips below the trusted height. Because it is Core's own compiled code, that path is byte-identical to Core and runs at Core's speed — so it is not a path on which bitcoin-rs can be faster than Core. Taproot inputs instead run the parallel Rust validation path's interpreter even on the default build, and any speed advantage over Core must come from non-script paths.

### bitcoinkernel
Bitcoin Core's consensus engine exposed as a fuller library than bitcoinconsensus, treated here as the consensus source of truth: when the parallel Rust validation path and the kernel disagree on whether a block or transaction is valid, the kernel wins. Built only in isolation — it cannot coexist with bitcoinconsensus in a single binary because their native Core symbols overlap.

### Parallel Rust validation path
bitcoin-rs's own Rust implementation of block and transaction validation, including a script interpreter, maintained alongside the C engines. Its binding invariant is byte-identical accept/reject decisions versus bitcoinkernel. It exists so the node is not wholly dependent on Core's C code, and it is where Rust-side script-path optimization actually has headroom — unlike the default bitcoinconsensus path.
