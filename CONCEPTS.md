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
