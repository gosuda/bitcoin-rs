---
title: Exclude provably unspendable outputs from the UTXO set
date: 2026-07-29
category: docs/solutions/logic-errors
module: crates/node
problem_type: logic_error
component: utxo
symptoms:
  - OP_RETURN outputs remained in chainstate even though no transaction can spend them
  - Outputs with scripts above the consensus size limit remained in chainstate
  - Existing checkpoints could restore UTXO data written under the old admission rule
root_cause: missing_validation
resolution_type: code_fix
severity: high
tags:
  - utxo
  - unspendable-outputs
  - checkpoint-compatibility
  - script-size
---

# Exclude provably unspendable outputs from the UTXO set

## Problem

The block-apply path admitted every unspent output into `UtxoSet`. Outputs whose scripts start with `OP_RETURN`, and outputs whose scripts exceed `MAX_SCRIPT_SIZE`, can never be spent and must not occupy live chainstate.

Changing the admission rule also changes the meaning of a persisted UTXO snapshot. Loading a checkpoint written under the old rule would restore a validly encoded but semantically incompatible set.

## Symptoms

- `build_utxo_changes` created additions for `OP_RETURN` outputs.
- Scripts longer than 10,000 bytes remained in the UTXO set.
- The checkpoint loader could not distinguish legacy all-output snapshots from spendable-output snapshots.

## What Didn't Work

- Using `>= MAX_SCRIPT_SIZE` drops scripts of exactly 10,000 bytes. Bitcoin's rule is strictly greater than the limit; the boundary output remains spendable.
- Filtering only newly applied blocks leaves old checkpoints compatible at the byte level, so a restart can restore the excluded outputs.

## Solution

Reuse the consensus limit and reject only outputs that are provably unspendable while building block changes. The snippet shows the check as written for this fix; the filter now lives in `build_block_changes` (`crates/utxo/src/connect.rs`), which receives the limit as its `max_script_size` parameter, and `crates/node/src/apply.rs` passes `MAX_SCRIPT_SIZE`:

```rust
if txout.script_pubkey.is_op_return() || txout.script_pubkey.len() > MAX_SCRIPT_SIZE {
    continue;
}
```

Keep the strict boundary explicit in tests:

- `OP_RETURN` is excluded.
- A 10,000-byte script is retained.
- A 10,001-byte script is excluded.

Rename the checkpoint UTXO codec to `bitcoin-rs-utxo-spendable-v1`. A checkpoint carrying the previous codec now fails startup with an explicit datadir remove-and-resync instruction instead of restoring chainstate with obsolete admission semantics or retaining a validated-headers fallback.

## Why This Works

The UTXO set now represents only outputs that can still participate in a future spend. The filter uses the same `MAX_SCRIPT_SIZE` constant as consensus code, which prevents the node and validator from drifting at the size boundary.

The codec name binds persisted data to that semantic contract. Snapshot bytes written under the old contract are not silently accepted under the new one, even when their structure and digest remain valid.

## Prevention

- Test both sides of every consensus-size boundary, including the exact accepted maximum.
- Treat a change to UTXO admission semantics as a checkpoint codec change and
  require an explicit datadir resync when that codec is encountered.
- Keep the spendability filter in the block-to-UTXO change boundary so every storage and snapshot path sees the same set.
