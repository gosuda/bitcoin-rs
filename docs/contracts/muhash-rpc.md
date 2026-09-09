# MuHash RPC campaign contract

Target contract for the production full-UTXO query comparator.
`gettxoutsetinfo` owns the measured RPC arity and the coherent-view scan.
`tools/benchmark-campaign/muhash_rpc.py` owns trial transport, campaign
spawn, and receipt identity. The measured contract, cell evidence, and
acceptance rule live in
[docs/benchmarks/muhash-rpc.md](../benchmarks/muhash-rpc.md).

Owners:

- `crates/rpc/src/handlers/chain.rs` (`gettxoutsetinfo`)
- `tools/benchmark-campaign/muhash_rpc.py`

## Clauses

### `MRPC-01`: Production triplet arity

`gettxoutsetinfo` accepts at most three parameters. The measured call is
`["muhash", null, false]`. A fourth positional argument is `InvalidParams`.

### `MRPC-02`: Attested child owns the RPC connection

Before the trial writes the `Authorization` header, the client looks up the
unique ESTABLISHED loopback row for that connection in `/proc/net/tcp` or
`/proc/net/tcp6` and requires its inode in `/proc/<attested_pid>/fd`. The
attested starttime must still match. A LISTEN snapshot taken earlier is not
the send-time proof.

### `MRPC-03`: Spawned `{config}` is the pinned bytes

Campaign command templates include `{config}`. `run_campaign` copies the
pinned config into the workspace with `O_EXCL` and mode `0o400`. Every spawn
opens that copy through `_read_regular_file`, re-hashes the bytes, copies
them into a write-sealed memfd, and passes `/proc/self/fd/<n>` to the child.
Binary snapshots request `MFD_EXEC`; config snapshots request
`MFD_NOEXEC_SEAL`. `memfd_create(2)` returns `EINVAL` for unknown flag
bits; Linux 6.3 introduced those two flags, so older kernels retry with
`MFD_ALLOW_SEALING` only. A rename of the workspace pathname or a later
write to that inode cannot change the bytes the daemon reads. Receipts
keep the original FileRef identity.

### `MRPC-04`: Coherent whole-UTXO read

- The scan runs over one coherent view stamped with `ReadStamp`
  (`architecture.md`). The reported `height` and `best_block` come from
  the same stamp as the scanned set. The handler never composes the
  answer from a separately loaded tip and mutable UTXOs.
- The whole-UTXO read is ordered under the chain-transition reservation:
  a transition cannot commit between the stamp capture and the answer
  without invalidating the stamp. A scan that loses its view returns the
  declared typed `Retry` or `Unavailable`, never a mixed-tip answer.
- The scan is bounded and cancellable. Cancellation releases the retained
  snapshot. A public `gettxoutsetinfo` call cannot consume the CPU or
  memory quota needed to validate new blocks.

### `MRPC-05`: Cross-node commitment oracle

- The `muhash` commitment is compared against the pinned Bitcoin Core
  31.1 product oracle (`reference-set.md` `REF-02`) at the same pinned
  stop identity. Both nodes stand at the same tip. Identical `muhash`,
  `txouts`, and `total_amount` form the cross-node commitment. A version
  label alone is not the oracle.
- Core 31.1 performs `ForceFlushStateToDisk(false)` inside this RPC. That
  flush stays inside the measured interval because it is part of the
  call.

## Proven by

- `crates/rpc/src/handlers/chain.rs` test
  `gettxoutsetinfo_rejects_trailing_parameters` (existing)
- `crates/rpc/tests/handler_smoke.rs` tests
  `gettxoutsetinfo_rejects_trailing_parameters`,
  `gettxoutsetinfo_returns_real_utxo_counts`,
  `gettxoutsetinfo_empty_muhash_matches_core_digest`,
  `gettxoutsetinfo_production_triplet_matches_core_digest`,
  `gettxoutsetinfo_hash_type_modes_match_core_shapes` (existing)
- `tools/benchmark-campaign/test_muhash_rpc.py` tests
  `test_rpc_does_not_send_credentials_to_a_foreign_peer`,
  `test_readiness_rejects_a_listener_the_child_does_not_own`,
  `test_command_must_include_config_placeholder`,
  `test_pinned_config_copy_ignores_later_operator_path_writes`,
  `test_binary_snapshot_execs_and_config_snapshot_does_not`,
  `test_snapshot_falls_back_when_exec_flags_are_einval`,
  `test_verified_config_inode_survives_workspace_path_replace`,
  `test_spawn_reads_verified_config_after_workspace_replace`,
  `test_warm_campaign_agrees_across_all_backends` (existing)
- `docs/benchmarks/muhash-rpc.md` end-state cells (planned): cold and
  warm cache policy, comparison backends, and cancellation. All are
  `planned_not_executed` until the campaign runs.

## Vocabulary

[ReadStamp](../../CONCEPTS.md),
[chain-transition reservation](../../CONCEPTS.md).
