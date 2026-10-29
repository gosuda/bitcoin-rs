# MuHash RPC campaign contract
Production full-UTXO comparator: `gettxoutsetinfo` owns arity; `tools/benchmark-campaign/muhash_rpc.py` owns transport, spawn, receipt identity. Owners: `crates/rpc/src/handlers/chain.rs`, `tools/benchmark-campaign/muhash_rpc.py`. Procedure: [muhash-rpc.md](../benchmarks/muhash-rpc.md).
## Clauses
### `MRPC-01`: Production triplet arity
`gettxoutsetinfo` accepts at most three parameters; measured call `["muhash", null, false]`; a fourth positional argument is `InvalidParams`.
### `MRPC-02`: Attested child owns the RPC connection
Before writing `Authorization`, the client matches the connection's unique ESTABLISHED loopback row (`/proc/net/tcp` or `/proc/net/tcp6`) inode in `/proc/<attested_pid>/fd` with matching starttime; an earlier LISTEN snapshot is not send-time proof.
### `MRPC-03`: Spawned `{config}` is the pinned bytes
Templates include `{config}`; `run_campaign` copies pinned config (`O_EXCL`, `0o400`), re-reads via `_read_regular_file`, re-hashes, seals into memfd, passes `/proc/self/fd/<n>`; binary `MFD_EXEC`, config `MFD_NOEXEC_SEAL`, pre-6.3 `EINVAL` falls back to `MFD_ALLOW_SEALING`; rename/write cannot change daemon bytes; receipts keep FileRef identity.
Proven by `gettxoutsetinfo_rejects_trailing_parameters`; `tools/benchmark-campaign/test_muhash_rpc.py`: `test_rpc_does_not_send_credentials_to_a_foreign_peer`, `test_readiness_rejects_a_listener_the_child_does_not_own`, `test_command_must_include_config_placeholder`, `test_pinned_config_copy_ignores_later_operator_path_writes`, `test_binary_snapshot_execs_and_config_snapshot_does_not`, `test_snapshot_falls_back_when_exec_flags_are_einval`, `test_verified_config_inode_survives_workspace_path_replace`, `test_spawn_reads_verified_config_after_workspace_replace`, `test_warm_campaign_agrees_across_all_backends`.
