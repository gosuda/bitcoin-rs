# MuHash RPC campaign contract

The production full-UTXO query comparator. `gettxoutsetinfo` owns the measured
RPC arity. `tools/benchmark-campaign/muhash_rpc.py` owns trial transport,
campaign spawn, and receipt identity.

Owners:
- `crates/rpc/src/handlers/chain.rs` (`gettxoutsetinfo`)
- `tools/benchmark-campaign/muhash_rpc.py`

Operator procedure: [`docs/benchmarks/muhash-rpc.md`](../benchmarks/muhash-rpc.md).

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
pinned config into the workspace with `O_EXCL`, re-hashes that copy before
every spawn, and substitutes the copy path. Receipts keep the original
FileRef identity.

## Proven by

- `crates/rpc/src/handlers/chain.rs` test `gettxoutsetinfo_rejects_trailing_parameters`
- `crates/rpc/tests/handler_smoke.rs` test `gettxoutsetinfo_rejects_trailing_parameters`
- `tools/benchmark-campaign/test_muhash_rpc.py` tests
  `test_rpc_does_not_send_credentials_to_a_foreign_peer`,
  `test_readiness_rejects_a_listener_the_child_does_not_own`,
  `test_command_must_include_config_placeholder`,
  `test_pinned_config_copy_ignores_later_operator_path_writes`
