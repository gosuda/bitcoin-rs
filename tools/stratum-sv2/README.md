# Embedded bitcoin-rs behind the SRI Stratum V2 stack

This regtest example runs the production `bitcoin_rs_node::Node` and its SV2
Template Distribution adapter in one process. The unchanged pinned SRI pool,
translator and two mining devices remain external. The adapter borrows the
existing `MiningControl`, retains `Arc<Candidate>` jobs, and submits native
blocks through canonical validation and publication. There is no internal
HTTP, JSON, transaction hex, `NodeState`, or `test-seam` dependency.

```text
device-direct-1 -- SV2 --+
                       +--> SRI pool -- TDP/Noise --> adapter + embedded Node
device-direct-2 -- SV2 --+                                  |
                                                     MiningControl
```

## Run

Requires Docker Compose and the repository checkout. From the repository root:

```sh
docker compose -f tools/stratum-sv2/compose.yaml up --build -d
docker compose -f tools/stratum-sv2/compose.yaml logs -f template-provider pool
# After repeated accepted solutions, stop and join workers, retaining data:
docker compose -f tools/stratum-sv2/compose.yaml down --timeout 30
```

The provider builds from the repository root with Rust 1.99 and the standalone
lockfile. It uses native validation and Fjall, and stores its regtest node in
the existing `bitcoin-rs-data` volume. Do not run the previous separate node
against that volume concurrently. No volume is reset by startup or shutdown.
The optional SV1 translator still listens on host loopback port 3333. Pool
monitoring remains on loopback port 9090. Device core counts are deliberately
small; increase them only for the test host's capacity.

The default Noise key is example material, unchanged from the previous
example. `config/pool.toml` pins its public key:
`9bWTZifgp9aVa23vtHqGT74UwK9bDRQxm77jf3u2tZ3ysM2ncMW`.
If `TP_PRIVATE_KEY_HEX` is overridden, update that pin from the provider's
startup log before reconnecting the pool. External SRI image and source pins
remain in Compose and `device/Dockerfile`.

The pinned CPU devices cache the pool's resolved address. If a restart changes
the pool container's IP, restart the devices after the pool is ready. Their
upstream shutdown does not handle SIGTERM; Compose can kill those device
processes after its timeout. The embedded provider handles SIGINT and joins
its node workers before exiting.

For a local build without Docker:

```sh
cargo run --locked --manifest-path tools/stratum-sv2/template-provider/Cargo.toml
```

Configuration: `TP_LISTEN` (default `0.0.0.0:8442`), `TP_PRIVATE_KEY_HEX`,
`TP_CERT_VALIDITY_SECS` (default `3600`),
`BITCOINRS_DATA_DIR`, `BITCOINRS_P2P_LISTEN` and `BITCOINRS_RPC_BIND`.
The normal node lifecycle binds its diagnostic RPC listener to an ephemeral
loopback port by default; mining never contacts it. The example network is
fixed to regtest. Standard output contains diagnostic job/submission
microseconds, canonical submission results, and the resulting applied height.

## Ownership and bounds

- The mining owner builds every candidate and decides what fits. A pool's
  `CoinbaseOutputConstraints` become a `CoinbaseBudget` on the typed template
  request. The owner selects transactions that leave that room in the
  coinbase, or answers with the generation's ordinary candidate when it already
  admits the budget. `Candidate::admits` is the one fit rule. The adapter owns
  no selector, headroom constant or second fit check; it calls `admits` once
  more before writing a job and closes the session if the owner's candidate
  fails it. No job is sent before constraints arrive.
- A dedicated OS thread long-polls the owner's ordinary template only to learn
  that the generation moved, using the owner's opaque template identity. It
  wakes the sessions and publishes nothing: its candidate is never sent to a
  pool. Tip and same-tip membership changes reuse existing generation
  publication; there is no timer-based template poll. Generation races during
  acquisition retry after 100 milliseconds with the last seen identity.
  Shutdown and other errors end the worker.
- Each session asks the owner for its own candidate when constraints arrive or
  change and after each wake. A request never long-polls and runs on one
  awaited blocking task; a connection has at most one. Distinct budgets on one
  generation are distinct owner candidates, but the owner walks the pool for at
  most one budgeted candidate at a time, with bounded waits and retries.
  A transient owner refusal (the generation moved, or another budgeted walk held
  the owner's slot for its whole wait) is retried after 100 milliseconds and
  stops on session shutdown. The owner gives no liveness guarantee under
  unbroken churn or contention: the pool then keeps the last job it received in
  full. A budget that cannot fit even an empty block (`coinbase reservation
  exhausts the … limit`) closes only that session; other sessions and the worker
  continue.
- Jobs are identified by the owner's candidate id. Sessions handed an equal id
  share one retained job and one TDP template id. The hub retains the 16 most
  recently issued jobs. Each session also pins the job it last delivered in
  full, so other sessions' jobs cannot evict the job its pool is working on.
  Resident jobs are therefore at most 16 plus one per session (eight sessions):
  an entry count, not a byte bound, since every job holds its candidate's
  transactions, and memory has not been measured.
- `RequestTransactionData` and `SubmitSolution` resolve the exact template id:
  the session's pinned job first, then the shared history, never a newer job.
  A job is pinned only after both of its messages are written; the previous job
  stays pinned until then, and a failed write closes the session. New
  constraints leave jobs already delivered unchanged and request a new one. A
  superseded job evicted from the history receives `template-not-found` for its
  transaction data, and a solution for it is not applied. TDP has no reply to a
  solution, so the provider logs a warning.
- At most eight pool sessions are served. Solution assembly/validation,
  transaction-data serialization and template requests run on awaited blocking
  tasks. Sessions finish them, including an outstanding template request whose
  connection has gone, before Node teardown; the owner's bounds make that wait
  finite. No blocking Node call runs on a Tokio I/O worker.
- Shutdown stops accepts, closes incomplete session reads, drains submissions
  and template requests, signals the normal node shutdown input, joins the
  long-poll worker, and calls consuming `Node::shutdown`. Compose uses SIGINT
  and a 30-second grace period.
- The exact Noise read future survives template refreshes. Cancellation on
  shutdown closes the entire connection; a partial record is never resumed with
  a new decoder. Writes have a deadline and a failed write closes the session.
- Coinbase prefix, version, sequence, locktime, required outputs and commitment
  come from the native candidate. The pool adds its payout outputs; native
  submission supplies the ordinary witness reserved value if required. The node
  owns actual fee accounting, transaction selection, PoW, consensus validation,
  mempool removal, tip publication and announcements. Superseded solutions get
  those same checks rather than an adapter-defined stale-job verdict.

## Validation and measurement

```sh
cargo test --locked --manifest-path tools/stratum-sv2/template-provider/Cargo.toml
cargo clippy --locked --manifest-path tools/stratum-sv2/template-provider/Cargo.toml --all-targets -- -D warnings
```

The public-Node test uses a real datadir without a mock or test feature. It
checks wire coinbase outputs, independent block merkle reconstruction, typed
submission/duplicates, same-tip mempool refresh through the worker's wake, a
valid superseded solution, stale-parent refusal, recovery from injected
generation races before the first wake and after it, and cancellation on
shutdown. Its 100-block history is required to spend a matured coinbase.
Hub tests check that equal owner identities share one job and that history stays
at 16 entries.

Focused localhost Noise tests drive real sessions over an embedded Node. They
hold back part of an encrypted request across a job refresh and verify the
completed request and next record decode. They pause a real native block
submission through the existing mempool observer, request session shutdown, and
verify submission drains and the block commits before Node teardown. They also
cover the budgeted and retained jobs:

- a budget the unconstrained candidate cannot spare gets a fitting job, and a
  second session with a looser budget keeps the unconstrained one;
- another pool issuing more jobs than the history retains evicts the first
  session's job from the history, yet that session still answers
  `RequestTransactionData` for it and its `SubmitSolution` reaches consensus;
  an evicted superseded id gets `template-not-found` and its solution is not
  applied to any other job;
- an unsatisfiable budget closes only its own session;
- a failed write leaves the previously pinned job in place.

The [retained interoperability run](evidence/interop.md) records an earlier
provider image with two real SRI devices, pool reconnect, and checkpoint
restore. It predates owner-budgeted jobs and pinned-job retention and has not
been repeated for them. It is functional evidence, not a comparative benchmark.

This is limited regtest interoperability support, not production pool
qualification or a mining-throughput claim. For before/after measurements,
build the RPC example from base revision `a11021788` in a separate checkout;
its adapter is removed here rather than kept as a second production path.
Use the same node validation engine/backend, candidate transactions, host and
external SRI pins. Capture raw timestamps and command/build identities, CPU,
allocations and peak RSS. Compare fresh and reused HTTP connections separately.
Job-write and canonical-submission durations are diagnostic spans; they do not
measure mutation-to-candidate or first P2P announcement latency and cannot
establish an end-to-end speedup. Memory for the retained jobs, the serialised
budgeted selection and its job lag, and read-guard contention remain
unmeasured; full matched percentile measurements are required before making
performance claims.
