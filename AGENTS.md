# AGENTS.md

Keep this file behavioral. Put architecture, implementation details, vocabulary,
and rationale in `CONCEPTS.md`, policies, or subsystem documentation.

## Rules

- Before changing a settled area, identify its current contract and owner. Read
  relevant concepts, subsystem docs, source, policies, tests, and issue or PR
  before adding another representation of the same knowledge.
- Give each invariant, state transition, validation rule, default, and durable
  representation one owner. The owner table in `CONCEPTS.md` (Owners) is the
  assignment; `docs/contracts/architecture.md` and the `g17` gate enforce the
  dependency direction. Do not add parallel state, shadow models, duplicate
  implementations, broad wrappers, or speculative abstractions. Add indirection
  only for a real boundary or a current consumer. `crates/chainstate` is the
  only permitted new crate.
- Route every transaction admission (RPC, P2P, Esplora, package, reorg
  re-admission) through the one node-constructed `MempoolGateway`, in named
  `Preview` or `Commit` mode. No second evaluator, forwarding handle, or
  caller-side context resolution.
- Hold the lock order: acquire the chain-transition reservation before the pool
  chain-change fence. Never hold the mempool write lock during script
  verification, network I/O, fsync, or callbacks. Never await while holding a
  non-async mutex guard. Copy or retain owned facts, then release locks.
  Deliver observer callbacks outside all domain locks.
- Commit durably in this order: append body and undo frames, sync files and
  directories, apply one atomic coins-and-head batch, wait for the backend's
  durable completion, then publish the stable generation. A durable head never
  references an unsynced body or undo range. Disconnect is the exact inverse of
  connect. A failed transition leaves the fence closed until explicit recovery;
  no guard destructor reopens it.
- Change durable formats by fresh replay only: increment `CURRENT_SCHEMA` for
  authoritative chainstate bytes, keep no translator or legacy reader, and
  require an explicitly named fresh datadir. Existing operator datadirs stay
  untouched. Estimator, discovery, and index formats carry owner-local versions
  and never fail authoritative startup; a rejected owner-local file stays in
  place until an authorized rebuild.
- Validate with strict-Rust cryptography and the native engine. `bitcoinkernel`
  is an explicit opt-in oracle in its own build lane, never a silent fallback.
  Remove superseded paths, interfaces, and compatibility scaffolding in the same
  cut that makes the replacement authoritative: migrate every caller, keep no
  shim, alias, re-export, or compatibility flag. Stop a cut on any public
  boundary not listed in the approved break set.
- For persistence changes, review affected readers and writers together. Make
  ownership, commit point, durability, recovery, and failure classification
  explicit.
- For every TLS path, use Rustls with default features disabled and a reviewed
  non-C crypto provider, and keep the native-TLS/C-provider family in `deny.toml`
  complete, because Rustls and adapter feature defaults can reintroduce AWS-LC,
  ring, OpenSSL, or platform TLS transitively.

## Verification

- Verify protocol and compatibility changes against the pinned `ReferenceSet`:
  independent specifications, the Core 31.1 release binary, vectors, and
  observable public-process behavior. A version label is not a reference.
  Previous bitcoin-rs code is a temporary comparison control only.
- Unavailable is not empty. Unverified is not supported. Unknown is not false.
  A missing reference binary, corpus, consumer pin, digest, or hardware target
  blocks its gate with the missing identity named; it never passes by skip.
- Keep permanent tests and fixtures only for named current contracts. Discard
  old implementations, harnesses, corpora, outputs, and other development
  evidence unless they independently protect a current contract.
- Judge performance end-to-end across elapsed time, CPU, memory, and I/O, using
  matched workloads, validation, data sources, hardware, and resource limits.
  Keep physical and logical storage ledgers separate. Promote a default, SIMD
  kernel, backend, or release only with the stated evidence; a schema-valid
  record without an executed run proves nothing.
- Run the guard register in `CONSTRAINTS.md`: every applicable CL row must be
  measured or the owning task is not done. Run fast gates (`g17`-`g20`) only
  inside an integrated owner boundary, never while sibling edits are in flight.
- Put acceptance criteria in the issue or PR and execution proof in CI artifacts
  or the PR discussion. Keep local plans and scratch outside the repository.
