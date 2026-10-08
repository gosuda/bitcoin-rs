# External ecosystem compatibility contract

bitcoin-rs does not prove Bitcoin compatibility only with in-tree tests and
self-authored documents. The stronger evidence is existing Bitcoin ecosystem
software consuming bitcoin-rs through the same external surfaces it already
uses with Bitcoin Core. This page owns the strategy, the test-ownership
boundary, and the guardrails that keep that evidence thin. The maintained
evidence record is [../api/ecosystem-compat.toml](../api/ecosystem-compat.toml);
this page is its normative policy.

External integrations exist to produce **independent compatibility evidence**,
not to accumulate features. If external software consumes bitcoin-rs without a
bitcoin-rs-specific compatibility layer, that is stronger evidence than
asserting compatibility from inside this repository.

## Clauses

### `ECO-01`: Core-compatible boundaries, independent internals

- **Principle**: external protocol/API compatibility should be
  Core-compatible; internal architecture, storage, and test ownership remain
  independent.
- Compatibility is implemented at adapters and protocol boundaries so that:
  external consumers see the interfaces they already understand; internal
  crate ownership stays bitcoin-rs-native; storage and execution models stay
  independently evolvable; and adding or replacing an external consumer never
  requires production-code changes unless the public compatibility surface
  itself is missing or wrong.
- bitcoin-rs internals are never reshaped merely to resemble Bitcoin Core or
  to satisfy a particular external harness.
- This clause is the contract-side expression of the project compatibility
  boundary: external interoperability is the stability contract; internal
  compatibility — crate APIs, module boundaries, persistence formats — is not
  guaranteed and is no reason to keep a worse design.

### `ECO-02`: Two-tier test ownership

External ecosystem integrations are black-box compatibility evidence, not
duplicate correctness suites:

```text
Correctness: unit tests | contract tests | Core differential tests | focused internal e2e
  -> owns detailed state transitions, edge cases, implementation invariants

External compatibility: Bitcoin Core peer | RPC/REST/ZMQ consumer | bpftrace/BCC
                        | benchmark tooling | mining software
  -> proves the public surface is consumable in the real ecosystem
```

External evidence answers only consumability questions: can an unmodified
Core peer sync/relay with bitcoin-rs; can an existing RPC client parse a
response; can an existing ZMQ subscriber consume notifications; can a
Core-style USDT script attach and read the expected probe ABI; can mining or
benchmark tooling invoke bitcoin-rs through the documented public surface.
Detailed correctness stays owned by the correctness tier; external evidence
never re-tests internal branches.

### `ECO-03`: Black-box evidence only

External compatibility checks depend only on externally observable behavior
and documented compatibility surfaces. Evidence must not depend on internal
log strings, private structs, test-only RPCs, test-only callbacks or hooks,
extra production state kept only for evidence collection, or execution
branches enabled only for a particular tool. A refactor that preserves the
public compatibility surface must not break ecosystem evidence merely because
internals changed. Detailed internal diagnostics may be collected for
debugging, but they are never part of the compatibility contract.

**Deferred guarantee:** the live P2P compatibility lane (scripts/run-p2p-core-interop.sh)
still derives some assertions from private log markers (e.g. compact-block
reconstruction counts). This coupling is known and tracked; until the lane is
decoupled from log markers, refactors that change those markers may break the
lane even when public protocol behavior is unchanged. ECO-09 records that
restriction.

### `ECO-04`: One representative consumer is enough

Do not collect tools for their own sake. For a given surface, one
representative external consumer is sufficient unless another consumer proves
a materially different compatibility property: a distinct protocol mode, ABI
property, deployment environment, or regression risk. One real Core interop
lane proves basic P2P compatibility; one ordinary Core-compatible RPC client
proves RPC consumability; one bpftrace/BCC workflow proves the USDT ABI; one
mining consumer proves GBT/mining integration. External-tool count is never a
KPI.

### `ECO-05`: No production dependency creep

Third-party validation tooling lives outside core implementation crates:
external or upstream repositories, `tools/`, `scripts/`, or dedicated
interoperability CI jobs. External tooling libraries are never added to
`crates/*` merely to support compatibility tests, and no production state is
exposed solely to satisfy tooling.

### `ECO-06`: No duplicated internal tests

When an external tool exposes a bug, add the minimal missing internal
regression test at the correct owner boundary. The same detailed scenario is
never permanently encoded in both an external harness and internal suites
unless the two prove materially different contracts. There is no parallel
external correctness framework.

### `ECO-07`: Prefer upstream integrations

When an external project needs a change, prefer a generic multi-implementation
abstraction upstream over a bitcoin-rs-only fork or adapter:

```text
existing external tool -> generic Bitcoin implementation interface -> Core | bitcoin-rs
```

### `ECO-08`: Evidence matrix and status vocabulary

- **Owner**: [../api/ecosystem-compat.toml](../api/ecosystem-compat.toml),
  one row per independently tracked surface with the columns
  `surface | core_reference | status | representative_consumer | evidence`.
- `status` uses exactly this vocabulary:
  `implemented`, `externally verified`, `partially compatible`,
  `intentionally unsupported`, `experimental`.
- An implementation is **not** `externally verified` until a real external
  consumer has exercised it and the run is recorded in the row's `evidence`.
  In-tree tests, schema-shape comparison, and self-authored harnesses are
  `implemented` evidence only. `externally verified` scopes to the black-box
  outcomes the evidence names, never to unlisted behavior of the same surface.
- Compatibility surfaces are tracked independently: Network (P2P v1, BIP324
  /v2, tx/block relay, compact blocks and filters, peer lifecycle);
  Application APIs (JSON-RPC, REST, ZMQ); Mining (GBT, block
  submission/proposal, future mining IPC or Stratum V2 adapters);
  Observability (Core-compatible USDT, bpftrace/BCC, bitcoin-dev-tools);
  Process/component interfaces (optional Core IPC as a narrowly scoped
  adapter).
- This matrix is a different axis from
  `crates/rpc/core-compat.toml` (Core reference identity pins) and
  `crates/rpc/src/registry.rs` (per-method Core-schema status): those own
  what the API shape claims against Core; this matrix owns which real
  external consumers have exercised the surface. Neither substitutes for the
  other.

### `ECO-09`: Interop evidence is observable protocol outcomes

The live Bitcoin Core P2P interop lane is external evidence only where it
observes externally visible outcomes: handshake, sync, relay, serving
behavior, disconnect behavior, chain identity. Counts derived from internal
bitcoin-rs log markers (for example compact-block reconstruction log
messages) are diagnostic material, not a compatibility contract; they must
not become long-term external evidence. Those details belong to internal P2P
tests or benchmark/diagnostic tooling.

## Non-goals

- Cloning every Bitcoin Core interface.
- Supporting internal Core filesystem or database formats for parity.
- Importing Core's internal ownership model into bitcoin-rs.
- Bespoke integrations that no external project uses.
- Claiming compatibility from schema shape alone.
- Turning every experimental Core interface into a required bitcoin-rs
  feature.
- External-tool count as a project KPI.
- Exposing internal state solely to satisfy compatibility tooling.
- A parallel external correctness framework.

## Proven by

- [../api/ecosystem-compat.toml](../api/ecosystem-compat.toml): the
  maintained matrix; each row's `evidence` names its proof owner, and every
  current row is honestly downgraded to `implemented` or weaker wherever only
  in-tree proof exists.
- `scripts/run-p2p-core-interop.sh` with `crates/p2p/tests/core_interop_live.rs`
  (`docs/contracts/core-differential.md` `CORE-02`, `CORE-03`): the one
  real-consumer lane today — an unmodified Bitcoin Core 31.1 peer.
- Acceptance items that need real external validation runs (a representative
  real-world consumer per verified surface, an upstreamed or out-of-repo
  integration, thin CI separation of ecosystem lanes) are tracked in issue
  #1122 follow-up work, not claimed here.
