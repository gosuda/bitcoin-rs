# External ecosystem compatibility contract

bitcoin-rs does not prove Bitcoin compatibility with in-tree tests and self-authored documents alone.
Existing ecosystem software that consumes bitcoin-rs provides stronger evidence.
This software uses the same external surfaces that it uses with Bitcoin Core.
This document defines the strategy, test-ownership boundaries, and guardrails that keep that evidence concise.
The maintained evidence record is [../api/ecosystem-compat.toml](../api/ecosystem-compat.toml).
This document is the normative policy for that record.
External integrations produce independent compatibility evidence.
They do not accumulate features.
Consumption without a bitcoin-rs-specific layer provides stronger evidence than in-repo assertions.

## Clauses

### `ECO-01`: Core-compatible boundaries, independent internals
- External protocol and API compatibility SHOULD be Core-compatible.
- Internal architecture, storage, and test ownership stay independent.
- Compatibility logic lives in adapters and protocol boundaries.
- This structure gives external consumers familiar interfaces.
- Crate ownership stays native to bitcoin-rs.
- Storage and execution remain evolvable.
- Adding or replacing a consumer never requires changes to production code unless the public surface is missing or wrong.
- Engineers do not reshape internals to match Core or to satisfy one harness.
- External interoperability is the stability contract.
- Internal crate APIs, module boundaries, and persistence formats carry no compatibility guarantee and keep no worse design.

### `ECO-02`: Two-tier test ownership
- External integrations provide black-box compatibility evidence, not duplicate correctness tests.
- The correctness tier owns detailed state transitions, edge cases, and implementation invariants.
- That tier includes unit tests, contract tests, Core differential tests, and internal end-to-end tests.
- External compatibility proves that the public surface works in the real ecosystem.
- This includes Bitcoin Core peers, RPC/REST/ZMQ consumers, bpftrace/BCC scripts, benchmark tools, and mining software.
- External evidence answers only consumability questions.
- It tests if an unmodified Core peer can sync and relay with bitcoin-rs.
- It tests if an existing RPC client can parse a response.
- It tests if an existing ZMQ subscriber can consume notifications.
- It tests if a Core-style USDT script can attach and read the expected probe ABI.
- It tests if mining or benchmark tools can invoke bitcoin-rs through the documented public surface.
- Detailed correctness stays in the correctness tier.
- External evidence never re-tests internal branches.

### `ECO-03`: Black-box evidence only
- Compatibility checks MUST depend only on externally observable behavior and documented surfaces.
- Evidence MUST NOT depend on internal log strings, private structs, or test-only RPCs.
- Evidence MUST NOT depend on test-only callbacks, hooks, extra production state, or tool-specific branches.
- A refactor that preserves the public surface MUST NOT break ecosystem evidence.
- Developers MAY collect internal diagnostics for debugging, but diagnostics are never part of the contract.
- Deferred guarantee: the live P2P lane (`scripts/run-p2p-core-interop.sh`) still reads private log markers.
- For example, it counts compact-block reconstructions.
- Refactors that change those markers can break that lane before developers decouple them.
- `ECO-09` records that restriction.

### `ECO-04`: One representative consumer is enough
- For a given surface, one representative external consumer is sufficient.
- Another consumer is required only if it proves a materially different property.
- Distinct properties include a different protocol mode, ABI property, deployment environment, or regression risk.
- One real Core interop lane proves basic P2P behavior.
- One ordinary Core-compatible RPC client proves RPC consumability.
- One bpftrace/BCC workflow proves the USDT ABI.
- One mining consumer proves GBT and mining integration.
- External-tool count is never a KPI.

### `ECO-05`: No production dependency creep
- Third-party validation tools MUST live outside core implementation crates.
- Tools MUST live in external repositories, upstream repositories, `tools/`, `scripts/`, or dedicated interop CI jobs.
- Developers MUST NOT add external tooling libraries to `crates/*` for compatibility tests.
- Developers MUST NOT expose production state solely to satisfy test tools.

### `ECO-06`: No duplicated internal tests
- When an external tool exposes a bug, add the minimal missing regression test to the owning internal crate.
- Developers MUST NOT permanently duplicate the same scenario in both external harnesses and internal test suites.
- The only exception is when the two harnesses prove materially different contracts.
- There is no parallel external correctness framework.

### `ECO-07`: Prefer upstream integrations
- When an external project requires a change, prefer a generic multi-implementation abstraction upstream.
- Prefer that abstraction over a bitcoin-rs-only fork or adapter.
- Connect existing external tools to a generic Bitcoin implementation interface that targets Core or bitcoin-rs.

### `ECO-08`: Evidence matrix and status vocabulary
- Owner: [../api/ecosystem-compat.toml](../api/ecosystem-compat.toml).
- The matrix contains one row per independently tracked surface.
- The columns are `surface | core_reference | status | representative_consumer | evidence`.
- The `status` field MUST use exactly one of these values: `implemented`, `externally verified`, `partially compatible`, `intentionally unsupported`, or `experimental`.
- A surface is `externally verified` only after a real external consumer runs against it.
- Developers MUST record that run in the `evidence` column for that row.
- In-tree tests, schema-shape comparisons, and self-authored harnesses provide `implemented` evidence only.
- That evidence covers only the black-box outcomes that the evidence column names.
- The matrix tracks surfaces independently across five categories.
- Category one is Network: P2P v1, BIP324/v2, transaction and block relay, compact blocks and filters, and peer lifecycle.
- Category two is Application APIs: JSON-RPC, REST, and ZMQ.
- Category three is Mining: GBT, block submission and proposal, the experimental regtest Stratum V2 adapter in [../../tools/stratum-sv2/README.md](../../tools/stratum-sv2/README.md), and future mining IPC.
- Category four is Observability: Core-compatible USDT, bpftrace/BCC, and bitcoin-dev-tools.
- Category five is Process and component interfaces: optional Core IPC as a narrowly scoped adapter.
- The Stratum V2 adapter surface requires specific proof.
- That proof includes localhost Noise and embedded-Node tests in `tools/stratum-sv2/template-provider`.
- Examples include `tight_budget_gets_a_fitting_job_and_budgets_stay_independent`.
- Examples include `partial_noise_frame_survives_a_job_refresh`.
- Examples include `embedded_templates_preserve_wire_data_commit_and_cancel_on_shutdown`.
- Proof also requires the retained functional compose run named in the owner matrix row.
- This matrix uses a different axis from `crates/rpc/core-compat.toml` and `crates/rpc/src/registry.rs`.
- `crates/rpc/core-compat.toml` owns Core reference identity pins.
- `crates/rpc/src/registry.rs` owns per-method Core-schema status.
- Those files record API shape claims against Core.
- This matrix records which real consumers exercised the surface.
- Neither mechanism substitutes for the other.

### `ECO-09`: Interop evidence is observable protocol outcomes
- The live Bitcoin Core P2P interop lane provides external evidence only for externally visible outcomes.
- Visible outcomes include handshake, sync, relay, serving behavior, disconnect behavior, and chain identity.
- Counts derived from internal bitcoin-rs log markers are diagnostic data, not a compatibility contract.
- For example, this includes log messages for compact-block reconstructions.
- Those details belong to internal P2P tests, benchmark tooling, or diagnostic tooling.

## Non-goals

- Do not clone every Bitcoin Core interface.
- Do not support internal Core filesystem or database formats for parity.
- Do not import the internal ownership model of Core.
- Do not build bespoke integrations that no external project uses.
- Do not make compatibility claims from schema shape alone.
- Do not require every experimental Core interface as a required feature.
- External-tool count is never a KPI.
- Do not keep internal state solely to satisfy tooling.
- Do not build a parallel external correctness framework.

## Verification boundaries

- Public-surface fixtures and the existing process harness own the named consumer boundaries.
- Adapter compilation and in-tree protocol tests do not establish deployment or independent external-consumer interoperability.
- The clause qualifications remain in force.
