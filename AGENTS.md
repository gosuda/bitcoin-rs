# AGENTS.md

Keep this file behavioral. Put architecture, implementation details, vocabulary,
and rationale in `CONCEPTS.md`, policies, or subsystem documentation.

## Rules

- Before changing a settled area, identify its current contract and owner. Read
  relevant concepts, subsystem docs, source, policies, tests, and issue or PR
  before adding another representation of the same knowledge.
- Give each invariant, state transition, validation rule, default, and durable
  representation one owner. Prefer single ownership, serialization, or an
  explicit commit boundary; preserve complete ownership units when moving
  responsibility. Avoid parallel state, shadow models, duplicate
  implementations, broad wrappers, and speculative abstractions. Add
  indirection only for a real boundary or current consumer.
- Remove superseded paths, interfaces, compatibility scaffolding, and temporary
  state when a replacement becomes authoritative, unless compatibility requires
  them.
- For persistence changes, review affected readers and writers together. Make
  ownership, commit point, durability, recovery, and failure classification
  explicit.
- For every TLS path, use Rustls with default features disabled and a reviewed
  non-C crypto provider, and keep the native-TLS/C-provider family in `deny.toml`
  complete, because Rustls and adapter feature defaults can reintroduce AWS-LC,
  ring, OpenSSL, or platform TLS transitively.

## Verification

- Verify protocol and compatibility changes against independent specifications,
  reference implementations, vectors, or observable behavior. Use independent
  external authorities for durable compatibility tests; previous bitcoin-rs code
  is a temporary comparison control only.
- Keep permanent tests and fixtures only for named current contracts. Discard
  old implementations, harnesses, corpora, outputs, and other development
  evidence unless they independently protect a current contract.
- Judge performance end-to-end across elapsed time, CPU, memory, and I/O, using
  matched workloads, validation, data sources, hardware, and resource limits.
- Put acceptance criteria in the issue or PR and execution proof in CI artifacts
  or the PR discussion. Keep local plans and scratch outside the repository.
