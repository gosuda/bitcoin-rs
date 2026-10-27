# Source and test organization

This policy owns repository-wide placement and naming defaults. The
[architecture contract](../contracts/architecture.md) owns dependency and
state boundaries; the [test-evidence contract](../contracts/test-evidence.md)
owns which guarantees need independent proof. A directory change does not
change either contract. These defaults guide new and reorganized code; they
do not describe every existing path or require unrelated file moves.

Choose the existing owner and the behavior being changed before choosing a
file. Keep one authority for each invariant, mutation, and durable format.
Files may divide an owner's implementation without creating another owner.

| Decision | Default |
| --- | --- |
| Add a production module | Give it a named responsibility, protocol, or algorithm within the existing crate. Keep the tree flat while those responsibilities remain readable. |
| Split an existing module | Keep its entrypoint in `owner.rs` and private implementation children in `owner/part.rs`, using ordinary Rust module declarations. Children may implement the parent's type; a file split needs no new facade or state. |
| Name a file or directory | Use the current responsibility or behavior. Split by a meaningful seam, not a line limit, numbered shard, completed task, or issue number. Keep useful regression provenance in a concise test comment. |
| Expose a module or type | Use the narrowest visibility required by actual consumers. Organizing files is not a reason to add re-exports, wrappers, a crate, or a test-only production API. |

Logical module paths should follow physical paths. Prefer
`owner/part.rs` for `owner::part` over a root-level prefixed file selected by
`#[path]`. Keep platform selection and justified shared-fixture imports
explicit. A large file is a reason to inspect its responsibilities and test
volume, not proof that it needs splitting. Dense algorithms and small crates
need no uniform directory depth.

Choose the test boundary by the guarantee and required access, then choose
its location:

| Proof boundary | Default location |
| --- | --- |
| Owner-local behavior, including required private access | A short inline `#[cfg(test)] mod tests`; extract a larger suite to `src/owner/tests.rs`, declared under `#[cfg(test)]` by its owner. Further splits use behavioral names under `src/owner/tests/`. For crate-root behavior, use `src/tests.rs`. |
| Behavior at the crate-consumer boundary or an independent public-surface oracle | A Cargo integration target under `tests/<behavior>.rs`. Keep helper modules under `tests/support/` so they are not accidental test targets. |
| Actual daemon lifecycle, restart, or cross-process/reference behavior | A target using the existing process harness at the package or e2e boundary that owns that behavior. Preserve real process and persistence evidence where the guarantee requires it. |

Reading a socket or reopening a store does not by itself require a separate
integration target. Likewise, a file under `tests/unit/` imported by a library
through `#[path]` is still a unit-test module. Use owner-local source paths
for extracted private tests rather than creating another such cross-tree
layout. Keep registry classification, dispatcher policy, transport behavior,
and authoritative state transitions with their respective proof owners.
Overlapping inputs are justified when the oracle or failure boundary differs.

Fixtures and helpers belong to the smallest test scope that uses them. Keep
a local fixture with its suite; share within a crate's integration targets
through `tests/support/`. For cross-crate consumers, reuse an existing domain
fixture or process-harness owner with its intended test feature and dependency
boundary. Do not copy fixtures, reach into another package's private test tree,
or create a shared test framework merely to make paths uniform. If no suitable
owner exists, justify the smallest shared boundary from the actual consumers.

An exception needs a concrete current reason, such as platform selection,
independent oracle custody, or a required compilation boundary. Explain it in
the PR; retain a nearby comment only when future maintainers need that reason
to understand the code. Existing placement alone is not a reason for a new
exception. This requires no waiver registry, new approval step, or directory
shape test.

For a reorganization, preserve intended visibility, test registration,
cfg/feature/backend/platform selection, independent references, and failure
coverage. Remove superseded paths and helpers with their replacements. Run
the smallest meaningful checks for the affected boundaries, and review tests
by the guarantee they retain rather than by file or test counts. Update
existing guidance if a justified exception changes a default; keep one owner
for the rule instead of copying it into crate-local instructions.
