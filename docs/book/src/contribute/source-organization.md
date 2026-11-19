# Source and test organization

Pick the owner and the behavior before you pick a path. A directory change moves code; it does not create a new owner.

## Ownership first

Place new code in the existing crate that owns the responsibility. Start with a named module for a protocol, algorithm, or responsibility, and keep the tree flat while it stays readable. When a module grows, the entry point stays `owner.rs` and private children live in `owner/part.rs` through ordinary module declarations. Do not add a facade module or a state object to hold the split.

Name a module by what it does now, not by a line limit, a task, a shard, or an issue number. A seam is justified by a real boundary, not by a file that feels long. Logical paths follow physical paths: `owner/part.rs`, not a root-level file pulled in with `#[path]`.

Expose the narrowest visibility that works. Do not add re-exports, wrappers, crates, or test-only production APIs for organization. A large file is a reason to inspect its responsibilities, not to split it automatically. A dense algorithm or a small crate needs no uniform directory depth.

One authority owns each invariant, mutation, and durable format. A split does not create a second one. [`docs/contracts/architecture.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md) owns dependency and state boundaries, and [`docs/contracts/test-evidence.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/test-evidence.md) owns which guarantees need independent proof.

## Where a test lives

Owner-local behavior uses an inline `#[cfg(test)]` module inside its source owner file. Keep the module's name, configuration conditions, and visibility. File length alone does not justify a separate test module file.

A crate-consumer boundary or an independent oracle uses the crate-root `tests.rs` file, registered as the `suite` integration target. Put behavior modules inside that file. Do not create one integration test file per case, and do not create test-only source directories under `crates/`, including `tests/`.

Keep a separate crate-root test executable only when a process, platform, allocator, global counter, or artifact boundary requires it; preserve each target name and its Cargo configuration. Daemon lifecycle, restart, or cross-process behavior uses the existing process harness at the owning package or `e2e` boundary, because that harness preserves real process and persistence evidence. A socket read or a store reopen alone does not need a separate executable.

Inline a test helper in the test module that uses it. A helper shared by independent test executables uses one crate-root helper file; do not copy it into each executable. Two tests may share an input when their oracle or failure boundary differs; the overlap is the point.

## Fixtures

Reference data belongs under `testdata/<owner>/`, outside `crates/`. A fixture belongs to the smallest scope that uses it. Use an existing cross-crate domain fixture or harness when multiple crates need the same bytes. Preserve external vectors, provenance, and fixture bytes when paths change. Never copy a fixture into a second owner. Never reach into another package's private test tree.

Do not build a shared framework to make every path look the same. The smallest shared boundary that actual consumers need is the right one.

## Exceptions and reorganizations

An exception needs a concrete current reason: platform selection, independent oracle custody, or a required compilation boundary. Explain it in the pull request, and add a nearby comment only when a future maintainer would otherwise remove the exception by mistake. Existing placement never justifies a new exception.

There is no waiver registry, approval step, or directory-shape test. The policy is a default for new and reorganized code, not a license to churn working paths.

A reorganization preserves intended visibility and test registration. It also preserves `cfg`, feature, backend, and platform selection, independent references, and failure coverage. Remove a superseded path and its helpers in the same change. Run the smallest meaningful checks for the affected boundaries. Review tests by the guarantee they retain, not by their count. Update guidance at its single owning rule, never in a crate-local copy.

The full policy is [`docs/policies/source-organization.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/source-organization.md). The defaults here are a reading of that policy, not a second copy of it.

Owner: [`docs/policies/source-organization.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/source-organization.md). Next: [Contracts and evidence](contracts.md) explains how a test earns a clause tag.
