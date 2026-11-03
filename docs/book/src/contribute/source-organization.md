# Source and test organization

Pick the owner and the behavior before you pick a path. A directory change moves code; it does not create a new owner.

## Ownership first

Place new code in the existing crate that owns the responsibility. Start with a named module for a protocol, algorithm, or responsibility, and keep the tree flat while it stays readable. When a module grows, the entry point stays `owner.rs` and private children live in `owner/part.rs` through ordinary module declarations. Do not add a facade module or a state object to hold the split.

Name a module by what it does now, not by a line limit, a task, a shard, or an issue number. A seam is justified by a real boundary, not by a file that feels long. Logical paths follow physical paths: `owner/part.rs`, not a root-level file pulled in with `#[path]`.

Expose the narrowest visibility that works. Do not add re-exports, wrappers, crates, or test-only production APIs for organization. A large file is a reason to inspect its responsibilities, not to split it automatically. A dense algorithm or a small crate needs no uniform directory depth.

One authority owns each invariant, mutation, and durable format. A split does not create a second one. [`docs/contracts/architecture.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md) owns dependency and state boundaries, and [`docs/contracts/test-evidence.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/test-evidence.md) owns which guarantees need independent proof.

## Where a test lives

Owner-local behavior uses a short inline `#[cfg(test)] mod tests`. A larger suite for one owner lives in `src/owner/tests.rs`, declared by the owner with `#[cfg(test)]`. Further behavioral splits go under `src/owner/tests/`. Crate-root behavior goes in `src/tests.rs`.

A crate-consumer boundary or an independent oracle uses one explicitly registered `tests/suite.rs` per crate. Put behavior modules beside it and one shared `tests/support/` owner for fixtures and helpers. Do not create one integration test file per case.

A separate executable is justified by a current process, platform, or compilation boundary. Daemon lifecycle, restart, or cross-process behavior uses the existing process harness at the owning package or `e2e` boundary, because that harness preserves real process and persistence evidence. A socket read or a store reopen alone does not need an integration target.

Files under `tests/unit/` that are pulled in with `#[path]` remain unit tests. Keep classification, dispatcher policy, transport behavior, and state transitions with the proof owner that already covers them. Two tests may share an input when their oracle or failure boundary differs; the overlap is the point.

## Fixtures

A fixture belongs to the smallest scope that uses it. Keep it local to its suite, put an intra-crate fixture in `tests/support/`, and use an existing cross-crate domain fixture or harness when multiple crates need the same bytes. Never copy a fixture into a second owner. Never reach into another package's private test tree.

Do not build a shared framework to make every path look the same. The smallest shared boundary that actual consumers need is the right one.

## Exceptions and reorganizations

An exception needs a concrete current reason: platform selection, independent oracle custody, or a required compilation boundary. Explain it in the pull request, and add a nearby comment only when a future maintainer would otherwise remove the exception by mistake. Existing placement never justifies a new exception.

There is no waiver registry, approval step, or directory-shape test. The policy is a default for new and reorganized code, not a license to churn working paths.

A reorganization preserves intended visibility and test registration. It also preserves `cfg`, feature, backend, and platform selection, independent references, and failure coverage. Remove a superseded path and its helpers in the same change. Run the smallest meaningful checks for the affected boundaries. Review tests by the guarantee they retain, not by their count. Update guidance at its single owning rule, never in a crate-local copy.

The full policy is [`docs/policies/source-organization.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/source-organization.md). The defaults here are a reading of that policy, not a second copy of it.

Owner: [`docs/policies/source-organization.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/source-organization.md). Next: [Contracts and evidence](contracts.md) explains how a test earns a clause tag.
