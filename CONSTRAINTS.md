# Project invariants

These invariants apply across the repository. Detailed behavior, numeric limits,
tool pins, and verification procedures belong with their code, contract, policy,
or CI workflow; this file is not a gate ledger or task checklist.

## Consensus correctness

Consensus results and Bitcoin wire identities must remain correct for accepted
and rejected inputs. A change to consensus behavior requires an explicit
contract change and independent evidence at the affected boundary.

## Single ownership

Each invariant, mutation path, and durable representation has one authoritative
owner. Derived views are rebuildable projections, not alternate authorities.
Reuse existing boundaries instead of adding parallel state or forwarding layers.

## Durable state

Persistence defines explicit commit points, typed failures, and recovery
semantics. Publish state only after the owning durable commit succeeds, and
review reads, writes, restart behavior, and rollback together.

## Operator data safety

Never discard, reinterpret, repair, or reset operator data implicitly. Format
changes follow their owning migration or replay policy and fail closed when the
stored state cannot be opened safely.

## Bounded resources

Externally driven work, queues, traversals, responses, and retained state have
an owner and an enforceable bound. Concrete limits live beside the code or
domain contract that enforces them.

## Observable compatibility

Compatibility is defined at observable public boundaries and by their owning
manifests or contracts. Internal layout and call shape are not compatibility
promises unless a current public contract makes them observable.

## Implementation independence

Correctness evidence must not be derived solely from the implementation under
test. Use independent vectors, references, models, or externally observable
properties appropriate to the claim.

## Evidence discipline

Tests and measurements prove only the behavior and environment they exercise.
Missing, skipped, blocked, or unavailable evidence is not a passing result.
Performance, compatibility, and correctness claims remain unmade until their
owning evidence workflow records them.
