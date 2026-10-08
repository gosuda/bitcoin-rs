# AGENTS.md

- Preserve consensus behavior and externally observable behavior unless the task explicitly changes it.
- Keep one authoritative owner for each invariant and durable representation. Prefer existing boundaries and direct calls over duplicate state, forwarding wrappers, or speculative abstractions.
- Keep changes scoped to the task. Remove superseded code with its replacement, and do not mix unrelated cleanup into the same change.
- Minimize the project's active state. Keep code, tests, abstractions, contracts, and documentation only while they protect current behavior, a safety or correctness invariant, operator data, or an active requirement, or are the evidence for one. Historical implementation shapes, completed plans, duplicate rules, and superseded scaffolding belong in Git history, not the active tree.
- Before changing consensus, persistence, or concurrency, inspect the owning contracts and the tests that exercise success, failure, commit, recovery, and lock-order behavior.
- Preserve operator data. Schema changes must use the documented migration or replay path and must never reset data implicitly.
- Run the smallest meaningful verification for the changed surface. Broad integration, reference, platform, and performance campaigns belong to their owning CI or evidence workflows.
- Describe implemented behavior as implemented and target design as target design. Do not claim correctness, compatibility, durability, or performance without the evidence owned by that claim.
