# Mining selection

The mining selector consumes the mempool snapshot as an immutable topology contract and does not re-validate its DAG.

- **MIN-01** — Snapshot ancestor lists are trusted for package ordering; missing indices are rejected, while cyclic topology is not re-checked. Owner: `crates/mining/src/policy.rs` (`residual_package`). Proof: `crates/mining/tests/policy_pareto.rs` (`missing_ancestors_fail_assembly_without_rechecking_the_dag`).
