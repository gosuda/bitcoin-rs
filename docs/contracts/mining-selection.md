# Mining selection contract

The snapshot-based transaction selection and candidate assembly path in
`crates/mining`.

## Clauses

### `MIN-01`: Assemble the supplied mempool snapshot without topology revalidation

- Candidate assembly consumes the supplied `MempoolMiningSnapshot` as its
  selection input and does not re-check the mempool dependency graph.
- An entry whose declared ancestor is absent still fails assembly with
  `MiningError::MissingAncestor`; this is a malformed snapshot input, not a
  reason to perform a second graph validation pass.
- Cyclic ancestor metadata is accepted by the mining selection path when the
  entries can be ordered and assembled from the snapshot. Snapshot topology
  validation belongs to the snapshot producer.

Proven by `crates/mining/tests/policy_pareto.rs` test
`missing_ancestors_fail_assembly_without_rechecking_the_dag`.
