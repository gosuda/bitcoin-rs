# PR #146 review fixes

- Remove the stale `NODE_COMPACT_FILTERS` capability advertisement after compact-filter indexing is deleted.
- Remove benchmark and diagnostic-tool assumptions about the deleted `blockfilterindex` option and output fields.
- Reconcile the remaining project documentation with the compact-filter removal.
- Provide a Windows shutdown path that can actually request graceful shutdown.
- Verify the changed Rust and Python surfaces, then commit the fixes on the PR-based branch.
