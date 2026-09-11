# Node refactoring workbench

This branch is temporary tooling for the requested breaking cleanup of
`crates/node`. Product branches must contain only the refactor and caller
migrations. The workbench must never write to `main`, force-push a branch,
change stored data, or add a compatibility facade.

Build candidates from pinned main `0e10cd7e1cfc3d37654c1d622be19cebc2dda196`.
Check Clippy before publishing each of five atomic commits. Retain test
assertions, migrate callers, and record build/test evidence separately.
