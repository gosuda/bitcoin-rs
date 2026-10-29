# Comment and documentation ownership

Keep each fact with the owner that can enforce it. Other documents link to that
owner instead of maintaining a second description.

| Fact | Owner |
| --- | --- |
| Local, non-obvious invariant or ordering requirement | A brief comment at the enforcing code. |
| Numeric limit or default | Its named constant and that constant's documentation. Contracts name the symbol and the guarantee, not a copied value. |
| Cross-module behavioral guarantee | The owning clause in `docs/contracts/`. |
| Operator configuration and commands | The relevant operator guide under `docs/`. |
| Public API usage | Rustdoc at the API; a crate README introduces the crate and links to detailed owners. |
| Dependency version | `Cargo.toml` and `Cargo.lock`; external reference releases use the reference-set owner. |
| Executed verification and measurements | CI artifacts, the PR discussion, or a pinned benchmark record with its limitations. |

Comments explain why a non-obvious rule holds or what a caller must guarantee.
Do not narrate implementation history, incidents, former behavior, or another
module's policy. Git retains that history. Use `PRE`, `POST`, or `INVARIANT`
only for obligations the signature and types do not express, and do not repeat
the same obligation in prose and again in tags.

Preserve `SAFETY` explanations, consensus-rule citations, and non-obvious lock
ordering, publication, durability, and recovery requirements. Shortening prose
must not weaken a guarantee or turn an unverified claim into a verified one.

Use repository paths plus symbol names, not `file.rs:LINE` references. For an
external implementation, cite a pinned revision and a file/function; keep the
release identity at its existing reference owner. Dated benchmark records may
refer to a file at their recorded revision even if that file has since moved.

Contracts name proof boundaries and remaining gaps, not inventories of test
function names. Test names and owner-local placement provide discovery; use
Cargo's test listing when selecting a check. The
[test-evidence contract](../contracts/test-evidence.md) owns the independent references and
failure boundaries. Removing a documentation inventory does not remove tests
or relax those obligations.

When removing duplicate text, record in the PR which owner retains each fact
and which text was only historical. Keep examples where they teach actual use;
do not copy complete module or contract descriptions into them.
