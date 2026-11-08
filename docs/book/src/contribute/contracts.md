# Contracts and evidence

A contract clause states a rule. A tagged artifact proves a bounded part of it. The evidence index is the generated map between the two. Keep the three separate when you describe coverage.

## Clause ids

[`docs/contracts/`](https://github.com/gosuda/bitcoin-rs/tree/main/docs/contracts) is normative. A clause id has a prefix and a number, and some ids carry a letter or word suffix. Examples are `API-05`, `ARCH-07a`, and `RCV-02`. The [contract index](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/README.md) lists every contract file and its clause range.

Precedence is fixed: contracts rank above source comments, source comments rank above policies, and policies rank above informative docs. When code and a contract disagree, fix one in the same change-set. Cite the clause; do not paste the contract text into a second owner.

Two contract files carry rules without clause ids: `formal-verification.md` and `test-evidence.md`. They still own their rules. They have no tag namespace.

## Tag an artifact

A tag is a comment line immediately above the item that proves the clause. Rust uses `//`, Lean uses `--`, and TLA+ uses `\*`. Multiple ids on one line are separated by commas:

```
// API-05
#[test]
fn generate_without_submit_does_not_advance_the_tip() {
    // ...
}
```

The checker classifies the item that follows. A `#[test]`, an attribute whose path ends in `::test`, or a `proptest!` block is a test artifact. `#[kani::proof]` is a Kani artifact. An item in a file ending in `_model.rs` is a model artifact. A Lean or TLA+ file supplies its own kind. Any other Rust item is an owner artifact.

Owner artifacts appear in the index but do not count as proof artifacts. A clause with only an owner tag remains a gap.

A tag that names an unknown clause fails the check. A tag that is not followed by an item fails the check. A tag above a doc comment or a blank line does not reach the item and also fails.

## Generate the index

The index and the contract list in `docs/contracts/README.md` are generated. Do not edit either by hand.

```
cargo run --locked -p contract-index -- --check
```

The check verifies that both generated files are current, that every tag resolves, and that Markdown links in the checked documents resolve. A stale file prints the path and the regeneration command. `./scripts/ci-pr.sh contracts` runs the same check as a CI profile.

The [evidence index](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/evidence-index.md) at this commit records 204 clauses, 157 with proof artifacts, and 47 gap clauses. The numbers come from the tree, not from a target. Quote them with the index link, or not at all.

## Gaps stay gaps

A gap row has no tagged proof artifact. It is not a waiver, not a skip, and not a pass. The 47 gap clauses stay gaps until an artifact lands with a tag and the index is regenerated in the same change-set. Adding an owner tag does not close one.

Do not write a dashboard that turns the absence of a tag into a percentage of coverage. The contract index is a per-clause map. It has no denominator for correctness.

## What makes a good artifact

A tagged test must fail when the behavior it claims breaks. A test that passes for the wrong reason, or asserts only that a function returned without panicking, does not prove the clause. [`docs/contracts/test-evidence.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/test-evidence.md) owns which guarantees need independent proof, such as a process harness, a second backend, or an external reference.

Keep the artifact with its owner. A contract test belongs where the behavior lives, not in a central test crate. A process boundary, restart, or reference comparison belongs in the existing process harness at the package or `e2e` boundary.

## Update a contract without copying it

When a behavior changes, update the owning clause, the code, and the tagged artifact in one change-set. When another owner holds the rule, link to the clause id and keep your sentence short. Apply the same rule in policies and crate READMEs.

The generated [evidence index](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/evidence-index.md) shows which artifacts currently claim a clause. The list is evidence of tagging, not evidence that the clause is correct. Read the artifact before you rely on the claim.

Owner: [`docs/contracts/README.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/README.md) for precedence and [`docs/contracts/test-evidence.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/test-evidence.md) for proof families. Next: [Source and test organization](source-organization.md) explains where the artifact lives.
