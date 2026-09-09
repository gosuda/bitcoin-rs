# Agent guidelines

Read the relevant source, tests, current contract, and PR discussion before changing settled behavior. Architecture belongs in `CONCEPTS.md` and `docs/contracts/`.

- Keep one owner per invariant and durable representation. Reuse existing boundaries; do not add parallel state, forwarding wrappers, or speculative APIs.
- Describe implemented behavior as implemented and target design as target design.
- Review persistence reads and writes together. Preserve typed failures, commit points, durability, and recovery semantics.
- Follow lock order. Keep expensive verification, I/O, and callbacks outside write locks; recheck captured state before commit.
- Preserve operator data. Schema changes follow the documented replay or migration path; never reset implicitly.
- Delete superseded code with its replacement. Keep compatibility adapters only when a current public contract requires them.
- `docs/policies/source-compatibility.md` §3.4 owns TLS provider and transport policy; keep `deny.toml` aligned with it.
- Tie permanent tests to current contracts and independent references. Missing evidence blocks a claim; it does not prove it.
- Run the applicable `CONSTRAINTS.md` checks and report results. Do not claim performance or promote defaults without evidence.
- Keep plans and scratch outside the PR; keep acceptance evidence in the PR or CI artifacts.
