# Agent guidelines

Read the relevant source, tests, current contract, and PR discussion before
changing a settled area. Architecture and vocabulary belong in `CONCEPTS.md`
and `docs/contracts/`, not in this file.

- Give each invariant and durable representation one owner. Reuse the existing
  boundary; do not add parallel state, forwarding wrappers, or speculative APIs.
- Distinguish implemented behavior from target design. Do not advertise a feature,
  guarantee, or proof merely because its contract or test plan has been written.
- Review persistence readers and writers together. State the commit point,
  durability guarantee, failure classification, and recovery owner. Never turn
  storage failures or corruption into ordinary absence or confirmed success.
- Follow the documented lock order. Keep expensive verification, I/O, and observer
  callbacks outside domain write locks, and recheck captured state before commit.
- Preserve operator data. Format changes require the documented schema/replay
  procedure and an explicitly authorized fresh directory, never an implicit reset.
- Remove superseded code with its replacement and migrate affected callers. Keep
  compatibility adapters only where a current public contract requires them.
- Test observable behavior against named current contracts and independent pinned
  references. Missing tools, corpora, or identities block their checks; they do not
  make a passing result. Preserve historical evidence as historical evidence.
- Use the applicable checks in `CONSTRAINTS.md`. Report which checks ran and their
  results; do not promote defaults or claim performance gains without evidence.
- Keep plans and scratch outside the PR. Put acceptance criteria and execution
  evidence in the PR discussion or CI artifacts.
