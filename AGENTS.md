# AGENTS.md

Keep this file behavioral. Put architecture, implementation details, vocabulary,
and rationale in `CONCEPTS.md`, policies, or subsystem documentation.

- Read the current contract, source, tests, and PR discussion before changing a
  settled area.
- Give each invariant and durable representation one owner. Do not add parallel
  state, duplicate implementations, forwarding wrappers, or speculative APIs.
- Distinguish implemented behavior from target design. Do not advertise a
  feature, guarantee, benchmark result, or proof before the implementation and
  evidence exist.
- Review persistence readers and writers together. State the commit point,
  durability guarantee, failure classification, and recovery owner. Never turn
  storage failure or corruption into ordinary absence or confirmed success.
- Follow the documented lock order. Keep expensive verification, I/O, and
  observer callbacks outside domain write locks; revalidate captured state
  before committing.
- Remove superseded code with its replacement. Keep compatibility adapters only
  where a current public contract requires them.
- Keep permanent tests traceable to named current contracts and independent
  references. Missing tools, corpora, or identities block a check; they do not
  make it pass.
- Put acceptance criteria in the issue or PR and execution evidence in CI
  artifacts or the PR discussion. Keep local plans and scratch out of the repo.
