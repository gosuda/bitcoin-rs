# Consensus divergence

### `DIV-01`: Verdict identity

The optional monitor in `scripts/consensus_monitor.py` MUST compare the same block bytes at the same active parent on the same network. It MUST check genesis, height, parent work, deployment rules and the operators' effective parameter records. It MUST keep a consensus rejection separate from a missing body, a cached invalid flag, a stale view, incomplete validation, a policy result and an operational failure. A valid verdict needs the same bytes on a fully validated active chain. A successful proposal on either implementation MUST NOT establish acceptance. Proposal checks can omit proof of work or the signet solution.

### `DIV-02`: Incident publication

The monitor owns the divergence decision. It MUST reproduce a direct valid/consensus-invalid disagreement in two observations before it publishes a confirmed incident. The network, bytes, parent, tips, settings, versions and verdicts MUST agree across the observations. A higher-work active chain that contains a hash with an invalid tree flag MUST raise suspicion only. A tip difference alone MUST NOT publish an incident.

The first confirmed record in the private node data directory is the single durable containment decision. Publication MUST preserve a prior incident. Evidence MUST have a finite size. It MUST identify the block, its parent and work context, both witnesses, and the observation time. The monitor MUST NOT submit blocks or change an authoritative chain or peer score.

### `DIV-03`: Service containment

The node MUST read the record before it opens mining service admission. At runtime it MUST latch containment when it observes the record. A marker access error MUST suspend exposed services. It MUST NOT count as a peer consensus rejection.

The latch MUST cancel template preparation and long polls, refuse fresh jobs and local block submissions, invalidate pool work, and disconnect mining sessions. Work already admitted to a chain transition MAY finish. The node MUST NOT reverse such a transition. Economic JSON-RPC, REST and Esplora calls MUST report unavailability. Diagnostic access MUST include incident health, hash-addressed block examination and graceful shutdown. Indexes, peer observation and the storage recovery owner keep their normal authority.

### `DIV-04`: Restart and release

The node MUST NOT clear the latch in a live process. Restart with an incident MUST restore containment. An operator MUST preserve evidence, reproduce the mismatch, verify a reviewed correction, verify chainstate and derived services, and record the regression vector before release. Release MUST hold the node data-directory lock and durably archive the identified incident before it removes the marker. It MUST NOT reset data, adopt a reference tip or change validation rules.

The [operator runbook](../consensus-divergence.md) specifies evidence limits and the release procedure. The [recovery contract](recovery.md) owns storage and replay failures.
