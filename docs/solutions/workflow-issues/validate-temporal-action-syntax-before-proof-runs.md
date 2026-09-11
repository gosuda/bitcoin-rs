---
title: Validate temporal action syntax before proof runs
date: 2026-09-07
category: docs/solutions/workflow-issues
module: docs/models
problem_type: workflow_issue
component: formal-verification
severity: medium
applies_when:
  - "Editing a fairness clause in a ConditionalProgress conjunction"
  - "Replacing <<A>>_vars with A after proving A forces a state change"
  - "Reading a native rc 255 from an Apalache temporal invocation"
  - "Deciding whether a rejected candidate justifies another K128 attempt"
tags:
  - apalache
  - tla
  - fairness
  - sany
  - syntax-check
  - proof-workflow
---

# Validate temporal action syntax before proof runs

## Context

A candidate for the Apalache 0.62.2 temporal heap failures replaced `<<A>>_vars` with the bare action `A` at 38 selected fairness-expression sites. Reviewers had proved that each selected action forces a state change. The proposed expressions were logically equivalent, but the review did not check whether the temporal language accepted their form.

The isolated ChainAdmission diagnostic at K1 exited native 255 after 1.422 seconds. SANY rejected the file before temporal translation: `<> followed by action not of form <<A>>_v.` The run never tested temporal translation memory use. All 38 edits were reverted, the inventory hashes were restored, and the inventory-only test passed. The earlier heap failures remained unresolved; this was not a `g20` pass.

## Guidance

- Action relation identity is a semantic fact about states. Syntactic admissibility inside `[]<>` is a level rule that SANY applies to the expression form. Proving `A` equals `<<A>>_vars` under every guard does not make `A` a legal operand of `<>`.
- Keep the `<<A>>_vars` wrapper unless a replacement has passed its own parse and level check. Check guards, fairness, state, observers and bounds separately; an expression rewrite must not silently change them.
- Do not recommend a smaller witness subscript as a working fix without checking it. That alternative was unverified when this note was written.
- Obtain any required run authorization, then check syntax and levels before an expensive proof. Confirm the pinned tool's command interface rather than guessing a parse-only flag.
- Classify a failure by its message and phase, not its exit code alone. This SANY rejection and the earlier PeerLeases heap exhaustion recorded in the inventory both returned native 255. The repository's mapping assigns skill 14 to that code, but the causes require different remedies.

## Why This Matters

The review established a semantic argument before checking the target language. The diagnostic used a 16 GiB maximum heap, not a measured 16 GiB allocation. Its immediate rejection supplied no evidence about the scalability problem. An earlier syntax check would have rejected the candidate before the full equivalence review and application.

## When to Apply

Any edit to a temporal formula in `docs/models/*.tla`, especially one motivated by translation size rather than by the property it encodes. Any reading of an rc 14 result. Any request to schedule a K128 run after a rewrite.

Retry only after the rewritten consequent passes syntax and level checks and its semantic argument still holds. Then request the bounded diagnostic required by the current workflow. Diagnostic success does not replace the acceptance contract in `CONSTRAINTS.md`.

## Examples

Accepted, as in `docs/models/ChainAdmission.tla` `FairInternal`:

```tla
( ( <>[] EnEnterDone ) => ( []<> <<EnterDone>>_vars ) )
```

Rejected by SANY on 0.62.2, even though `EnterDone` always changes `lifePhase`:

```tla
( ( <>[] EnEnterDone ) => ( []<> EnterDone ) )
```

## Related

- [Proof inventory](../../../CONSTRAINTS.md#proof-inventory): the current tool pin, return-code mapping and acceptance contract.
- [ChainAdmission model](../../models/ChainAdmission.tla): the restored temporal action form in `FairInternal`.
