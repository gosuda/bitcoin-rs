# Blueprint issue diagrams

These SVGs illustrate the proposed design in issues #621 and #624. They are planning diagrams, not evidence that an implementation or performance gate has passed.

| File | View |
| --- | --- |
| [01-ownership.svg](01-ownership.svg) | Selected dependency and construction edges |
| [02-durable-commit.svg](02-durable-commit.svg) | Durable commit and publication order |
| [03-admission.svg](03-admission.svg) | Shared transaction admission and preview |
| [04-recovery.svg](04-recovery.svg) | Restart and crash recovery |
| [05-waterfall.svg](05-waterfall.svg) | Acceptance stages |
| [06-index-capabilities.svg](06-index-capabilities.svg) | Optional-index state transitions |
| [07-validation-window.svg](07-validation-window.svg) | Ordered preparation and parallel verification |
| [08-runtime-flow.svg](08-runtime-flow.svg) | Cross-owner runtime coordination |

Diagram 01 is a selected dependency view, not a complete Cargo graph. Diagram 08 shows runtime flow separately. Retry and lifecycle loops in diagrams 03 and 06 are state transitions, not circular module dependencies.

The supplied D2 atlas used a local D2-subset/Graphviz renderer. These files retain its node labels and edges; redundant SVG markup has been reduced. Do not claim they were rendered with the official D2 CLI.

Issue images use commit-pinned raw GitHub URLs. This documentation branch does not change production code or the main branch.
