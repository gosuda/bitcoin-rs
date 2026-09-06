# Blueprint issue diagrams

These SVGs illustrate the proposed architecture in issue #624. They do not show implemented behavior or prove a correctness or performance result.

The original diagrams were authored in D2. A local D2-subset/Graphviz renderer produced the SVGs; official D2 compilation was not verified. The issue copies use system fonts and include a compact runtime-flow version.

- `02-durable-commit.svg`: durable chain commit and coherent publication.
- `05-waterfall.svg`: twelve acceptance stages.
- `07-validation-window.svg`: ordered preparation and parallel script verification.
- `08-runtime-flow.svg`: chain, mempool, relay, mining, and optional index coordination.

Issue descriptions embed these files with commit-pinned raw URLs. The diagrams belong to the documentation branch, not the production runtime. Keep the branch while issues use the assets.
