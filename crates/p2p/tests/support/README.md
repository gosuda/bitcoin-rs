# AddrMan reference fixtures

The `core-addrman-*.cpp` programs call unmodified Bitcoin Core31.1
translation units from commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`.
They do not link candidate AddrMan code or replacement algorithm stubs. The
placement driver also asserts Core's official Tried40/New786 anchors. The
operational driver uses Core's existing deterministic-test friend boundary and
real FastRandomContext seeds to arrange accepted/refused reference draws.

An optional Linux-only reproduction command is:

```sh
bash crates/p2p/tests/support/regenerate-core-addrman.sh /path/to/pinned-bitcoin /path/to/disposable-output
```

It requires CMake and a C++20 compiler, writes only the supplied output directory,
and produces placement/ring TSV, health JSONL and operational JSONL. Its generated
platform header uses the recorded Linux feature flags and pinned template; it
is not a successful full upstream CMake build claim. Source, driver, compiler,
configuration and executable digests are retained in the JSON fixture provenance.
No Core sources or binaries are vendored, and this is not a new CI lane.

Permanent Rust tests compare the stored rows with candidate placement, grouping,
health and the corresponding operation sequences. Compare GetChance with a narrow
floating tolerance: exact Linux/libm output bits are recorded for provenance,
not required on every platform. The separate selection fixture is explicitly an
independent source/formula oracle; its chance-escalation distribution is not a
claim that a Core process was sampled. None of these fixtures proves complete
P2P/Core behavioral equivalence.

The ASMap driver additionally calls Core's validator, mapper and group owner for
four unchanged maps and checks the official Tried236/New795 anchors. The 224 rows
in `core-addrman-asmap-v31.1.json` include exact map bytes/hashes, ASN0 fallback,
linked IPv4 endpoint distinctions, Internal sources and two fixed secrets.
The reproduction script also writes `asmap.tsv`; the binary maps remain the
existing #1477 fixtures and the official map in the pinned Core source tree.
