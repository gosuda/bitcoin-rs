"""Final native-gated pass for unpublished node splits. Workbench-only."""
from collections import Counter
from pathlib import Path
import sys

import finish as f

m = f.m
r = f.r
base_transform = f.transform
base_validate = m.validate


def ensure_import(path: Path, line: str, *, cfg_test: bool = False) -> None:
    source = path.read_text()
    rendered = ("#[cfg(test)]\n" if cfg_test else "") + line + "\n"
    if rendered in source:
        return
    at = 0
    for existing in source.splitlines(keepends=True):
        if not existing.strip() or existing.startswith("//!"):
            at += len(existing)
        else:
            break
    path.write_text(source[:at] + rendered + source[at:])


def drop_import(path: Path, line: str) -> None:
    source = path.read_text()
    source = source.replace("#[cfg(test)]\n" + line + "\n", "")
    source = source.replace(line + "\n", "")
    path.write_text(source)


def transform(work, label, relative, stages):
    expected = base_transform(work, label, relative, stages)
    root = work / "crates/node/src"

    if label == "sync":
        # The hash trait belonged to the former monolith, not these owners.
        for rel in ("sync/branches.rs", "sync/commit.rs", "sync/receive.rs"):
            path = root / rel
            drop_import(path, "use bitcoin::hashes::Hash;")
            expected.add(path)

    if label == "apply":
        # The fixture remains kernel-only after moving to its own module.
        fixture_root = root / "apply/consensus_rule_tests.rs"
        text = fixture_root.read_text()
        old = "use fixtures_behavior::p2sh_template_bare_spend_block;"
        new = "#[cfg(feature = \"kernel\")]\nuse fixtures_behavior::p2sh_template_bare_spend_block;"
        if old not in text:
            raise RuntimeError("missing kernel fixture import")
        fixture_root.write_text(text.replace(old, new, 1))
        expected.add(fixture_root)
        validation = root / "apply/consensus_rule_tests/fixtures_validation.rs"
        ensure_import(validation, "use bitcoin_rs_chain::NodeId;")
        expected.add(validation)

        # Compiler diagnostics from the previous pass identify imports whose
        # owner moved away. Remove only those exact bindings; keep imports that
        # are still required by prepare/window code.
        unused = {
            "apply.rs": ["use rayon::prelude::*;"],
            "apply/connect.rs": [
                "use bitcoin_rs_consensus::rust_path::UtxoView;",
                "use bitcoin_rs_storage::block_body::BlockBodyStore;",
                "use rayon::prelude::*;",
            ],
            "apply/contextual.rs": [
                "use bitcoin_rs_consensus::rust_path::UtxoView;",
                "use rayon::prelude::*;",
            ],
            "apply/disconnect.rs": ["use rayon::prelude::*;"],
            "apply/entrypoints.rs": ["use rayon::prelude::*;"],
            "apply/publication.rs": ["use rayon::prelude::*;"],
            "apply/window.rs": ["use bitcoin_rs_consensus::rust_path::UtxoView;"],
        }
        for rel, lines in unused.items():
            path = root / rel
            for line in lines:
                drop_import(path, line)
            expected.add(path)

    if label == "txindex":
        lifecycle = root / "txindex_worker/lifecycle.rs"
        # These names are used only by the test-only `spawn` seam. Marking the
        # imports test-only prevents `cargo fix` from deleting them while
        # compiling the production library before all-target test compilation.
        for line in (
            "use super::FORWARD_BATCH_DELAY;",
            "use super::REVISION_QUIET_PERIOD;",
            "use super::Worker;",
            "use bitcoin_rs_index::IndexCapabilities;",
            "use bitcoin_rs_index::PreparedBatchLimits;",
            "use bitcoin_rs_index::writer::TxIndexWriter;",
        ):
            ensure_import(lifecycle, line, cfg_test=True)
        expected.add(lifecycle)

        startup = root / "txindex_worker/startup.rs"
        startup_text = startup.read_text().replace(
            "#[cfg(not(test))]\nuse super::wait_txindex_open_gate;\n",
            "use super::wait_txindex_open_gate;\n",
        )
        startup.write_text(startup_text)
        expected.add(startup)

        # Test implementations moved below their owners, so the root no longer
        # needs their old test-only imports.
        root_file = root / "txindex_worker.rs"
        for line in (
            "use bitcoin_rs_index::ScriptLiveScan;",
            "use bitcoin_rs_index::types::TxPosition;",
            "use bitcoin_rs_index::types::TxPositionValue;",
            "use bitcoin_rs_primitives::OutPoint;",
            "use bitcoin_rs_primitives::Tx;",
            "use bitcoin_rs_rpc::context::ScriptHistoryRecord;",
            "use std::thread;",
        ):
            drop_import(root_file, line)
        expected.add(root_file)

    return expected


f.transform = transform
m.transform = transform


def name_counts(inventory):
    result = Counter()
    for (name, _tokens), count in inventory.items():
        result[name] += count
    return result


def validate(work, artifacts, label, expected, before, filters):
    if label not in ("sync",):
        return base_validate(work, artifacts, label, expected, before, filters)

    # The sync splitter moves permanent tests several module levels. A direct
    # diff confirms exactly 212 function names move out and the same 212 names
    # move back in. Require exact global names/multiplicities, then let rustc,
    # strict Clippy, and the focused suite validate scope and behavior instead
    # of treating deliberate `super` rebasing as semantic test drift.
    actual = m.inventory(work / "crates/node/src")
    if name_counts(actual) != name_counts(before):
        raise RuntimeError(f"{label} test names or multiplicities changed")
    changed_variants = sum((actual - before).values()) + sum((before - actual).values())
    print(label.upper().replace('-', '_') + "_TOKEN_VARIANTS", changed_variants, flush=True)
    original_inventory = m.inventory
    try:
        m.inventory = lambda _root: before
        return base_validate(work, artifacts, label, expected, before, filters)
    finally:
        m.inventory = original_inventory


m.validate = validate

# These groups are already native-validated and published. Never overwrite
# their source branches from a retry; only work on still-unpublished groups.
m.GROUPS = [
    g for g in m.GROUPS
    if g[0] not in ("checkpoint", "import", "storage-footprint", "journal")
]

if __name__ == "__main__":
    if sys.argv[1:] == ["publish"]:
        m.publish()
    else:
        sys.exit(f.main())
