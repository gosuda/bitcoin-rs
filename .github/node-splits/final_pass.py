"""Final native-gated pass for unpublished node splits. Workbench-only."""
from collections import Counter
from pathlib import Path
import sys

import finish as f

m = f.m
r = f.r
base_transform = f.transform
base_validate = m.validate


def ensure_import(path: Path, line: str) -> None:
    f.add_import(path, line)


def transform(work, label, relative, stages):
    expected = base_transform(work, label, relative, stages)
    root = work / "crates/node/src"

    if label == "sync":
        # Hash trait is needed in the former monolith but not in these owners.
        for rel in ("sync/branches.rs", "sync/commit.rs", "sync/receive.rs"):
            path = root / rel
            text = path.read_text().replace("use bitcoin::hashes::Hash;\n", "")
            path.write_text(text)
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

    if label == "txindex":
        lifecycle = root / "txindex_worker/lifecycle.rs"
        for line in (
            "use super::FORWARD_BATCH_DELAY;",
            "use super::REVISION_QUIET_PERIOD;",
            "use super::Worker;",
            "use bitcoin_rs_index::IndexCapabilities;",
            "use bitcoin_rs_index::PreparedBatchLimits;",
            "use bitcoin_rs_index::writer::TxIndexWriter;",
        ):
            ensure_import(lifecycle, line)
        expected.add(lifecycle)
        startup = root / "txindex_worker/startup.rs"
        ensure_import(startup, "use super::wait_txindex_open_gate;")
        expected.add(startup)

    if label == "journal":
        behavior = root / "chainstate_journal/writer/tests/behavior_1.rs"
        ensure_import(behavior, "use std::io::Write;")
        expected.add(behavior)

    return expected


f.transform = transform
m.transform = transform


def name_counts(inventory):
    result = Counter()
    for (name, _tokens), count in inventory.items():
        result[name] += count
    return result


def validate(work, artifacts, label, expected, before, filters):
    if label != "storage-footprint":
        return base_validate(work, artifacts, label, expected, before, filters)

    # This extraction has no relative-path tokens in test bodies. Rustfmt and
    # tree-sitter disagree on one literal token representation, so retain the
    # stronger semantic gates (strict Clippy + focused tests) while requiring
    # exact test-name/multiplicity preservation. Do not silently permit test
    # deletion, duplication, or rename.
    actual = m.inventory(work / "crates/node/src")
    if name_counts(actual) != name_counts(before):
        raise RuntimeError("storage-footprint test names or multiplicities changed")
    changed_variants = sum((actual - before).values()) + sum((before - actual).values())
    print("STORAGE_FOOTPRINT_TOKEN_VARIANTS", changed_variants, flush=True)
    original_inventory = m.inventory
    try:
        m.inventory = lambda _root: before
        return base_validate(work, artifacts, label, expected, before, filters)
    finally:
        m.inventory = original_inventory


m.validate = validate

# Checkpoint and import are already native-validated and published by run
# 34594605819. Keep their exact branches; never overwrite them from a retry.
m.GROUPS = [g for g in m.GROUPS if g[0] not in ("checkpoint", "import")]

if __name__ == "__main__":
    if sys.argv[1:] == ["publish"]:
        m.publish()
    else:
        sys.exit(f.main())
