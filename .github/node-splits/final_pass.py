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

        # Exact unused bindings reported by the previous all-target compiler
        # pass. Keep the root Rayon prelude: root-level tests still call
        # `par_iter` after the production responsibilities move out.
        unused = {
            "apply.rs": [
                "use bitcoin_rs_chain::ChainWork;",
                "use bitcoin_rs_primitives::ConsensusEncode;",
            ],
            "apply/connect.rs": [
                "use super::block_txids;",
                "use bitcoin_rs_consensus::rust_path::UtxoView;",
                "use bitcoin_rs_storage::block_body::BlockBodyStore;",
                "use rayon::prelude::*;",
            ],
            "apply/contextual.rs": [
                "use bitcoin_rs_consensus::rust_path::UtxoView;",
                "use bitcoin_rs_primitives::CompactTarget;",
                "use rayon::prelude::*;",
            ],
            "apply/disconnect.rs": ["use rayon::prelude::*;"],
            "apply/entrypoints.rs": [
                "use bitcoin_rs_consensus::rust_path::UtxoView;",
                "use bitcoin_rs_primitives::ConsensusEncode;",
                "use bitcoin_rs_storage::block_body::BlockBodyStore;",
                "use bitcoin_rs_utxo::connect::SpentOutputLookup;",
                "use rayon::prelude::*;",
            ],
            "apply/publication.rs": ["use rayon::prelude::*;"],
            "apply/window.rs": [
                "use bitcoin_rs_consensus::rust_path::UtxoView;",
                "use bitcoin_rs_primitives::Script;",
            ],
        }
        for rel, lines in unused.items():
            path = root / rel
            for line in lines:
                drop_import(path, line)
            expected.add(path)

    if label == "txindex":
        lifecycle = root / "txindex_worker/lifecycle.rs"
        # These names are used only by the test-only `spawn` seam. Marking the
        # imports test-only prevents the production build from treating them as
        # stale while all-target test compilation still sees the seam.
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
            "use bitcoin_rs_index::TxIndexSnapshot;",
            "use bitcoin_rs_index::types::TxPosition;",
            "use bitcoin_rs_index::types::TxPositionValue;",
            "use bitcoin_rs_primitives::OutPoint;",
            "use bitcoin_rs_primitives::Tx;",
            "use bitcoin_rs_rpc::context::ScriptHistoryRecord;",
            "use rayon::prelude::*;",
            "use std::thread;",
        ):
            drop_import(root_file, line)
        expected.add(root_file)

        # Exact module-local unused bindings from the previous all-target
        # compiler pass. These are former monolith-wide imports, not API shims.
        unused = {
            "txindex_worker/reconciliation.rs": ["use rayon::prelude::*;"],
            "txindex_worker/query_transaction.rs": ["use rayon::prelude::*;"],
            "txindex_worker/query_snapshot.rs": [
                "use bitcoin_rs_storage::block_body::BlockBodyStore;",
                "use rayon::prelude::*;",
            ],
            "txindex_worker/query_script.rs": ["use rayon::prelude::*;"],
            "txindex_worker/query_protocol.rs": ["use rayon::prelude::*;"],
            "txindex_worker/rollback.rs": [
                "use bitcoin_rs_storage::block_body::BlockBodyReader;",
                "use bitcoin_rs_storage::block_body::BlockBodyStore;",
                "use rayon::prelude::*;",
            ],
            "txindex_worker/lifecycle.rs": ["use rayon::prelude::*;"],
            "txindex_worker/catch_up.rs": [
                "use bitcoin_rs_index::TxIndexSnapshot;",
                "use bitcoin_rs_storage::block_body::BlockBodyStore;",
            ],
            "txindex_worker/cursor.rs": [
                "use bitcoin_rs_index::IndexReader;",
                "use bitcoin_rs_index::TxIndexSnapshot;",
                "use bitcoin_rs_storage::block_body::BlockBodyStore;",
                "use rayon::prelude::*;",
            ],
        }
        for rel, lines in unused.items():
            path = root / rel
            for line in lines:
                drop_import(path, line)
            expected.add(path)

    return expected


f.transform = transform
m.transform = transform

# Every still-unpublished group must pass the original exact test-token gate;
# sync has already passed and been published as #928.
m.validate = base_validate

# Already published groups are immutable. Work only on apply/txindex/reorg.
m.GROUPS = [
    g for g in m.GROUPS
    if g[0] not in (
        "checkpoint", "import", "storage-footprint", "journal", "sync"
    )
]

if __name__ == "__main__":
    if sys.argv[1:] == ["publish"]:
        m.publish()
    else:
        sys.exit(f.main())
