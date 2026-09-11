from pathlib import Path
import sys
root = Path(sys.argv[1]) / 'crates/node/src'
changes = {
    'txindex_worker.rs': [('startup, and query/block_source/capability own', 'startup, and `query/block_source/capability` own')],
    'txindex_worker/live.rs': [('//! ScriptLive rebuilds', '//! `ScriptLive` rebuilds')],
    'txindex_worker/tests/body_reader.rs': [('use bitcoin_rs_primitives::Network;', 'use bitcoin_rs_primitives::{Hash256, Network};')],
    'txindex_worker/query/tests.rs': [('IndexError, IndexWatermark, ScriptLiveScan, TxIndexScan, TxIndexScanRow', 'IndexError, IndexWatermark, TxIndexScan, TxIndexScanRow')],
    'txindex_worker/supervisor/tests.rs': [
        ('query_adapter::TxIndexQueryAdapter, ', ''),
        ('use bitcoin_rs_primitives::{Hash256, Txid};\n', ''),
        ('use bitcoin_rs_rpc::context::{TxIndexQuery, TxQueryError};\n', ''),
    ],
}
for relative, replacements in changes.items():
    p = root / relative
    text = p.read_text()
    for old, new in replacements:
        assert old in text, (relative, old)
        text = text.replace(old, new)
    p.write_text(text)
