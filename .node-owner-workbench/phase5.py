"""Mining, storage measurement and block-import source ownership."""
from pathlib import Path
import re
from support import r, assign, migration


def run():
    groups = assign({}, {
        'generation': 'GenerationKey MempoolSequenceWake MiningGenerationSignal parse_long_poll_id LONG_POLL_SLICE DEFAULT_MEMPOOL_UPDATE_WAIT',
        'cache': 'InFlight CoordinatorState CANDIDATE_CACHE_LIMIT',
        'candidate': 'CANDIDATE_GENERATION_RETRIES GENERATION_RACE generation_race is_generation_race',
        'submission': 'map_apply_error snapshot_for_selection snapshot_entry_from_raw hex_decode decode_nibble',
        'hashrate': 'hashps_missing_height resolve_hash_ps_start hash_ps_at estimate_network_hashps hashes_per_second',
        'encoding': 'hex_encode',
        'template': 'MAX_BLOCK_WEIGHT MAX_BLOCK_SIZE signet_info',
    })
    methods = assign({}, {
        'generation': 'publish_generation publish_generation_from live_generation_key current_time_secs ensure_published wait_for_generation_change',
        'candidate': 'live_candidate candidate_for_key assemble_for_key assemble_fresh',
        'submission': 'generate_blocks propose submit',
        'info': 'mining_info_snapshot',
        'template': 'template_from_candidate version_bits_for',
    })
    r.split_owner('mining', 'mining', groups, {'MiningCoordinator': methods})
    path = r.ROOT / 'lib.rs'
    path.write_text(re.sub(r'pub use mining::\{[^}]*\};\s*', '', path.read_text()))
    r.add_map('GenerationKey', 'mining::generation::GenerationKey')
    r.add_map('MiningCoordinator', 'mining::MiningCoordinator')
    r.migrate_paths()

    groups = assign({}, {
        'format': 'EVIDENCE_FORMAT StorageFootprintEvidence EvidenceIdentity IndexWatermarkEvidence WatermarkEvidence LogicalEvidence LogicalOwnerEvidence PhysicalEvidence PhysicalNamespaceEvidence BudgetEvidence storage_footprint_json',
        'identity': 'evidence_identity resolve_stop read_witness_from_anchor index_lane script_index_name compiled_features cargo_lock_sha256 sha256_file hex_sha256 watermark_evidence watermark_json',
        'logical': 'collect_logical scan_store LogicalScan scan_store_with_watermarks TxIndexScan',
        'budget': 'DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES budget_evidence is_default_unpruned_mainnet',
    })
    r.split_owner('storage_footprint', 'storage_footprint', groups)
    path = r.ROOT / 'lib.rs'
    path.write_text(re.sub(r'pub use storage_footprint::\{.*?\};\s*', '', path.read_text(), flags=re.S))
    for name in 'MeasureStorageRequest measure_storage_footprint'.split():
        r.add_map(name, 'storage_footprint::' + name)
    for name in 'StorageFootprintEvidence EVIDENCE_FORMAT storage_footprint_json'.split():
        r.add_map(name, 'storage_footprint::format::' + name)
    r.add_map('DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES', 'storage_footprint::budget::DEFAULT_UNPRUNED_PEAK_BUDGET_BYTES')
    r.migrate_paths()
    path = Path('bin/bitcoin-rs/tests/support/ownership_scan.rs')
    path.write_text(path.read_text().replace('crates/node/src/storage_footprint.rs', 'crates/node/src/storage_footprint/logical.rs'))
    path = r.ROOT / 'storage_backend.rs'
    text = path.read_text().replace('"storage_footprint.rs",\n            include_str!("storage_footprint.rs"),\n            Some("mod tests {"),', '"storage_footprint/logical.rs",\n            include_str!("storage_footprint/logical.rs"),\n            None,')
    path.write_text(text)
    for owner in ['mining', 'storage_footprint', 'import']:
        path = r.ROOT / (owner + '.rs')
        if owner == 'import':
            r.extract_inline_tests(path)
        for path in list((r.ROOT / owner).rglob('*.rs')):
            if path.stem == 'tests':
                r.test_partition(path)
    path = r.ROOT / 'import.rs'
    text = path.read_text()
    first_import = text.index('use anyhow')
    text = '''//! Block decoding and admission through the authoritative node chainstate.
//!
//! Import reports a result only after chainstate validation, durable mutation,
//! and committed-effect publication complete.

''' + text[first_import:]
    text = text.replace('    /// Successful decode now publishes the block as a synthetic active-chain\n    /// tip through [`NodeState::apply_block`].', '    /// Success requires [`NodeState::apply_block`] to commit the block.')
    text = text.replace('/// V1 contract: synthetically apply after decode. Returns an error if the bytes\n/// are malformed or the block cannot connect to the current synthetic tip.', '/// Returns an error for malformed encoding, failed validation, or a block that\n/// cannot connect to the current applied tip.')
    path.write_text(text)
    migration('''## Mining, storage measurement, and import

Import `MiningCoordinator` from `mining` and `GenerationKey` from
`mining::generation`, not the crate root. Candidate assembly, generation wakeups,
single-flight caching, template construction, submission, and hashrate calculations
have separate implementations around the one coordinator state.

Storage measurement entry points and requests live in `storage_footprint`;
evidence DTOs and JSON rendering live in `storage_footprint::format`, and the peak
budget constant lives in `storage_footprint::budget`. Their crate-root aliases
are removed. Identity collection and logical-store scanning have direct owners.

Block import keeps the actual decode/admission entry point; its tests are
separate from runtime code. No legacy pipeline or alternate mutation route exists.
''')
