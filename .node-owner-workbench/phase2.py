"""Move block synchronization to its owner and delete superseded aliases."""
from pathlib import Path
import re
from support import r, assign, migration

ALIASES = {
    'prefix_probe_state_does_not_survive_owner_replacement': 'tick_fanout_deferred_for_fresh_probe_engages_at_deadline',
    'sole_peer_staller_disconnected_and_usable_again_as_last_resort': 'tick_allows_demoted_peer_when_it_is_the_only_eligible_peer',
    'tick_does_not_request_above_peer_advertised_height': 'clean_fast_path_caps_request_at_peer_height',
    'stale_queued_block_keeps_payload_without_peer_credit': 'unsolicited_stale_block_retries_from_resolved_header_height',
    'reconnecting_staller_held_out_of_window_front_by_cooldown': 'stalled_frontier_peer_disconnected_after_adaptive_timeout_and_stripe_requeued',
}


def run():
    r.phase_sync()
    removed = []
    for path in (r.ROOT / 'block_sync/tests').rglob('*.rs'):
        source = path.read_text()
        edits = []
        for node, raw in r.items(source):
            name = r.name_of(source, node)
            if node.type == 'function_item' and name in ALIASES:
                body = r.txt(source, node.child_by_field_name('body'))
                assert re.sub(r'\s', '', body) == '{' + ALIASES[name] + '()}', (name, body)
                start = node.start_byte
                previous = node.prev_named_sibling
                while previous and previous.type in ('attribute_item', 'line_comment', 'block_comment'):
                    start = previous.start_byte
                    previous = previous.prev_named_sibling
                edits.append((start, node.end_byte))
                removed.append(name)
        data = source.encode()
        for start, end in sorted(edits, reverse=True):
            data = data[:start] + data[end:]
        if edits:
            path.write_text(data.decode())
    assert set(removed) == set(ALIASES), removed
    for path in Path('.').rglob('*'):
        if not path.is_file() or path.suffix not in ('.rs', '.md', '.toml', '.sh') or '.git' in path.parts or 'target' in path.parts:
            continue
        source = path.read_text()
        text = source
        for old, new in ALIASES.items():
            text = text.replace(old, new)
        text = text.replace('crates/node/src/sync.rs', 'crates/node/src/block_sync.rs')
        if source != text:
            path.write_text(text)
    groups = assign({}, {
        'download_fixtures': 'ExhaustionFixture staging_exhaustion_fixture DETERMINISTIC_PROXY_BLOCKS DETERMINISTIC_PROXY_TIP_HEIGHT DETERMINISTIC_PROXY_HEADER_HEIGHT DeterministicProxyFixture deterministic_proxy_fixture ApplyCacheFixture apply_cache_fixture stage_body cache_snapshot WedgeFixture wedge_budget staged_count_wedge',
        'chains': 'SyncFixture InboundBlockSender sync_with_header_chain sync_with_header_chain_and_blocks MinedChainFixture sync_with_mined_chain header_chain_block GENESIS_TIME test_header nbits_mismatch_header far_future_header pow_met HeaderSyncFixture header_sync_with_genesis genesis_header coinbase_transaction transaction mined_block_with_prev_hash merkle_root assert_applied_genesis MaturedChain matured_chain apply_handles',
        'peer_fixtures': 'assert_fallback_with_ineligible_candidate next_getdata assert_no_getdata witness_block_inventory current_source register_info synthetic_peer eligible_peer test_addr connect_peer',
        'recorder': 'TestMetric TestRecorder TestCounter TestGauge TestHistogram assert_gauge assert_metric_absent assert_histogram',
        'faults': 'FailOnceBodyStore DisarmFailsUndoStore',
    })
    r.split_owner('block_sync/tests', 'block_sync/tests', groups)
    path = r.ROOT / 'block_sync/tests.rs'
    text = path.read_text()
    for group in sorted(set(groups.values())):
        text += '\nuse ' + group + '::*;\n'
    r.write(path, text)
    r.migrate_paths()
    for path in [r.ROOT / 'block_sync.rs', *(r.ROOT / 'block_sync').rglob('*.rs')]:
        path.write_text(path.read_text().replace('#[allow(unused_imports)]\n', ''))
    migration('''## Block synchronization

`sync` and the crate-root `BlockSync` alias are removed. Import the orchestrator
from `bitcoin_rs_node::block_sync::BlockSync`. Import `SyncBudget` and
`default_sync_budget` from `bitcoin_rs_p2p::download_window`, their actual owner.

Header negotiation, peer selection, requests, staging, branch switching, apply
settlement, expected-frontier caching, and telemetry have dedicated modules.
The orchestrator still owns one download window and one staging buffer.

Five duplicate test-name wrappers are removed. Their documentation selectors now
name the original tests containing the assertions. The assertions and the latest
mainline synchronization regression tests remain in the implementation owners.
''')
