"""One-shot node extraction plans; deliberately excluded from product PRs."""
import argparse
import json
from pathlib import Path
from split_core import MOVES, extract_tests, function_bodies, parse, source_paths, split, standalone_imports, update_consumers

BASE = 'e6c5eae02738260b5b7240738323098afd6d7c5b'


def apply(root):
    path = root/'crates/node/src/apply.rs'
    groups = {
        'admission': 'ApplyAdmission TransitionLock begin_chain_transition ChainChangeProof PruneAuthority PruneGuard',
        'assume_valid': 'AssumeValidGate BlockProvenance',
        'connect': 'ApplyIntent ApplyFinish apply_block_inner apply_committed_block_admitted apply_block_admitted apply_block_with_serialized_admitted map_block_change_error',
        'disconnect': 'DisconnectPlan plan_disconnect disconnect_block_admitted',
        'publication': 'AppliedPublication begin_applied_publication tx_count_delta_for advance_chain_tx_count rewind_chain_tx_count',
        'window': 'SCRIPT_BATCH_WINDOW SCRIPT_BATCH_MAX_BYTES window_len apply_window_admitted invalidate_failed_subtree is_permanent_apply_error WindowApplyError WindowApplyDisposition prove_window',
        'prepare': 'BlockValidationContext BlockValidationProof ProvenApply PreparedApply ByteEquality bytes_are_block parse_block_for_apply prepare_apply',
        'prevouts': 'LOCAL_OVERLAY_TXID_SET_THRESHOLD BlockTxPlan WitnessPresence plan_block_transactions ResolvedUtxoView resolve_block_prevouts BlockLocalUtxoView',
        'validation': 'COINBASE_MATURITY BIP68_DISABLE_FLAG BIP68_TYPE_FLAG BIP68_MASK BIP68_TIME_GRANULARITY_SECONDS BIP34_IMPLIES_BIP30_LIMIT Bip68Context run_non_script_checks_only verify_block_transactions check_coinbase_maturity check_coinbase_maturity_with_tx_plan check_coinbase_input_maturity check_bip68_sequence_locks bip68_prevout_mtp check_bip30_and_bip34 should_scan_bip30_duplicates compute_verify_flags',
        'headers': 'compact_to_target compact_is_met_by applied_predecessor check_unseen_header_timestamp applied_header_tip check_pow_limit_and_continuity apply_nbits_error',
    }
    docs = {
        'admission': 'Admission, transition proofs, and destructive-pruning authority.',
        'assume_valid': 'Hash-pinned script-verification trust and block provenance.',
        'connect': 'Ordered connect/proposal validation and the UTXO commit boundary.',
        'disconnect': 'Preflight refusal and fatal rollback, with durable marker ordering.',
        'publication': 'Coherent applied-tip and cumulative-transaction-count publication.',
        'window': 'Bounded multi-block preparation and ordered prefix commits.',
        'prepare': 'Parse-once block preparation and single-use validation evidence.',
        'prevouts': 'Transaction planning and ordered same-block prevout resolution.',
        'validation': 'Contextual transaction checks over the captured authoritative view.',
        'headers': 'Header identity, predecessor, timestamp, and target validation.',
    }
    changed = split(path, groups, docs=docs, public_modules=('assume_valid','window'))
    return changed | extract_tests(path)


def sync(root):
    path = root/'crates/node/src/sync.rs'
    groups = {
        'peers': 'is_peer_fault sync_peer_candidate outranks active_demonstrated_height body_capability_height',
        'apply': 'settle_window_failure settle_window_success restore_split',
        'observability': 'metric_count',
    }
    methods = {'BlockSync': {
        'headers': 'on_peer_ready reconcile_peer_sessions drain_inbound_headers refresh_active_peer_credit request_headers_from_best_peer send_getheaders has_pending_getheaders build_locator ensure_genesis_tip',
        'receive': 'drain_inbound_blocks fill_inbound_block_chunk indexed_applied_ancestry_tip buffer_received_block_chunk',
        'apply': 'apply_window_followed switch_branch_if_outweighed retire_applied_reorg_body outweighed_branch_target note_fatal_settlement apply_buffered_blocks',
        'expected': 'expected_apply_horizon expected_block_hashes populate_expected_apply_cache drain_cached_expected_blocks advance_expected_apply_cache next_expected_block_hash',
        'peers': 'sync_peer_selection send_prefix_probes send_getdata_for_pending_blocks send_cold_front_hedge disconnect_window_staller disconnect_timed_out_peer select_and_evict_window_peer',
        'observability': 'emit_sync_progress record_sync_metrics record_pending_sync_metrics',
    }}
    docs = {
        'headers': 'Session-bound header acquisition and peer-credit reconciliation.',
        'receive': 'Bounded inbound body draining and staged-body admission.',
        'apply': 'Applied-chain handoff, prefix settlement, and reorg recovery.',
        'expected': 'Tip-pinned expected-block runs and cache advancement.',
        'peers': 'Peer selection, request dispatch, hedging, and staller policy.',
        'observability': 'Read-only synchronization progress and metric projection.',
    }
    changed = split(path, groups, methods, docs)
    return changed | extract_tests(path) | extract_tests(root/'crates/node/src/sync/stage.rs')


def mining(root):
    path = root/'crates/node/src/mining.rs'
    groups = {
        'generation': 'GenerationKey MempoolSequenceWake MiningGenerationSignal parse_long_poll_id hex_encode hex_decode decode_nibble generation_race is_generation_race',
        'hashrate': 'hashps_missing_height resolve_hash_ps_start hash_ps_at estimate_network_hashps hashes_per_second',
        'selection': 'snapshot_for_selection snapshot_entry_from_raw',
        'validation': 'map_apply_error signet_info',
    }
    methods = {'MiningCoordinator': {
        'generation': 'publish_generation publish_generation_from notify_shutdown live_generation_key current_time_secs ensure_published wait_for_generation_change',
        'assembly': 'live_candidate candidate_for_key assemble_for_key assemble_fresh generate_blocks',
        'template': 'template_from_candidate version_bits_for mining_info_snapshot',
        'validation': 'propose submit',
    }}
    docs = {
        'generation': 'Applied-tip/mempool generation identity, long polling, and wake signals.',
        'hashrate': 'Network hash-rate estimation over a captured header ancestry.',
        'selection': 'Mempool snapshot conversion for candidate selection.',
        'assembly': 'Single-flight candidate construction and local block generation.',
        'template': 'Candidate-bound template and mining-information projection.',
        'validation': 'Proposal/submission outcomes and consensus refusal mapping.',
    }
    changed = split(path, groups, methods, docs, public_modules=('generation',))
    return changed | extract_tests(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--group', choices=('apply','sync-mining'), required=True)
    args = parser.parse_args()
    root = Path('.')
    before = function_bodies((root/'crates/node/src').rglob('*.rs'))
    changed = apply(root) if args.group == 'apply' else sync(root) | mining(root)
    changed |= update_consumers(root)
    for path in sorted(changed):
        standalone_imports(Path(path))
        parse(Path(path).read_bytes())
    reverse = {}
    for (path,name),mod in MOVES.items():
        local = path.removeprefix('crates/node/src/').removesuffix('.rs').replace('/','::')
        for prefix in ('crate::','bitcoin_rs_node::'):
            reverse[prefix+local+'::'+mod+'::'+name] = prefix+local+'::'+name
    after = function_bodies((root/'crates/node/src').rglob('*.rs'),reverse)
    report = {
        'base': BASE, 'group': args.group, 'changed_paths': sorted(changed),
        'moves': [{'source':p,'symbol':n,'module':m} for (p,n),m in sorted(MOVES.items())],
        'function_bodies_before': sum(before.values()), 'function_bodies_after': sum(after.values()),
        'body_multiset_removed': dict(before-after), 'body_multiset_added': dict(after-before),
    }
    Path('/tmp/node-splits-report.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
