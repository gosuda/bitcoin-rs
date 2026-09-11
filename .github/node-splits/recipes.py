"""Pinned, reviewed source cuts. This helper never enters a product branch."""
from pathlib import Path
import re
import extract as r

RETIRED={'sync':{
    'sole_peer_staller_disconnected_and_usable_again_as_last_resort',
    'tick_does_not_request_above_peer_advertised_height',
    'stale_queued_block_keeps_payload_without_peer_credit',
    'prefix_probe_state_does_not_survive_owner_replacement',
    'reconnecting_staller_held_out_of_window_front_by_cooldown',
}}

APPLY_GROUPS={
    'admission':'ApplyAdmission TransitionLock begin_chain_transition ChainChangeProof PruneAuthority PruneGuard',
    'assume_valid':'AssumeValidGate BlockProvenance',
    'chainstate':'Chainstate ChainstateSnapshot',
    'transition':'ChainTransition',
    'outcome':'ConnectOutcome DisconnectOutcome',
    'connect':'ApplyIntent ApplyFinish apply_block_inner apply_committed_block_admitted apply_block_admitted apply_block_with_serialized_admitted map_block_change_error',
    'disconnect':'DisconnectPlan plan_disconnect disconnect_block_admitted',
    'publication':'AppliedPublication begin_applied_publication tx_count_delta_for advance_chain_tx_count rewind_chain_tx_count',
    'window':'SCRIPT_BATCH_WINDOW SCRIPT_BATCH_MAX_BYTES window_len apply_window_admitted invalidate_failed_subtree is_permanent_apply_error WindowApplyError WindowApplyDisposition prove_window',
    'prepare':'BlockValidationContext BlockValidationProof ProvenApply PreparedApply ByteEquality bytes_are_block parse_block_for_apply prepare_apply',
    'prevouts':'LOCAL_OVERLAY_TXID_SET_THRESHOLD BlockTxPlan WitnessPresence plan_block_transactions ResolvedUtxoView resolve_block_prevouts BlockLocalUtxoView',
    'validation':'COINBASE_MATURITY BIP68_DISABLE_FLAG BIP68_TYPE_FLAG BIP68_MASK BIP68_TIME_GRANULARITY_SECONDS BIP34_IMPLIES_BIP30_LIMIT Bip68Context run_non_script_checks_only verify_block_transactions check_coinbase_maturity check_coinbase_maturity_with_tx_plan check_coinbase_input_maturity check_bip68_sequence_locks bip68_prevout_mtp check_bip30_and_bip34 should_scan_bip30_duplicates compute_verify_flags',
    'headers':'compact_to_target compact_is_met_by applied_predecessor check_unseen_header_timestamp applied_header_tip check_pow_limit_and_continuity apply_nbits_error',
}
APPLY_DOCS={
    'admission':'Admission, transition proofs, and destructive-pruning authority.',
    'assume_valid':'Hash-pinned script-verification trust and block provenance.',
    'chainstate':'Authoritative chainstate handles, coherent snapshots, and admission.',
    'transition':'An admitted chain mutation and its explicit completion boundary.',
    'outcome':'Committed transitions handed to post-commit consumers.',
    'connect':'Ordered connect/proposal validation and the UTXO commit boundary.',
    'disconnect':'Preflight refusal and fatal rollback, with durable marker ordering.',
    'publication':'Coherent applied-tip and cumulative-transaction-count publication.',
    'window':'Bounded multi-block preparation and ordered prefix commits.',
    'prepare':'Parse-once block preparation and single-use validation evidence.',
    'prevouts':'Transaction planning and ordered same-block prevout resolution.',
    'validation':'Contextual transaction checks over the captured authoritative view.',
    'headers':'Header identity, predecessor, timestamp, and target validation.',
}
SYNC_GROUPS={
    'peers':'is_peer_fault sync_peer_candidate outranks active_demonstrated_height body_capability_height GetdataRequestOutcome',
    'apply':'settle_window_failure settle_window_success restore_split',
    'observability':'metric_count',
    'expected':'ExpectedBlockHashes ExpectedApplyCache ExpectedRun',
    'headers':'PendingHeaderRequest LOCATOR_MAX_ENTRIES PROTOCOL_VERSION HEADER_REQUEST_TIMEOUT',
}
SYNC_METHODS={'BlockSync':{
    'headers':'on_peer_ready reconcile_peer_sessions drain_inbound_headers refresh_active_peer_credit request_headers_from_best_peer send_getheaders has_pending_getheaders build_locator ensure_genesis_tip',
    'receive':'drain_inbound_blocks fill_inbound_block_chunk indexed_applied_ancestry_tip buffer_received_block_chunk',
    'apply':'apply_window_followed switch_branch_if_outweighed retire_applied_reorg_body outweighed_branch_target note_fatal_settlement apply_buffered_blocks',
    'expected':'expected_apply_horizon expected_block_hashes populate_expected_apply_cache drain_cached_expected_blocks advance_expected_apply_cache next_expected_block_hash',
    'peers':'sync_peer_selection send_prefix_probes send_getdata_for_pending_blocks send_cold_front_hedge disconnect_window_staller disconnect_timed_out_peer select_and_evict_window_peer',
    'observability':'emit_sync_progress record_sync_metrics record_pending_sync_metrics',
}}
MINING_GROUPS={
    'generation':'GenerationKey MempoolSequenceWake MiningGenerationSignal parse_long_poll_id hex_encode hex_decode decode_nibble generation_race is_generation_race',
    'hashrate':'hashps_missing_height resolve_hash_ps_start hash_ps_at estimate_network_hashps hashes_per_second',
    'selection':'snapshot_for_selection snapshot_entry_from_raw',
    'validation':'map_apply_error signet_info',
}
MINING_METHODS={'MiningCoordinator':{
    'generation':'publish_generation publish_generation_from notify_shutdown live_generation_key current_time_secs ensure_published wait_for_generation_change',
    'assembly':'live_candidate candidate_for_key assemble_for_key assemble_fresh generate_blocks',
    'template':'template_from_candidate version_bits_for mining_info_snapshot',
    'validation':'propose submit',
}}


def rewrite_paths(maps):
    for path in r.sources():
        data=path.read_bytes(); edits=[]
        def visit(node):
            if node.type=='use_declaration':
                m=re.match(r'((?:pub(?:\([^)]*\))?\s+)?use\s+)(.*);$',node.text.decode(),re.S)
                if m:
                    old=r.parse_uses(m[2]); new=[(maps.get(p,p),a) for p,a in old]
                    if old!=new:
                        text=m[1]+'{'+', '.join(p+((' as '+a) if a else '') for p,a in new)+'};'
                        edits.append((node.start_byte,node.end_byte,text.encode()))
                return
            for child in node.named_children: visit(child)
        visit(r.parse(data).root_node)
        for a,b,text in sorted(edits,reverse=True): data=data[:a]+text+data[b:]
        for old,new in maps.items(): data=re.sub(re.escape(old.encode())+rb'\b',new.encode(),data)
        if data!=path.read_bytes(): r.write(path,data)


def remove_pool_authority():
    path=Path('crates/node/src/apply/chainstate.rs')
    data=path.read_bytes(); edits=[]
    for item in r.parse(data).root_node.named_children:
        if item.type=='struct_item' and item.child_by_field_name('name').text==b'Chainstate':
            body=item.child_by_field_name('body'); previous=body.start_byte+1
            for field in body.named_children:
                if field.type!='field_declaration': continue
                end=field.end_byte+(data[field.end_byte:field.end_byte+1]==b',')
                if field.child_by_field_name('name').text==b'mempool': edits.append((previous,end,b''))
                previous=end
        if item.type=='impl_item' and item.child_by_field_name('type').text==b'Chainstate':
            for method in item.child_by_field_name('body').named_children:
                if method.type!='function_item' or method.child_by_field_name('name').text!=b'new': continue
                params=method.child_by_field_name('parameters')
                p=next(p for p in params.named_children if p.type=='parameter' and p.child_by_field_name('pattern').text==b'mempool')
                edits.append((p.start_byte,p.end_byte+(data[p.end_byte:p.end_byte+1]==b','),b''))
                def walk(node):
                    if node.type=='shorthand_field_initializer' and node.text==b'mempool': edits.append((node.start_byte,node.end_byte+(data[node.end_byte:node.end_byte+1]==b','),b''))
                    for c in node.named_children: walk(c)
                walk(method)
    if len(edits)!=3: raise ValueError(f'Unexpected pool ownership shape: {len(edits)}')
    for a,b,text in sorted(edits,reverse=True): data=data[:a]+text+data[b:]
    data=data.replace(b'    /// from the weak registry. The raw `mempool` field stays for read-only\n    /// node code that still needs the pool.\n',b'    /// from the weak registry. Reads use the same gateway-owned pool.\n')
    data=data.replace(b'    #[allow(clippy::too_many_arguments)]\n    #[must_use]\n    pub fn new(',b'    #[must_use]\n    pub fn new(')
    r.write(path,data)
    callers=[]
    for path in r.sources():
        data=path.read_bytes(); edits=[]
        def visit(node):
            if node.type=='call_expression' and re.search(rb'(?:^|::)Chainstate::new$',node.child_by_field_name('function').text):
                args=[c for c in node.child_by_field_name('arguments').named_children if c.type not in ('line_comment','block_comment')]
                if len(args)!=9: raise ValueError(f'{path}: unexpected constructor argument count {len(args)}')
                arg=args[6]; edits.append((arg.start_byte,arg.end_byte+(data[arg.end_byte:arg.end_byte+1]==b','),b'')); callers.append(str(path))
            if node.type=='struct_expression' and re.search(rb'(?:^|::)Chainstate$',node.child_by_field_name('name').text):
                for f in node.child_by_field_name('body').named_children:
                    if f.type=='field_initializer' and f.child_by_field_name('field').text==b'mempool': edits.append((f.start_byte,f.end_byte+(data[f.end_byte:f.end_byte+1]==b','),b''))
            for child in node.named_children: visit(child)
        visit(r.parse(data).root_node)
        for a,b,text in sorted(edits,reverse=True): data=data[:a]+text+data[b:]
        data=data.replace(b'handles.mempool.read()',b'handles.mempool_gateway.read()')
        if data!=path.read_bytes(): r.write(path,data)
    print('Migrated Chainstate constructor callers:',callers,flush=True)


def restrict_proofs():
    path=Path('crates/node/src/apply/admission.rs'); data=path.read_bytes(); edits=[]
    for item in r.parse(data).root_node.named_children:
        if item.type=='struct_item' and item.child_by_field_name('name').text in (b'ApplyAdmission',b'TransitionLock',b'ChainChangeProof',b'PruneGuard'):
            for field in item.child_by_field_name('body').named_children:
                if field.type!='field_declaration': continue
                visibility=next((c for c in field.named_children if c.type=='visibility_modifier'),None)
                if visibility: edits.append((visibility.start_byte,visibility.end_byte+1,b''))
    for a,b,text in sorted(edits,reverse=True): data=data[:a]+text+data[b:]
    data=data.replace(b'    pub(super) fn ensure_open(&self)',b'    #[cfg(test)]\n    pub(super) fn has_in_flight(&self) -> bool {\n        self.barrier.is_locked()\n    }\n\n    pub(super) fn ensure_open(&self)')
    r.write(path,data)
    for path in Path('crates/node/src/apply').rglob('*.rs'):
        data=path.read_bytes(); changed=data.replace(b'handles.admission.barrier.is_locked()',b'handles.admission.has_in_flight()')
        if data!=changed: r.write(path,changed)


def place_apply_tests():
    root=Path('crates/node/src/apply.rs'); text=root.read_text()
    for path in list(Path('crates/node/src/apply').glob('*_tests.rs')):
        target=path.parent/'tests'/path.name; target.parent.mkdir(exist_ok=True)
        subtree=path.with_suffix(''); destination=target.with_suffix('')
        if subtree.is_dir():
            subtree.rename(destination)
            target=destination/'mod.rs'
            path.rename(target)
        else: path.rename(target)
        r.CHANGED.discard(str(path))
        r.CHANGED.add(str(target))
        if destination.is_dir():
            for new in destination.rglob('*.rs'): r.CHANGED.add(str(new))
            for old in list(r.CHANGED):
                if old.startswith(str(subtree)+'/'): r.CHANGED.discard(old)
        relative=str(target.relative_to(root.parent))
        text=text.replace('mod '+path.stem+';',f'#[path = "{relative}"]\nmod {path.stem};')
    r.write(root,text)


def update_ledger(stage_paths):
    path=Path('docs/benchmarks/hot-path-ledger.toml'); parts=path.read_text().split('[[paths]]')
    for index,part in enumerate(parts):
        m=re.search(r'^id = "([^"]+)"',part,re.M)
        if not m or m[1] not in stage_paths: continue
        old, replacements=stage_paths[m[1]]
        for p in replacements:
            if not Path(p).exists(): raise ValueError(f'Ledger path does not exist: {p}')
        parts[index]=part.replace('"'+old+'"',', '.join('"'+p+'"' for p in replacements))
    r.write(path,'[[paths]]'.join(parts))


def doc_fixes():
    # Existing stale intra-doc links become visible when the new owner modules
    # are documented with warnings denied. Fix links, not the underlying APIs.
    fixes={
        'mining.rs':{'[`TemplateId`]':'[`bitcoin_rs_mining::TemplateId`]'},
        'reconcile.rs':{'[`ConsumerCursor`]':'[`crate::reconcile::ConsumerCursor`]','[`Self::CURSOR_BYTE_LEN`]':'[`CURSOR_BYTE_LEN`]'},
        'reorg.rs':{'[`plan_reorg`]':'[`bitcoin_rs_chain::plan_reorg`]','[`crate::apply::disconnect_block`]':'[`crate::ChainTransition::disconnect`]','[`crate::apply::apply_block_with_serialized`]':'[`crate::ChainTransition::connect_serialized`]'},
        'sync.rs':{'[`crate::apply::apply_block`]':'[`crate::ChainTransition::connect_window`]'},
        'metrics/prometheus.rs':{'[`start_metrics`]':'`start_metrics`'},
        'state/checkpoint.rs':{'[`crate::checkpoint_worker::CHECKPOINT_INTERVAL_BLOCKS`]':'`CHECKPOINT_INTERVAL_BLOCKS`','[`crate::checkpoint_worker::CHECKPOINT_INTERVAL_SECS`]':'`CHECKPOINT_INTERVAL_SECS`'},
    }
    for name,replacements in fixes.items():
        path=Path('crates/node/src')/name; text=path.read_text(); original=text
        for a,b in replacements.items(): text=text.replace(a,b)
        if original!=text: r.write(path,text)


def apply(group):
    if group=='apply':
        # Storage representations are imported from their owner, not forwarded
        # through apply. Child modules derive the imports they actually need.
        rewrite_paths({'crate::apply::'+n:'bitcoin_rs_storage::'+n for n in ('UndoStore','KvUndoStore','DisconnectPhase')})
        path=Path('crates/node/src/apply.rs'); text=path.read_text().replace('pub(crate) use bitcoin_rs_storage::{DisconnectPhase, KvUndoStore, UndoStore};','use bitcoin_rs_storage::{DisconnectPhase, KvUndoStore, UndoStore};'); r.write(path,text)
        r.split(path,APPLY_GROUPS,public=('assume_valid','chainstate','transition','outcome','window'),docs=APPLY_DOCS)
        r.extract_tests(path)
        remove_pool_authority()
        restrict_proofs()
        place_apply_tests()
    elif group=='sync':
        # Remove only alias tests whose bodies call an independently retained
        # test. The real regression bodies and their assertions are untouched.
        path=Path('crates/node/src/sync.rs'); data=path.read_bytes(); edits=[]
        def visit(node):
            if node.type=='mod_item' and node.child_by_field_name('body'):
                _,children,_=r.items(data,node.child_by_field_name('body'))
                for item in children:
                    if item.kind=='function_item' and item.name in RETIRED['sync']:
                        if len(re.findall(rb'\bassert(?:_eq|_ne)?!',item.code)) or item.code.count(b'(')>3: raise ValueError(f'Alias test grew independent logic: {item.name}')
                        edits.append((item.node.start_byte-len(item.prefix),item.node.end_byte,b''))
            for child in node.named_children: visit(child)
        visit(r.parse(data).root_node)
        if len(edits)!=len(RETIRED['sync']): raise ValueError('Missing alias tests')
        for a,b,text in sorted(edits,reverse=True): data=data[:a]+text+data[b:]
        data=data.replace(b'#[allow(unused_imports)]\n',b'')
        r.write(path,data)
        r.split(path,SYNC_GROUPS,SYNC_METHODS,docs={
            'headers':'Session-bound header acquisition and peer-credit reconciliation.',
            'receive':'Bounded inbound body draining and staged-body admission.',
            'apply':'Applied-chain handoff, prefix settlement, and reorg recovery.',
            'expected':'Tip-pinned expected-block runs and cache advancement.',
            'peers':'Peer selection, request dispatch, hedging, and staller policy.',
            'observability':'Synchronization progress and metric projection.',
        })
        r.extract_tests(path)
        r.extract_tests('crates/node/src/sync/stage.rs')
        r.write(path,path.read_bytes().replace(b'pub(crate) mod ',b'mod '))
    elif group=='mining':
        r.split('crates/node/src/mining.rs',MINING_GROUPS,MINING_METHODS,public=('generation',),docs={
            'generation':'Applied-tip/mempool generation identity, long polling, and wake signals.',
            'hashrate':'Network hash-rate estimation over a captured header ancestry.',
            'selection':'Mempool snapshot conversion for candidate selection.',
            'assembly':'Single-flight candidate construction and local block generation.',
            'template':'Candidate-bound template and mining-information projection.',
            'validation':'Proposal/submission outcomes and consensus refusal mapping.',
        })
        r.extract_tests('crates/node/src/mining.rs')
    else: raise ValueError(f'Unknown group {group}')


def finish(group):
    if group=='apply':
        doc_fixes()
        path=Path('bin/bitcoin-rs/tests/support/ownership_scan.rs'); text=path.read_text()
        old='("crates/node/src/apply.rs", "handles.mempool_gateway")'
        if old not in text: raise ValueError('Ownership scanner owner changed')
        text=text.replace(old,'("crates/node/src/apply/connect.rs", "handles.mempool_gateway")')
        needle='    #[test]\n    fn a_raw_write_chain_is_never_authorized()'
        regression='''    #[test]
    fn block_eviction_is_authorized_only_in_the_connect_owner() {
        let source = "handles.mempool_gateway.remove_for_block(origin, txs, txids, height);";
        for (path, allowed) in [
            ("/workspace/crates/node/src/apply/connect.rs", true),
            ("/workspace/crates/node/src/apply.rs", false),
            ("/workspace/crates/node/src/apply/chainstate.rs", false),
            ("/workspace/crates/node/src/apply/disconnect.rs", false),
        ] {
            let mut result = empty_result();
            scan_source(path, source, &mut result);
            assert_eq!(result.violations.is_empty(), allowed, "{path}");
            assert_eq!(result.mutating_calls_found, 1);
        }
    }

'''
        if needle not in text: raise ValueError('Ownership scanner test anchor changed')
        r.write(path,text.replace(needle,regression+needle))
        stages={
            'apply.header_accept':['apply/window.rs','apply/headers.rs'],
            'apply.block_decode':['apply/prepare.rs'],
            'apply.window_overlay':['apply/window.rs','apply/prevouts.rs'],
            'apply.script_verify':['apply/validation.rs','apply/window.rs'],
            'apply.contextual_checks':['apply/validation.rs','apply/headers.rs'],
            'apply.body_persist':['apply/connect.rs'],
            'apply.tip_publish':['apply/connect.rs','apply/publication.rs','apply/headers.rs'],
            'class.lock_sched':['apply/admission.rs','apply/transition.rs'],
        }
        ledger={k:('crates/node/src/apply.rs',['crates/node/src/'+v for v in values]) for k,values in stages.items()}
        ledger['apply.body_persist'][1].append('crates/storage/src/block_body.rs')
        update_ledger(ledger)
        replacements={
            'docs/contracts/mempool-mutations.md':{
                '`crates/node/src/apply.rs` (inline tests, `chain_generation_tests` module):':'`crates/node/src/apply/tests/chain_generation_tests.rs`:',
                '`crates/node/src/apply.rs`: RPC body preflight':'`crates/node/src/apply/tests/consensus_rule_tests/`: RPC body preflight'},
            'docs/contracts/chain-events.md':{'`crates/node/src/apply.rs` existing tests:':'`crates/node/src/apply/tests/consensus_rule_tests/` existing tests:'},
            'docs/contracts/indexing.md':{'`crates/node/src/apply.rs`:\n  `txindex_worker_failure':'`crates/node/src/apply/tests/consensus_rule_tests/`:\n  `txindex_worker_failure'},
        }
        for name,changes in replacements.items():
            path=Path(name); text=path.read_text()
            for a,b in changes.items(): text=text.replace(a,b)
            r.write(path,text)
        path=Path('docs/contracts/architecture.md'); text=path.read_text()
        text=text.replace('is the same function commit runs. Owner: `crates/node/src/apply.rs`.','is the same function commit runs. Owner: `crates/node/src/apply/connect.rs`.')
        needle='- `Chainstate::begin_transition` is the only public constructor of a\n'
        addition='''- Chainstate operations have explicit source owners under `apply/`:
  `chainstate` owns the facade and snapshots; `admission` owns lock proofs;
  `transition` owns the admitted mutation API; `connect`, `disconnect`, and
  `publication` own their ordered state changes. `window`, `prepare`,
  `prevouts`, `headers`, and `validation` own preparation and checks. These
  boundaries do not introduce independent commit authorities.
- `Chainstate` owns one `MempoolGateway`, not an independently supplied raw
  mempool cell. Its constructor accepts that gateway; reads and mutations
  refer to its pool. The crate-root facade remains unchanged. The former
  `apply::*` type paths are removed: use `apply::chainstate`,
  `apply::transition`, `apply::outcome`, `apply::window`, and
  `apply::assume_valid`, or the crate-root facade.
'''
        if needle not in text: raise ValueError('Architecture contract anchor changed')
        text=text.replace(needle,addition+needle)
        text=text.replace('domain mechanics: UTXO undo persistence and disconnect markers (`apply.rs`),','domain mechanics: UTXO undo persistence and disconnect marker ordering\n  (`apply/connect.rs`, `apply/disconnect.rs`),')
        text=text.replace('`crates/node/src/apply.rs` tests `snapshot_reads_applied_tip_without_taking_a_transition`,','`crates/node/src/apply/tests/chain_generation_tests.rs` and\n  `crates/node/src/apply/tests/consensus_rule_tests/` tests\n  `snapshot_reads_applied_tip_without_taking_a_transition`,')
        text=text.replace('`crates/node/src/apply.rs` tests `apply_block_publishes_rawtx_bytes_in_block_order`,','`crates/node/src/apply/tests/consensus_rule_tests/` and\n  `crates/node/src/apply/tests/with_zmq_publisher_tests.rs` tests\n  `apply_block_publishes_rawtx_bytes_in_block_order`,')
        r.write(path,text)
    if group=='sync':
        path=Path('docs/contracts/architecture.md'); text=path.read_text()
        text+='''
### Synchronization implementation ownership

`crates/node/src/sync.rs` owns the orchestrator state and tick composition.
Its private modules separate header acquisition (`headers`), body admission
(`receive`), expected-chain cache (`expected`), ordered apply/reorg handoff
(`apply`), peer scheduling (`peers`), and metric projection (`observability`).
Expected-run and pending-header representations live with their interpreters;
none of these modules creates another chain-mutation authority.
'''
        r.write(path,text)
    if group=='mining':
        path=Path('docs/contracts/architecture.md'); text=path.read_text()
        text+='''
### Mining coordinator implementation ownership

`crates/node/src/mining.rs` composes the coordinator and protocol trait.
`mining::generation` owns generation identity and wake signals; `assembly`
owns single-flight candidate construction; `selection`, `template`,
`validation`, and `hashrate` own their respective computations. Generation
source types are accessed through `mining::generation` (or the crate-root
`GenerationKey` facade), not compatibility aliases under `mining::*`.
'''
        r.write(path,text)
