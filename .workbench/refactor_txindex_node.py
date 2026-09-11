#!/usr/bin/env python3
"""Node worker source cut. Workbench only, not part of either source PR."""
from refactor_txindex import *

def refactor_node():
    path=ROOT/'crates/node/src/txindex_worker.rs'
    source=path.read_text()
    assert hashlib.sha256(source.encode()).hexdigest() == '69a0e89bd194a6fbb811dc023688e74b7464f4652bc3c49d74fa3bd5881e7c00'
    parsed=items(source)
    groups=collections.defaultdict(list)
    external=[]
    defs={}
    exported={}
    tests=[]
    existing_modules=[]
    for i in parsed:
        if i.kind=='use':
            external.append(i.text[significant(i.text)[0][0]:].strip())
            continue
        if i.kind=='mod':
            if i.name=='body_reader_tests':
                body=textwrap.dedent(i.text[i.body_start+1:i.body_end]).strip()+'\n'
                (path.with_suffix('')/'body_reader_tests.rs').write_text(body)
                tests.append('#[cfg(test)]\nmod body_reader_tests;')
            elif i.name.endswith('_tests'):
                tests.append(i.text.strip())
            else:
                existing_modules.append(i.name)
            continue
        name=i.name
        if name=='TxIndexRuntime': owner='runtime'
        elif name in {'Generation','TxIndexLifecycle','TxIndexOpenSpec','TxIndexWorker','publish_lifecycle'}: owner='lifecycle'
        elif name=='TxIndexQueryAdapter': owner='query_adapter'
        elif name in {'TXINDEX_OPEN_GATE','install_txindex_open_gate','wait_txindex_open_gate','run_worker_with_open','fail_worker','open_and_run'}: owner='startup'
        elif name in {'OpenTxIndex','open_tx_index_with_timeout','open_tx_index_on_worker','TxIndexComposer','open_tx_index_store_on_worker','TXINDEX_OPEN_TIMEOUT','ROCKSDB_BATCH_LIMITS','DEFAULT_BATCH_LIMITS','REDB_BATCH_LIMITS','BATCH_BYTE_LIMIT'}: owner='open'
        elif name=='UndoScripts': owner='live'
        elif name in {'detached_chain_publisher','test_recovery_reporter'}: owner='test_support'
        elif name in {'Worker','REVISION_QUIET_PERIOD','FORWARD_BATCH_DELAY'}: owner='worker'
        elif name in {'CursorCommit','ReconcileAction','index_ahead_capability_label','DEFAULT_ROLLBACK_REBUILD_CUTOVER'}: owner='reconcile'
        elif name in {'PendingForward','BlockIdentity','ChunkAction','IDENTITY_CHUNK_BLOCKS','POSITION_PREFETCH_BLOCKS','PREPARE_CHUNK_BLOCKS','PREPARE_CHUNK_BYTES'}: owner='forward'
        elif name=='TxIndexWorkerError': owner='error'
        elif name in {'QueryBudget','QueryEngineLive','TxIndexQueryEngine','QUERY_SCAN_ROW_LIMIT','QUERY_SCAN_BYTE_LIMIT','QUERY_SCAN_COUNT_LIMIT','QUERY_BODY_READ_LIMIT'}: owner='query'
        elif name in {'IndexProgress','TxIndexCapability','PROGRESS_READ_ATTEMPTS'}: owner='progress'
        elif name in {'IndexBlockSource','MAX_SERIALIZED_BLOCK_BYTES'}: owner='source'
        else: raise AssertionError(('unassigned',name))
        if i.kind=='impl' and not re.search(r'\bfor\b', ' '.join(v for _,_,v in significant(i.text[:i.body_start]))):
            byowner=collections.defaultdict(list)
            for m in i.methods():
                dest=owner
                if name=='Worker':
                    if m.name in {'seed_live_from_utxo','live_anchor'}: dest='live'
                    elif m.name in {'rollback_one','load_body'}: dest='rollback'
                    elif m.name in {'collect_target_chain','catch_up_to','prepare_and_admit_chunk','finish_catch_up','sync_and_commit','cursor_for_result','commit_pending'}: dest='forward'
                    elif m.name!='run': dest='reconcile'
                elif name=='TxIndexQueryEngine':
                    if m.name=='index_progress_for': dest='progress'
                    elif m.name in {'new','query_health','require_enabled','with_snapshot'}: pass
                    elif m.name in {'resolve_hash_at_height','hash_at_height','resolve_block','resolve_block_body_bytes','verify_block','validated_positions','resolve_positioned_transaction','transaction_from_full_block','transaction_for','locate_transaction_for','outpoint_value_for','spending_input'}: dest='query_body'
                    else: dest='query_script'
                m.text=promote_item(m)
                byowner[dest].append(m)
            for dest,ms in byowner.items():
                groups[dest].append(Item(i.with_methods(ms),i.kind,name))
            continue
        if i.kind not in ('impl','use'):
            assert defs.get(name,owner)==owner
            defs[name]=owner
            sig=' '.join(v for _,_,v in significant(i.text))
            if sig.startswith('pub '):
                visibility='pub(crate)' if sig.startswith('pub ( crate )') else 'pub'
                exported[name]=(owner,visibility)
            else:
                i.text=promote_item(i)
            if i.kind=='struct':
                i.text=re.sub(r'^(    )([a-zA-Z_]\w*\s*:)',r'\1pub(super) \2',i.text,flags=re.M)
        groups[owner].append(i)
    adapter_path=path.with_suffix('')/'query_adapter.rs'
    original_adapter=adapter_path.read_text()
    for i in items(original_adapter):
        if i.kind!='use': groups['query_adapter'].append(i)
    titles={
      'runtime':'Shared nonblocking wake, health, and reconciliation-phase publication.',
      'lifecycle':'Generation-fenced lifecycle publication and worker-handle ownership.',
      'query_adapter':'Protocol adapters over one atomically captured lifecycle payload.',
      'startup':'Supervised open-to-serving orchestration and failure publication.',
      'open':'Bounded backend open and composition through the sole storage-backend owner.',
      'live':'Authoritative spent-script anchoring and live-view seeding.',
      'test_support':'Permanent worker test fixtures.',
      'worker':'The node-owned reconciliation loop and its owned state.',
      'reconcile':'Exact capability alignment, reset decisions, and consumer-cursor reconciliation.',
      'forward':'Bounded parse-once forward preparation and durable batch commits.',
      'rollback':'Single-block rollback against authoritative body and undo storage.',
      'error':'Typed failures for the supervised index worker.',
      'query':'Coherent query admission, snapshot fencing, and aggregate work budgets.',
      'query_body':'Identity-checked block, position, and transaction resolution.',
      'query_script':'Exact script-history, spending, and live-output query composition.',
      'progress':'Coherent capability progress and operator-facing status.',
      'source':'Authoritative block-source adaptation for index resolution.',
    }
    test_only={'TXINDEX_OPEN_GATE','install_txindex_open_gate','detached_chain_publisher','test_recovery_reporter'}
    outdir=path.with_suffix('')
    for owner, its in groups.items():
        code='\n\n'.join(i.text.strip() for i in its)+'\n'
        ids=identifiers(code)
        imports=[]
        for line in external:
            for module in existing_modules:
                line=line.replace('use '+module+'::','use super::'+module+'::')
            imports.append(line)
        for other in sorted(groups):
            names=sorted(n for n,o in defs.items() if o==other and n in ids and other!=owner and n not in test_only)
            if names: imports.append('use super::'+other+'::{'+', '.join(names)+'};')
            gated=sorted(n for n,o in defs.items() if o==other and n in ids and other!=owner and n in test_only)
            if gated: imports.append('#[cfg(test)]\nuse super::'+other+'::{'+', '.join(gated)+'};')
        for n,other in defs.items():
            if other!=owner: code=code.replace('[`'+n+'`]', '[`super::'+other+'::'+n+'`]')
        code=code.replace('[`ScriptIndexQuery`]', '[`bitcoin_rs_rpc::context::ScriptIndexQuery`]')
        (outdir/(owner+'.rs')).write_text('//! '+titles[owner]+'\n\n'+'\n'.join(imports)+'\n\n'+code)
    facade=source[:source.index('use arc_swap')].replace('[`ScriptIndexQuery`]', '[`bitcoin_rs_rpc::context::ScriptIndexQuery`]')
    for module in sorted(set(existing_modules)|set(groups)):
        if module=='test_support': facade+='#[cfg(test)]\n'
        facade+='mod '+module+';\n'
    facade+='\n'
    for name,(owner,vis) in sorted(exported.items()):
        if name in test_only: facade+='#[cfg(test)]\n'
        facade+=vis+' use '+owner+'::'+name+';\n'
    for owner in sorted(groups):
        names=sorted(n for n,o in defs.items() if o==owner and n not in exported)
        if names: facade+='#[cfg(test)]\nuse '+owner+'::{'+', '.join(names)+'};\n'
    for line in external:
        facade+='#[cfg(test)]\n'+line+'\n'
    facade+='\n'+'\n\n'.join(tests)+'\n'
    path.write_text(facade)
    gate=ROOT/'crates/node/src/storage_backend.rs'
    text=gate.read_text()
    old='''        (
            "txindex_worker.rs",
            include_str!("txindex_worker.rs"),
            Some("mod body_reader_tests {"),
        ),'''
    names=['txindex_worker.rs']+['txindex_worker/'+m+'.rs' for m in sorted(set(existing_modules)|set(groups)) if m!='test_support']
    new='\n'.join('        ("'+n+'", include_str!("'+n+'"), None),' for n in names)
    assert old in text
    gate.write_text(text.replace(old,new))
    before=function_inventory(source)+function_inventory(original_adapter)
    after=function_inventory(path.read_text())
    for module in list(groups)+['body_reader_tests']:
        after.update(function_inventory((outdir/(module+'.rs')).read_text()))
    assert before==after, ('function drift', [(n,c) for (n,_),c in (before-after).items()], [(n,c) for (n,_),c in (after-before).items()])
    print('NODE:',len(source.splitlines()),'->',len(facade.splitlines()),'root lines;',sum(before.values()),'exact function bodies preserved')
    print({m:len((outdir/(m+'.rs')).read_text().splitlines()) for m in groups})

if __name__=='__main__': refactor_node()
