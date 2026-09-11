"""Reconstruct the reviewed remaining node changes and validate before publishing."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess as sp
import sys
import zlib

BASE = '729f0e8691ec25401b8150ea9934c890a37e988a'
INPUT = '80ab1f18f43ea1f32ef4c27169fcd98063ec482f'
PLAN_SHA = 'f4cd3394c12e8c4a03be469f589ab333fa5a312814272359919bdd1c3c0170b3'
STAGES = [
    ('validation', 'refactor/node-validation-729f0e86', '891163a6f5f9e4c80c7c8e82736961e20ffc1864', 'Restore node cleanup validation and ownership gates'),
    ('txindex', 'refactor/node-txindex-729f0e86', '52a17119ece5fd3b0a7e768adda9ab0865c027f1', 'Consolidate txindex runtime, query, and reconciliation owners'),
    ('checkpoint', 'refactor/node-checkpoint-729f0e86', 'a0539b0dd6859b944de9a95fba23458c256154eb', 'Group checkpoint filesystem and periodic worker under one owner'),
    ('mining', 'fix/node-mining-capabilities-729f0e86', '474d0bf1a9bb876e8d62c09fefaa6f9987736be0', 'Advertise only implemented mining template capabilities'),
]
ROOT = Path('crates/node/src')


def git(*args):
    return sp.check_output(['git', *args])


def digest(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def replace(path, old, new, count=None):
    path = Path(path)
    text = path.read_text()
    if old not in text or (count is not None and text.count(old) != count):
        raise ValueError('Source changed at ' + str(path) + ': ' + old[:60])
    path.write_text(text.replace(old, new))


def reconstruct(stage, path):
    spec = stage['files'][path]
    if spec is None:
        raise ValueError('Unexpected deletion in extraction')
    source = spec['source']
    lines = []
    if source:
        sha = stage['sources'][source]
        raw = git('cat-file', 'blob', sha)
        if digest(raw) != sha:
            raise ValueError('Input blob mismatch')
        lines = raw.decode().splitlines(True)
    d = spec['dedent']
    if d not in (0, 4, 8):
        raise ValueError('Invalid dedent')
    lines = [line[d:] if d and line.startswith(' ' * d) else line for line in lines]
    result = []
    for op in spec['ops']:
        if isinstance(op, str):
            result.append(op)
        else:
            a, b = op
            if not 0 <= a <= b <= len(lines):
                raise ValueError('Invalid source slice')
            result.extend(lines[a:b])
    raw = ''.join(result).encode()
    if digest(raw) != spec['sha']:
        raise ValueError('Output blob mismatch: ' + path)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(raw)


def validation(plan):
    replace(ROOT / 'embed.rs', ', clippy::unused_async_trait_impl', '', 5)
    reconstruct(plan['stages'][0], 'bin/bitcoin-rs/tests/support/ownership_scan.rs')
    p = ROOT / 'state/tests/prune.rs'
    text = p.read_text()
    start = text.index('fn manual_prune_removes_pruned_block_transactions_from_cache()')
    old = '''    service
        .prune_to_height(11)
        .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;

    let transactions = state.transactions.read();'''
    new = '''    // Pruning cannot evict cached transactions while their block still lies
    // above the durable checkpoint's reorg-retention floor (ARCH-07).
    service
        .prune_to_height(11)
        .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;
    assert!(state.transactions.read().contains_key(&pruned_txid));
    assert!(state.transactions.read().contains_key(&unrelated_txid));

    // The synthetic applied-tip fixture must also publish durability before
    // any block below the requested height becomes eligible for pruning.
    state
        .durable_tip_height
        .store(11 + CORE_REORG_SAFETY_MARGIN, Ordering::Release);
    service
        .prune_to_height(11)
        .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;

    let transactions = state.transactions.read();'''
    tail = text[start:]
    if tail.count(old) != 1:
        raise ValueError('Prune test changed')
    p.write_text(text[:start] + tail.replace(old, new))
    replace(ROOT / 'storage_backend.rs', '''        (
            "storage_footprint.rs",
            include_str!("storage_footprint.rs"),
            Some("mod tests {"),
        ),''', '''        ("storage_footprint.rs", include_str!("storage_footprint.rs"), None),
        ("storage_footprint/budget.rs", include_str!("storage_footprint/budget.rs"), None),
        ("storage_footprint/identity.rs", include_str!("storage_footprint/identity.rs"), None),
        ("storage_footprint/scan.rs", include_str!("storage_footprint/scan.rs"), None),''', 1)


def txindex(plan):
    stage = plan['stages'][-1]
    for path, spec in stage['files'].items():
        if spec and (path.startswith('crates/node/src/txindex/') or path == 'crates/node/src/txindex.rs'):
            reconstruct(stage, path)
    for path in ROOT.glob('txindex_worker*.rs'):
        path.unlink()
    shutil.rmtree(ROOT / 'txindex_worker')
    for path in ROOT.rglob('*.rs'):
        text = path.read_text().replace('txindex_worker', 'txindex')
        text = text.replace('crate::reconcile::ConsumerCursor::from_snapshot(', 'crate::reconcile::cursor_from_snapshot(')
        text = text.replace('fn txindex_failure_', 'fn txindex_worker_failure_')
        text = text.replace('fn drop_joins_txindex_before_reopen(', 'fn drop_joins_txindex_worker_before_reopen(')
        path.write_text(text)
    replace(ROOT / 'storage_backend.rs', '''        (
            "txindex.rs",
            include_str!("txindex.rs"),
            Some("mod body_reader_tests {"),
        ),''', '''        ("txindex.rs", include_str!("txindex.rs"), None),
        ("txindex/lifecycle.rs", include_str!("txindex/lifecycle.rs"), None),
        ("txindex/worker.rs", include_str!("txindex/worker.rs"), None),
        ("txindex/query.rs", include_str!("txindex/query.rs"), None),''', 1)
    path = Path('docs/contracts/indexing.md')
    text = path.read_text().replace('txindex_worker.rs', 'txindex.rs').replace('txindex_worker/', 'txindex/').replace('txindex_worker::', 'txindex::')
    for group in ('query', 'integration', 'lifecycle', 'recovery', 'block_source'):
        text = text.replace('txindex_worker_' + group + '_tests.rs', 'txindex/' + group + '_tests.rs')
    text = text.replace('- `TxIndexRuntime`, `TxIndexQueryEngine`, `Worker` in `crates/node/src/txindex.rs`', '''- `TxIndexRuntime` in `crates/node/src/txindex/runtime.rs` owns the process-local
  revision, health, phase, and nonblocking wake signal.
- `TxIndexQueryEngine` and the single-snapshot outer adapter in
  `crates/node/src/txindex/query.rs` own query gating and the shared work budget;
  `query/transactions.rs` and `query/scripts.rs` implement the bounded queries.
- `Worker` in `crates/node/src/txindex/worker.rs` owns reconciliation execution;
  `worker/reconcile.rs`, `worker/commit.rs`, and `forward.rs` keep rollback,
  cursor/commit fences, and bounded forward preparation separate. Positional
  reconciliation policy remains in `bitcoin_rs_index::reconcile`.''')
    text = text.replace('`crates/node/src/txindex.rs` mapped by `TxIndexCapability`', '`crates/node/src/txindex/lifecycle.rs` mapped by `TxIndexCapability`')
    path.write_text(text)


def checkpoint(_plan):
    (ROOT / 'checkpoint_fs.rs').rename(ROOT / 'checkpoint/fs.rs')
    (ROOT / 'checkpoint_worker.rs').rename(ROOT / 'checkpoint/worker.rs')
    for path in ROOT.rglob('*.rs'):
        text = path.read_text().replace('crate::checkpoint_fs::', 'crate::checkpoint::fs::').replace('crate::checkpoint_worker::', 'crate::checkpoint::worker::')
        if path == ROOT / 'lib.rs':
            text = text.replace('mod checkpoint_fs;\n', '').replace('/// Periodic chainstate checkpoint publication during sync.\nmod checkpoint_worker;\n', '')
        if path == ROOT / 'checkpoint.rs':
            text = '//! Checkpoint formats, loading, publication, and periodic scheduling.\n\n' + text.replace('mod format;', 'mod format;\npub(crate) mod fs;').replace('mod publish;', 'mod publish;\npub(crate) mod worker;')
        path.write_text(text)


def mining(_plan):
    p = ROOT / 'mining/candidate.rs'
    text = p.read_text().replace('use bitcoin_rs_mining::BlockTemplateRequest;\n', '').replace('        request: &BlockTemplateRequest,\n', '')
    start = text.index('        let mut capabilities = vec![')
    end = text.index('        BlockTemplate {', start)
    text = text[:start] + '''        // API-11 advertises producer capabilities, never client-requested names.
        let capabilities = vec![
            MiningCapability::new("proposal"),
            MiningCapability::new("longpoll"),
        ];
''' + text[end:]
    p.write_text(text)
    replace(ROOT / 'mining/control.rs', '                    &request,\n', '', 1)
    p = ROOT / 'mining/candidate_template_tests.rs'
    text = p.read_text()
    start = text.index('fn empty_request()')
    end = text.index('fn template_for(', start)
    p.write_text((text[:start] + text[end:]).replace('        &empty_request(),\n', ''))
    p = Path('crates/node/tests/mining.rs')
    text = p.read_text()
    start = text.index('fn template_does_not_echo_client_capabilities()')
    end = text.index('\n#[test]', start)
    part = text[start:end].replace('capabilities: vec![MiningCapability::new("coinbasetxn")],', '''capabilities: vec![
            MiningCapability::new("coinbasetxn"),
            MiningCapability::new("unknown-client-only"),
            MiningCapability::new("proposal"),
        ],''').replace("// Bitcoin Core's getblocktemplate contract advertises server capabilities,", '// API-11 advertises only implemented server capabilities,')
    p.write_text(text[:start] + part + text[end:])
    replace('docs/contracts/external-api.md', '''- **Owner**: `MiningCoordinator::template_from_candidate` in
  `crates/node/src/mining.rs`; JSON projection in''', '''- **Owner**: `MiningCoordinator::template_from_candidate` in
  `crates/node/src/mining/candidate.rs`; JSON projection in''', 1)


def check(command, name, output):
    print('CHECK', name, flush=True)
    path = output / (name + '.log')
    with path.open('wb') as log:
        result = sp.run(command, stdout=log, stderr=sp.STDOUT, timeout=1200)
    record = {'name': name, 'argv': command, 'rc': result.returncode, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    if result.returncode:
        print(path.read_text(errors='replace')[-16000:], flush=True)
        raise sp.CalledProcessError(result.returncode, command)
    return record


def main():
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    prepare_only = '--prepare-only' in sys.argv[2:]
    encoded = b''.join(git('show', INPUT + f':.github/node-final/plan-{i:02}.b64').strip() for i in range(6))
    raw = zlib.decompress(base64.b64decode(encoded, validate=True))
    if hashlib.sha256(raw).hexdigest() != PLAN_SHA:
        raise ValueError('Reviewed reference recipe differs')
    plan = json.loads(raw)
    if git('status', '--porcelain').strip():
        raise ValueError('Dirty worktree')
    sp.run(['git', 'checkout', '--detach', BASE], check=True)
    transforms = (validation, txindex, checkpoint, mining)
    node = ['--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq']
    gates = ['cargo', 'test', '--locked', '-p', 'bitcoin-rs', '--no-default-features', '--features', 'fjall', '--test', 'overhaul_ownership', '--test', 'overhaul_evidence', '--', '--nocapture']
    records = []
    refs = []
    for (label, branch, expected_tree, message), transform in zip(STAGES, transforms):
        parent = git('rev-parse', 'HEAD').decode().strip()
        transform(plan)
        sp.run(['cargo', 'fmt', '-p', 'bitcoin-rs-node'], check=True)
        if label == 'validation':
            sp.run(['rustfmt', '--edition', '2024', '--config', 'skip_children=true', 'bin/bitcoin-rs/tests/support/ownership_scan.rs'], check=True)
        sp.run(['git', 'add', '--all'], check=True)
        tree = git('write-tree').decode().strip()
        if tree != expected_tree:
            raise ValueError(f'{label}: expected tree {expected_tree}, got {tree}')
        paths = git('diff', '--cached', '--no-renames', '--name-only').decode().splitlines()
        allowed_extra = {'bin/bitcoin-rs/tests/support/ownership_scan.rs', 'docs/contracts/indexing.md', 'docs/contracts/external-api.md'}
        if any(not p.startswith('crates/node/') and p not in allowed_extra for p in paths):
            raise ValueError('Unexpected source-only scope')
        checks = []
        if not prepare_only:
            checks.append(check(['cargo', 'fmt', '-p', 'bitcoin-rs-node', '--', '--check'], label + '-format', output))
            checks.append(check(['git', 'diff', '--cached', '--check'], label + '-whitespace', output))
            checks.append(check(['cargo', 'clippy', *node, '--all-targets', '--', '-D', 'warnings'], label + '-clippy', output))
            selection = {'validation': 'state::tests::prune', 'txindex': 'txindex::', 'checkpoint': 'checkpoint::', 'mining': 'mining::'}[label]
            checks.append(check(['cargo', 'test', *node, '--lib', selection, '--', '--test-threads=1'], label + '-tests', output))
            if label == 'validation':
                checks.append(check(gates, 'validation-owner-gates', output))
            if label == 'mining':
                checks.append(check(['cargo', 'clippy', '--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,redb,zmq', '--all-targets', '--', '-D', 'warnings'], 'final-matrix-clippy', output))
                checks.append(check(['cargo', 'test', *node, '--lib', '--', '--test-threads=1'], 'final-node-tests', output))
                checks.append(check(gates, 'final-owner-gates', output))
                checks.append(check(['cargo', 'test', *node, '--test', 'mining', '--test', 'embed', '--test', 'shutdown', '--', '--test-threads=1'], 'final-integration', output))
        if git('diff', '--name-only').strip() or git('write-tree').decode().strip() != expected_tree:
            raise ValueError('Validation changed source')
        commit = sp.check_output(['git', '-c', 'user.name=github-actions[bot]', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'commit-tree', tree, '-p', parent], input=(message + '\n').encode()).decode().strip()
        ref = 'refs/heads/' + branch
        sp.run(['git', 'update-ref', ref, commit, '0' * 40], check=True)
        sp.run(['git', 'checkout', '--detach', commit], check=True)
        records.append({'label': label, 'branch': branch, 'parent': parent, 'commit': commit, 'tree': tree, 'paths': paths, 'checks': checks})
        refs.append(ref)
        print('VERIFIED', label, tree, flush=True)
    bundle = output / 'sources.bundle'
    sp.run(['git', 'bundle', 'create', str(bundle), *refs, '^' + BASE], check=True)
    result = {'base': BASE, 'validated': not prepare_only, 'stages': records, 'bundle_sha256': hashlib.sha256(bundle.read_bytes()).hexdigest()}
    (output / 'publication.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
