"""Validate existing review corrections; never rewrite a product PR or main."""
from pathlib import Path
import json
import os
import signal
import subprocess
import sys
import urllib.request

BASE = '76baf086b861057f5700da34c4ad0d4f5aab5966'
CASES = {
    771: ('b69a9de7cf14860d21fb4cade9796b2467488e4f', 'crates/script/src/stack.rs',
          'crates/script/tests/stack_depth.rs', 'bitcoin-rs-script', 'stack_depth'),
    772: ('f72faff3a484db054f8e3ca60c22346a1559935d', 'crates/script/src/stack.rs',
          'crates/script/tests/stack_transfer.rs', 'bitcoin-rs-script', 'stack_transfer'),
    773: ('6d1372d763869be573712fcb7249193bfa52ad35', 'crates/p2p/src/banlist.rs',
          'crates/p2p/tests/banlist_load.rs', 'bitcoin-rs-p2p', 'banlist_load'),
}
FORMATTING = {
    'bin/bitcoin-rs/tests/gates/g20_formal_models.rs',
    'crates/utxo/src/set/persistent.rs',
    'crates/utxo/tests/overhaul_persistent_coins.rs',
}
EVIDENCE = Path('/tmp/review-contract-evidence')
EVIDENCE.mkdir(exist_ok=True)


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def run(args, log, timeout=1200):
    with log.open('w') as stream:
        stream.write('COMMAND ' + json.dumps(args) + '\n')
        stream.flush()
        process = subprocess.Popen(args, stdout=stream, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            rc = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            rc = 124
    print(log.name + ': exit=' + str(rc), flush=True)
    print(log.read_text()[-24000:], flush=True)
    return rc


def replace(path, old, new):
    text = path.read_text()
    assert text.count(old) == 1, (str(path), text.count(old), old)
    path.write_text(text.replace(old, new, 1))


def correction(number, source, test):
    if number == 771:
        replace(source, '    /// Returns an item at `depth`, where zero is the top item.\n',
                '    /// Returns an item at `depth`, where zero is the top item.\n'
                '    /// Out-of-range depths return [`StackError::Underflow`].\n')
        replace(source, '    /// Removes and returns an item at `depth`, where zero is the top item.\n',
                '    /// Removes and returns an item at `depth`, where zero is the top item.\n'
                '    /// Out-of-range depths return [`StackError::Underflow`] without mutation.\n')
        replace(source, '    /// Moves the item at `depth` to the top.\n',
                '    /// Moves the item at `depth` to the top.\n'
                '    /// Out-of-range depths return [`StackError::Underflow`] without mutation.\n')
        replace(test, '//! Checked depth arithmetic and mutation boundaries of the public script stack.\n',
                '//! Public indexing contract: `crates/script/src/stack.rs`,\n'
                '//! `Stack::peek_at`, `Stack::remove_at`, and `Stack::roll` Rustdoc.\n'
                '//! Those methods own top-relative order, underflow, and failure atomicity.\n')
    elif number == 772:
        replace(source, '    /// Moves the top item to another bounded stack.\n',
                '    /// Moves the top item to another bounded stack.\n'
                '    /// An empty source returns [`StackError::Underflow`] before checking\n'
                '    /// destination capacity. A full destination returns [`StackError::Overflow`].\n'
                '    /// Either error leaves both stacks unchanged; success appends the item\n'
                '    /// above the destination\'s existing items.\n')
        replace(test, '//! Ownership-preserving transfers between bounded script stacks.\n',
                '//! Public transfer contract: `crates/script/src/stack.rs`,\n'
                '//! `Stack::move_to`, `Stack::move_from`, and `Stack::MAX_DEPTH` Rustdoc.\n'
                '//! Verify values, ordering, capacity, and failure atomicity, not allocation layout.\n')
        replace(test, 'fn transfers_move_heap_backed_bytes_without_cloning()',
                'fn transfers_preserve_byte_values_and_order()')
        replace(test, '    assert!(bytes.spilled());\n    let allocation = bytes.as_ptr();\n', '')
        replace(test, '    assert_eq!(moved.as_ptr(), allocation);\n', '')
        replace(test, '    assert_eq!(restored.as_ptr(), allocation);\n', '')
    else:
        replace(source, '    /// Load a ban list from a dedicated file.\n',
                '    /// Load a ban list from a dedicated file.\n'
                '    /// Blank lines are ignored. Records contain tab-separated IP, score,\n'
                '    /// UNIX expiry seconds, and an optional reason. Zero expiry means no deadline.\n'
                '    /// An opening [`ErrorKind::NotFound`] starts an empty list. Other I/O\n'
                '    /// errors propagate. Malformed or unrepresentable expiries return\n'
                '    /// [`PeerError::InvalidBanEntry`]. Loading never rewrites the file.\n')
        replace(test,
                '//! Ban-list loading must distinguish missing files from corrupt or inaccessible data.\n',
                '//! File/expiry contract: `crates/p2p/src/banlist.rs`, `BanList::load`\n'
                '//! and `BanEntry::is_banned` Rustdoc. `CONSTRAINTS.md` CL-23 requires\n'
                '//! unavailable or corrupt state not to be reported as an empty success.\n')


def validate(number, case):
    head, source_path, test_path, package, target = case
    evidence = EVIDENCE / str(number)
    evidence.mkdir(exist_ok=True)
    subprocess.run(['git', 'diff', '--exit-code'], check=True)
    subprocess.run(['git', 'switch', '--detach', head], check=True)
    source, test = Path(source_path), Path(test_path)
    correction(number, source, test)
    subprocess.run(['cargo', 'fmt', '--all'], check=True)
    changes = set(output('git', 'diff', '--name-only').splitlines())
    assert changes <= FORMATTING | {source_path, test_path}, sorted(changes)
    for path in sorted(changes & FORMATTING):
        assert output('git', 'rev-parse', head + ':' + path) == output(
            'git', 'rev-parse', BASE + ':' + path), path
    inherited = sorted(changes & FORMATTING)
    if inherited:
        (evidence / 'inherited-formatting.patch').write_text(output(
            'git', 'diff', '--', *inherited) + '\n')
        subprocess.run(['git', 'restore', '--source=HEAD', '--', *inherited], check=True)
    assert set(output('git', 'diff', '--name-only').splitlines()) == {source_path, test_path}
    subprocess.run(['git', 'diff', '--check'], check=True)
    (evidence / 'review-correction.patch').write_text(output('git', 'diff') + '\n')
    subprocess.run(['git', 'add', '--', source_path, test_path], check=True)
    subprocess.run(['git', '-c', 'user.name=github-actions[bot]', '-c',
                    'user.email=41898282+github-actions[bot]@users.noreply.github.com',
                    'commit', '-m', f'docs(test): bind PR #{number} regressions to their API owners'],
                   check=True)
    candidate = output('git', 'rev-parse', 'HEAD')
    (evidence / 'head.txt').write_text(candidate + '\n')
    (evidence / 'source.patch').write_text(output('git', 'diff', BASE, 'HEAD') + '\n')
    command = ['cargo', 'test', '--locked', '-p', package, '--test', target, '--', '--nocapture']
    original = source.read_bytes()
    try:
        source.write_bytes(subprocess.check_output(['git', 'show', BASE + ':' + source_path]))
        rc = run(command, evidence / 'baseline-control.txt')
        text = (evidence / 'baseline-control.txt').read_text()
        if number == 771:
            assert rc != 0 and 'attempt to add with overflow' in text
            assert 'test result: FAILED. 1 passed; 1 failed;' in text
        elif number == 772:
            assert rc == 0 and 'test result: ok. 2 passed;' in text
        else:
            assert rc != 0 and 'test result: FAILED. 2 passed; 2 failed;' in text
            assert 'filesystem_errors_are_not_an_empty_ban_list' in text
            assert 'unrepresentable_expiry_is_an_invalid_entry' in text
    finally:
        source.write_bytes(original)
    commands = [
        ('regression', command),
        ('release-regression', ['cargo', 'test', '--locked', '--release', '-p', package,
                                '--test', target]),
        ('adjacent', ['cargo', 'test', '--locked', '-p', package, '--lib', '--test',
                      'core_vectors' if number != 773 else 'core_compat', '--test',
                      'verifier_boundaries' if number != 773 else 'listener_ban', '--no-fail-fast']),
        ('clippy-workspace', ['cargo', 'clippy', '--locked', '--workspace', '--all-targets',
                             '--exclude', 'bitcoin-rs-consensus', '--exclude', 'bitcoin-rs-node',
                             '--', '-D', 'warnings']),
        ('clippy-consensus', ['cargo', 'clippy', '--locked', '-p', 'bitcoin-rs-consensus',
                             '--no-default-features', '--all-targets', '--', '-D', 'warnings']),
        ('clippy-node', ['cargo', 'clippy', '--locked', '-p', 'bitcoin-rs-node',
                        '--no-default-features', '--features', 'fjall,zmq', '--all-targets',
                        '--', '-D', 'warnings']),
    ]
    results = {name: run(args, evidence / (name + '.txt')) for name, args in commands}
    results['workspace-fmt'] = run(['cargo', 'fmt', '--all', '--', '--check'],
                                   evidence / 'workspace-fmt.txt')
    (evidence / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    subprocess.run(['git', 'diff', '--exit-code'], check=True)
    assert output('git', 'rev-parse', 'HEAD') == candidate
    assert all(code == 0 for name, code in results.items() if name != 'workspace-fmt'), results
    assert results['workspace-fmt'] == (1 if inherited else 0), results
    # A known, recorded baseline formatting failure does not become a pass.
    # Keep the PR draft; these branches carry only tested scope-local corrections.
    with urllib.request.urlopen(
        f'https://api.github.com/repos/gosuda/bitcoin-rs/pulls/{number}', timeout=30
    ) as response:
        pr = json.load(response)
    assert pr['state'] == 'open' and not pr['merged'] and pr['head']['sha'] == head
    branch = f'refs/heads/validated/pr{number}-contract-review-20260910'
    assert not output('git', 'ls-remote', '--heads', 'origin', branch), branch
    subprocess.run(['git', 'push', 'origin', candidate + ':' + branch], check=True)
    return {'head': candidate, 'branch': branch, 'checks': results,
            'readiness': 'draft; inherited full-workspace formatting is separate'}


subprocess.run(['git', 'fetch', '--no-tags', '--depth=1', 'origin', BASE,
                *[case[0] for case in CASES.values()]], check=True)
summary = {}
for number, case in CASES.items():
    try:
        summary[number] = validate(number, case)
    except Exception as error:
        summary[number] = {'failed': str(error)}
        print(f'PR {number}: {error}', file=sys.stderr, flush=True)
        if output('git', 'status', '--porcelain'):
            break
(EVIDENCE / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
if len(summary) != len(CASES) or any('failed' in row for row in summary.values()):
    raise SystemExit(1)
