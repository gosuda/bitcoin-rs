"""Reconstruct the reviewed apply split, validate it, and export a source-only bundle."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess as sp
import sys
import zlib

BASE = 'b59ce9160bb031d623b37cf798e53b963d18ef00'
BRANCH = 'refactor/node-apply-owners-20260911'
PAYLOAD_SHA256 = 'f4cd3394c12e8c4a03be469f589ab333fa5a312814272359919bdd1c3c0170b3'
ADMISSION_SHA = '1e14fc2ab82d6a4be299f5067f140a2b8c030d11'
DOC_PATH = 'crates/node/src/checkpoint/tests/behavior_2.rs'
DOC_BEFORE = '66252f5766f7ee9b750562d664f71370816bae82'
DOC_AFTER = '23210eaa3d8e1899ff8bf7f321bd937d759076da'


def git(*args):
    return sp.check_output(['git', *args])


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def allowed(path):
    p = Path(path)
    valid = path.startswith('crates/node/src/apply/') or path in {
        'crates/node/src/apply.rs',
        'bin/bitcoin-rs/tests/support/ownership_scan.rs',
        'docs/contracts/architecture.md',
        DOC_PATH,
    }
    if not valid or p.is_absolute() or '..' in p.parts or p.is_symlink():
        raise ValueError('Unexpected destination: ' + path)
    if any(q.is_symlink() for q in p.parents):
        raise ValueError('Symlink ancestor: ' + path)
    return p


def check(argv, name, output):
    print('CHECK', name, flush=True)
    log = output / (name + '.log')
    with log.open('wb') as stream:
        result = sp.run(argv, stdout=stream, stderr=sp.STDOUT, timeout=1200)
    if result.returncode:
        print(log.read_text(errors='replace')[-18000:], flush=True)
        raise sp.CalledProcessError(result.returncode, argv)
    return {'name': name, 'argv': argv, 'rc': 0,
            'sha256': hashlib.sha256(log.read_bytes()).hexdigest()}


def main():
    inputs, output = map(lambda x: Path(x).resolve(), sys.argv[1:])
    output.mkdir(parents=True, exist_ok=True)
    encoded = ''.join((inputs / f'plan-{i:02}.b64').read_text().strip() for i in range(6))
    payload = zlib.decompress(base64.b64decode(encoded, validate=True))
    if hashlib.sha256(payload).hexdigest() != PAYLOAD_SHA256:
        raise ValueError('Reviewed payload identity changed')
    plan = json.loads(payload)
    stage = plan['stages'][0]
    if stage['label'] != 'apply' or len(stage['files']) != 28:
        raise ValueError('Unexpected source scope')
    if set(stage['sources']) != {
        'crates/node/src/apply.rs',
        'bin/bitcoin-rs/tests/support/ownership_scan.rs',
        'docs/contracts/architecture.md',
    }:
        raise ValueError('Unexpected original sources')
    if git('status', '--porcelain').strip():
        raise ValueError('Dirty worktree')
    sp.run(['git', 'checkout', '--detach', BASE], check=True)
    sources = {}
    for path, expected in stage['sources'].items():
        raw = git('show', 'HEAD:' + path)
        if blob(raw) != expected:
            raise ValueError('Current base source differs: ' + path)
        sources[path] = raw.decode().splitlines(True)
    for path, spec in stage['files'].items():
        p = allowed(path)
        if spec is None:
            raise ValueError('Apply extraction must not remove source paths')
        indent = spec['dedent']
        if indent not in (0, 4, 8):
            raise ValueError('Unexpected indentation')
        lines = sources[spec['source']] if spec['source'] else []
        lines = [s[indent:] if indent and s.startswith(' ' * indent) else s for s in lines]
        result = []
        for op in spec['ops']:
            if isinstance(op, str):
                result.append(op)
            else:
                a, b = op
                if type(a) is not int or type(b) is not int or not 0 <= a <= b <= len(lines):
                    raise ValueError('Invalid source slice')
                result.extend(lines[a:b])
        raw = ''.join(result).encode()
        if blob(raw) != spec['sha']:
            raise ValueError('Reconstructed source differs: ' + path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
    admission = Path('crates/node/src/apply/admission.rs')
    text = admission.read_text().replace(
        '    pub(crate) fn new(transition:', '    pub(super) fn new(transition:',
    ).replace(
        '    /// Private to this module: only the entry-point functions that begin a\n    /// chain change call this.',
        '    /// Restricted to the apply owner; production construction goes through\n    /// `Chainstate::begin_transition_locked`.',
    )
    if blob(text.encode()) != ADMISSION_SHA:
        raise ValueError('Admission visibility correction differs')
    admission.write_text(text)
    # Main's checkpoint test documentation independently fails strict Clippy.
    # Repair only the checked documentation token; do not suppress the lint.
    documentation = allowed(DOC_PATH)
    raw = documentation.read_bytes()
    if blob(raw) != DOC_BEFORE:
        raise ValueError('Baseline checkpoint documentation changed')
    raw = raw.replace(b': MuHash numerator/denominator,', b': `MuHash` numerator/denominator,')
    if blob(raw) != DOC_AFTER:
        raise ValueError('Documentation correction differs')
    documentation.write_bytes(raw)
    sp.run(['git', 'add', '--all'], check=True)
    paths = git('diff', '--cached', '--name-only').decode().splitlines()
    if paths != sorted(set(stage['files']) | {DOC_PATH}):
        raise ValueError('Unexpected changed paths')
    tree = git('write-tree').decode().strip()
    node = ['--locked', '-p', 'bitcoin-rs-node', '--no-default-features', '--features', 'fjall,zmq']
    rust = [p for p in paths if p.endswith('.rs')]
    checks = [
        check(['rustfmt', '--edition', '2024', '--config', 'skip_children=true', '--check', *rust], 'format', output),
        check(['git', 'diff', '--cached', '--check'], 'whitespace', output),
        check(['cargo', 'clippy', *node, '--all-targets', '--', '-D', 'warnings'], 'clippy', output),
        check(['cargo', 'test', *node, '--lib', 'apply::', '--', '--test-threads=1'], 'apply-tests', output),
        check(['cargo', 'test', *node, '--lib', '--', '--test-threads=1'], 'node-tests', output),
        check(['cargo', 'test', '--locked', '-p', 'bitcoin-rs', '--no-default-features', '--features', 'fjall', '--test', 'overhaul_ownership', '--test', 'overhaul_evidence', '--', '--nocapture'], 'owner-gates', output),
    ]
    if git('diff', '--name-only').strip() or git('write-tree').decode().strip() != tree:
        raise ValueError('Validation modified source')
    commit = sp.check_output([
        'git', '-c', 'user.name=github-actions[bot]',
        '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
        'commit-tree', tree, '-p', BASE,
    ], input=b'Refactor apply into typed chainstate operation owners\n').decode().strip()
    ref = 'refs/heads/' + BRANCH
    sp.run(['git', 'update-ref', ref, commit, '0' * 40], check=True)
    bundle = output / 'apply.bundle'
    sp.run(['git', 'bundle', 'create', str(bundle), ref, '^' + BASE], check=True)
    (output / 'apply.patch').write_bytes(git('diff', '--binary', BASE, commit))
    record = {'base': BASE, 'branch': BRANCH, 'commit': commit, 'tree': tree,
              'paths': paths, 'checks': checks, 'validated': True,
              'bundle_sha256': hashlib.sha256(bundle.read_bytes()).hexdigest()}
    (output / 'publication.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record), flush=True)


if __name__ == '__main__':
    main()
