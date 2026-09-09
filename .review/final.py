#!/usr/bin/env python3
"""Reproduce the locally reviewed patch; this helper never enters the PR."""
import hashlib
import re
import subprocess
import sys
import textwrap
from pathlib import Path

root = Path(sys.argv[1]).resolve()
helpers = Path(__file__).resolve().parent
assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root).strip()


def blob(path):
    data = path.read_bytes()
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


before = {
    'crates/storage/src/fjall_impl.rs': '09c9f1cf003c4db404dc30ac915390814712385b',
    'crates/storage/src/mdbx_impl.rs': '878c30adcb2810b9af4c670a0e83cc14dd3f494e',
    'crates/storage/src/redb_impl.rs': '8bdfe8599ca808ff14045deead2d5b0022525b7c',
    'crates/storage/src/rocksdb_impl.rs': '01458096384e7bb4d86e332ac58f165780fdb980',
    'crates/storage/src/trait_.rs': 'acf74c0688f9fd3e6ce030dcc8846d4f64315868',
    'crates/storage/tests/overhaul_atomic_durability.rs': 'f5f8052d9c74393fe0597108ed53179dc01a2062',
    'crates/utxo/src/set.rs': 'cc19b5ed2e7bcbd5493d5f69d7f056321f6d2787',
    'crates/utxo/src/shard.rs': '467fbfd8182f4c36403a6734e4326feea85ab412',
    'crates/utxo/tests/overhaul_persistent_coins.rs': '5e679711285161a2b71c945d4246ac97f11863db',
}
for name, expected in before.items():
    assert blob(root / name) == expected, f'{name}: changed since local review; refusing replacement'

assert blob(helpers / 'apply_20_persistent.py') == 'ab37da7cce5caf7d975946f02f36f35f508e479c'
source = (helpers / 'apply_20_persistent.py').read_text()
start = source.index('# Rust 2024 impl-Trait capture:')
end = source.index("path = 'crates/utxo/src/set.rs'", start)
source = source[:start] + source[end:]
source = source.replace('8444c99a5e7cf09e8c161d5ab215fba06ee4f92e', 'cc19b5ed2e7bcbd5493d5f69d7f056321f6d2787')
exec(compile(source, 'reviewed-persistent-edits', 'exec'), {'__name__': '__main__'})

FAULT_MATCH = re.compile(r'(?m)^(?P<indent> *)return match fault \{\n(?P<body>[\s\S]*?)^(?P=indent)\};')
PARTIAL_ARM = re.compile(r'(?m)^(?P<indent> *)crate::PersistFault::PartialApply => \{\n(?P<body>[\s\S]*?)^(?P=indent)\},?')


def simplify_fault_match(match):
    indent, body = match.group('indent', 'body')
    faults = set(re.findall(r'crate::PersistFault::(\w+)', body))
    if faults in ({'FailSync', 'LostSync'}, {'FailFlush', 'LostFlush'}):
        return indent + 'return Err(fault.injected_error());'
    if faults == {'FailApply', 'LostApply', 'PartialApply'}:
        partial = PARTIAL_ARM.search(body)
        if partial is None:
            assert body.count('Err(fault.injected_error())') == 1
            return indent + 'return Err(fault.injected_error());'
        lines = textwrap.dedent(partial.group('body')).rstrip().splitlines()
        assert lines[-1] == 'Err(fault.injected_error())'
        staged = textwrap.indent('\n'.join(lines[:-1]).rstrip(), indent + '    ')
        return (indent + 'if fault == crate::PersistFault::PartialApply {\n' + staged
                + '\n' + indent + '}\n' + indent + 'return Err(fault.injected_error());')
    raise AssertionError(f'Unexpected persistence fault match: {faults}')


for backend in ('fjall', 'redb', 'rocksdb', 'mdbx'):
    path = root / f'crates/storage/src/{backend}_impl.rs'
    updated, count = FAULT_MATCH.subn(simplify_fault_match, path.read_text())
    path.write_text(updated)
    print(f'{backend}: removed {count} redundant fault matches')

path = root / 'crates/storage/src/trait_.rs'
path.write_text(path.read_text().replace(
    '/// Return from flush without syncing deferred writes.',
    '/// Lose flush completion and return an error without confirming durability.'))

path = root / 'crates/storage/tests/overhaul_atomic_durability.rs'
source = path.read_text().replace('    Write,\n', '    Write,\n    WriteDeferred,\n')
source = source.replace('            Self::Write => store.write(batch),',
    '            Self::Write => store.write(batch),\n            Self::WriteDeferred => store.write_deferred(batch),')
source = source.replace('            Self::FlushDeferred => fault == PersistFault::FailFlush,\n            Self::Write => false,',
    '            Self::FlushDeferred => matches!(fault, PersistFault::FailFlush | PersistFault::LostFlush),\n            Self::Write | Self::WriteDeferred => false,')
source = source.replace('        Route::Write,\n', '        Route::Write,\n        Route::WriteDeferred,\n')
old = '''                store.arm_persist_fault(fault);
                route.apply(&store, batch(&store, rows, b"new"), rows[0].0)
            };
            let store = open().expect("reopen to inspect");
            assert_atomic_recovery(&snapshot_all(&store, rows), &old, &proposed, &label);'''
new = '''                store.arm_persist_fault(fault);
                let outcome = route.apply(&store, batch(&store, rows, b"new"), rows[0].0);
                let visible = snapshot_all(&store, rows);
                assert_atomic_recovery(&visible, &old, &proposed, &label);
                if outcome.is_ok() {
                    assert_eq!(visible, proposed, "{label}: successful write was not visible");
                }
                if matches!(fault, PersistFault::FailApply | PersistFault::LostApply | PersistFault::PartialApply) {
                    assert!(outcome.is_err(), "{label}: failed apply reported success");
                    assert_eq!(visible, old, "{label}: failed apply changed visible rows");
                }
                outcome
            };
            let store = open().expect("reopen to inspect");
            let recovered = snapshot_all(&store, rows);
            assert_atomic_recovery(&recovered, &old, &proposed, &label);
            if outcome.is_ok() && !matches!(route, Route::Write | Route::WriteDeferred) {
                assert_eq!(recovered, proposed, "{label}: successful durable write was lost");
            }
            if matches!(fault, PersistFault::FailApply | PersistFault::LostApply | PersistFault::PartialApply) {
                assert_eq!(recovered, old, "{label}: aborted apply survived reopen");
            }'''
assert source.count(old) == 1
path.write_text(source.replace(old, new))
subprocess.run(['cargo', 'fmt', '--all'], cwd=root, check=True)

after = {
    'crates/storage/src/fjall_impl.rs': 'e5b559435e6f94c09c13b9e017e42b781ff47faa',
    'crates/storage/src/mdbx_impl.rs': 'eddc7b0f85da49dcf3f37c1234c18d67a2a66c4f',
    'crates/storage/src/redb_impl.rs': '20bc9247fd0f62d103388ebafc4ee35303d77a8f',
    'crates/storage/src/rocksdb_impl.rs': 'd8a3bc837964bfe4a55b1104cfb2dd5101afdd01',
    'crates/storage/src/trait_.rs': 'ae5aef0cc722515ace745c115512293510555722',
    'crates/storage/tests/overhaul_atomic_durability.rs': 'ec882e663097ea2fd745c278fd736f9fe32e1eb4',
    'crates/utxo/src/set.rs': '5281590a59bd7c47568ff5d0c2946d369fe19fd3',
    'crates/utxo/src/set/persistent.rs': 'abb04d6688664ef7f9972a225f7d90154a4d0801',
    'crates/utxo/src/shard.rs': 'd1d18047f9c4275dfa8d885ecc859e526c8e22e6',
    'crates/utxo/tests/overhaul_persistent_coins.rs': 'b01df04e7f7ea30f9e3f826480b84c1d6dfb9ce1',
}
for name, expected in after.items():
    assert blob(root / name) == expected, f'{name}: candidate differs from tested local contents'
print('Verified all ten changed files against the tested local blob hashes.')
