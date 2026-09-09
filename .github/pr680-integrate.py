from pathlib import Path
import subprocess

root = Path.cwd()
source = root / '.review-source'
preimages = {
    'crates/node/src/run.rs': 'ab8ab5385085a4232b4f33ec4ed2e3c16e6c4fc1',
    'crates/node/src/tx_ingress.rs': 'd71556131655b462831b39ff659aba9d2c6b892d',
    'crates/node/tests/tx_ingress_e2e.rs': '31b64d54db8a97cc9287e128f9e5ab7fd5894b29',
    'crates/rpc/src/context.rs': 'c9f41c05b3fe13ac99c8c2b6ac5b9752b8f37a6a',
    'docs/contracts/mempool-mutations.md': 'b0d4d6731be00d0080c774c2cafa42d17ef18a82',
    'fuzz/Cargo.lock': '2e7ed462032a76911ab3283cd780a3dcf60bbc09',
    'crates/consensus/src/verify_tx.rs': '92ab1f3c0240afcc4a1e6d1904362c98f8be1a62',
    'crates/consensus/src/sigops.rs': '61e04279909dad8982a6d38ea1b0e1ad5e6dc985',
    'crates/mempool/src/accounting.rs': 'c379277deaaf3f7c5f6babc87933aa76a2e0f894',
    'crates/consensus/src/lib.rs': 'c1026646e7a234da3b8e1c4d3bb8ed6ce4e4a9fe',
}
for path, expected in preimages.items():
    actual = subprocess.check_output(['git', 'hash-object', path], text=True).strip()
    assert actual == expected, (path, expected, actual)

# Retain concurrent inventory, quota, reorg, documentation, and toolchain edits.
# These six paths have not changed since the candidate's reviewed base.
for path in list(preimages)[:6]:
    (root / path).write_bytes((source / path).read_bytes())

# Keep the concurrent consensus module as the one transaction-cost owner.
# Callers provide their existing lookups, avoiding both a quadratic scan in
# admission and a new map/allocation in the block-verification hot path.
for path in ['crates/consensus/src/verify_tx.rs', 'crates/mempool/src/accounting.rs']:
    text = (source / path).read_text()
    old = 'use bitcoin_rs_script::sigops::count_tx_cost;'
    assert text.count(old) == 1
    replacement = 'use crate::transaction_sigop_cost;' if '/consensus/' in path else 'use bitcoin_rs_consensus::transaction_sigop_cost;'
    text = text.replace(old, replacement).replace('count_tx_cost(', 'transaction_sigop_cost(')
    (root / path).write_text(text)

p = root / 'crates/consensus/src/sigops.rs'
s = p.read_text()
old = '''pub fn transaction_sigop_cost(tx: &Tx, prevouts: &[(OutPoint, TxOut)]) -> u32 {'''
assert s.count(old) == 1
s = s.replace(old, '''pub fn transaction_sigop_cost<'a>(
    tx: &Tx,
    mut lookup: impl FnMut(&OutPoint) -> Option<&'a TxOut>,
) -> u32 {''')
old = '''        let Some(prevout) = prevouts
            .iter()
            .find(|(outpoint, _)| *outpoint == input.previous_output)
            .map(|(_, output)| output)
'''
assert s.count(old) == 1
s = s.replace(old, '''        let Some(prevout) = lookup(&input.previous_output)
''')
s = s.replace('/// preparing a transaction to retain an explicit missing-input fact.', '''/// preparing a transaction to retain an explicit missing-input fact.
/// The caller supplies its existing coin lookup, so counting creates no
/// duplicate input index and does not change that caller's lookup complexity.''')
a = s.index('        assert_eq!(\n', s.index('    fn non_push_only_p2sh_does_not_count_redeem_sigops()'))
b = s.index('\n    }', a)
s = s[:a] + '''        let prevout = TxOut {
            value: 10_000,
            script_pubkey: p2sh,
        };
        assert_eq!(
            transaction_sigop_cost(&tx, |point| (*point == outpoint).then_some(&prevout)),
            0
        );''' + s[b:]
p.write_text(s)
