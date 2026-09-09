"""Prepare the source-only fixes and migrate the existing wire expectation."""
import hashlib
import runpy
import subprocess
import sys
from pathlib import Path

runpy.run_path(str(Path(__file__).with_name('pr680_base_prepare.py')), run_name='__main__')
lane, root = sys.argv[1], Path(sys.argv[2])
if lane == 'p2p':
    path = root / 'crates/p2p/tests/core_compat.rs'
    raw = path.read_bytes()
    digest = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    assert digest == 'dd08dc042f60ea88ca3c3e3cf68530389618c738', digest
    text = raw.decode()
    old = '''    // Inbound inv announcements are answered with getdata echoing the items
    // verbatim (a wtxid-relay peer announces MSG_WTX and is asked for MSG_WTX).
    let tx_inv = Inventory::Transaction(Txid::from_byte_array([9u8; 32]));
    let response = dispatch_collect(&mut peer, &Message::Inv(vec![tx_inv]), Some(&chain))?;
    assert_eq!(response, vec![Message::GetData(vec![tx_inv])]);'''
    new = '''    // P2P-01 / BIP144: this handshake advertises NODE_WITNESS, so request
    // witness serialization without changing the announced transaction's txid.
    let txid = Txid::from_byte_array([9u8; 32]);
    let tx_inv = Inventory::Transaction(txid);
    let response = dispatch_collect(&mut peer, &Message::Inv(vec![tx_inv]), Some(&chain))?;
    assert_eq!(
        response,
        vec![Message::GetData(vec![Inventory::WitnessTransaction(txid)])],
    );'''
    assert text.count(old) == 1
    path.write_text(text.replace(old, new))
    expected = {
        'crates/p2p/src/dispatch.rs', 'crates/p2p/src/inv.rs',
        'crates/p2p/tests/core_compat.rs', 'crates/node/tests/tx_ingress_e2e.rs',
        'docs/policies/p2p-compatibility.md',
    }
    actual = set(subprocess.check_output(['git', 'diff', '--name-only'], cwd=root, text=True).splitlines())
    assert actual == expected, actual
