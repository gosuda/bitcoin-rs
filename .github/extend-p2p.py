"""Extend pinned P2P preparation to its existing node integration-test consumer."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "prepare", Path(__file__).with_name("prepare-pr680-followups.py")
)
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)

path = "crates/node/tests/tx_ingress_e2e.rs"
prepare.FILES["p2p"][path] = "00894a8bac613d08d77c28f26662a4f51de23888"
original = prepare.p2p


def p2p(contents):
    contents = original(contents)
    contents[path] = prepare.replace(
        contents[path],
        '''/// True when one of `frames` requests `txid` with `getdata`.
fn requests_tx(frames: &[Message], txid: &Txid) -> bool {
    frames.iter().any(|message| match message {
        Message::GetData(items) => items.iter().any(|item| match item {
            Inventory::Transaction(hash) => hash.as_byte_array() == txid.as_bytes(),
            _ => false,
        }),
        _ => false,
    })
}''',
        '''/// P2P-01 / BIP144: either txid request form names the same transaction.
/// Witness-capable fixture peers receive `MSG_WITNESS_TX`; announcements
/// remain governed independently by their negotiated relay preference.
fn requests_tx(frames: &[Message], txid: &Txid) -> bool {
    frames.iter().any(|message| match message {
        Message::GetData(items) => items.iter().any(|item| match item {
            Inventory::Transaction(hash) | Inventory::WitnessTransaction(hash) => {
                hash.as_byte_array() == txid.as_bytes()
            }
            _ => false,
        }),
        _ => false,
    })'''+"\n}" ,
    )
    return contents


prepare.p2p = p2p
prepare.main()
