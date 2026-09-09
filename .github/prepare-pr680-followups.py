"""Apply the reviewed #680 follow-ups to a pinned clean checkout, one PR at a time."""
from pathlib import Path
import subprocess
import sys

BASE = "f211c2f99174cdc41ffac0a6cc5d15013a1eb961"
FILES = {
    "p2p": {
        "crates/p2p/src/inv.rs": "c83d2e911c0cc6a5ddf541d4934ef46ff8a75af9",
        "crates/p2p/src/dispatch.rs": "1b171257da0246f2f12792c6c18a5df435ca2fc2",
        "docs/policies/p2p-compatibility.md": "bdf95fd02b249748434ac49a2911cb50d59f3ac3",
    },
    "rpc": {
        "crates/rpc/src/handlers/tx.rs": "066f746f1b1588672f2caf521949f569b5715769",
        "docs/policies/mempool-policy.md": "20e0ec2b9bc4a704ae26f719bba0e745fc6a7530",
    },
}


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def replace(text, before, after):
    count = text.count(before)
    if count != 1:
        raise RuntimeError(f"Expected exactly one replacement site, found {count}: {before[:100]!r}")
    return text.replace(before, after, 1)


P2P_TEST = '''    /// P2P-01 / BIP144: request witnesses by service flags, not relay preference.
    /// <https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki#relay>
    #[test]
    fn announced_transactions_request_witness_without_changing_hashes() {
        use bitcoin::p2p::ServiceFlags;

        let held = bitcoin::Txid::from_byte_array([0x44; 32]);
        let unknown = bitcoin::Txid::from_byte_array([0x55; 32]);
        let wtxid = bitcoin::Wtxid::from_byte_array([0x66; 32]);
        let block = bitcoin::BlockHash::from_byte_array([0x77; 32]);
        let items = vec![
            Inventory::Transaction(held),
            Inventory::Transaction(unknown),
            Inventory::WTx(wtxid),
            Inventory::Block(block),
        ];
        for witness in [false, true] {
            for negotiated in [false, true] {
                for filtered in [false, true] {
                    let mut peer = ready_peer();
                    let mut version = crate::handshake::version_message(1, 0);
                    version.services = if witness {
                        ServiceFlags::NETWORK | ServiceFlags::WITNESS
                    } else {
                        ServiceFlags::NETWORK
                    };
                    peer.remote_version = Some(version);
                    peer.received_verack = true;
                    if negotiated {
                        peer.wtxid_relay.mark_local_advertised();
                        peer.wtxid_relay.mark_peer_supported();
                    }
                    let inventory = FakeTxInventory::empty().with_have([0x44; 32]);
                    let view: Option<&dyn TxInventory> = filtered.then_some(&inventory);
                    let request = |txid| {
                        if witness {
                            Inventory::WitnessTransaction(txid)
                        } else {
                            Inventory::Transaction(txid)
                        }
                    };
                    let mut expected = Vec::new();
                    if !filtered {
                        expected.push(request(held));
                    }
                    expected.extend([
                        request(unknown),
                        Inventory::WTx(wtxid),
                        Inventory::Block(block),
                    ]);
                    assert_eq!(
                        dispatch_collect_full(
                            &mut peer,
                            &Message::Inv(items.clone()),
                            None,
                            view,
                        ),
                        vec![Message::GetData(expected)],
                    );
                }
            }
        }
    }

'''

RPC_TEST = '''    /// POL-01 / BIP141: package prevouts retain the scripts used by accounting.
    /// <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#sigops>
    #[test]
    fn package_prevouts_preserve_sigops_without_mutating_the_pool() {
        let ctx = Context::new();
        let pool = ctx.mempool.read();
        let sequence = pool.sequence_number();
        let p2sh = [vec![0xa9, 0x14], vec![1; 20], vec![0x87]].concat();
        let p2wpkh = [vec![0x00, 0x14], vec![2; 20]].concat();
        let p2wsh = [vec![0x00, 0x20], vec![3; 32]].concat();
        let multisig = vec![0x52, 0xae];
        let cases = [
            (p2wpkh, Vec::new(), Vec::new(), 1),
            (p2sh.clone(), vec![2, 0x52, 0xae], Vec::new(), 8),
            (p2wsh.clone(), Vec::new(), vec![multisig.clone()], 2),
            (p2sh, [vec![34], p2wsh].concat(), vec![multisig], 2),
        ];
        for (script_pubkey, script_sig, witness, input_cost) in cases {
            let parent = Tx {
                version: 2,
                lock_time: 0,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0),
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: Vec::new(),
                }],
                outputs: vec![
                    TxOut { value: 1, script_pubkey: vec![0x51] },
                    TxOut { value: 9_000, script_pubkey },
                ],
            };
            let child = Tx {
                version: 2,
                lock_time: 0,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(parent.txid(), 1),
                    script_sig,
                    sequence: u32::MAX,
                    witness,
                }],
                outputs: vec![TxOut { value: 8_000, script_pubkey: vec![0xac] }],
            };
            // Preparation only: no script execution or successful package
            // acceptance is claimed. The parent's chain input is absent.
            let vsize = child.vsize();
            let contexts = super::package_contexts(&ctx, &pool, &[parent, child]);
            assert_eq!(contexts.len(), 2);
            assert!(contexts[0].missing_inputs);
            assert!(!contexts[1].missing_inputs);
            assert_eq!(contexts[1].fee, 1_000);
            assert_eq!(u64::from(contexts[1].vsize), vsize);
            // BIP141: the legacy output CHECKSIG adds four to the input cost.
            assert_eq!(contexts[1].sigop_cost, 4 + input_cost);
            assert_eq!(pool.sequence_number(), sequence);
            assert!(pool.is_empty());
        }
    }

'''


def p2p(contents):
    path = "crates/p2p/src/inv.rs"
    text = contents[path]
    text = replace(text, "    let items: Vec<Inventory> = parents\n", "    let mut items: Vec<Inventory> = parents\n")
    text = replace(text, '''        .map(|txid| {
            let txid = bitcoin::Txid::from_byte_array(*txid.as_bytes());
            if witness {
                Inventory::WitnessTransaction(txid)
            } else {
                Inventory::Transaction(txid)
            }
        })''', '''        .map(|txid| Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes())))''')
    text = replace(text, "    // Capability metadata belongs to the same connection as the token.\n", "    request_transaction_witness(&mut items, witness);\n    // Capability metadata belongs to the same connection as the token.\n")
    text = replace(text, "/// Classify an inbound inventory announcement into a getdata request.\n", '''/// Selects BIP144 witness serialization for txid-based getdata requests.
/// This does not change identifiers or outbound inv announcement types.
pub(crate) fn request_transaction_witness(items: &mut [Inventory], witness: bool) {
    if witness {
        for item in items {
            if let Inventory::Transaction(txid) = *item {
                *item = Inventory::WitnessTransaction(txid);
            }
        }
    }
}

/// Classify an inbound inventory announcement into a getdata request.
''')
    contents[path] = text
    path = "crates/p2p/src/dispatch.rs"
    text = contents[path]
    text = replace(text, "    inventory_tx_hash, is_within_inventory_bound, request_inventory, request_inventory_filtered,\n", "    inventory_tx_hash, is_within_inventory_bound, request_inventory, request_inventory_filtered,\n    request_transaction_witness,\n")
    text = replace(text, '''            if let Some(response) = response {
                send(response)?;
            }
''', '''            if let Some(mut response) = response {
                if let Message::GetData(items) = &mut response {
                    let witness = peer.remote_version.as_ref().is_some_and(|version| {
                        version.services.to_u64() & bitcoin::p2p::ServiceFlags::WITNESS.to_u64() != 0
                    });
                    request_transaction_witness(items, witness);
                }
                send(response)?;
            }
''')
    text = replace(text, '''/// transaction inventory (the node's mempool): a held tx is emitted as a
/// `tx` message (witness serialization), and a tx the node does not have is
''', '''/// transaction inventory (the node's mempool): a held tx is emitted as a
/// `tx` message using the requested serialization, and an unknown tx is
''')
    text = replace(text, '''/// items are resolved by wtxid; `Transaction`/`WitnessTransaction` items by
/// txid.
''', '''/// items are resolved by wtxid; `Transaction`/`WitnessTransaction` items by
/// txid. BIP144 plain `Transaction` requests receive stripped copies;
/// witness-typed requests retain witnesses without mutating stored bodies.
''')
    text = replace(text, '''                if let Some(tx) = inv.get_tx(native) {
                    send(Message::Tx(tx))?;
''', '''                if let Some(mut tx) = inv.get_tx(native) {
                    if matches!(item, Inventory::Transaction(_)) {
                        for input in &mut tx.inputs {
                            input.witness.clear();
                        }
                    }
                    send(Message::Tx(tx))?;
''')
    text = replace(text, "    #[test]\n    fn gateway_inventory_filters_and_serves_txid_and_wtxid() {\n", P2P_TEST + "    /// P2P-01 / BIP144 / BIP339: lookup identity and requested serialization.\n    #[test]\n    fn gateway_inventory_filters_and_serves_txid_and_wtxid() {\n")
    text = replace(text, '''        // BIP339 MSG_WTX resolves the witness hash; txid requests keep their
        // own lookup even on a wtxid-relay connection. Unknowns remain notfound.
''', '''        let witness_item =
            Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
        let mut stripped = tx.clone();
        for input in &mut stripped.inputs {
            input.witness.clear();
        }
        assert_eq!(stripped.txid(), tx.txid());
        assert_ne!(stripped.wtxid(), tx.wtxid());
        // BIP144 chooses serialization from the request type, while BIP339
        // chooses the lookup hash. Neither may alter the retained body.
''')
    text = replace(text, "&Message::GetData(vec![txid_item, wtxid_item, missing]),", "&Message::GetData(vec![txid_item, witness_item, wtxid_item, missing]),")
    text = replace(text, '''            vec![
                Message::Tx(tx.clone()),
                Message::Tx(tx),
                Message::NotFound(vec![missing])
            ],
        );
''', '''            vec![
                Message::Tx(stripped),
                Message::Tx(tx.clone()),
                Message::Tx(tx.clone()),
                Message::NotFound(vec![missing])
            ],
        );
        assert_eq!(gateway.get_tx_by_wtxid(tx.wtxid()), Some(tx));
''')
    contents[path] = text
    path = "docs/policies/p2p-compatibility.md"
    text = contents[path]
    text = replace(text, "a wtxid-relay peer announcing `MSG_WTX` is asked for `MSG_WTX`.", "`MSG_WTX` is requested unchanged, while `MSG_TX` is requested as `MSG_WITNESS_TX` from `NODE_WITNESS` peers and as `MSG_TX` otherwise (BIP144). Inventory type, not the peer's announcement preference, determines the lookup hash.")
    text = replace(text, "transaction inventory is served from the mempool / orphan map. Misses resolve", "transaction inventory is served from the mempool / orphan map. Plain `MSG_TX` receives a stripped copy; `MSG_WITNESS_TX` and `MSG_WTX` retain witnesses. Serving does not alter the stored body. Misses resolve")
    text = replace(text, "  `gateway_inventory_filters_and_serves_txid_and_wtxid` exercises the\n  `TxInventory` implementation over the shared gateway.", "  `gateway_inventory_filters_and_serves_txid_and_wtxid` exercises the\n  `TxInventory` implementation, requested serialization, and stored-body\n  preservation over the shared gateway.\n  `announced_transactions_request_witness_without_changing_hashes` covers\n  witness-capable and legacy sources, both relay preferences, filtered and\n  unfiltered requests, and unchanged wtxid/block vectors.")
    contents[path] = text
    return contents


def rpc(contents):
    path = "crates/rpc/src/handlers/tx.rs"
    text = contents[path]
    text = replace(text, "    let mut package_outputs: HashMap<(Txid, u32), u64> = HashMap::new();", "    let mut package_outputs: HashMap<OutPoint, &TxOut> = HashMap::new();")
    text = replace(text, '''            let key = (input.previous_output.txid, input.previous_output.vout);
            if let Some(value) = package_outputs.get(&key) {
                prevouts.push((
                    input.previous_output,
                    TxOut {
                        value: *value,
                        script_pubkey: Vec::new(),
                    },
                ));''', '''            if let Some(&output) = package_outputs.get(&input.previous_output) {
                prevouts.push((input.previous_output, output.clone()));''')
    text = replace(text, '''        // Package outputs deliberately retain the existing value-only facts;
        // completing preview script verification is a separate contract.
''', "")
    text = replace(text, "            package_outputs.insert((txid, vout), output.value);", "            package_outputs.insert(OutPoint::new(txid, vout), output);")
    text = replace(text, "    #[test]\n    fn getrawtransaction_falls_back_to_mempool_for_unconfirmed()\n", RPC_TEST + "    #[test]\n    fn getrawtransaction_falls_back_to_mempool_for_unconfirmed()\n")
    contents[path] = text
    path = "docs/policies/mempool-policy.md"
    text = contents[path]
    text = replace(text, "not evidence that scripts or relative locks have been validated.\n", '''not evidence that scripts or relative locks have been validated.
Package preview retains complete outputs from earlier package transactions as
prevout facts, including their scripts. The
`package_prevouts_preserve_sigops_without_mutating_the_pool` regression in
`crates/rpc/src/handlers/tx.rs` covers P2SH, native witness-v0, and nested witness
accounting, the selected output index, fee, vsize, and unchanged pool state.
This accounting requirement does not close the preview script-verification gap.
''')
    contents[path] = text
    return contents


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in FILES:
        raise SystemExit("usage: prepare.py {p2p|rpc} CHECKOUT")
    kind, root = sys.argv[1], Path(sys.argv[2]).resolve()
    if git(root, "rev-parse", "HEAD") != BASE:
        raise RuntimeError("Wrong base: refusing to apply stale edits")
    if git(root, "status", "--porcelain"):
        raise RuntimeError("Checkout is not clean")
    contents = {}
    for path, expected in FILES[kind].items():
        if git(root, "hash-object", path) != expected:
            raise RuntimeError(f"Source hash mismatch: {path}")
        contents[path] = (root / path).read_text()
    result = {"p2p": p2p, "rpc": rpc}[kind](contents)
    # All preconditions and replacement sites pass before any file is written.
    for path, text in result.items():
        (root / path).write_text(text)
    changed = set(git(root, "diff", "--name-only").splitlines())
    if changed != set(FILES[kind]):
        raise RuntimeError(f"Unexpected changed paths: {changed}")
    subprocess.run(["git", "-C", str(root), "diff", "--check"], check=True)
    print(f"Prepared {kind} on {BASE}: {', '.join(sorted(changed))}")


if __name__ == "__main__":
    main()
