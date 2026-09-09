"""Prepare two source-only follow-ups on the reviewed main snapshot."""
import hashlib
import subprocess
import sys
from pathlib import Path

BASE = "8e1bc07a9648293768ca1109118ba89e87f7b6de"
LANE, ROOT = sys.argv[1], Path(sys.argv[2])
HASHES = {
    "crates/p2p/src/dispatch.rs": "1b171257da0246f2f12792c6c18a5df435ca2fc2",
    "crates/p2p/src/inv.rs": "c83d2e911c0cc6a5ddf541d4934ef46ff8a75af9",
    "crates/node/tests/tx_ingress_e2e.rs": "00894a8bac613d08d77c28f26662a4f51de23888",
    "docs/policies/p2p-compatibility.md": "bdf95fd02b249748434ac49a2911cb50d59f3ac3",
    "crates/rpc/src/handlers/tx.rs": "066f746f1b1588672f2caf521949f569b5715769",
    "docs/policies/mempool-policy.md": "20e0ec2b9bc4a704ae26f719bba0e745fc6a7530",
}

def read(path):
    raw = (ROOT / path).read_bytes()
    sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if sha != HASHES[path]:
        raise RuntimeError(f"Refusing changed source {path}: {sha}")
    return raw.decode("utf-8")

def replace(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError(f"Expected one match, got {text.count(old)}: {old[:120]!r}")
    return text.replace(old, new, 1)

def write(path, text):
    (ROOT / path).write_text(text, encoding="utf-8")

if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != BASE:
    raise RuntimeError("Candidate must start at the reviewed main commit")

if LANE == "p2p":
    path = "crates/p2p/src/inv.rs"
    text = read(path)
    text = replace(text, "    let items: Vec<Inventory> = parents", "    let mut items: Vec<Inventory> = parents")
    text = replace(text, '''        .map(|txid| {
            let txid = bitcoin::Txid::from_byte_array(*txid.as_bytes());
            if witness {
                Inventory::WitnessTransaction(txid)
            } else {
                Inventory::Transaction(txid)
            }
        })''', '''        .map(|txid| Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes())))''')
    text = replace(text, "    // Capability metadata belongs to the same connection as the token.", "    request_transaction_witness(&mut items, witness);\n    // Capability metadata belongs to the same connection as the token.")
    anchor = "/// Classify an inbound inventory announcement into a getdata request."
    text = replace(text, anchor, '''/// Applies BIP144's transaction witness request flag without changing hashes.
/// Only getdata requests use this flag; announcements retain their own types.
pub(crate) fn request_transaction_witness(items: &mut [Inventory], witness: bool) {
    if !witness {
        return;
    }
    for item in items {
        if let Inventory::Transaction(txid) = item {
            *item = Inventory::WitnessTransaction(*txid);
        }
    }
}

''' + anchor)
    write(path, text)

    path = "crates/p2p/src/dispatch.rs"
    text = read(path)
    text = replace(text, "    inventory_tx_hash, is_within_inventory_bound, request_inventory, request_inventory_filtered,\n", "    inventory_tx_hash, is_within_inventory_bound, request_inventory, request_inventory_filtered,\n    request_transaction_witness,\n")
    text = replace(text, '''            if let Some(response) = response {
                send(response)?;
            }''', '''            if let Some(mut response) = response {
                if let Message::GetData(items) = &mut response {
                    let witness = peer.remote_version.as_ref().is_some_and(|version| {
                        version.services.to_u64() & bitcoin::p2p::ServiceFlags::WITNESS.to_u64() != 0
                    });
                    request_transaction_witness(items, witness);
                }
                send(response)?;
            }''')
    text = replace(text, '''/// `tx` message (witness serialization), and a tx the node does not have is
/// collected into the trailing `notfound`. Block-typed items continue to''', '''/// `tx` message with the serialization requested by its inventory type
/// (P2P-01 / BIP144). Unknown transactions enter the trailing `notfound`.
/// Block-typed items continue to''')
    text = replace(text, '''                if let Some(tx) = inv.get_tx(native) {
                    send(Message::Tx(tx))?;''', '''                if let Some(mut tx) = inv.get_tx(native) {
                    if matches!(item, Inventory::Transaction(_)) {
                        for input in &mut tx.inputs {
                            input.witness.clear();
                        }
                    }
                    send(Message::Tx(tx))?;''')
    marker = "    #[test]\n    fn gateway_inventory_filters_and_serves_txid_and_wtxid() {"
    text = replace(text, marker, '''    /// P2P-01 / BIP144: NODE_WITNESS controls getdata serialization, not hashes.
    /// <https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki#relay>
    #[test]
    fn announced_transactions_request_witness_without_changing_hashes() {
        let inventory = FakeTxInventory::empty();
        for witness in [false, true] {
            for filtered in [false, true] {
                let mut peer = ready_peer();
                let mut version = crate::handshake::version_message(1, 0);
                version.services = if witness {
                    bitcoin::p2p::ServiceFlags::WITNESS
                } else {
                    bitcoin::p2p::ServiceFlags::NETWORK
                };
                peer.remote_version = Some(version);
                let txid = bitcoin::Txid::from_byte_array([1; 32]);
                let wtxid = Inventory::WTx(bitcoin::Wtxid::from_byte_array([2; 32]));
                let block = Inventory::Block(bitcoin::BlockHash::from_byte_array([3; 32]));
                let requested = if witness {
                    Inventory::WitnessTransaction(txid)
                } else {
                    Inventory::Transaction(txid)
                };
                let view: Option<&dyn TxInventory> = filtered.then_some(&inventory);
                assert_eq!(
                    dispatch_collect_full(
                        &mut peer,
                        &Message::Inv(vec![Inventory::Transaction(txid), wtxid, block]),
                        None,
                        view,
                    ),
                    vec![Message::GetData(vec![requested, wtxid, block])],
                );
            }
        }
    }

    /// P2P-01 / BIP144 / BIP339: requested serialization must preserve stored witnesses.
''' + marker)
    start = text.index("    fn gateway_inventory_filters_and_serves_txid_and_wtxid() {")
    end = text.index("    #[test]", start)
    test = text[start:end]
    test = replace(test, "        let wtxid_item = Inventory::WTx", "        let witness_txid_item =\n            Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));\n        let wtxid_item = Inventory::WTx")
    test = replace(test, "        let missing = Inventory::WTx", "        let mut stripped = tx.clone();\n        for input in &mut stripped.inputs {\n            input.witness.clear();\n        }\n        let missing = Inventory::WTx")
    test = replace(test, "&Message::GetData(vec![txid_item, wtxid_item, missing])", "&Message::GetData(vec![txid_item, witness_txid_item, wtxid_item, missing])")
    test = replace(test, '''                Message::Tx(tx.clone()),
                Message::Tx(tx),''', '''                Message::Tx(stripped),
                Message::Tx(tx.clone()),
                Message::Tx(tx.clone()),''')
    test = replace(test, "        );\n    }\n", "        );\n        assert_eq!(gateway.get_tx_by_wtxid(tx.wtxid()), Some(tx));\n    }\n")
    text = text[:start] + test + text[end:]
    write(path, text)

    path = "crates/node/tests/tx_ingress_e2e.rs"
    text = read(path)
    start = text.index("/// True when one of `frames` requests `txid` with `getdata`.")
    end = text.index("/// Collects frames until", start)
    helper = text[start:end]
    helper = replace(helper, "/// True when one of `frames` requests `txid` with `getdata`.", "/// P2P-01 / BIP144: these dialers advertise NODE_WITNESS, so require\n/// witness-serialized getdata rather than accepting the legacy request.")
    helper = replace(helper, "Inventory::Transaction(hash)", "Inventory::WitnessTransaction(hash)")
    write(path, text[:start] + helper + text[end:])

    path = "docs/policies/p2p-compatibility.md"
    text = read(path)
    text = replace(text, "a wtxid-relay peer announcing `MSG_WTX` is asked for `MSG_WTX`. Bound:", "`MSG_TX` announcements are requested as `MSG_WITNESS_TX` from `NODE_WITNESS` peers and as `MSG_TX` otherwise; `MSG_WTX` requests retain their wtxid and type. Bound:")
    text = replace(text, "transaction inventory is served from the mempool / orphan map. Misses", "transaction inventory is served from the mempool / orphan map. `MSG_TX` receives stripped serialization; `MSG_WITNESS_TX` and `MSG_WTX` receive witness serialization (BIP144/BIP339), without changing the retained body. Misses")
    text = replace(text, "  `gateway_inventory_filters_and_serves_txid_and_wtxid` exercises the\n  `TxInventory` implementation over the shared gateway.", "  `gateway_inventory_filters_and_serves_txid_and_wtxid` exercises lookup,\n  requested serialization, and retained-body immutability over the gateway.\n  `announced_transactions_request_witness_without_changing_hashes` covers\n  ordinary inventory requests with and without the inventory filter.\n  Node's `tx_ingress_e2e` suite requires witness requests from its\n  `NODE_WITNESS` dialers before delivering transactions.")
    write(path, text)
elif LANE == "rpc":
    path = "crates/rpc/src/handlers/tx.rs"
    text = read(path)
    text = replace(text, "let mut package_outputs: HashMap<(Txid, u32), u64> = HashMap::new();", "let mut package_outputs: HashMap<OutPoint, &TxOut> = HashMap::new();")
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
    text = replace(text, "        // Package outputs deliberately retain the existing value-only facts;\n        // completing preview script verification is a separate contract.\n", "")
    text = replace(text, "package_outputs.insert((txid, vout), output.value);", "package_outputs.insert(OutPoint::new(txid, vout), output);")
    marker = "    #[test]\n    fn getrawtransaction_falls_back_to_mempool_for_unconfirmed()"
    text = replace(text, marker, '''    /// POL-01 / BIP141: package prevouts retain scripts for contextual sigop cost.
    /// This exercises accounting, not the separately scoped preview script checks.
    /// <https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#sigops>
    #[test]
    fn package_prevouts_preserve_contextual_sigops_without_mutating_the_pool() {
        let p2sh = [vec![0xa9, 0x14], vec![1; 20], vec![0x87]].concat();
        let p2wpkh = [vec![0x00, 0x14], vec![2; 20]].concat();
        let p2wsh = [vec![0x00, 0x20], vec![3; 32]].concat();
        let multisig = vec![0x52, 0xae];
        let cases = [
            (p2wpkh, Vec::new(), Vec::new(), 5),
            (p2sh.clone(), super::push_data(&multisig), Vec::new(), 12),
            (p2wsh.clone(), Vec::new(), vec![multisig.clone()], 6),
            (p2sh, super::push_data(&p2wsh), vec![multisig], 6),
        ];
        for (prevout_script, script_sig, witness, expected) in cases {
            let ctx = Context::new();
            let pool = ctx.mempool.read();
            let sequence = pool.sequence_number();
            let parent = Tx {
                version: 2,
                lock_time: 0,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0),
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: Vec::new(),
                }],
                outputs: vec![TxOut { value: 9_000, script_pubkey: prevout_script }],
            };
            let child = Tx {
                version: 2,
                lock_time: 0,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(parent.txid(), 0),
                    script_sig,
                    sequence: u32::MAX,
                    witness,
                }],
                outputs: vec![TxOut { value: 8_000, script_pubkey: vec![0xac] }],
            };
            // Independent rust-bitcoin accounting, with explicit BIP141 costs:
            // one legacy output CHECKSIG costs four; input costs are 1, 8, 2, 2.
            let oracle: bitcoin::Transaction = bitcoin::consensus::deserialize(&consensus_bytes(&child))
                .expect("accounting fixture must decode in the independent oracle");
            let oracle_output = bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(parent.outputs[0].value),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(parent.outputs[0].script_pubkey.clone()),
            };
            assert_eq!(oracle.total_sigop_cost(|_| Some(oracle_output.clone())), expected);
            let txs = [parent, child];
            let contexts = super::package_contexts(&ctx, &pool, &txs);
            assert!(contexts[0].missing_inputs);
            assert!(!contexts[1].missing_inputs);
            assert_eq!(contexts[1].fee, 1_000);
            assert_eq!(u64::from(contexts[1].vsize), txs[1].vsize());
            assert_eq!(u64::from(contexts[1].sigop_cost), expected);

            // An existing package parent cannot fabricate a nonexistent output.
            let mut missing = txs[1].clone();
            missing.inputs[0].previous_output.vout = 1;
            let contexts = super::package_contexts(&ctx, &pool, &[txs[0].clone(), missing]);
            assert!(contexts[1].missing_inputs);
            assert_eq!(contexts[1].fee, 0);
            assert_eq!(pool.sequence_number(), sequence);
            assert!(pool.is_empty());
        }
    }

''' + marker)
    write(path, text)
    path = "docs/policies/mempool-policy.md"
    text = read(path)
    text = replace(text, "Incomplete preview context remains explicitly missing-input context; it is", "RPC package preparation retains full outputs, including scripts, from earlier\npackage transactions when resolving descendant accounting. Value-only synthetic\noutputs must not erase P2SH or witness costs.\nIncomplete preview context remains explicitly missing-input context; it is")
    text = replace(text, "- A policy change that alters any §3 row", "- **Package-parent accounting**: `package_prevouts_preserve_contextual_sigops_without_mutating_the_pool`\n  in `crates/rpc/src/handlers/tx.rs` checks native and nested witness/P2SH\n  costs against BIP141 and rust-bitcoin, preserves missing-output classification,\n  and leaves pool membership and sequence unchanged.\n- A policy change that alters any §3 row")
    write(path, text)
else:
    raise RuntimeError(f"Unknown lane {LANE}")

expected = set(HASHES) - {"crates/rpc/src/handlers/tx.rs", "docs/policies/mempool-policy.md"} if LANE == "p2p" else {"crates/rpc/src/handlers/tx.rs", "docs/policies/mempool-policy.md"}
changed = set(subprocess.check_output(["git", "diff", "--name-only"], cwd=ROOT, text=True).splitlines())
if changed != expected:
    raise RuntimeError(f"Unexpected changed files: {changed ^ expected}")
print(f"Prepared {LANE} from {BASE}: {sorted(changed)}")
