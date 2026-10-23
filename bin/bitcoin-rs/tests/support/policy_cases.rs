//! Signed policy scenarios against two isolated public regtest processes.

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute, transaction,
};
use serde_json::{Value, json};

use bitcoin_rs_e2e::differential::mine_common_chain;
use bitcoin_rs_e2e::helpers::sign_p2pkh_inputs;
use bitcoin_rs_e2e::node::START_TIMEOUT;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, SpawnOptions};

type Coin = (OutPoint, TxOut);

struct Pair {
    core: ProcessNode,
    node: ProcessNode,
    coins: Vec<Coin>,
}

impl Pair {
    fn new() -> Self {
        // These are the repository's selected values, explicitly supplied to
        // Core. They are not claims about Core 31.1's changed fee defaults.
        // The two process launches are independent; start them concurrently.
        let (core, node) = std::thread::scope(|scope| {
            let core = scope.spawn(|| {
                ProcessNode::spawn_with(
                    Kind::Core,
                    &SpawnOptions {
                        extra_args: &[
                            "-acceptnonstdtxn=0",
                            "-minrelaytxfee=0.00001000",
                            "-incrementalrelayfee=0.00001000",
                            "-dustrelayfee=0.00003000",
                            "-datacarriersize=83",
                        ],
                        timeout: Some(START_TIMEOUT),
                        ..Default::default()
                    },
                )
            });
            let node = scope.spawn(|| ProcessNode::spawn(Kind::BitcoinRs));
            (
                core.join().expect("reference launch panicked"),
                node.join().expect("candidate launch panicked"),
            )
        });
        let mut core = core.expect("standard Core policy profile");
        let mut node = node.expect("candidate process");
        std::thread::scope(|scope| {
            for process in [&mut core, &mut node] {
                scope.spawn(move || {
                    let policy = process
                        .rpc("getmempoolinfo", &json!([]))
                        .expect("selected settings");
                    assert_eq!(policy["minrelaytxfee"], json!(0.00001));
                    assert_eq!(policy["incrementalrelayfee"], json!(0.00001));
                    assert_eq!(policy["limitclustercount"], json!(64));
                    assert_eq!(policy["limitclustersize"], json!(101_000));
                    assert_eq!(policy["maxdatacarriersize"], json!(83));
                    assert_eq!(policy["fullrbf"], json!(true));
                });
            }
        });
        let funds = mine_common_chain(&mut core, &mut node, 101).expect("identical chain");
        let funding = funds.confirmed_output(0).expect("confirmed funding");
        let split = transaction(&[funding], 140, 20_000, 2);
        let split_raw = &serialize_hex(&split);
        let split_txid = &split.compute_txid().to_string();
        std::thread::scope(|scope| {
            for process in [&mut core, &mut node] {
                scope.spawn(move || {
                    assert_eq!(
                        process
                            .rpc("sendrawtransaction", &json!([split_raw]))
                            .expect("funding split"),
                        json!(split_txid)
                    );
                });
            }
        });
        mine_common_chain(&mut core, &mut node, 1).expect("confirm shared split");
        let coins = (0..split.output.len())
            .map(|index| output(&split, index))
            .collect();
        Self { core, node, coins }
    }

    fn check(&mut self, tx: &Transaction, rejection: Option<&str>) {
        let raw = serialize_hex(tx);
        let txid = tx.compute_txid().to_string();
        // The per-process observation sequences are independent; run the
        // reference and candidate checks concurrently.
        let check_one = |process: &mut ProcessNode| {
            let before = process
                .rpc("getrawmempool", &json!([false, true]))
                .expect("before state");
            let preview = process
                .rpc("testmempoolaccept", &json!([[raw]]))
                .expect("preview");
            assert_eq!(
                preview[0]["allowed"],
                json!(rejection.is_none()),
                "{txid}: {preview}"
            );
            assert_eq!(
                process
                    .rpc("getrawmempool", &json!([false, true]))
                    .expect("after preview"),
                before,
                "preview purity"
            );
            if let Some(reason) = rejection {
                assert_eq!(preview[0]["reject-reason"], json!(reason), "{preview}");
                let submitted = process.rpc("sendrawtransaction", &json!([raw]));
                assert!(
                    matches!(submitted, Err(Error::Rpc { code: -26, ref message, .. }) if message.contains(reason)),
                    "{submitted:?}"
                );
                assert_eq!(
                    process
                        .rpc("getrawmempool", &json!([false, true]))
                        .expect("after failure"),
                    before,
                    "rejection purity"
                );
            } else {
                assert_eq!(preview[0]["vsize"], json!(tx.vsize()));
                assert_eq!(
                    process
                        .rpc("sendrawtransaction", &json!([raw]))
                        .expect("commit"),
                    json!(txid)
                );
            }
        };
        std::thread::scope(|scope| {
            let reference = scope.spawn(|| check_one(&mut self.core));
            let candidate = scope.spawn(|| check_one(&mut self.node));
            reference.join().expect("reference check panicked");
            candidate.join().expect("candidate check panicked");
        });
        let (core, node) = std::thread::scope(|scope| {
            let core = scope.spawn(|| self.core.rpc("getrawmempool", &json!([])));
            let node = scope.spawn(|| self.node.rpc("getrawmempool", &json!([])));
            (
                core.join().expect("reference member request panicked"),
                node.join().expect("candidate member request panicked"),
            )
        });
        let core = core.expect("reference members");
        let node = node.expect("candidate members");
        let sorted = |value: Value| {
            let mut rows: Vec<_> = value
                .as_array()
                .expect("members")
                .iter()
                .map(|id| id.as_str().expect("txid").to_owned())
                .collect();
            rows.sort();
            rows
        };
        assert_eq!(sorted(core), sorted(node), "committed membership matches");
    }

    fn preview(&mut self, txs: &[Transaction]) -> (Value, Value) {
        let raw: Vec<_> = txs.iter().map(serialize_hex).collect();
        // The per-process preview observation is independent on each node.
        let preview_one = |process: &mut ProcessNode| {
            let before = process
                .rpc("getrawmempool", &json!([false, true]))
                .expect("before package");
            let reply = process
                .rpc("testmempoolaccept", &json!([raw]))
                .expect("package preview");
            assert_eq!(
                process
                    .rpc("getrawmempool", &json!([false, true]))
                    .expect("after package"),
                before
            );
            reply
        };
        std::thread::scope(|scope| {
            let reference = scope.spawn(|| preview_one(&mut self.core));
            let candidate = scope.spawn(|| preview_one(&mut self.node));
            (
                reference.join().expect("reference preview panicked"),
                candidate.join().expect("candidate preview panicked"),
            )
        })
    }
}

fn output(tx: &Transaction, index: usize) -> Coin {
    (
        OutPoint::new(
            tx.compute_txid(),
            u32::try_from(index).expect("output index"),
        ),
        tx.output[index].clone(),
    )
}

fn transaction(inputs: &[Coin], count: usize, fee: u64, version: i32) -> Transaction {
    let total: u64 = inputs.iter().map(|(_, coin)| coin.value.to_sat()).sum();
    let available = total.checked_sub(fee).expect("funding covers fee");
    let each = available / u64::try_from(count).expect("output count");
    let mut outputs = vec![
        TxOut {
            value: Amount::from_sat(each),
            script_pubkey: inputs[0].1.script_pubkey.clone()
        };
        count
    ];
    outputs[0].value += Amount::from_sat(available % u64::try_from(count).expect("count"));
    signed(inputs, outputs, version)
}

fn signed(inputs: &[Coin], outputs: Vec<TxOut>, version: i32) -> Transaction {
    let mut tx = Transaction {
        version: transaction::Version(version),
        lock_time: absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|(previous_output, _)| TxIn {
                previous_output: *previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    };
    sign_p2pkh_inputs(
        &mut tx,
        &inputs
            .iter()
            .map(|(_, coin)| coin.clone())
            .collect::<Vec<_>>(),
    )
    .expect("signed inputs");
    tx
}

/// Compare the scoped submitpackage wire result and committed public state.
/// Numeric suffixes in native rejection details remain documented deviations.
fn submit_pair(pair: &mut Pair, txs: &[Transaction], extra: &[Value]) -> Value {
    let mut args = vec![json!(txs.iter().map(serialize_hex).collect::<Vec<_>>())];
    args.extend_from_slice(extra);
    let params = Value::Array(args);
    let core = pair
        .core
        .rpc("submitpackage", &params)
        .expect("Core submitpackage");
    let node = pair
        .node
        .rpc("submitpackage", &params)
        .expect("native submitpackage");
    assert_eq!(core["package_msg"], node["package_msg"], "{core} vs {node}");
    assert_eq!(core["replaced-transactions"], node["replaced-transactions"]);
    for tx in txs {
        let key = tx.compute_wtxid().to_string();
        let (reference, candidate) = (&core["tx-results"][&key], &node["tx-results"][&key]);
        if let Some(error) = reference["error"].as_str() {
            assert!(candidate["error"].is_string(), "{reference} vs {candidate}");
            assert_eq!(reference["txid"], candidate["txid"]);
            // Existing native consensus/script errors intentionally omit Core's
            // verbose script diagnostics. Fee errors retain their reason prefix.
            if error.starts_with("min relay fee not met")
                || error.starts_with("max feerate exceeded")
            {
                assert!(
                    error.starts_with(candidate["error"].as_str().expect("error string")),
                    "{reference} vs {candidate}"
                );
            }
        } else {
            assert_eq!(reference, candidate, "{key}");
        }
    }
    let mut core_members = pair
        .core
        .rpc("getrawmempool", &json!([]))
        .expect("Core pool")
        .as_array()
        .expect("members")
        .clone();
    let mut node_members = pair
        .node
        .rpc("getrawmempool", &json!([]))
        .expect("native pool")
        .as_array()
        .expect("members")
        .clone();
    core_members.sort_by_key(Value::to_string);
    node_members.sort_by_key(Value::to_string);
    assert_eq!(core_members, node_members);
    for tx in txs {
        if node_members.contains(&json!(tx.compute_txid().to_string())) {
            let entry = pair
                .node
                .rpc("getmempoolentry", &json!([tx.compute_txid().to_string()]))
                .expect("accepted entry");
            if node["tx-results"][tx.compute_wtxid().to_string()]["other-wtxid"].is_null() {
                assert_eq!(
                    entry["vsize"],
                    node["tx-results"][tx.compute_wtxid().to_string()]["vsize"]
                );
            }
        }
    }
    node
}

/// A signed P2WSH child whose unexecuted branch still incurs sigop cost.
fn sigop_cpfp(coin: &Coin, fee: u64) -> [Transaction; 2] {
    use bitcoin::hashes::Hash as _;
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_ENDIF, OP_IF};
    use bitcoin::script::Builder;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[42; 32]).expect("test key");
    let public =
        bitcoin::PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &key));
    let mut builder = Builder::new()
        .push_key(&public)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_int(0)
        .push_opcode(OP_IF);
    for _ in 0..150 {
        builder = builder.push_opcode(OP_CHECKSIG);
    }
    let script = builder.push_opcode(OP_ENDIF).push_int(1).into_script();
    let parent = signed(
        std::slice::from_ref(coin),
        vec![TxOut {
            value: coin.1.value,
            script_pubkey: script.to_p2wsh(),
        }],
        2,
    );
    let mut child = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: output(&parent, 0).0,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: coin.1.value - Amount::from_sat(fee),
            script_pubkey: coin.1.script_pubkey.clone(),
        }],
    };
    let hash = SighashCache::new(&child)
        .p2wsh_signature_hash(0, &script, coin.1.value, EcdsaSighashType::All)
        .expect("child sighash");
    let signature = bitcoin::ecdsa::Signature {
        signature: secp.sign_ecdsa(&Message::from_digest(hash.to_byte_array()), &key),
        sighash_type: EcdsaSighashType::All,
    };
    child.input[0].witness = Witness::from_slice(&[signature.to_vec(), script.into_bytes()]);
    [parent, child]
}

#[test]
fn submitpackage_cpfp_partial_acceptance_and_guards() {
    let mut pair = Pair::new();
    submitpackage_cpfp_and_resident_members(&mut pair);
    submitpackage_fee_sigop_and_truc_guards(&mut pair);
    submitpackage_structure_burn_and_size_guards(&mut pair);
    submitpackage_refuses_wider_tree(&mut pair);
}

fn submitpackage_cpfp_and_resident_members(pair: &mut Pair) {
    // A zero-fee signed parent is rejected by the unchanged pure preview.
    let parent = transaction(&[pair.coins[0].clone()], 1, 0, 2);
    let child = transaction(&[output(&parent, 0)], 1, 2_000, 2);
    let (core_preview, node_preview) = pair.preview(&[parent.clone(), child.clone()]);
    assert_eq!(core_preview[0]["allowed"], json!(false));
    assert_eq!(node_preview[0]["allowed"], json!(false));
    let accepted = submit_pair(pair, &[parent.clone(), child.clone()], &[]);
    assert_eq!(accepted["package_msg"], json!("success"));
    for process in [&mut pair.core, &mut pair.node] {
        let template = process
            .rpc("getblocktemplate", &json!([{"rules": ["segwit"]}]))
            .expect("package mining template");
        let rows = template["transactions"]
            .as_array()
            .expect("template transactions");
        let parent_index = rows
            .iter()
            .position(|row| row["txid"] == json!(parent.compute_txid().to_string()))
            .expect("parent selected");
        let child_index = rows
            .iter()
            .position(|row| row["txid"] == json!(child.compute_txid().to_string()))
            .expect("child selected");
        assert!(parent_index < child_index);
        assert_eq!(rows[parent_index]["fee"], json!(0));
        assert_eq!(rows[child_index]["fee"], json!(2_000));
    }
    for process in [&mut pair.core, &mut pair.node] {
        let named = process.rpc("submitpackage", &json!({"package": [serialize_hex(&parent), serialize_hex(&child)], "maxfeerate": "0", "maxburnamount": "0"})).expect("named parameters");
        assert_eq!(named["package_msg"], json!("success"));
        assert!(
            named["tx-results"][child.compute_wtxid().to_string()]["fees"]["effective-feerate"]
                .is_null()
        );
    }
    let mut variant = child.clone();
    variant.input[0].witness = Witness::from_slice(&[vec![0]]);
    submit_pair(pair, &[variant], &[]); // resident txid ignores another witness
    submit_pair(pair, &[parent, child], &[]); // resident fees are not reused

    // Individually admissible members use their own effective fee rates.
    let parent = transaction(&[pair.coins[1].clone()], 1, 1_000, 2);
    let child = transaction(&[output(&parent, 0)], 1, 2_000, 2);
    submit_pair(pair, &[parent, child], &[]);

    // Public partial acceptance: the good parent survives a bad child.
    let parent = transaction(&[pair.coins[2].clone()], 1, 1_000, 2);
    let mut child = transaction(&[output(&parent, 0)], 1, 2_000, 2);
    child.input[0].script_sig = ScriptBuf::new();
    let partial = submit_pair(pair, &[parent, child], &[]);
    assert_eq!(partial["package_msg"], json!("transaction failed"));

    // A resident parent cannot donate fees to a new zero-fee child.
    let parent = transaction(&[pair.coins[3].clone()], 1, 1_000, 2);
    submit_pair(pair, std::slice::from_ref(&parent), &[]);
    let child = transaction(&[output(&parent, 0)], 1, 0, 2);
    submit_pair(pair, &[parent.clone(), child], &[]);
    let paying_child = transaction(&[output(&parent, 0)], 1, 2_000, 2);
    submit_pair(pair, &[parent, paying_child], &[]);

    let parent = transaction(&[pair.coins[4].clone()], 1, 0, 2);
    let child = transaction(&[output(&parent, 0)], 1, 1, 2);
    submit_pair(pair, &[parent, child], &[]); // aggregate underpayment
}

fn submitpackage_fee_sigop_and_truc_guards(pair: &mut Pair) {
    // The public maxfeerate guard uses modified fees, not just actual fees.
    let parent = transaction(&[pair.coins[5].clone()], 1, 1_000, 2);
    for process in [&mut pair.core, &mut pair.node] {
        process
            .rpc(
                "prioritisetransaction",
                &json!([parent.compute_txid().to_string(), 0, 10_000]),
            )
            .expect("priority");
    }
    submit_pair(pair, &[parent], &[json!(0.00001)]);
    let low_fee = transaction(&[pair.coins[13].clone()], 1, 10, 2);
    submit_pair(pair, &[low_fee], &[json!(0.000_000_01)]); // own floor before caller cap

    let sigop_package = sigop_cpfp(&pair.coins[14], 700);
    assert!(sigop_package.iter().map(Transaction::vsize).sum::<usize>() < 700);
    assert_eq!(
        submit_pair(pair, &sigop_package, &[])["package_msg"],
        json!("transaction failed")
    );
    let sigop_package = sigop_cpfp(&pair.coins[14], 2_000);
    let accepted = submit_pair(pair, &sigop_package, &[]);
    assert_eq!(accepted["package_msg"], json!("success"));
    assert_eq!(
        accepted["tx-results"][sigop_package[1].compute_wtxid().to_string()]["vsize"],
        json!(775) // 151 witness sigops plus four legacy output sigops
    );

    // TRUC ephemeral dust is admissible only with the paying dust spender.
    let coin = pair.coins[6].clone();
    let parent = signed(
        std::slice::from_ref(&coin),
        vec![
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: coin.1.script_pubkey.clone(),
            },
            TxOut {
                value: coin.1.value - Amount::from_sat(1),
                script_pubkey: coin.1.script_pubkey.clone(),
            },
        ],
        3,
    );
    let child = transaction(&[output(&parent, 0), output(&parent, 1)], 1, 2_000, 3);
    submit_pair(pair, &[parent, child], &[]);

    let coin = pair.coins[10].clone();
    let parent = signed(
        std::slice::from_ref(&coin),
        vec![
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: coin.1.script_pubkey.clone(),
            },
            TxOut {
                value: coin.1.value - Amount::from_sat(1),
                script_pubkey: coin.1.script_pubkey.clone(),
            },
        ],
        3,
    );
    let child = transaction(&[output(&parent, 1)], 1, 2_000, 3);
    assert_eq!(
        submit_pair(pair, &[parent, child], &[])["package_msg"],
        json!("unspent-dust")
    );

    let parent = transaction(&[pair.coins[11].clone()], 1, 0, 3);
    let child = transaction(&[output(&parent, 0)], 1, 2_000, 2);
    // Core includes transaction-specific TRUC diagnostics; the native profile
    // retains the typed reason. Both must reject without accepting the parent.
    let raws = json!([[serialize_hex(&parent), serialize_hex(&child)]]);
    for process in [&mut pair.core, &mut pair.node] {
        let before = process
            .rpc("getrawmempool", &json!([false, true]))
            .expect("before TRUC refusal");
        let reply = process
            .rpc("submitpackage", &raws)
            .expect("TRUC package result");
        assert!(
            reply["package_msg"]
                .as_str()
                .expect("message")
                .starts_with("TRUC-violation"),
            "{reply}"
        );
        assert_eq!(
            process
                .rpc("getrawmempool", &json!([false, true]))
                .expect("after TRUC refusal"),
            before
        );
    }
}

fn submitpackage_structure_burn_and_size_guards(pair: &mut Pair) {
    // Reversed order, duplicates, and unrelated members fail before admission.
    let parent = transaction(&[pair.coins[7].clone()], 1, 0, 2);
    let child = transaction(&[output(&parent, 0)], 1, 2_000, 2);
    let unrelated = transaction(&[pair.coins[12].clone()], 1, 2_000, 2);
    for txs in [
        vec![child.clone(), parent.clone()],
        vec![parent.clone(), parent.clone()],
        vec![parent.clone(), unrelated],
    ] {
        for process in [&mut pair.core, &mut pair.node] {
            let before = process
                .rpc("getrawmempool", &json!([false, true]))
                .expect("before topology refusal");
            assert!(matches!(
                process.rpc(
                    "submitpackage",
                    &json!([txs.iter().map(serialize_hex).collect::<Vec<_>>()])
                ),
                Err(Error::Rpc { code: -25, .. })
            ));
            assert_eq!(
                process
                    .rpc("getrawmempool", &json!([false, true]))
                    .expect("after refusal"),
                before
            );
        }
    }
    let conflicting = transaction(&[pair.coins[7].clone(), output(&parent, 0)], 1, 2_000, 2);
    assert_eq!(
        submit_pair(pair, &[parent.clone(), conflicting], &[])["package_msg"],
        json!("conflict-in-package")
    );
    // Burning is checked for the entire request before the good parent commits.
    let mut burn = child;
    burn.output.push(TxOut {
        value: Amount::from_sat(1),
        script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
    });
    for process in [&mut pair.core, &mut pair.node] {
        assert!(matches!(
            process.rpc(
                "submitpackage",
                &json!([[serialize_hex(&parent), serialize_hex(&burn)]])
            ),
            Err(Error::Rpc { code: -25, .. })
        ));
        assert!(matches!(
            process.rpc("submitpackage", &json!([[]])),
            Err(Error::Rpc { code: -8, .. })
        ));
        assert!(matches!(
            process.rpc("submitpackage", &json!([vec![serialize_hex(&parent); 26]])),
            Err(Error::Rpc { code: -8, .. })
        ));
    }
    let coin = output(&parent, 0);
    let allowed_burn = signed(
        std::slice::from_ref(&coin),
        vec![
            TxOut {
                value: coin.1.value - Amount::from_sat(2_001),
                script_pubkey: coin.1.script_pubkey.clone(),
            },
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
            },
        ],
        2,
    );
    submit_pair(
        pair,
        &[parent, allowed_burn],
        &[json!(0), json!("0.00000001")],
    );
    // Large signed CPFP below the boundary, then refusal above it.
    let parent = transaction(&[pair.coins[8].clone()], 2, 0, 2);
    let child = transaction(&[output(&parent, 0)], 2_900, 300_000, 2);
    let weight = parent.weight().to_wu() + child.weight().to_wu();
    assert!((390_000..=404_000).contains(&weight));
    assert_eq!(
        submit_pair(pair, &[parent, child], &[])["package_msg"],
        json!("success")
    );
    let parent = transaction(&[pair.coins[9].clone()], 2, 0, 2);
    let child = transaction(&[output(&parent, 0)], 3_000, 300_000, 2);
    assert!(parent.weight().to_wu() + child.weight().to_wu() > 404_000);
    let oversized = submit_pair(pair, &[parent, child], &[]);
    assert_eq!(oversized["package_msg"], json!("package-too-large"));
}

fn submitpackage_refuses_wider_tree(pair: &mut Pair) {
    // The scoped API refuses a valid wider tree before any member commits.
    let first = transaction(&[pair.coins[15].clone()], 1, 0, 2);
    let second = transaction(&[pair.coins[16].clone()], 1, 0, 2);
    let child = transaction(&[output(&first, 0), output(&second, 0)], 1, 4_000, 2);
    let args = json!([[
        serialize_hex(&first),
        serialize_hex(&second),
        serialize_hex(&child)
    ]]);
    let before = pair
        .node
        .rpc("getrawmempool", &json!([false, true]))
        .expect("before wider package");
    assert!(
        matches!(pair.node.rpc("submitpackage", &args), Err(Error::Rpc { code: -25, ref message, .. }) if message.contains("at most one parent and one child"))
    );
    assert_eq!(
        pair.node
            .rpc("getrawmempool", &json!([false, true]))
            .expect("after wider refusal"),
        before
    );
}

#[test]
fn replacement_graph_merges_splits_and_conflict_cluster_boundary() {
    let mut pair = Pair::new();
    let parent = transaction(&[pair.coins[0].clone()], 2, 1_000, 2);
    let other = transaction(&[pair.coins[1].clone()], 1, 1_000, 2);
    pair.check(&parent, None);
    pair.check(&other, None);
    let child = transaction(&[output(&parent, 0)], 1, 2_000, 2);
    let sibling = transaction(&[output(&parent, 1)], 1, 2_000, 2);
    pair.check(&child, None);
    pair.check(&sibling, None);
    let merge = transaction(&[output(&parent, 0), output(&other, 0)], 1, 10_000, 2);
    pair.check(&merge, None);
    // Replacing the parent removes its descendants; the other parent survives
    // in a separate component. Both sides of the affected diagram matter.
    let split = transaction(&[pair.coins[0].clone()], 1, 25_000, 2);
    pair.check(&split, None);
    let crossing = transaction(&[pair.coins[0].clone()], 120, 35_000, 2);
    pair.check(&crossing, Some("replacement-failed"));
    for index in 10..111 {
        let original = transaction(&[pair.coins[index].clone()], 1, 2_000, 2);
        pair.check(&original, None);
    }
    let too_many = transaction(&pair.coins[10..111], 1, 1_000_000, 2);
    pair.check(&too_many, Some("too many potential replacements"));
    let boundary = transaction(&pair.coins[10..110], 1, 1_000_000, 2);
    pair.check(&boundary, None);
}

#[test]
fn truc_siblings_versions_sizes_and_ephemeral_fees() {
    let mut pair = Pair::new();
    let parent = transaction(&[pair.coins[0].clone()], 2, 1_000, 3);
    pair.check(&parent, None);
    let mixed = transaction(&[output(&parent, 0)], 1, 2_000, 2);
    pair.check(&mixed, Some("TRUC-violation"));
    let oversized_child = transaction(&[output(&parent, 0)], 30, 2_000, 3);
    pair.check(&oversized_child, Some("TRUC-violation"));
    let child = transaction(&[output(&parent, 0)], 1, 2_000, 3);
    pair.check(&child, None);
    let grandchild = transaction(&[output(&child, 0)], 1, 3_000, 3);
    pair.check(&grandchild, Some("TRUC-violation"));
    let weak_sibling = transaction(&[output(&parent, 1)], 1, 1_500, 3);
    pair.check(
        &weak_sibling,
        Some("insufficient fee (including sibling eviction)"),
    );
    let sibling = transaction(&[output(&parent, 1)], 1, 4_000, 3);
    pair.check(&sibling, None);
    let oversized = transaction(&[pair.coins[1].clone()], 300, 20_000, 3);
    pair.check(&oversized, Some("TRUC-violation"));
    let coin = pair.coins[2].clone();
    let dust = TxOut {
        value: Amount::from_sat(1),
        script_pubkey: coin.1.script_pubkey.clone(),
    };
    let change = TxOut {
        value: coin.1.value - Amount::from_sat(1_001),
        script_pubkey: coin.1.script_pubkey.clone(),
    };
    let paid_dust = signed(std::slice::from_ref(&coin), vec![change, dust.clone()], 3);
    pair.check(&paid_dust, Some("dust"));
    let zero_change = TxOut {
        value: coin.1.value - Amount::from_sat(1),
        script_pubkey: coin.1.script_pubkey.clone(),
    };
    let zero_dust = signed(&[coin], vec![zero_change, dust], 3);
    pair.check(&zero_dust, Some("min relay fee not met"));

    let legacy_parent = transaction(&[pair.coins[3].clone()], 1, 1_000, 2);
    pair.check(&legacy_parent, None);
    let mixed_child = transaction(&[output(&legacy_parent, 0)], 1, 2_000, 3);
    pair.check(&mixed_child, Some("TRUC-violation"));
    let other_parent = transaction(&[pair.coins[4].clone()], 1, 1_000, 3);
    pair.check(&other_parent, None);
    let two_parents = transaction(&[output(&parent, 0), output(&other_parent, 0)], 1, 5_000, 3);
    pair.check(&two_parents, Some("TRUC-violation"));
}

#[test]
fn package_structure_and_fail_fast_verdicts() {
    let mut pair = Pair::new();
    let parent = transaction(&[pair.coins[0].clone()], 2, 1_000, 2);
    let child = transaction(&[output(&parent, 0)], 1, 2_000, 2);
    let (core, node) = pair.preview(&[parent.clone(), child.clone()]);
    assert_eq!(
        core, node,
        "accepted package facts including effective fees"
    );
    assert_eq!(core[0]["allowed"], json!(true));
    assert_eq!(core[1]["allowed"], json!(true));
    let mut invalid_script = child.clone();
    invalid_script.input[0].script_sig = ScriptBuf::new();
    let (core, node) = pair.preview(&[parent.clone(), invalid_script]);
    assert_eq!(core[0], node[0], "earlier script success is retained");
    assert_eq!(core[0]["allowed"], json!(true));
    assert_eq!(core[1]["allowed"], json!(false));
    assert_eq!(node[1]["allowed"], json!(false));
    // Detailed consensus errors are intentionally generic in the candidate.
    // Value failures are prechecks, so other rows remain unfinished.
    let overspend_coin = pair.coins[5].clone();
    let overspend = signed(
        std::slice::from_ref(&overspend_coin),
        vec![TxOut {
            value: overspend_coin.1.value + Amount::from_sat(1),
            script_pubkey: overspend_coin.1.script_pubkey.clone(),
        }],
        2,
    );
    let (core, node) = pair.preview(&[parent.clone(), overspend]);
    assert!(core[0].get("allowed").is_none());
    assert_eq!(core[0], node[0]);
    assert_eq!(core[1]["allowed"], json!(false));
    assert_eq!(node[1]["allowed"], json!(false));
    for (txs, error) in [
        (vec![child, parent.clone()], "package-not-sorted"),
        (
            vec![parent.clone(), parent.clone()],
            "package-contains-duplicates",
        ),
        (
            vec![
                parent.clone(),
                transaction(&[pair.coins[0].clone()], 1, 3_000, 2),
            ],
            "conflict-in-package",
        ),
    ] {
        let (core, node) = pair.preview(&txs);
        assert_eq!(core, node);
        for row in core.as_array().expect("rows") {
            assert_eq!(row["package-error"], json!(error));
            assert!(row.get("allowed").is_none());
        }
    }
    let cheap = transaction(&[pair.coins[1].clone()], 1, 1, 2);
    let (core, node) = pair.preview(&[parent.clone(), cheap]);
    assert_eq!(core[0], node[0]);
    assert!(core[0].get("allowed").is_none());
    assert_eq!(core[1]["allowed"], node[1]["allowed"]);
    assert_eq!(core[1]["reject-reason"], node[1]["reject-reason"]);
    pair.check(&parent, None);
    let replacement = transaction(&[pair.coins[0].clone()], 1, 10_000, 2);
    let unrelated = transaction(&[pair.coins[2].clone()], 1, 1_000, 2);
    let (core, node) = pair.preview(&[replacement, unrelated]);
    assert_eq!(
        core[0]["reject-reason"],
        json!("bip125-replacement-disallowed")
    );
    assert_eq!(core[0]["reject-reason"], node[0]["reject-reason"]);
    assert_eq!(core[1], node[1]);
}

#[test]
fn cluster_limit_fee_increment_and_prioritisation_boundaries() {
    let mut pair = Pair::new();
    let parent = transaction(&[pair.coins[0].clone()], 64, 10_000, 2);
    pair.check(&parent, None);
    for index in 0..63 {
        // Different rates exercise many chunks in one maximal cluster.
        let fee = 1_000 + u64::try_from((index * 37) % 101).expect("bounded fee") * 50;
        let child = transaction(&[output(&parent, index)], 1, fee, 2);
        pair.check(&child, None);
    }
    let overflow = transaction(&[output(&parent, 63)], 1, 10_000, 2);
    pair.check(&overflow, Some("too-large-cluster"));

    // The replacement does not grow the full cluster. DER signature lengths
    // vary by a byte, so find the exact signed incremental-fee boundaries.
    for shortfall in [1, 0] {
        let candidate = (1_100..1_400)
            .map(|fee| (fee, transaction(&[output(&parent, 0)], 1, fee, 2)))
            .find(|(fee, tx)| *fee - 1_000 + shortfall == u64::try_from(tx.vsize()).expect("vsize"))
            .expect("signed one-satoshi boundary")
            .1;
        pair.check(&candidate, (shortfall == 1).then_some("insufficient fee"));
    }

    let original = transaction(&[pair.coins[1].clone()], 1, 2_000, 2);
    let replacement = transaction(&[pair.coins[1].clone()], 1, 2_500, 2);
    pair.check(&original, None);
    for process in [&mut pair.core, &mut pair.node] {
        assert_eq!(
            process
                .rpc(
                    "prioritisetransaction",
                    &json!([original.compute_txid().to_string(), 0, 2_000])
                )
                .expect("victim fee delta"),
            json!(true)
        );
    }
    pair.check(&replacement, Some("insufficient fee"));
    for process in [&mut pair.core, &mut pair.node] {
        assert_eq!(
            process
                .rpc(
                    "prioritisetransaction",
                    &json!([replacement.compute_txid().to_string(), 0, 3_000])
                )
                .expect("candidate fee delta"),
            json!(true)
        );
    }
    let (core, node) = pair.preview(core::slice::from_ref(&replacement));
    assert_eq!(
        core, node,
        "modified effective fee rate is captured on both nodes"
    );
    pair.check(&replacement, None);

    // Core PreChecks uses modified fees for the relay floor as well as RBF.
    let low_base_fee = transaction(&[pair.coins[3].clone()], 1, 1, 2);
    pair.check(&low_base_fee, Some("min relay fee not met"));
    for process in [&mut pair.core, &mut pair.node] {
        assert_eq!(
            process
                .rpc(
                    "prioritisetransaction",
                    &json!([low_base_fee.compute_txid().to_string(), 0, 1_000,])
                )
                .expect("pre-admission fee delta"),
            json!(true)
        );
    }
    pair.check(&low_base_fee, None);

    // At more than 1,000 vbytes a floor(fee*1000/vsize) comparison can hide
    // one excess satoshi. Core applies GetFee(vsize) to the caller's limit.
    let above_max = (1_800..2_000)
        .map(|fee| (fee, transaction(&[pair.coins[2].clone()], 50, fee, 2)))
        .find(|(fee, tx)| *fee == u64::try_from(tx.vsize()).expect("vsize") + 1)
        .expect("signed maximum-fee boundary")
        .1;
    for process in [&mut pair.core, &mut pair.node] {
        let before = process
            .rpc("getrawmempool", &json!([false, true]))
            .expect("before fee guard");
        let preview = process
            .rpc(
                "testmempoolaccept",
                &json!([[serialize_hex(&above_max)], 0.00001]),
            )
            .expect("maximum fee preview");
        assert_eq!(preview[0]["allowed"], json!(false), "{preview}");
        assert_eq!(preview[0]["reject-reason"], json!("max-fee-exceeded"));
        assert_eq!(
            process
                .rpc("getrawmempool", &json!([false, true]))
                .expect("after fee guard"),
            before
        );
    }
}
