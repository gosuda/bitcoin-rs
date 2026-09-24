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
