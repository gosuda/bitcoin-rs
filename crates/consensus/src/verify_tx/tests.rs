use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::{
    Amount, Block, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx, TxIn,
    TxOut, Txid, Witness, Wtxid, consensus_bytes, deserialize,
};
#[cfg(not(feature = "kernel"))]
use bitcoin_rs_primitives::{Sighash, SighashCache};
use bitcoin_rs_script::opcode::{OP_EQUAL, OP_HASH160};
use bitcoin_rs_script::push_data;
use bitcoin_rs_script::{VerifyFlags, push_int};

use super::{ScriptStageTimings, is_final_tx, verify_coinbase_script_sig_size, verify_transaction};
use crate::ValidationEngine;

fn parsed_block_for(txs: &[Tx], engine: ValidationEngine) -> crate::kernel::BlockScriptSource {
    let block = Block {
        header: Header {
            version: 1,
            bits: CompactTarget::from_consensus(0x2000_ffff),
            ..Header::default()
        },
        txs: txs.to_vec(),
    };
    crate::kernel::BlockParse::parse(&consensus_bytes(&block), engine)
        .unwrap_or_else(|error| panic!("synthetic block must parse: {error}"))
        .into_parts(txs)
        .unwrap_or_else(|error| panic!("synthetic facts: {error}"))
        .0
}

#[cfg(feature = "kernel")]
const TEST_ENGINE: ValidationEngine = ValidationEngine::Kernel;
#[cfg(not(feature = "kernel"))]
const TEST_ENGINE: ValidationEngine = ValidationEngine::Native;

fn test_block_parse(txs: &[Tx]) -> crate::kernel::BlockScriptSource {
    parsed_block_for(txs, TEST_ENGINE)
}

fn block_view_for(
    txs: &[Tx],
    resolved: Vec<Vec<Option<TxOut>>>,
) -> crate::block_view::BlockView<'_> {
    let mut view = crate::block_view::BlockView::from_facts(
        txs,
        crate::block_view::BlockFacts::from_txids(txs, txs.iter().map(Tx::txid).collect()),
    );
    view.set_resolved(resolved);
    view
}
use crate::{ConsensusError, ScriptEngine, UtxoView};

impl UtxoView for hashbrown::HashMap<OutPoint, TxOut> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.get(outpoint).cloned()
    }
}

#[test]
fn assume_valid_and_prepared_sigop_checks_follow_witness_activation()
-> Result<(), Box<dyn std::error::Error>> {
    let cost = crate::MAX_BLOCK_SIGOPS_COST + 1;
    let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[9; 32])), 0);
    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0xac; usize::try_from(cost)?]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::ZERO,
    };
    let prevouts = hashbrown::HashMap::from([(
        outpoint,
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes([vec![0x00, 0x20], vec![1; 32]].concat()),
        },
    )]);
    assert_eq!(
        super::verify_transaction_non_script(&tx, &prevouts, 0, 0, VerifyFlags::P2SH),
        Ok(()),
    );
    assert_eq!(
        super::verify_transaction_non_script(&tx, &prevouts, 0, 0, VerifyFlags::MANDATORY),
        Err(ConsensusError::SigopsLimit {
            cost,
            max: crate::MAX_BLOCK_SIGOPS_COST
        }),
    );
    let txs = vec![tx];
    let block = test_block_parse(&txs);
    let resolved = vec![vec![prevouts.get(&outpoint).cloned()]];
    let inactive = super::prepare_block_script_checks(
        &mut block_view_for(&txs, resolved.clone()),
        0,
        0,
        VerifyFlags::P2SH,
        &block,
        None,
    )?;
    assert!(inactive.prepared[0].post_error.is_none());
    assert!(super::verify_prepared_units(core::slice::from_ref(&inactive)).is_ok());
    let active = super::prepare_block_script_checks(
        &mut block_view_for(&txs, resolved),
        0,
        0,
        VerifyFlags::MANDATORY,
        &block,
        None,
    )?;
    assert_eq!(
        active.prepared[0].post_error,
        Some(ConsensusError::SigopsLimit {
            cost,
            max: crate::MAX_BLOCK_SIGOPS_COST,
        })
    );
    Ok(())
}

#[test]
fn coinbase_script_sig_size_bounds_are_enforced_without_prevout_lookup() {
    let utxos = hashbrown::HashMap::new();
    for len in [0usize, 1, 2, 50, 100, 101] {
        let tx = coinbase_transaction_with_script_sig_len(len);
        let expected = if (2..=100).contains(&len) {
            Ok(())
        } else {
            Err(ConsensusError::CoinbaseScriptSigSize { len })
        };
        assert_eq!(verify_coinbase_script_sig_size(&tx), expected, "len {len}");
        assert_eq!(
            verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY, TEST_ENGINE, None),
            expected,
            "len {len}"
        );
    }
}

#[test]
fn duplicate_non_coinbase_input_is_rejected() {
    let spent = outpoint(1);
    let tx = spend_tx(vec![spending_input(spent), spending_input(spent)], 50);
    assert_eq!(
        verify_transaction(
            &tx,
            &utxo_set([(spent, op1_txout(100))]),
            0,
            0,
            VerifyFlags::NONE,
            TEST_ENGINE,
            None
        ),
        Err(ConsensusError::DuplicateInput { input_index: 1 })
    );
}

#[test]
#[cfg(not(feature = "kernel"))]
fn verify_transaction_routes_taproot_spends_to_interpreter() {
    let tx = spend_tx(
        vec![
            true_spending_input(outpoint(5)),
            true_spending_input(outpoint(6)),
        ],
        50,
    );
    let taproot = TxOut {
        value: Amount::from_sat(50),
        script_pubkey: [vec![0x51, 0x20], vec![7; 32]].concat().into(),
    };
    assert_eq!(
        verify_transaction(
            &tx,
            &utxo_set([(outpoint(5), taproot), (outpoint(6), op1_txout(50))]),
            0,
            0,
            VerifyFlags::MANDATORY,
            TEST_ENGINE,
            None
        ),
        Err(ConsensusError::Script {
            input_index: 0,
            reason: "script failed: WITNESS_PROGRAM_WITNESS_EMPTY".to_owned(),
            engine: ScriptEngine::Native,
        })
    );
}

#[test]
#[cfg(not(feature = "kernel"))]
fn verify_transaction_accepts_valid_multi_input_taproot_keypath() {
    use secp256k1::{Keypair, Message, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
    use sha2::{Digest, Sha256};

    let secp = Secp256k1::new();
    let seeds = [1u8, 2u8];
    let mut keypairs = Vec::new();
    let mut prevouts = Vec::new();
    let mut outpoints = Vec::new();
    for (index, seed) in seeds.into_iter().enumerate() {
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap_or_else(|_| panic!("secret key"));
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        let tag = {
            let mut h = Sha256::new();
            h.update(b"TapTweak");
            h.finalize()
        };
        let mut tweak_hash = Sha256::new();
        tweak_hash.update(tag);
        tweak_hash.update(tag);
        tweak_hash.update(xonly.serialize());
        tweak_hash.update([0u8; 32]);
        let tweak_arr: [u8; 32] = tweak_hash.finalize().into();
        let tweak = Scalar::from_be_bytes(tweak_arr).unwrap_or_else(|_| panic!("tweak scalar"));
        let tweaked_keypair = keypair
            .add_xonly_tweak(&secp, &tweak)
            .unwrap_or_else(|e| panic!("tweak: {e}"));
        let (output_key, _) = XOnlyPublicKey::from_keypair(&tweaked_keypair);
        let outpoint = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[seed; 32])),
            vout: u32::try_from(index).unwrap_or_else(|_| panic!("vout")),
        };
        outpoints.push(outpoint);
        let mut script_pubkey = Vec::with_capacity(34);
        script_pubkey.push(0x51);
        script_pubkey.push(0x20);
        script_pubkey.extend_from_slice(&output_key.serialize());
        prevouts.push(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: script_pubkey.into(),
        });
        keypairs.push(tweaked_keypair);
    }

    let mut tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: outpoints
            .iter()
            .copied()
            .map(|previous_output| TxIn {
                previous_output,
                sequence: Sequence::MAX,
                ..TxIn::default()
            })
            .collect(),
        outputs: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: push_int(1).into(),
        }],
    };

    for (input_idx, keypair) in keypairs.iter().enumerate() {
        let cache = SighashCache::new(&tx);
        let sighash = cache
            .taproot_signature_hash(input_idx, &prevouts, None, None, Sighash::Default)
            .unwrap_or_else(|_| panic!("taproot sighash"));
        let message = Message::from_digest(sighash.to_le_bytes());
        let signature = secp.sign_schnorr(&message, keypair);
        tx.inputs[input_idx].witness = vec![signature.serialize().to_vec()].into();
    }

    let mut utxos = hashbrown::HashMap::new();
    for (outpoint, prevout) in outpoints.into_iter().zip(prevouts) {
        utxos.insert(outpoint, prevout);
    }

    assert_eq!(
        verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY, TEST_ENGINE, None),
        Ok(())
    );
}

#[test]
#[cfg(feature = "kernel")]
fn kernel_scripts_preserve_verdicts_and_non_script_bypass() {
    for (seed, rhs, accepted) in [(7, 7, true), (8, 8, false), (9, 8, false)] {
        let outpoint = outpoint(seed);
        let mut input = spending_input(outpoint);
        input.script_sig = [push_int(7), push_int(rhs)].concat().into();
        let mut tx = spend_tx(vec![input], 50);
        tx.version = 1;
        let utxos = utxo_set([(outpoint, op_equal_txout(100))]);
        assert_eq!(
            super::verify_transaction_non_script(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY),
            Ok(()),
            "non-script seed {seed}"
        );
        let verdict =
            verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY, TEST_ENGINE, None);
        if accepted {
            assert_eq!(verdict, Ok(()), "seed {seed}");
        } else {
            let Err(ConsensusError::Script {
                input_index,
                reason,
                engine,
            }) = verdict
            else {
                panic!("seed {seed}: expected a kernel script rejection");
            };
            assert_eq!(input_index, 0, "seed {seed}");
            assert_eq!(engine, ScriptEngine::Kernel, "seed {seed}");
            assert!(
                reason
                    .strip_prefix("kernel script verification failed: ")
                    .is_some_and(|verdict| !verdict.is_empty()),
                "seed {seed}: {reason}"
            );
        }
    }
}

#[test]
fn locktime_finality_uses_the_height_and_the_caller_supplied_cutoff() {
    const TIMESTAMP: u32 = 500_000_100;
    let cases: [(u32, u32, u32, bool); 8] = [
        (0, 0, 0, true),
        (200, 100, 0, false),
        (200, 200, 0, false),
        (200, 201, 0, true),
        (TIMESTAMP, 1, TIMESTAMP - 1, false),
        (TIMESTAMP, 1, TIMESTAMP, false),
        (TIMESTAMP, 1, TIMESTAMP + 1, true),
        (TIMESTAMP, u32::MAX, 0, false),
    ];
    let utxos = hashbrown::HashMap::new();
    for (lock_time, height, cutoff, is_final) in cases {
        let mut tx = spend_tx(vec![spending_input(outpoint(1))], 1_000);
        tx.lock_time = LockTime::from_consensus(lock_time);
        tx.inputs[0].sequence = Sequence::from_consensus(0);
        let label = format!("locktime {lock_time} height {height} cutoff {cutoff}");
        assert_eq!(is_final_tx(&tx, height, cutoff), is_final, "{label}");

        let verdict = verify_transaction(
            &tx,
            &utxos,
            height,
            cutoff,
            VerifyFlags::MANDATORY,
            TEST_ENGINE,
            None,
        );
        if is_final {
            assert_eq!(
                verdict,
                Err(ConsensusError::MissingPrevout { input_index: 0 }),
                "{label}"
            );
        } else {
            assert!(
                matches!(verdict, Err(ConsensusError::Bip { bip: "BIP113", .. })),
                "{label}: {verdict:?}"
            );
        }

        tx.inputs[0].sequence = Sequence::MAX;
        assert!(is_final_tx(&tx, height, cutoff), "{label} final sequence");
    }
}

fn spending_input(outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: push_int(1).into(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

#[test]
fn prepared_units_keep_block_order_slices_and_flags() {
    let clean_txs = vec![
        coinbase_transaction_with_script_sig_len(2),
        spend_tx(vec![true_spending_input(outpoint(11))], 50),
        spend_tx(vec![true_spending_input(outpoint(12))], 50),
    ];
    let clean_block = test_block_parse(&clean_txs);
    let clean_resolved = vec![
        Vec::new(),
        vec![Some(op1_txout(50))],
        vec![Some(op1_txout(50))],
    ];
    let late_txs = vec![
        coinbase_transaction_with_script_sig_len(2),
        spend_tx(vec![true_spending_input(outpoint(1))], 50),
        spend_tx(vec![mismatch_input(outpoint(2))], 50),
    ];
    let late_block = test_block_parse(&late_txs);
    let late_resolved = vec![
        Vec::new(),
        vec![Some(op1_txout(50))],
        vec![Some(op_equal_txout(50))],
    ];
    let early_txs = vec![
        coinbase_transaction_with_script_sig_len(2),
        spend_tx(vec![mismatch_input(outpoint(3))], 50),
    ];
    let early_block = test_block_parse(&early_txs);
    let early_resolved = vec![Vec::new(), vec![Some(op_equal_txout(50))]];

    let redeem_script = [0_u8];
    let redeem_hash = bitcoin::hashes::hash160::Hash::hash(&redeem_script);
    let p2sh_txs = vec![
        coinbase_transaction_with_script_sig_len(2),
        spend_tx(
            vec![TxIn {
                previous_output: outpoint(10),
                script_sig: push_data(&redeem_script).into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            50,
        ),
    ];
    let p2sh_block = test_block_parse(&p2sh_txs);
    let p2sh_resolved = vec![
        Vec::new(),
        vec![Some(TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::from_bytes(
                [
                    vec![OP_HASH160],
                    push_data(&redeem_hash.to_byte_array()),
                    vec![OP_EQUAL],
                ]
                .concat(),
            ),
        })],
    ];

    let clean = |flags| prepared_unit(&clean_txs, clean_resolved.clone(), &clean_block, flags);
    let late = |flags| prepared_unit(&late_txs, late_resolved.clone(), &late_block, flags);
    let early = |flags| prepared_unit(&early_txs, early_resolved.clone(), &early_block, flags);
    let p2sh = |flags| prepared_unit(&p2sh_txs, p2sh_resolved.clone(), &p2sh_block, flags);
    let failing_unit = |units: &[super::BlockScriptChecks<'_>]| {
        super::verify_prepared_units(units)
            .err()
            .map(|failure| failure.unit)
    };

    let mandatory = VerifyFlags::MANDATORY;
    assert_eq!(
        failing_unit(&[late(mandatory), clean(mandatory), early(mandatory)]),
        Some(0),
        "block order must beat position within a block"
    );
    assert_eq!(
        failing_unit(&[clean(mandatory), clean(mandatory), early(mandatory)]),
        Some(2),
        "misaligned result offsets would blame a clean unit"
    );
    assert_eq!(
        failing_unit(&[p2sh(mandatory)]),
        Some(0),
        "the P2SH fixture must fail under the strict flag set"
    );
    assert_eq!(
        failing_unit(&[clean(mandatory), p2sh(VerifyFlags::NONE)]),
        None,
        "each unit must be checked under the flags bound to it"
    );
}

#[test]
fn a_batched_unit_matches_the_single_block_path() {
    let txs = vec![
        coinbase_transaction_with_script_sig_len(2),
        spend_tx(vec![mismatch_input(outpoint(7))], 50),
    ];
    let block = test_block_parse(&txs);
    let resolved = vec![Vec::new(), vec![Some(op_equal_txout(50))]];

    let single = super::verify_block_input_scripts(
        &mut block_view_for(&txs, resolved.clone()),
        0,
        0,
        VerifyFlags::MANDATORY,
        &mut ScriptStageTimings::default(),
        &block,
        None,
    );
    let units = [prepared_unit(
        &txs,
        resolved,
        &block,
        VerifyFlags::MANDATORY,
    )];
    let batched = super::verify_prepared_units(&units);

    match (single, batched) {
        (Err(single_error), Err(failure)) => assert_eq!(
            format!("{single_error}"),
            format!("{}", failure.error),
            "batched and single-block verdicts must be identical"
        ),
        (single, batched) => panic!(
            "both paths must reject this block: single={:?} batched_ok={}",
            single.err(),
            batched.is_ok()
        ),
    }
}

fn prepared_unit<'b>(
    txs: &'b [Tx],
    resolved: Vec<Vec<Option<TxOut>>>,
    block: &'b crate::kernel::BlockScriptSource,
    flags: VerifyFlags,
) -> super::BlockScriptChecks<'b> {
    let mut view = block_view_for(txs, resolved);
    match super::prepare_block_script_checks(&mut view, 0, 0, flags, block, None) {
        Ok(unit) => unit,
        Err(error) => panic!("test fixture prevout matrix is malformed: {error}"),
    }
}

fn true_spending_input(outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: outpoint,
        sequence: Sequence::MAX,
        ..TxIn::default()
    }
}

fn utxo_set<const N: usize>(
    entries: [(OutPoint, TxOut); N],
) -> hashbrown::HashMap<OutPoint, TxOut> {
    entries.into_iter().collect()
}

fn coinbase_transaction_with_script_sig_len(len: usize) -> Tx {
    Tx {
        version: 1,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: vec![1; len].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::new(),
        }],
    }
}

fn op1_txout(value: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: push_int(1).into(),
    }
}

fn op_equal_txout(value: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: vec![OP_EQUAL].into(),
    }
}

#[test]
fn script_cache_hit_skips_scripts_for_exact_flags_only() -> Result<(), Box<dyn std::error::Error>> {
    use crate::script_cache::{ScriptExecutionCache, WindowCacheTakes};

    let txs = vec![
        coinbase_transaction_with_script_sig_len(2),
        spend_tx(vec![mismatch_input(outpoint(3))], 50),
    ];
    let resolved = vec![vec![], vec![Some(op_equal_txout(50))]];
    let flags = VerifyFlags::MANDATORY;
    let wtxid = txs[1].wtxid();

    let parsed = test_block_parse(&txs);
    let mut view = block_view_for(&txs, resolved.clone());
    let miss = super::prepare_block_script_checks(&mut view, 0, 0, flags, &parsed, None)?;
    assert!(super::verify_prepared_units(core::slice::from_ref(&miss)).is_err());

    let cache = ScriptExecutionCache::new();
    cache.insert(wtxid, flags);
    let parsed = test_block_parse(&txs);
    let mut view = block_view_for(&txs, resolved.clone());
    let _ = view.witness_ids();
    let mut takes = WindowCacheTakes::new(&cache);
    let hit =
        super::prepare_block_script_checks(&mut view, 0, 0, flags, &parsed, Some(&mut takes))?;
    assert!(super::verify_prepared_units(core::slice::from_ref(&hit)).is_ok());

    let parsed = test_block_parse(&txs);
    let mut view = block_view_for(&txs, resolved.clone());
    let replay =
        super::prepare_block_script_checks(&mut view, 0, 0, flags, &parsed, Some(&mut takes))?;
    assert!(super::verify_prepared_units(core::slice::from_ref(&replay)).is_err());

    let other = ScriptExecutionCache::new();
    other.insert(wtxid, VerifyFlags::P2SH);
    let mut other_takes = WindowCacheTakes::new(&other);
    let parsed = test_block_parse(&txs);
    let mut view = block_view_for(&txs, resolved);
    let wrong = super::prepare_block_script_checks(
        &mut view,
        0,
        0,
        flags,
        &parsed,
        Some(&mut other_takes),
    )?;
    assert!(super::verify_prepared_units(core::slice::from_ref(&wrong)).is_err());
    Ok(())
}

#[test]
fn prepared_error_selection_keeps_pre_script_post_order() {
    let resolved = vec![vec![], vec![Some(op1_txout(50))]];
    let balanced_txs = vec![
        coinbase_transaction_with_script_sig_len(2),
        spend_tx(vec![true_spending_input(outpoint(1))], 50),
    ];
    let overdraft_txs = vec![
        coinbase_transaction_with_script_sig_len(2),
        spend_tx(vec![true_spending_input(outpoint(1))], 60),
    ];
    let parsed = test_block_parse(&overdraft_txs);

    let mut view = block_view_for(&overdraft_txs, resolved.clone());
    let overdraft =
        super::prepare_block_script_checks(&mut view, 0, 0, VerifyFlags::NONE, &parsed, None)
            .unwrap_or_else(|error| panic!("fixture prevouts resolve: {error}"));
    assert!(overdraft.prepared[1].script_state.is_some());
    let verdict = super::verify_prepared_units(core::slice::from_ref(&overdraft));
    assert!(
        matches!(
            verdict,
            Err(super::BatchScriptFailure {
                unit: 0,
                error: ConsensusError::InputsLessThanOutputs {
                    input_value: 50,
                    output_value: 60,
                },
            })
        ),
        "actual: {verdict:?}"
    );

    let mut view = block_view_for(&balanced_txs, resolved);
    let balanced =
        super::prepare_block_script_checks(&mut view, 0, 0, VerifyFlags::NONE, &parsed, None)
            .unwrap_or_else(|error| panic!("fixture prevouts resolve: {error}"));
    assert!(super::verify_prepared_units(core::slice::from_ref(&balanced)).is_ok());
}

fn mismatch_input(outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: [push_int(7), push_int(8)].concat().into(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

fn witnessed_mismatch_input(outpoint: OutPoint) -> TxIn {
    TxIn {
        witness: Witness::from_stack(vec![vec![0x51]]),
        ..mismatch_input(outpoint)
    }
}

#[test]
fn script_cache_hit_uses_derived_witness_ids_for_witness_bearing_bodies()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::script_cache::{ScriptExecutionCache, WindowCacheTakes};

    let txs = vec![
        coinbase_transaction_with_script_sig_len(2),
        spend_tx(vec![witnessed_mismatch_input(outpoint(3))], 50),
    ];
    let resolved = vec![vec![], vec![Some(op_equal_txout(50))]];
    let flags = VerifyFlags::MANDATORY;
    let wtxid = txs[1].wtxid();
    assert_ne!(
        wtxid,
        Wtxid(txs[1].txid().0),
        "the fixture must separate wtxid from txid"
    );

    let cache = ScriptExecutionCache::new();
    cache.insert(wtxid, flags);
    let parsed = test_block_parse(&txs);
    let mut view = block_view_for(&txs, resolved);
    assert!(
        view.facts().wtxids().is_none(),
        "the fixture must carry no precomputed witness ids"
    );
    let mut takes = WindowCacheTakes::new(&cache);
    let hit =
        super::prepare_block_script_checks(&mut view, 0, 0, flags, &parsed, Some(&mut takes))?;
    assert!(super::verify_prepared_units(core::slice::from_ref(&hit)).is_ok());
    Ok(())
}

fn spend_tx(inputs: Vec<TxIn>, output_value: u64) -> Tx {
    Tx {
        version: 1,
        lock_time: LockTime::ZERO,
        inputs,
        outputs: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: push_int(1).into(),
        }],
    }
}

type OrderingCase = (&'static str, Vec<Tx>, Vec<Vec<Option<TxOut>>>, Expect);

enum Expect {
    Accepted,
    ScriptAtFirstInput,
    Exact(ConsensusError),
}

fn outpoint(seed: u8) -> OutPoint {
    OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[seed; 32])),
        vout: 0,
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one case table, not one case per test"
)]
fn block_script_verification_reports_the_earliest_block_ordered_error() {
    let coinbase = coinbase_transaction_with_script_sig_len(2);

    let mut parallel_txs = vec![
        coinbase.clone(),
        spend_tx(vec![mismatch_input(outpoint(1))], 50),
    ];
    let mut parallel_resolved = vec![Vec::new(), vec![Some(op_equal_txout(100))]];
    for seed in 2..=u8::try_from(super::MIN_PARALLEL_SCRIPT_CHECKS).unwrap_or(u8::MAX) {
        parallel_txs.push(spend_tx(vec![mismatch_input(outpoint(seed))], 50));
        parallel_resolved.push(vec![Some(op_equal_txout(100))]);
    }

    let produced = spend_tx(vec![true_spending_input(outpoint(1))], 100);
    let produced_out = OutPoint {
        txid: produced.txid(),
        vout: 0,
    };
    let produced_output = produced.outputs[0].clone();
    let bad_producer = spend_tx(vec![mismatch_input(outpoint(1))], 100);
    let bad_producer_out = OutPoint {
        txid: bad_producer.txid(),
        vout: 0,
    };
    let bad_producer_output = bad_producer.outputs[0].clone();

    let cases: [OrderingCase; 7] = [
        (
            "a prevout matrix that does not cover the block",
            vec![coinbase.clone()],
            Vec::new(),
            Expect::Exact(ConsensusError::PrevoutMatrixSize {
                expected: 1,
                actual: 0,
            }),
        ),
        (
            "an earlier script error beats a later missing prevout",
            vec![
                coinbase.clone(),
                spend_tx(vec![mismatch_input(outpoint(1))], 50),
                spend_tx(vec![true_spending_input(outpoint(2))], 50),
            ],
            vec![Vec::new(), vec![Some(op_equal_txout(100))], vec![None]],
            Expect::ScriptAtFirstInput,
        ),
        (
            "a script error beats the same transaction's value error",
            vec![
                coinbase.clone(),
                spend_tx(vec![mismatch_input(outpoint(1))], 100),
            ],
            vec![Vec::new(), vec![Some(op_equal_txout(50))]],
            Expect::ScriptAtFirstInput,
        ),
        (
            "a later pre-error does not outrank an earlier post-error",
            vec![
                coinbase.clone(),
                spend_tx(vec![true_spending_input(outpoint(1))], 100),
                spend_tx(
                    vec![
                        true_spending_input(outpoint(2)),
                        true_spending_input(outpoint(2)),
                    ],
                    50,
                ),
            ],
            vec![
                Vec::new(),
                vec![Some(op1_txout(50))],
                vec![Some(op1_txout(50)), Some(op1_txout(50))],
            ],
            Expect::Exact(ConsensusError::InputsLessThanOutputs {
                input_value: 50,
                output_value: 100,
            }),
        ),
        (
            "the parallel fan-out still reports the first failure",
            parallel_txs,
            parallel_resolved,
            Expect::ScriptAtFirstInput,
        ),
        (
            "a same-block spend of a valid producing transaction",
            vec![
                coinbase.clone(),
                produced,
                spend_tx(vec![true_spending_input(produced_out)], 90),
            ],
            vec![
                Vec::new(),
                vec![Some(op1_txout(100))],
                vec![Some(produced_output)],
            ],
            Expect::Accepted,
        ),
        (
            "a same-block spend surfaces the producing transaction's error",
            vec![
                coinbase,
                bad_producer,
                spend_tx(vec![true_spending_input(bad_producer_out)], 90),
            ],
            vec![
                Vec::new(),
                vec![Some(op_equal_txout(100))],
                vec![Some(bad_producer_output)],
            ],
            Expect::ScriptAtFirstInput,
        ),
    ];

    for (label, txs, resolved, expect) in cases {
        let result = super::verify_block_input_scripts(
            &mut block_view_for(&txs, resolved),
            0,
            0,
            VerifyFlags::MANDATORY,
            &mut ScriptStageTimings::default(),
            &test_block_parse(&txs),
            None,
        );
        match expect {
            Expect::Accepted => assert_eq!(result, Ok(()), "{label}"),
            Expect::ScriptAtFirstInput => assert!(
                matches!(result, Err(ConsensusError::Script { input_index: 0, .. })),
                "{label}: {result:?}"
            ),
            Expect::Exact(error) => assert_eq!(result, Err(error), "{label}"),
        }
    }
}

struct TaprootScriptPathFixture {
    tx: Tx,
    prevouts: Vec<TxOut>,
    flags: VerifyFlags,
    height: u32,
}

#[derive(serde::Deserialize)]
struct TaprootScriptPathFile {
    tx_hex: String,
    prevouts: Vec<TaprootScriptPathPrevout>,
    flags: String,
    height: u32,
}

#[derive(serde::Deserialize)]
struct TaprootScriptPathPrevout {
    script_hex: String,
    amount_sat: u64,
}

fn decode_hex(hex: &str) -> Vec<u8> {
    bitcoin::hex::FromHex::from_hex(hex).unwrap_or_else(|error| panic!("bad hex: {error}"))
}

fn load_taproot_scriptpath_fixture() -> TaprootScriptPathFixture {
    let json = include_str!("../../tests/vectors/scripts/taproot_scriptpath_spend.json");
    let file: TaprootScriptPathFile = sonic_rs::from_str(json)
        .unwrap_or_else(|error| panic!("taproot scriptpath fixture parses: {error}"));
    let tx: Tx = deserialize(&decode_hex(&file.tx_hex))
        .unwrap_or_else(|error| panic!("taproot scriptpath tx hex decodes: {error}"));
    assert_eq!(
        file.prevouts.len(),
        tx.inputs.len(),
        "taproot scriptpath fixture: prevout count must match input count"
    );
    let prevouts = file
        .prevouts
        .iter()
        .map(|prevout| TxOut {
            value: Amount::from_sat(prevout.amount_sat),
            script_pubkey: decode_hex(&prevout.script_hex).into(),
        })
        .collect::<Vec<_>>();
    let flags = VerifyFlags::from_core_names(&file.flags)
        .unwrap_or_else(|error| panic!("taproot scriptpath flags parse: {error}"));
    TaprootScriptPathFixture {
        tx,
        prevouts,
        flags,
        height: file.height,
    }
}

#[test]
fn verify_transaction_accepts_the_mainnet_taproot_scriptpath_spend() {
    let fixture = load_taproot_scriptpath_fixture();
    let mut utxos = hashbrown::HashMap::new();
    for (index, prevout) in fixture.prevouts.iter().enumerate() {
        utxos.insert(fixture.tx.inputs[index].previous_output, prevout.clone());
    }
    assert_eq!(
        verify_transaction(
            &fixture.tx,
            &utxos,
            fixture.height,
            0,
            fixture.flags,
            TEST_ENGINE,
            None
        ),
        Ok(())
    );
}

#[test]
fn coinbase_maturity_boundaries() {
    let error = match super::check_coinbase_maturity(true, 10, 109) {
        Ok(()) => panic!("depth 99 must reject"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        ConsensusError::Bip {
            bip: "COINBASE_MATURITY",
            ..
        }
    ));
    assert_eq!(super::check_coinbase_maturity(true, 10, 110), Ok(()));
    assert_eq!(super::check_coinbase_maturity(false, 10, 10), Ok(()));
}
