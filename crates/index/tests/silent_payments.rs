#![cfg(feature = "silent-payments")]

use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin_hashes::{Hash as _, hash160};
use bitcoin_rs_index::silent_payments::{
    MAX_BODY_BYTES, MAX_PREVOUT_BYTES, TransactionTweak, TweakError, block_tweaks,
    transaction_tweak,
};
use bitcoin_rs_primitives::{Amount, Block, OutPoint, Script, Tx, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_utxo::{
    UtxoCoin,
    contract::{BlockSpends, BlockSpendsError, HistoryUnavailable},
};
use serde::Deserialize;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
struct Vector {
    comment: String,
    vin: Vec<Input>,
    outputs: Vec<String>,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    input_pub_key_sum: Option<String>,
    tweak: Option<String>,
}

#[derive(Deserialize)]
struct Input {
    txid: String,
    vout: u32,
    #[serde(rename = "scriptSig")]
    script_sig: String,
    txinwitness: String,
    prevout: Prevout,
}

#[derive(Deserialize)]
struct Prevout {
    #[serde(rename = "scriptPubKey")]
    script: HexScript,
}

#[derive(Deserialize)]
struct HexScript {
    hex: String,
}

fn vectors() -> Result<Vec<Vector>> {
    Ok(serde_json::from_str(include_str!(
        "data/bip352-public-scan.json"
    ))?)
}

fn vector_tx(vector: &Vector) -> Result<(Tx, Vec<Script>)> {
    let mut tx = Tx {
        version: 2,
        ..Tx::default()
    };
    let mut scripts = Vec::new();
    for vin in &vector.vin {
        let witness = if vin.txinwitness.is_empty() {
            Witness::new()
        } else {
            let bytes = Vec::from_hex(&vin.txinwitness)?;
            bitcoin::consensus::deserialize::<bitcoin::Witness>(&bytes)?
                .to_vec()
                .into()
        };
        tx.inputs.push(TxIn {
            previous_output: OutPoint::new(vin.txid.parse()?, vin.vout),
            script_sig: Vec::from_hex(&vin.script_sig)?.into(),
            witness,
            ..TxIn::default()
        });
        scripts.push(Vec::from_hex(&vin.prevout.script.hex)?.into());
    }
    for output in &vector.outputs {
        let mut script = vec![0x51, 0x20];
        script.extend_from_slice(&Vec::from_hex(output)?);
        tx.outputs.push(TxOut {
            script_pubkey: script.into(),
            value: Amount::from_sat(0),
        });
    }
    // No-output negative cases still exercise input extraction/aggregation,
    // rather than passing only because there was no candidate output.
    if tx.outputs.is_empty() {
        tx.outputs.push(TxOut {
            script_pubkey: [vec![0x51, 0x20], vec![0x11; 32]].concat().into(),
            ..TxOut::default()
        });
    }
    Ok((tx, scripts))
}

fn derive(tx: &Tx, scripts: &[Script]) -> Result<Option<TransactionTweak>> {
    Ok(transaction_tweak(
        tx,
        &scripts.iter().map(Some).collect::<Vec<_>>(),
        true,
    )?)
}

fn sample() -> Result<(Tx, Vec<Script>, TransactionTweak)> {
    let cases = vectors()?;
    let (tx, scripts) = vector_tx(&cases[0])?;
    let tweak = derive(&tx, &scripts)?.ok_or("sample is eligible")?;
    Ok((tx, scripts, tweak))
}

#[test]
fn pinned_bip352_public_vectors() -> Result {
    let cases = vectors()?;
    assert_eq!(cases.len(), 29);
    for case in cases {
        let (tx, scripts) = vector_tx(&case)?;
        let material = derive(&tx, &scripts)?;
        match case.expected.tweak {
            Some(expected) => {
                let material = material.ok_or_else(|| format!("{} was skipped", case.comment))?;
                assert_eq!(
                    material.tweak.to_lower_hex_string(),
                    expected,
                    "{}",
                    case.comment
                );
                assert_eq!(
                    Some(material.input_public_key_sum.to_lower_hex_string()),
                    case.expected.input_pub_key_sum,
                    "{}",
                    case.comment
                );
                assert_eq!(
                    material.outputs.len(),
                    case.outputs.len(),
                    "{}",
                    case.comment
                );
                for (candidate, output) in material.outputs.iter().zip(&case.outputs) {
                    assert_eq!(candidate.output_key.to_lower_hex_string(), *output);
                }
                assert_eq!(material.txid, tx.txid());
            }
            None => assert!(material.is_none(), "{}", case.comment),
        }
    }
    Ok(())
}

#[test]
fn missing_prevouts_never_become_empty_success() -> Result {
    let (mut tx, scripts, _) = sample()?;
    assert_eq!(
        transaction_tweak(&tx, &[], true),
        Err(TweakError::PrevoutCount)
    );
    assert_eq!(
        transaction_tweak(&tx, &[Some(&scripts[0]), None], true),
        Err(TweakError::Unavailable { input: 1 })
    );
    tx.outputs.clear();
    assert_eq!(
        transaction_tweak(&tx, &[Some(&scripts[0]), None], true),
        Err(TweakError::Unavailable { input: 1 })
    );
    assert!(derive(&tx, &scripts)?.is_none());
    Ok(())
}

fn p2sh_script(redeem_script: &[u8]) -> Script {
    let hash = hash160::Hash::hash(redeem_script);
    let mut script = Vec::with_capacity(23);
    script.extend_from_slice(&[0xa9, 0x14]);
    script.extend_from_slice(hash.as_byte_array());
    script.push(0x87);
    script.into()
}

#[test]
fn future_witness_excludes_transaction_but_malformed_program_does_not() -> Result {
    let (mut tx, mut scripts, initial) = sample()?;
    let mut last_p2sh_script = None;
    for len in [2_u8, 20, 32, 40] {
        for version in [0x52, 0x60] {
            let future_prog = [vec![version, len], vec![0x11; usize::from(len)]].concat();
            // Native future witness program in prevout scriptPubKey excludes the transaction
            // (matching BIP352 specification and Core GetSilentPaymentsPrevoutsSummary).
            scripts[1] = future_prog.clone().into();
            assert!(derive(&tx, &scripts)?.is_none());

            // P2SH-wrapped future witness: P2SH scriptPubKey is derived from HASH160(redeem_script).
            // It is not a witness program, so the input contributes no key (per BIP352 input list
            // and Core GetSilentPaymentsPrevoutsSummary), but does not disqualify other eligible inputs.
            tx.inputs[1].script_sig = [vec![len + 2], future_prog.clone()].concat().into();
            let p2sh = p2sh_script(&future_prog);
            scripts[1] = p2sh.clone();
            let p2sh_derived = derive(&tx, &scripts)?.ok_or("eligible via input 0")?;
            assert_eq!(p2sh_derived.outputs.len(), initial.outputs.len());
            last_p2sh_script = Some(p2sh);
        }
    }
    let p2sh_script = last_p2sh_script.ok_or("p2sh script")?;

    // A malformed native witness program in input 1 does not exclude the transaction,
    // and input 0 remains eligible:
    let mut malformed_scripts = scripts.clone();
    malformed_scripts[1] = vec![0x52, 0x20, 0x11].into();
    assert!(derive(&tx, &malformed_scripts)?.is_some());

    // When the only input is P2SH-wrapped future witness, the transaction has
    // no eligible keys and produces None.
    let single_input_tx = Tx {
        version: 2,
        inputs: vec![tx.inputs[1].clone()],
        outputs: tx.outputs.clone(),
        ..Tx::default()
    };
    assert!(derive(&single_input_tx, &[p2sh_script])?.is_none());
    Ok(())
}

#[test]
fn lowest_outpoint_includes_ineligible_inputs_and_uses_wire_order() -> Result {
    let (mut tx, mut scripts, _) = sample()?;
    tx.inputs.push(TxIn {
        previous_output: OutPoint::new(Txid::default(), 256),
        ..TxIn::default()
    });
    scripts.push(vec![0x51].into());
    let first = derive(&tx, &scripts)?.ok_or("eligible")?;
    tx.inputs[2].previous_output = OutPoint::new(Txid::default(), 1);
    let second = derive(&tx, &scripts)?.ok_or("eligible")?;
    assert_eq!(first.input_public_key_sum, second.input_public_key_sum);
    assert_ne!(first.input_hash, second.input_hash);
    tx.inputs.reverse();
    scripts.reverse();
    assert_eq!(
        derive(&tx, &scripts)?.ok_or("eligible")?.tweak,
        second.tweak
    );
    Ok(())
}

#[test]
fn taproot_annex_and_script_path_nums_are_handled_without_mutation() -> Result {
    let cases = vectors()?;
    let case = cases
        .iter()
        .find(|case| case.comment == "Single recipient: taproot only inputs with even y-values")
        .ok_or("taproot vector")?;
    let (mut tx, scripts) = vector_tx(case)?;
    let initial = derive(&tx, &scripts)?.ok_or("eligible")?;
    tx.inputs[0].witness.push(vec![0x50, 0x99]);
    assert_eq!(derive(&tx, &scripts)?.ok_or("annex")?.tweak, initial.tweak);
    let before = tx.clone();
    derive(&tx, &scripts)?;
    assert_eq!(tx, before);
    let mut control = vec![0xc0];
    control.extend_from_slice(&Vec::from_hex(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )?);
    tx.inputs[0].witness = vec![vec![0x51], control.clone(), vec![0x50]].into();
    let with_nums = derive(&tx, &scripts)?.ok_or("other input remains")?;
    assert_ne!(with_nums.input_public_key_sum, initial.input_public_key_sum);
    control[1] ^= 1;
    tx.inputs[0].witness = vec![vec![0x51], control, vec![0x50]].into();
    assert_eq!(
        derive(&tx, &scripts)?.ok_or("non-NUMS script path")?.tweak,
        initial.tweak
    );
    tx.inputs[0].witness = vec![vec![0x51], vec![]].into();
    assert!(derive(&tx, &scripts).is_err());
    Ok(())
}

#[test]
fn candidates_keep_indices_duplicates_and_dust_without_wallet_filtering() -> Result {
    let (mut tx, scripts, initial) = sample()?;
    let candidate = tx.outputs[0].clone();
    tx.outputs.insert(
        0,
        TxOut {
            script_pubkey: vec![0x51].into(),
            ..TxOut::default()
        },
    );
    tx.outputs.push(candidate);
    let material = derive(&tx, &scripts)?.ok_or("eligible")?;
    assert_eq!(material.tweak, initial.tweak);
    assert_eq!(material.outputs.len(), 2);
    assert_eq!(material.outputs[0].vout, 1);
    assert_eq!(material.outputs[1].vout, 2);
    assert_eq!(
        material.outputs[0].output_key,
        material.outputs[1].output_key
    );
    Ok(())
}

fn view(tx: Tx, scripts: &[Script]) -> BlockSpends {
    let coins = tx
        .inputs
        .iter()
        .zip(scripts)
        .map(|(input, script)| UtxoCoin {
            outpoint: input.previous_output,
            txout: TxOut {
                script_pubkey: script.clone(),
                ..TxOut::default()
            },
            coinbase: false,
            height: 1,
        })
        .collect();
    BlockSpends {
        block: Block {
            txs: vec![tx],
            ..Block::default()
        },
        spent: Ok(vec![coins]),
    }
}

#[test]
fn retained_block_projection_is_hash_scoped_and_deterministic() -> Result {
    let (tx, scripts, material) = sample()?;
    let mut view = view(tx, &scripts);
    let first = block_tweaks(&view, true)?;
    assert_eq!(first.transactions, vec![material]);
    assert_eq!(first.hash, view.block.block_hash());
    assert_eq!(block_tweaks(&view, true)?, first);
    view.block.header.nonce ^= 1;
    let replacement = block_tweaks(&view, true)?;
    assert_ne!(replacement.hash, first.hash);
    assert_eq!(replacement.transactions, first.transactions);
    // Replaying the original body has no cache/cursor to recover or invalidate.
    view.block.header.nonce ^= 1;
    assert_eq!(block_tweaks(&view, true)?, first);
    view.spent.as_mut().map_err(|_| "spent")?[0].reverse();
    assert!(matches!(
        block_tweaks(&view, true),
        Err(BlockSpendsError::Corrupt(_))
    ));
    Ok(())
}

#[test]
fn incomplete_history_is_typed_even_for_empty_blocks() -> Result {
    let mut view = BlockSpends {
        block: Block::default(),
        spent: Ok(vec![]),
    };
    assert_eq!(
        block_tweaks(&view, true)?.transactions,
        Vec::<TransactionTweak>::new()
    );
    assert_eq!(
        block_tweaks(&view, false)?.transactions,
        Vec::<TransactionTweak>::new()
    );
    for reason in [
        HistoryUnavailable::Missing,
        HistoryUnavailable::Pruned { below: 10 },
        HistoryUnavailable::Reserved { below: 10 },
        HistoryUnavailable::Shutdown,
    ] {
        view.spent = Err(reason);
        assert!(
            matches!(block_tweaks(&view, true), Err(BlockSpendsError::History(actual)) if actual == reason)
        );
        assert!(
            matches!(block_tweaks(&view, false), Err(BlockSpendsError::History(actual)) if actual == reason)
        );
    }
    view.spent = Ok(vec![vec![]]);
    assert!(matches!(
        block_tweaks(&view, true),
        Err(BlockSpendsError::Corrupt(_))
    ));
    Ok(())
}

#[test]
fn materialization_limits_fail_explicitly() -> Result {
    let (mut tx, mut scripts, _) = sample()?;
    scripts[0] = vec![0x51; MAX_PREVOUT_BYTES + 1].into();
    assert_eq!(
        derive(&tx, &scripts).err().map(|err| err.to_string()),
        Some(TweakError::ResourceLimit.to_string())
    );
    let oversized_view = view(tx.clone(), &scripts);
    assert!(matches!(
        block_tweaks(&oversized_view, true),
        Err(BlockSpendsError::ResourceLimit)
    ));
    scripts[0] = Script::new();
    tx.outputs[0].script_pubkey = vec![0x51; MAX_BODY_BYTES + 1].into();
    assert!(matches!(
        transaction_tweak(&tx, &[], true),
        Err(TweakError::ResourceLimit)
    ));
    assert!(matches!(
        block_tweaks(&view(tx, &scripts), true),
        Err(BlockSpendsError::ResourceLimit)
    ));
    Ok(())
}

#[test]
fn pre_activation_witness_v1_spends_produce_no_tweaks_without_failing() -> Result {
    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), 0),
            witness: Witness::new(), // Pre-activation consensus allowed empty witness on v1
            ..TxIn::default()
        }],
        outputs: vec![TxOut {
            script_pubkey: [vec![0x51, 0x20], vec![0x33; 32]].concat().into(),
            value: Amount::from_sat(1000),
        }],
        ..Tx::default()
    };
    let v1_prevout: Script = [vec![0x51, 0x20], vec![0x44; 32]].concat().into();
    let scripts = [Some(&v1_prevout)];

    // Pre-activation: caller specifies taproot_active = false.
    // Transaction produces no tweaks and block projection succeeds with empty tweaks.
    assert_eq!(transaction_tweak(&tx, &scripts, false)?, None);
    let view_inactive = view(tx.clone(), std::slice::from_ref(&v1_prevout));
    let tweaks_inactive = block_tweaks(&view_inactive, false)?;
    assert_eq!(tweaks_inactive.transactions.len(), 0);

    // Post-activation: caller specifies taproot_active = true.
    // The empty witness is now an invalid Taproot spend, failing as corrupt material.
    assert_eq!(
        transaction_tweak(&tx, &scripts, true),
        Err(TweakError::InvalidInput { input: 0 })
    );
    let view_active = view(tx, std::slice::from_ref(&v1_prevout));
    assert!(matches!(
        block_tweaks(&view_active, true),
        Err(BlockSpendsError::Corrupt(_))
    ));
    Ok(())
}
