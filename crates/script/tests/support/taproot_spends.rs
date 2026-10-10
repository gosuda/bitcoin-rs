//! Independently signed BIP341 spends shared by native and process regressions.
//! Fixed fixture keys never enter production code or a wallet.

use bitcoin::hashes::Hash as _;
use bitcoin::key::TapTweak as _;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute, transaction,
};

pub(crate) struct Case {
    pub(crate) name: String,
    pub(crate) tx: Transaction,
    pub(crate) accepted: bool,
}

fn tree() -> (Keypair, TaprootSpendInfo, ScriptBuf) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[37; 32]).expect("fixed fixture key");
    let key = Keypair::from_secret_key(&secp, &secret);
    let leaf = ScriptBuf::from_bytes(vec![0x51]);
    let tree = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .expect("one public leaf")
        .finalize(&secp, key.x_only_public_key().0)
        .expect("complete tree");
    (key, tree, leaf)
}

pub(crate) fn funding_script() -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(tree().1.output_key())
}

fn template(outpoint: OutPoint, prevout: &TxOut) -> Transaction {
    Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(prevout.value.to_sat() - 10_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([42; 20])),
        }],
    }
}

/// Every signature message, tweak, signature and control block is produced by
/// rust-bitcoin/secp256k1, independently of bitcoin-rs's native sighash code.
pub(crate) fn cases(outpoint: OutPoint, prevout: &TxOut) -> Vec<Case> {
    let secp = Secp256k1::new();
    let (key, tree, leaf) = tree();
    let tweaked = key.tap_tweak(&secp, tree.merkle_root());
    let control = tree
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .expect("known leaf");
    let mut cases = Vec::new();
    for annex in [None, Some(vec![0x50, 0xab, 0xcd])] {
        let suffix = if annex.is_some() { "-annex" } else { "" };
        for (mode, hash_byte) in [
            (TapSighashType::Default, 0x00),
            (TapSighashType::All, 0x01),
            (TapSighashType::None, 0x02),
            (TapSighashType::Single, 0x03),
            (TapSighashType::AllPlusAnyoneCanPay, 0x81),
            (TapSighashType::NonePlusAnyoneCanPay, 0x82),
            (TapSighashType::SinglePlusAnyoneCanPay, 0x83),
        ] {
            let mut tx = template(outpoint, prevout);
            let hash = SighashCache::new(&tx)
                .taproot_signature_hash(
                    0,
                    &Prevouts::All(std::slice::from_ref(prevout)),
                    annex
                        .as_deref()
                        .map(|bytes| Annex::new(bytes).expect("annex")),
                    None,
                    mode,
                )
                .expect("independent BIP341 digest");
            let sig = secp.sign_schnorr_no_aux_rand(
                &Message::from_digest(hash.to_byte_array()),
                tweaked.as_keypair(),
            );
            let mut bytes = sig.serialize().to_vec();
            if mode != TapSighashType::Default {
                bytes.push(hash_byte);
            }
            let mut witness = vec![bytes];
            if let Some(annex) = &annex {
                witness.push(annex.clone());
            }
            tx.input[0].witness = Witness::from_slice(&witness);
            cases.push(Case {
                name: format!("key-{mode:?}{suffix}"),
                tx: tx.clone(),
                accepted: true,
            });
            if mode == TapSighashType::Default {
                let mut malformed = tx.clone();
                for extra in [0x00, 0x04, 0x80, 0x84, 0xff] {
                    let mut wit = witness.clone();
                    wit[0].push(extra);
                    malformed.input[0].witness = Witness::from_slice(&wit);
                    cases.push(Case {
                        name: format!("key-suffix-{extra:02x}{suffix}"),
                        tx: malformed.clone(),
                        accepted: false,
                    });
                }
                for size in [0, 63, 66] {
                    let mut wit = witness.clone();
                    wit[0].resize(size, 0);
                    malformed.input[0].witness = Witness::from_slice(&wit);
                    cases.push(Case {
                        name: format!("key-size-{size}{suffix}"),
                        tx: malformed.clone(),
                        accepted: false,
                    });
                }
                add_script_sig_cases(&mut cases, tx, "key", suffix);
            }
        }
        let mut tx = template(outpoint, prevout);
        let mut witness = vec![leaf.to_bytes(), control.serialize()];
        if let Some(annex) = &annex {
            witness.push(annex.clone());
        }
        tx.input[0].witness = Witness::from_slice(&witness);
        cases.push(Case {
            name: format!("script-true{suffix}"),
            tx: tx.clone(),
            accepted: true,
        });
        add_script_sig_cases(&mut cases, tx, "script", suffix);
    }
    cases
}

fn add_script_sig_cases(cases: &mut Vec<Case>, mut tx: Transaction, path: &str, suffix: &str) {
    for (script, name) in [(0x00, "nonempty"), (0x6a, "opreturn")] {
        tx.input[0].script_sig = ScriptBuf::from_bytes(vec![script]);
        cases.push(Case {
            name: format!("{path}-{name}-scriptSig{suffix}"),
            tx: tx.clone(),
            accepted: false,
        });
    }
}

fn success_tree() -> (TaprootSpendInfo, Vec<ScriptBuf>) {
    let secp = Secp256k1::new();
    let key = tree().0;
    let mut large_push = vec![0x4d, 0x09, 0x02];
    large_push.extend([0; 521]);
    large_push.push(0x50);
    let scripts = vec![
        vec![0x50],
        vec![0x6a, 0x50],
        vec![0x50, 0x4c],
        vec![0x4c, 0x50],
        vec![0x01, 0x50, 0x75, 0x00],
        vec![0x51],
        large_push,
        vec![0x4c],
    ]
    .into_iter()
    .map(ScriptBuf::from_bytes)
    .collect::<Vec<_>>();
    let mut builder = TaprootBuilder::new();
    for script in &scripts {
        builder = builder
            .add_leaf(3, script.clone())
            .expect("balanced eight-leaf tree");
    }
    (
        builder
            .finalize(&secp, key.x_only_public_key().0)
            .expect("complete tree"),
        scripts,
    )
}

pub(crate) fn success_funding_script() -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(success_tree().0.output_key())
}

pub(crate) fn success_cases(outpoint: OutPoint, prevout: &TxOut) -> Vec<Case> {
    let (tree, scripts) = success_tree();
    let mut cases = Vec::new();
    for annex in [false, true] {
        for (name, leaf, stack, accepted) in [
            ("success-empty", 0, vec![], true),
            ("success-false", 0, vec![vec![]], true),
            ("success-dirty", 0, vec![vec![1], vec![1]], true),
            ("success-large-element", 0, vec![vec![0; 521]], true),
            ("success-large-stack", 0, vec![vec![]; 1001], true),
            ("success-after-return", 1, vec![], true),
            ("success-before-malformed", 2, vec![], true),
            ("malformed-before-success-byte", 3, vec![], false),
            ("pushed-success-byte", 4, vec![], false),
            ("ordinary-large-element", 5, vec![vec![0; 521]], false),
            ("ordinary-large-stack", 5, vec![vec![]; 1001], false),
            ("success-after-large-push", 6, vec![], true),
            ("malformed-no-success", 7, vec![], false),
            ("success-bad-control", 0, vec![], false),
        ] {
            let script = &scripts[leaf];
            let mut control = tree
                .control_block(&(script.clone(), LeafVersion::TapScript))
                .expect("known leaf")
                .serialize();
            if name == "success-bad-control" {
                control[1] ^= 1;
            }
            let mut witness = stack;
            witness.push(script.to_bytes());
            witness.push(control);
            if annex {
                witness.push(vec![0x50, 0xab]);
            }
            let mut tx = template(outpoint, prevout);
            tx.input[0].witness = Witness::from_slice(&witness);
            cases.push(Case {
                name: format!("{name}{}", if annex { "-annex" } else { "" }),
                tx,
                accepted,
            });
        }
    }
    cases
}
