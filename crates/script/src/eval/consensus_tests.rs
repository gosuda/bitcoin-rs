#![expect(
    clippy::expect_used,
    reason = "independent-oracle fixture construction"
)]

use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{
    Amount as BitcoinAmount, OutPoint as BitcoinOutPoint, ScriptBuf, Sequence as BitcoinSequence,
    Transaction, TxIn as BitcoinTxIn, TxOut as BitcoinTxOut, Witness as BitcoinWitness, absolute,
    transaction,
};
use bitcoin_rs_primitives::{Amount, Script, Tx, TxOut, deserialize};

use crate::{Interpreter, PreparedTransaction, ScriptErrCode, ScriptError, VerifyFlags};

fn template() -> Transaction {
    Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![BitcoinTxIn {
            previous_output: BitcoinOutPoint::new(bitcoin::Txid::from_byte_array([17; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: BitcoinSequence::MAX,
            witness: BitcoinWitness::new(),
        }],
        output: vec![BitcoinTxOut {
            value: BitcoinAmount::from_sat(90_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([42; 20])),
        }],
    }
}

fn fixture_key() -> (Secp256k1<bitcoin::secp256k1::All>, Keypair) {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[37; 32]).expect("fixed fixture key");
    let key = Keypair::from_secret_key(&secp, &secret);
    (secp, key)
}

fn native_spend(tx: &Transaction, prevout: &BitcoinTxOut) -> (Tx, TxOut) {
    let native: Tx = deserialize(&bitcoin::consensus::serialize(tx)).expect("native decode");
    let native_prevout = TxOut {
        value: Amount::from_sat(prevout.value.to_sat()),
        script_pubkey: Script::from_bytes(prevout.script_pubkey.to_bytes()),
    };
    (native, native_prevout)
}

#[test]
fn witness_script_push_past_combined_stack_limit_is_rejected() {
    let mut leaf_bytes = Vec::with_capacity(2_001);
    for _ in 0..1_000 {
        leaf_bytes.push(0x51);
        leaf_bytes.push(0x6b);
    }
    leaf_bytes.extend_from_slice(&[0x01, 0x01]);
    let leaf = ScriptBuf::from_bytes(leaf_bytes);

    let (secp, key) = fixture_key();
    let tree = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .expect("one public leaf")
        .finalize(&secp, key.x_only_public_key().0)
        .expect("complete tree");
    let prevout = BitcoinTxOut {
        value: BitcoinAmount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(tree.output_key()),
    };
    let mut tx = template();
    let control = tree
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .expect("known leaf")
        .serialize();
    tx.input[0].witness = BitcoinWitness::from_slice(&[leaf.to_bytes(), control]);
    let (native, native_prevout) = native_spend(&tx, &prevout);

    let result = Interpreter.execute_with_prevouts(
        &native_prevout.script_pubkey,
        &[],
        &native.inputs[0].witness,
        VerifyFlags::MANDATORY,
        std::slice::from_ref(&native_prevout),
        &native,
        0,
    );

    assert_eq!(
        result,
        Err(ScriptError::Invalid {
            code: ScriptErrCode::StackSize
        }),
        "Bitcoin Core checks stack.size() + altstack.size() > MAX_STACK_SIZE (1000) after every \
         instruction, including a data push; the final one-byte push leaves 1 main-stack item and \
         1000 altstack items, so the script must fail with STACK_SIZE instead of accepting the \
         spend"
    );
}

#[test]
fn tapscript_codeseparator_sighash_hashes_the_opcode_index() {
    let (secp, key) = fixture_key();
    let internal_key = key.x_only_public_key().0;
    let mut leaf_bytes = vec![0xab, 0x20];
    leaf_bytes.extend_from_slice(&internal_key.serialize());
    leaf_bytes.push(0xac);
    let leaf = ScriptBuf::from_bytes(leaf_bytes);
    let tree = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .expect("one public leaf")
        .finalize(&secp, internal_key)
        .expect("complete tree");

    let prevout = BitcoinTxOut {
        value: BitcoinAmount::from_sat(100_000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(tree.output_key()),
    };
    let mut tx = template();
    let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
    let sighash = SighashCache::new(&tx)
        .taproot_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&prevout)),
            None,
            Some((leaf_hash, 0)),
            TapSighashType::Default,
        )
        .expect("independent BIP342 digest");
    let signature =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &key);
    let control = tree
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .expect("known leaf")
        .serialize();
    tx.input[0].witness =
        BitcoinWitness::from_slice(&[signature.serialize().to_vec(), leaf.to_bytes(), control]);

    let (native, native_prevout) = native_spend(&tx, &prevout);
    let rows = vec![(native.inputs[0].previous_output, native_prevout)];
    let result = PreparedTransaction::new(&native, &rows)
        .expect("ordered complete prevouts")
        .verify_input(0, VerifyFlags::MANDATORY, None);

    assert_eq!(
        result,
        Ok(true),
        "BIP342 commits to codesep_pos, the opcode index of the last executed OP_CODESEPARATOR \
         (0 here); the interpreter instead committed to the byte offset after the separator (1), \
         so a spend signed from the independent BIP342 digest was rejected"
    );
}
