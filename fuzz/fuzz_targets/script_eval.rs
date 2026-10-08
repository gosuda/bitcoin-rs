#![no_main]

use libfuzzer_sys::fuzz_target;

use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence};
use bitcoin_rs_script::{Interpreter, VerifyFlags};

/// Fuzz the production default script interpreter.
///
/// Every spend bitcoin-rs ever validates goes through
/// `Interpreter::execute_with_prevouts`; this target drives that single entry
/// point with arbitrary `(script_pubkey, script_sig, witness, flags)` tuples.
/// The default framing evaluates under Bitcoin Core's script-test template
/// (transaction_tests BuildCrediting + BuildSpending): a v1 crediting tx
/// paying the prevout amount to script_pubkey, spent by a v1 single-input
/// tx — the same single-input shape block and mempool callers produce, and
/// the context script_tests.json signatures were authored against. The
/// TX_CONTEXT framing instead evaluates a serialized upstream tx at a given
/// input, carrying every input's resolved prevout so signatures from
/// tx_valid/tx_invalid vectors verify under their original transaction.
///
/// Input framing (all lengths little-endian u16 unless noted):
///
/// ```text
/// byte 0      flags selector (mod FLAGS.len()), EXPLICIT_FLAGS, or TX_CONTEXT
/// [0xFF only] u32 LE  explicit Core-compatible VerifyFlags bits
/// u16  len    script_sig
/// bytes       script_sig
/// u16  len    script_pubkey
/// bytes       script_pubkey
/// byte        witness element count (cap 8)
/// per element u16 len + bytes
/// [optional]  u64 LE  prevout amount in satoshis (default 0, matching the
///               zero-value output Core's BuildCreditingTransaction pays)
/// [0xFD only] transaction-context frame:
///   u32 LE    explicit Core-compatible VerifyFlags bits
///   u16  len  serialized spending tx
///   u16       input index to evaluate
///   u8        prevout count (must equal the tx's input count)
///   per prevout: u16 len + script_pubkey bytes, u64 LE amount satoshis
/// rest        ignored
/// ```
///
/// Scripts from the qa-assets corpus are wrapped into this framing by
/// `scripts/import-qa-assets.sh`; seeds written by that script use the harness
/// `FLAGS` entry `NONE` for raw scripts and, for files >= 32 bytes, a P2TR
/// variant using its `TAPROOT` entry. Reference-vector seeds written by
/// `scripts/import-reference-corpora.sh` use `EXPLICIT_FLAGS` so each seed
/// carries its own row's flag bits and a trailing prevout amount when the
/// source row declares one (script_tests witness rows, tx_valid prevouts,
/// taproot-ref TxOuts).
const FLAGS: [VerifyFlags; 6] = [
    VerifyFlags::NONE,
    VerifyFlags::MANDATORY,
    VerifyFlags::STANDARD,
    VerifyFlags::TAPROOT,
    VerifyFlags::P2SH.union(VerifyFlags::WITNESS),
    VerifyFlags::MANDATORY
        .union(VerifyFlags::CLEANSTACK)
        .union(VerifyFlags::MINIMALIF)
        .union(VerifyFlags::NULLFAIL)
        .union(VerifyFlags::WITNESS_PUBKEYTYPE)
        .union(VerifyFlags::CONST_SCRIPTCODE),
];

const WITNESS_ELEMENTS_MAX: usize = 8;
/// Largest framed script or witness element. The u16 wire length can never
/// exceed this, so the bound is defensive, not a truncation of real vectors.
const ELEMENT_LEN_MAX: usize = 65_535;

/// Selector value choosing the explicit-flags framing: the next four input
/// bytes are little-endian `VerifyFlags` bits used verbatim, letting vector
/// importers carry each row's own flag set instead of a `FLAGS` table entry.
const EXPLICIT_FLAGS: u8 = 0xff;

/// Selector value choosing the transaction-context framing: the seed carries
/// the serialized spending transaction, the input index to evaluate, and the
/// resolved prevout for every input, so signatures authored against a real
/// upstream transaction verify under the context they were made for.
const TX_CONTEXT: u8 = 0xfd;

fuzz_target!(|data: &[u8]| {
    let Some((&selector_byte, mut rest)) = data.split_first() else {
        return;
    };

    // Length-prefixed cursor; every read is checked, nothing panics.

    fn take<'a>(rest: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
        let chunk = rest.get(..len)?;
        *rest = &rest[len.min(rest.len())..];
        Some(chunk)
    }
    fn take_u16(rest: &mut &[u8]) -> Option<usize> {
        let bytes = take(rest, 2)?;
        Some(usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
    }

    if selector_byte == TX_CONTEXT {
        let Some(bits) = take(&mut rest, 4) else {
            return;
        };
        let flags =
            VerifyFlags::from_bits_retain(u32::from_le_bytes(bits.try_into().unwrap_or([0; 4])));
        let Some(tx_len) = take_u16(&mut rest) else {
            return;
        };
        let Some(tx_bytes) = take(&mut rest, tx_len) else {
            return;
        };
        let Ok(tx) =
            bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Tx>(tx_bytes)
        else {
            return;
        };
        let Some(index) = take_u16(&mut rest) else {
            return;
        };
        let Some(&prevout_count) = rest.first() else {
            return;
        };
        rest = &rest[1..];
        if usize::from(prevout_count) != tx.inputs.len() || index >= tx.inputs.len() {
            return;
        }
        let mut prevouts = Vec::with_capacity(tx.inputs.len());
        for _ in 0..prevout_count {
            let Some(script_len) = take_u16(&mut rest) else {
                return;
            };
            let Some(script) = take(&mut rest, script_len) else {
                return;
            };
            let Some(value) = take(&mut rest, 8) else {
                return;
            };
            prevouts.push(bitcoin_rs_primitives::TxOut {
                value: Amount::from_sat(u64::from_le_bytes(
                    value.try_into().unwrap_or([0; 8]),
                )),
                script_pubkey: script.to_vec().into(),
            });
        }
        let input = &tx.inputs[index];
        let _ = Interpreter::default().execute_with_prevouts(
            prevouts[index].script_pubkey.as_slice(),
            input.script_sig.as_slice(),
            &input.witness,
            flags,
            &prevouts,
            &tx,
            index,
        );
        return;
    }

    let flags = if selector_byte == EXPLICIT_FLAGS {
        let Some(bits) = take(&mut rest, 4) else {
            return;
        };
        VerifyFlags::from_bits_retain(u32::from_le_bytes(bits.try_into().unwrap_or([0; 4])))
    } else {
        FLAGS[usize::from(selector_byte) % FLAGS.len()]
    };

    let Some(script_sig_len) = take_u16(&mut rest) else {
        return;
    };
    let script_sig_len = script_sig_len.min(ELEMENT_LEN_MAX);
    let Some(script_sig) = take(&mut rest, script_sig_len) else {
        return;
    };

    let Some(script_pubkey_len) = take_u16(&mut rest) else {
        return;
    };
    let script_pubkey_len = script_pubkey_len.min(ELEMENT_LEN_MAX);
    let Some(script_pubkey) = take(&mut rest, script_pubkey_len) else {
        return;
    };

    let Some(&witness_count) = rest.first() else {
        return;
    };
    rest = &rest[1..];
    let witness_count = (witness_count as usize).min(WITNESS_ELEMENTS_MAX);
    let mut witness: Vec<Vec<u8>> = Vec::with_capacity(witness_count);
    for _ in 0..witness_count {
        let Some(element_len) = take_u16(&mut rest) else {
            break;
        };
        let element_len = element_len.min(ELEMENT_LEN_MAX);
        let Some(element) = take(&mut rest, element_len) else {
            break;
        };
        witness.push(element.to_vec());
    }

    // Trailing optional prevout amount: seeds imported from rows that declare
    // one (witness rows sign over it) carry it here. Legacy rows declare none
    // and must default to Core's zero-value crediting output: the crediting
    // txid commits to nValue, so any other default would change the outpoint
    // txid legacy signatures hash.
    let amount = take(&mut rest, 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
        .unwrap_or(0);

    let script_sig = script_sig.to_vec();
    let script_pubkey = script_pubkey.to_vec();
    let prevout = bitcoin_rs_primitives::TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: script_pubkey.clone().into(),
    };
    // Core's script-test template (BuildCrediting + BuildSpending, which
    // btcd's txscript harness mirrors): a v1 crediting tx paying `amount` to
    // script_pubkey, then a v1 spend returning it to an empty script. The
    // crediting txid lands in the spend's outpoint, so signatures authored
    // against the upstream vectors verify under their intended context.
    let credit = bitcoin_rs_primitives::Tx {
        version: 1,
        inputs: vec![bitcoin_rs_primitives::TxIn {
            previous_output: bitcoin_rs_primitives::OutPoint::null(),
            script_sig: vec![0x00, 0x00].into(),
            sequence: Sequence::MAX,
            witness: bitcoin_rs_primitives::Witness::new(),
        }],
        outputs: vec![bitcoin_rs_primitives::TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: script_pubkey.clone().into(),
        }],
        lock_time: LockTime::ZERO,
    };
    let tx = bitcoin_rs_primitives::Tx {
        version: 1,
        inputs: vec![bitcoin_rs_primitives::TxIn {
            previous_output: bitcoin_rs_primitives::OutPoint::new(credit.txid(), 0),
            script_sig: script_sig.clone().into(),
            sequence: Sequence::MAX,
            witness: witness.clone().into(),
        }],
        outputs: vec![bitcoin_rs_primitives::TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::ZERO,
    };

    let interpreter = Interpreter::default();
    let _ = interpreter.execute_with_prevouts(
        &script_pubkey,
        &script_sig,
        &witness,
        flags,
        std::slice::from_ref(&prevout),
        &tx,
        0,
    );
});
