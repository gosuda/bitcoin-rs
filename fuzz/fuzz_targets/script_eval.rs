#![no_main]

use libfuzzer_sys::fuzz_target;

use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence};
use bitcoin_rs_script::{Interpreter, VerifyFlags};

/// Fuzz the production default script interpreter.
///
/// Every spend bitcoin-rs ever validates goes through
/// `Interpreter::execute_with_prevouts`; this target drives that single entry
/// point with arbitrary `(script_pubkey, script_sig, witness, flags)` tuples.
/// The transaction is single-input so the interpreter takes the borrow path
/// (`script_sig`/`witness` match `tx.input[0]`), the same shape block and
/// mempool validation callers produce.
///
/// Input framing (all lengths little-endian u16 unless noted):
///
/// ```text
/// byte 0      flags selector (mod FLAGS.len()), or EXPLICIT_FLAGS
/// [0xFF only] u32 LE  explicit Core-compatible VerifyFlags bits
/// u16  len    script_sig
/// bytes       script_sig
/// u16  len    script_pubkey
/// bytes       script_pubkey
/// byte        witness element count (cap 8)
/// per element u16 len + bytes
/// rest        ignored
/// ```
///
/// Scripts from the qa-assets corpus are wrapped into this framing by
/// `scripts/import-qa-assets.sh`; seeds written by that script use the harness
/// `FLAGS` entry `NONE` for raw scripts and, for files >= 32 bytes, a P2TR
/// variant using its `TAPROOT` entry. Reference-vector seeds written by
/// `scripts/import-reference-corpora.sh` use `EXPLICIT_FLAGS` so each seed
/// carries its own row's flag bits.
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
const ELEMENT_LEN_MAX: usize = 1024;

/// Selector value choosing the explicit-flags framing: the next four input
/// bytes are little-endian `VerifyFlags` bits used verbatim, letting vector
/// importers carry each row's own flag set instead of a `FLAGS` table entry.
const EXPLICIT_FLAGS: u8 = 0xff;

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

    let flags = if selector_byte == EXPLICIT_FLAGS {
        let Some(bits) = take(&mut rest, 4) else {
            return;
        };
        VerifyFlags::from_bits(u32::from_le_bytes(bits.try_into().unwrap_or([0; 4])))
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

    let script_sig = script_sig.to_vec();
    let script_pubkey = script_pubkey.to_vec();
    let prevout = bitcoin_rs_primitives::TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: script_pubkey.clone().into(),
    };
    let tx = bitcoin_rs_primitives::Tx {
        version: 2,
        inputs: vec![bitcoin_rs_primitives::TxIn {
            previous_output: bitcoin_rs_primitives::OutPoint::default(),
            script_sig: script_sig.clone().into(),
            sequence: Sequence::MAX,
            witness: witness.clone().into(),
        }],
        outputs: vec![bitcoin_rs_primitives::TxOut {
            value: Amount::from_sat(9_000),
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
