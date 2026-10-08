//! Mainnet script verdicts against bitcoinkernel; opted-in fixtures also run
//! the interpreter directly so the differential cannot dispatch kernel twice.
//! Per-input scripts only; fixtures include every prevout and provenance.

#![cfg(feature = "kernel")]

use std::error::Error;
use std::path::{Path, PathBuf};

use bitcoin::hex::FromHex;
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_primitives::{
    Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness, consensus_bytes,
    deserialize,
};
use bitcoin_rs_script::{Interpreter, VerifyFlags};
use serde::Deserialize;

type TestResult = Result<(), Box<dyn Error>>;

// Engines use different error taxonomies; compare consensus accept/reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    Reject,
}

impl Verdict {
    fn of<T, E>(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => Self::Accept,
            Err(_) => Self::Reject,
        }
    }
}

fn kernel_result(tx: &Tx, prevouts: &[TxOut], flags: VerifyFlags) -> Result<(), ConsensusError> {
    let spent: Vec<(OutPoint, TxOut)> = tx
        .inputs
        .iter()
        .zip(prevouts)
        .map(|(input, prevout)| (input.previous_output, prevout.clone()))
        .collect();
    bitcoin_rs_consensus::kernel::verify_tx_scripts(
        tx,
        &spent,
        flags,
        bitcoin_rs_consensus::ValidationEngine::Kernel,
    )
}

fn interpreter_result(tx: &Tx, prevouts: &[TxOut], flags: VerifyFlags) -> Result<(), String> {
    for (input_index, (input, prevout)) in tx.inputs.iter().zip(prevouts).enumerate() {
        let witness = input.witness.clone();
        Interpreter
            .execute_with_prevouts(
                &prevout.script_pubkey,
                &input.script_sig,
                &witness,
                flags,
                prevouts,
                tx,
                input_index,
            )
            .map_err(|error| format!("input {input_index}: {error}"))?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutation {
    Pristine,
    /// Invalidates a signature without changing its structural encoding.
    FlipSignatureBit,
    TruncateScriptSig,
    WrongSighashTypeByte,
    /// Corrupts the final witness element, including taproot control blocks.
    TamperWitness,
    TruncateWitness,
}

impl Mutation {
    const ALL: [Self; 6] = [
        Self::Pristine,
        Self::FlipSignatureBit,
        Self::TruncateScriptSig,
        Self::WrongSighashTypeByte,
        Self::TamperWitness,
        Self::TruncateWitness,
    ];

    const fn expected(self) -> Verdict {
        match self {
            Self::Pristine => Verdict::Accept,
            _ => Verdict::Reject,
        }
    }

    /// `None` means the mutation is inapplicable, never a no-op.
    fn apply(self, tx: &Tx) -> Option<Tx> {
        let mut tx = tx.clone();
        let applied = match self {
            Self::Pristine => true,
            Self::FlipSignatureBit => flip_signature_bit(&mut tx),
            Self::TruncateScriptSig => truncate_script_sig(&mut tx),
            Self::WrongSighashTypeByte => wrong_sighash_type_byte(&mut tx),
            Self::TamperWitness => tamper_witness(&mut tx),
            Self::TruncateWitness => truncate_witness(&mut tx),
        };
        applied.then_some(tx)
    }
}

/// First DER-signature push's `(payload_start, payload_len)`.
fn der_sig_range(script: &[u8]) -> Option<(usize, usize)> {
    let mut cursor = 0usize;
    while let Some(&opcode) = script.get(cursor) {
        let (payload_start, payload_len) = match opcode {
            1..=75 => (cursor.checked_add(1)?, usize::from(opcode)),
            0x4c => {
                let len = *script.get(cursor.checked_add(1)?)?;
                (cursor.checked_add(2)?, usize::from(len))
            }
            0x4d => {
                let low = *script.get(cursor.checked_add(1)?)?;
                let high = *script.get(cursor.checked_add(2)?)?;
                (
                    cursor.checked_add(3)?,
                    usize::from(u16::from_le_bytes([low, high])),
                )
            }
            _ => {
                cursor = cursor.checked_add(1)?;
                continue;
            }
        };
        let payload_end = payload_start.checked_add(payload_len)?;
        let payload = script.get(payload_start..payload_end)?;
        if looks_like_der_sig(payload) {
            return Some((payload_start, payload_len));
        }
        cursor = payload_end;
    }
    None
}

fn looks_like_der_sig(payload: &[u8]) -> bool {
    (9..=73).contains(&payload.len())
        && payload.first() == Some(&0x30)
        && payload
            .last()
            .is_some_and(|byte| matches!(byte & 0x7f, 1..=3))
}

fn is_signature_element(element: &[u8]) -> bool {
    looks_like_der_sig(element) || matches!(element.len(), 64 | 65)
}

fn flip_signature_bit(tx: &mut Tx) -> bool {
    for input in &mut tx.inputs {
        let mut bytes = input.script_sig.clone();
        if let Some((start, len)) = der_sig_range(&bytes)
            && let Some(mid) = start.checked_add(len / 2)
            && let Some(byte) = bytes.get_mut(mid)
        {
            *byte ^= 0x01;
            input.script_sig = bytes;
            return true;
        }
    }
    for input in &mut tx.inputs {
        let mut elements = input.witness.clone();
        if let Some(element) = elements
            .iter_mut()
            .find(|element| is_signature_element(element))
        {
            let mid = element.len() / 2;
            if let Some(byte) = element.get_mut(mid) {
                *byte ^= 0x01;
                input.witness = elements;
                return true;
            }
        }
    }
    false
}

fn truncate_script_sig(tx: &mut Tx) -> bool {
    for input in &mut tx.inputs {
        let mut bytes = input.script_sig.clone();
        if bytes.pop().is_some() {
            input.script_sig = bytes;
            return true;
        }
    }
    false
}

fn wrong_sighash_type_byte(tx: &mut Tx) -> bool {
    for input in &mut tx.inputs {
        let mut bytes = input.script_sig.clone();
        if let Some((start, len)) = der_sig_range(&bytes)
            && let Some(last) = start.checked_add(len.saturating_sub(1))
            && let Some(byte) = bytes.get_mut(last)
        {
            *byte ^= 0x02;
            input.script_sig = bytes;
            return true;
        }
    }
    for input in &mut tx.inputs {
        let mut elements = input.witness.clone();
        let mut mutated = false;
        for element in elements.iter_mut() {
            if looks_like_der_sig(element) || element.len() == 65 {
                if let Some(byte) = element.last_mut() {
                    *byte ^= 0x02;
                    mutated = true;
                    break;
                }
            }
            if element.len() == 64 {
                // A 64-byte signature implicitly commits to SIGHASH_DEFAULT.
                element.push(0x03);
                mutated = true;
                break;
            }
        }
        if mutated {
            input.witness = elements;
            return true;
        }
    }
    false
}

fn tamper_witness(tx: &mut Tx) -> bool {
    for input in &mut tx.inputs {
        let mut elements = input.witness.clone();
        if let Some(last) = elements.last_mut()
            && !last.is_empty()
        {
            let mid = last.len() / 2;
            if let Some(byte) = last.get_mut(mid) {
                *byte ^= 0x01;
                input.witness = elements;
                return true;
            }
        }
    }
    false
}

fn truncate_witness(tx: &mut Tx) -> bool {
    for input in &mut tx.inputs {
        let mut elements = input.witness.clone();
        if elements.pop().is_some() {
            input.witness = elements;
            return true;
        }
    }
    false
}

#[derive(Deserialize)]
struct FixtureFile {
    name: String,
    class: String,
    txid: String,
    wtxid: String,
    height: u32,
    #[allow(dead_code, reason = "provenance lives in the JSON; read by humans")]
    source: String,
    flags: String,
    interpreter_parity: bool,
    tx_hex: String,
    prevouts: Vec<PrevoutFile>,
}

#[derive(Deserialize)]
struct PrevoutFile {
    script_hex: String,
    amount_sat: u64,
}

struct Fixture {
    name: String,
    class: String,
    height: u32,
    interpreter_parity: bool,
    tx: Tx,
    prevouts: Vec<TxOut>,
    flags: VerifyFlags,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/scripts")
}

/// Loads the committed corpus; a missing directory, bad JSON, a txid mismatch
/// or a prevout-count mismatch is an error, never a skip.
fn load_fixtures() -> Result<Vec<Fixture>, Box<dyn Error>> {
    let dir = vectors_dir();
    let entries = std::fs::read_dir(&dir)
        .map_err(|error| format!("fixture corpus dir {}: {error}", dir.display()))?;
    let mut paths: Vec<PathBuf> = entries
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<_, _>>()?;
    paths.retain(|path| path.extension().is_some_and(|ext| ext == "json"));
    paths.sort();

    let mut fixtures = Vec::with_capacity(paths.len());
    for path in &paths {
        let text = std::fs::read_to_string(path)?;
        let file: FixtureFile =
            serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        fixtures.push(validate_fixture(file, path)?);
    }
    Ok(fixtures)
}

fn validate_fixture(file: FixtureFile, path: &Path) -> Result<Fixture, Box<dyn Error>> {
    let tx: Tx = deserialize(&decode_hex(&file.tx_hex)?)
        .map_err(|error| format!("{}: tx hex does not decode: {error}", path.display()))?;
    let computed_txid = tx.txid().to_string();
    if computed_txid != file.txid {
        return Err(format!(
            "{}: txid mismatch: manifest says {} but tx hex hashes to {computed_txid}",
            path.display(),
            file.txid
        )
        .into());
    }
    let computed_wtxid = tx.wtxid().to_string();
    if computed_wtxid != file.wtxid {
        return Err(format!(
            "{}: wtxid mismatch: manifest says {} but tx hex hashes to {computed_wtxid} \
             (witness bytes are not what was frozen)",
            path.display(),
            file.wtxid
        )
        .into());
    }
    if file.prevouts.len() != tx.inputs.len() {
        return Err(format!(
            "{}: {} prevouts for {} inputs; every input needs its prevout \
             (the kernel taproot path requires all of them)",
            path.display(),
            file.prevouts.len(),
            tx.inputs.len()
        )
        .into());
    }
    let flags = VerifyFlags::from_core_names(&file.flags)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let prevouts = file
        .prevouts
        .iter()
        .map(|prevout| {
            Ok(TxOut {
                value: Amount::from_sat(prevout.amount_sat),
                script_pubkey: decode_hex(&prevout.script_hex)?.into(),
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    Ok(Fixture {
        name: file.name,
        class: file.class,
        height: file.height,
        interpreter_parity: file.interpreter_parity,
        tx,
        prevouts,
        flags,
    })
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(Vec::from_hex(hex)?)
}

fn require_non_empty(fixtures: &[Fixture]) -> Result<(), Box<dyn Error>> {
    if fixtures.is_empty() {
        return Err(format!(
            "kernel parity fixture corpus is empty; commit fixtures under {}",
            vectors_dir().display()
        )
        .into());
    }
    Ok(())
}

#[test]
fn script_verdict_parity() -> TestResult {
    let fixtures = load_fixtures()?;
    require_non_empty(&fixtures)?;

    let mut interpreter_scoped = 0usize;
    for fixture in &fixtures {
        let pristine_bytes = consensus_bytes(&fixture.tx);
        let mut reject_mutations = 0usize;

        for mutation in Mutation::ALL {
            let Some(tx) = mutation.apply(&fixture.tx) else {
                continue;
            };
            if mutation != Mutation::Pristine {
                assert_ne!(
                    consensus_bytes(&tx),
                    pristine_bytes,
                    "mutation {mutation:?} must change tx bytes: fixture={}",
                    fixture.name,
                );
                reject_mutations = reject_mutations.saturating_add(1);
            }

            let kernel = kernel_result(&tx, &fixture.prevouts, fixture.flags);
            assert_eq!(
                Verdict::of(&kernel),
                mutation.expected(),
                "kernel verdict: fixture={} class={} height={} mutation={mutation:?} \
                 result={kernel:?}",
                fixture.name,
                fixture.class,
                fixture.height,
            );
            // Parse/precompute failures are not script rejection evidence.
            if mutation.expected() == Verdict::Reject {
                assert!(
                    matches!(kernel, Err(ConsensusError::Script { .. })),
                    "kernel rejection is not a script verdict (infrastructure \
                     failure, not a consensus reject): fixture={} class={} \
                     mutation={mutation:?} result={kernel:?}",
                    fixture.name,
                    fixture.class,
                );
            }

            if fixture.interpreter_parity {
                let interpreter = interpreter_result(&tx, &fixture.prevouts, fixture.flags);
                assert_eq!(
                    Verdict::of(&interpreter),
                    Verdict::of(&kernel),
                    "engine divergence: fixture={} class={} mutation={mutation:?} \
                     kernel={kernel:?} interpreter={interpreter:?}",
                    fixture.name,
                    fixture.class,
                );
            }
        }

        assert!(
            reject_mutations >= 2,
            "fixture {} exercised only {reject_mutations} reject mutations; \
             the catalog no longer bites on class {}",
            fixture.name,
            fixture.class,
        );
        if fixture.interpreter_parity {
            interpreter_scoped = interpreter_scoped.saturating_add(1);
        }
    }

    assert!(
        interpreter_scoped >= 1,
        "no fixture is interpreter-scoped: the kernel-vs-interpreter \
         differential dimension has silently vanished from the corpus"
    );
    Ok(())
}

#[test]
fn differential_is_non_vacuous() -> TestResult {
    let fixtures = load_fixtures()?;
    let script_path = fixtures
        .iter()
        .find(|fixture| fixture.class == "taproot_scriptpath")
        .ok_or("taproot_scriptpath fixture missing from the committed corpus")?;

    let kernel = kernel_result(&script_path.tx, &script_path.prevouts, script_path.flags);
    let interpreter = interpreter_result(&script_path.tx, &script_path.prevouts, script_path.flags);
    assert_eq!(
        Verdict::of(&kernel),
        Verdict::Accept,
        "kernel must accept the pristine taproot script-path fixture: {kernel:?}"
    );
    assert_eq!(
        Verdict::of(&interpreter),
        Verdict::Accept,
        "interpreter must accept the pristine taproot script-path fixture: {interpreter:?}"
    );

    let tampered = Mutation::TamperWitness
        .apply(&script_path.tx)
        .ok_or("TamperWitness must apply to a taproot script-path spend")?;
    let kernel = kernel_result(&tampered, &script_path.prevouts, script_path.flags);
    let interpreter = interpreter_result(&tampered, &script_path.prevouts, script_path.flags);
    assert_eq!(
        Verdict::of(&kernel),
        Verdict::Reject,
        "kernel must reject a tampered control block; a constant Accept means \
         the kernel arm is not reading the transaction: {kernel:?}"
    );
    assert_eq!(
        Verdict::of(&interpreter),
        Verdict::Reject,
        "interpreter must reject a tampered control block; a constant Accept \
         means the Rust arm is not reading the transaction: {interpreter:?}"
    );
    Ok(())
}

#[test]
fn pristine_mutation_is_identity() -> TestResult {
    let tx = Tx {
        version: 1,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: vec![0x51].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: Script::new(),
        }],
    };
    let pristine = Mutation::Pristine.apply(&tx).ok_or("Pristine must apply")?;
    assert_eq!(consensus_bytes(&tx), consensus_bytes(&pristine));
    assert_eq!(
        Mutation::ALL
            .iter()
            .filter(|mutation| matches!(mutation, Mutation::Pristine))
            .count(),
        1
    );
    Ok(())
}
