//! Phase-0b consensus guard: kernel script-verdict pinning plus a
//! kernel-vs-Rust-interpreter differential over committed mainnet fixtures.
//!
//! Consensus authority is `bitcoinkernel`. This harness replays real mainnet
//! transactions — one committed fixture per script class under
//! `tests/vectors/scripts/` — through the kernel entry the production apply
//! path uses (`bitcoin_rs_consensus::kernel::verify_tx_scripts`, the seam
//! `verify_transaction` dispatches to under `feature = "kernel"`), and asserts:
//!
//! * every pristine fixture is **accepted**, and
//! * every applicable in-code mutation (signature bit flip, scriptSig
//!   truncation, wrong sighash-type byte, witness tampering/truncation) is
//!   **rejected**.
//!
//! ## The differential is interpreter-vs-kernel, not kernel-vs-kernel (ADV-1)
//!
//! The Rust side of the differential calls `bitcoin_rs_script::Interpreter`
//! **directly**. It must never route through `RustValidator::verify_tx` /
//! `verify_transaction`: under `feature = "kernel"` those dispatch script
//! verdicts to the very same `kernel::verify_tx_scripts` as the kernel side
//! (by design, per R2/KTD5 of plan 2026-06-10-001), which would silently turn
//! this differential into kernel-vs-kernel and make it unable to detect any
//! interpreter divergence. That cfg structure is production-correct and is
//! pinned elsewhere (`verify_tx.rs` kernel tests); this file deliberately
//! bypasses it for the *test-only* Rust verdict. [`differential_is_non_vacuous`]
//! proves the bypass holds: it asserts the two engines *disagree* on inputs
//! where they are known to differ, which is impossible if both sides reach the
//! kernel.
//!
//! ## Honest interpreter scoping — no fake parity
//!
//! In this binary (`--no-default-features --features kernel`) the
//! `bitcoinconsensus` backend is excluded (overlapping native Core symbols;
//! `compile_error!` guard in `src/lib.rs`), so `Interpreter::execute`
//! (crates/script/src/interpreter.rs) natively executes exactly one class:
//! **single-input taproot key-path spends** with a one-element witness
//! (local BIP341 Schnorr verification). Legacy, P2SH, segwit v0, and taproot
//! script-path spends have no Rust execution path here. Fixtures therefore
//! carry an explicit `interpreter_parity` flag: only the taproot key-path
//! fixture asserts two-engine verdict parity; every other class is verified
//! against the kernel alone, with the scoping stated rather than faked.
//!
//! ## Fixtures
//!
//! `tests/vectors/scripts/*.json`, provenance in the adjacent `README.md`:
//! legacy classes extracted from the local mainnet datadir over `bitcoind
//! -rest`, post-activation classes (P2SH / segwit v0 / taproot) frozen from
//! public esplora block data. Each fixture carries raw tx hex plus **every**
//! input's prevout (script + amount) — the kernel's taproot path needs all
//! prevouts for `PrecomputedTransactionData`, even for inputs that are not
//! under test — and the Core-named verify flags active at its height.
//! Mutations are generated in code, never stored. [`require_non_empty`] keeps
//! the corpus red-on-empty: zero fixtures is a hard failure, not a vacuous
//! pass.
//!
//! ## Block-level parity (tracking note, KTD1)
//!
//! An earlier scaffold here carried a `block_verdict_parity` test comparing
//! `RustValidator::connect_block` against `KernelContext::connect_block`. It
//! was deleted, not env-gated: the kernel side it needed
//! (`ChainstateManager::process_block`) is **rejected** by KTD1 of plan
//! 2026-06-10-001 (kernel-owned chainstate would duplicate storage and invert
//! the storage-equivalence gate), and the in-tree `connect_block` is a stub
//! that cannot reject — the comparison could never red. Re-entry condition:
//! if the KTD1 full-block alternative is ever adopted, reintroduce block-level
//! accept/reject parity against `process_block`. Until then, block-level
//! coverage rests on the portable block rules tests plus the R3 0→150k
//! stop-hash differential between the kernel and portable builds.
//!
//! Run with the isolated kernel feature (needs system `libboost-dev` + `cmake`):
//!
//! ```sh
//! cargo test -p bitcoin-rs-consensus --no-default-features --features kernel \
//!     --test kernel_block_parity
//! ```

#![cfg(feature = "kernel")]

use std::error::Error;
use std::path::{Path, PathBuf};

use bitcoin::consensus::encode;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Witness};
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_script::{Interpreter, VerifyFlags};
use serde::Deserialize;

/// Convenient alias for fallible test bodies (house style: tests return a
/// `Result` and use `?`, mirroring `crates/utxo/tests/commit_commute.rs`).
type TestResult = Result<(), Box<dyn Error>>;

// ---------------------------------------------------------------------------
// Verdict model
// ---------------------------------------------------------------------------

/// A coarse accept/reject verdict, the only thing this harness compares. We
/// intentionally collapse *why* a path rejected: the kernel and the Rust path
/// classify failures with different error taxonomies, and requiring identical
/// reasons would test the taxonomy, not consensus. Identical accept/reject is
/// the invariant; reason strings are surfaced only in assertion messages for
/// triage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// The engine accepted the spend.
    Accept,
    /// The engine rejected the spend.
    Reject,
}

impl Verdict {
    /// Maps any `Result` to a verdict: `Ok` is accept, any `Err` is reject.
    fn of<T, E>(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => Self::Accept,
            Err(_) => Self::Reject,
        }
    }
}

// ---------------------------------------------------------------------------
// Engines
// ---------------------------------------------------------------------------

/// Kernel verdict for every input of `tx`, through the same free function the
/// production `verify_transaction` dispatches to under `feature = "kernel"`.
fn kernel_result(
    tx: &Transaction,
    prevouts: &[TxOut],
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    let spent: Vec<(OutPoint, TxOut)> = tx
        .input
        .iter()
        .zip(prevouts)
        .map(|(input, prevout)| (input.previous_output, prevout.clone()))
        .collect();
    bitcoin_rs_consensus::kernel::verify_tx_scripts(tx, &spent, flags)
}

/// Rust-interpreter verdict for every input of `tx`, calling
/// `bitcoin_rs_script::Interpreter` directly. Deliberately does NOT go through
/// `RustValidator::verify_tx` / `verify_transaction`: under the kernel feature
/// those route script verdicts into the kernel (see module docs, ADV-1), which
/// would make the differential kernel-vs-kernel. Returns the first failing
/// input's error, `Ok` when all inputs pass.
fn interpreter_result(
    tx: &Transaction,
    prevouts: &[TxOut],
    flags: VerifyFlags,
) -> Result<(), String> {
    for (input_index, (input, prevout)) in tx.input.iter().zip(prevouts).enumerate() {
        let witness = input.witness.to_vec();
        Interpreter
            .execute(
                prevout.script_pubkey.as_bytes(),
                input.script_sig.as_bytes(),
                &witness,
                flags,
                prevout,
                tx,
                input_index,
            )
            .map_err(|error| format!("input {input_index}: {error}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mutation catalog (in-code; mutations are never stored as fixtures)
// ---------------------------------------------------------------------------

/// One adversarial transformation of a known-valid transaction. Each variant
/// is a single, well-understood corruption so a verdict failure points at one
/// rule. The unmutated transaction (`Pristine`) is included so the harness
/// also pins that the engines accept the genuine article — a catalog of
/// only-rejects would pass trivially if an engine rejected everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutation {
    /// No change; engines must accept.
    Pristine,
    /// Flip one bit in the middle of the first located signature (DER push in
    /// a scriptSig, or DER/Schnorr witness element): invalidates the
    /// signature while keeping the script structurally intact.
    FlipSignatureBit,
    /// Drop the last byte of the first non-empty scriptSig: truncates the
    /// signature push (P2PK/P2PKH) or the redeem-script push (P2SH).
    TruncateScriptSig,
    /// Change the sighash-type byte of the first located signature: the
    /// signature then commits to a different hash than the verifier computes.
    WrongSighashTypeByte,
    /// Flip one bit in the middle of the last element of the first non-empty
    /// witness: corrupts the pubkey (P2WPKH), witness script (P2WSH), Schnorr
    /// signature (taproot key path), or control block (taproot script path).
    TamperWitness,
    /// Drop the last element of the first non-empty witness: breaks the
    /// witness-program structure for every witness class.
    TruncateWitness,
}

impl Mutation {
    /// Every catalog entry, applied to each fixture in turn.
    const ALL: [Self; 6] = [
        Self::Pristine,
        Self::FlipSignatureBit,
        Self::TruncateScriptSig,
        Self::WrongSighashTypeByte,
        Self::TamperWitness,
        Self::TruncateWitness,
    ];

    /// The verdict both engines must return for this mutation.
    const fn expected(self) -> Verdict {
        match self {
            Self::Pristine => Verdict::Accept,
            _ => Verdict::Reject,
        }
    }

    /// Applies the mutation to a clone of `tx`. Returns `None` when the
    /// mutation does not apply (e.g. witness tampering on a legacy spend) so
    /// the caller skips it rather than asserting on a no-op.
    fn apply(self, tx: &Transaction) -> Option<Transaction> {
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

/// Locates the first DER-signature push in a scriptSig, returning the byte
/// range `(payload_start, payload_len)` of the push payload. A payload counts
/// as a signature when it is 9..=73 bytes, starts with the DER sequence tag
/// `0x30`, and ends in a plausible sighash byte — this skips `OP_0` multisig
/// dummies, pubkeys, and redeem-script pushes (which end in an opcode like
/// `OP_CHECKMULTISIG`, not a sighash byte).
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

/// `true` for an ECDSA signature-plus-sighash-type payload.
fn looks_like_der_sig(payload: &[u8]) -> bool {
    (9..=73).contains(&payload.len())
        && payload.first() == Some(&0x30)
        && payload
            .last()
            .is_some_and(|byte| matches!(byte & 0x7f, 1..=3))
}

/// `true` for a witness element that carries a signature: a DER signature
/// (segwit v0) or a 64/65-byte Schnorr signature (taproot).
fn is_signature_element(element: &[u8]) -> bool {
    looks_like_der_sig(element) || matches!(element.len(), 64 | 65)
}

fn flip_signature_bit(tx: &mut Transaction) -> bool {
    for input in &mut tx.input {
        let mut bytes = input.script_sig.to_bytes();
        if let Some((start, len)) = der_sig_range(&bytes)
            && let Some(mid) = start.checked_add(len / 2)
            && let Some(byte) = bytes.get_mut(mid)
        {
            *byte ^= 0x01;
            input.script_sig = ScriptBuf::from_bytes(bytes);
            return true;
        }
    }
    for input in &mut tx.input {
        let mut elements = input.witness.to_vec();
        if let Some(element) = elements
            .iter_mut()
            .find(|element| is_signature_element(element))
        {
            let mid = element.len() / 2;
            if let Some(byte) = element.get_mut(mid) {
                *byte ^= 0x01;
                input.witness = Witness::from_slice(&elements);
                return true;
            }
        }
    }
    false
}

fn truncate_script_sig(tx: &mut Transaction) -> bool {
    for input in &mut tx.input {
        let mut bytes = input.script_sig.to_bytes();
        if bytes.pop().is_some() {
            input.script_sig = ScriptBuf::from_bytes(bytes);
            return true;
        }
    }
    false
}

fn wrong_sighash_type_byte(tx: &mut Transaction) -> bool {
    for input in &mut tx.input {
        let mut bytes = input.script_sig.to_bytes();
        if let Some((start, len)) = der_sig_range(&bytes)
            && let Some(last) = start.checked_add(len.saturating_sub(1))
            && let Some(byte) = bytes.get_mut(last)
        {
            // XOR with 0x02 maps ALL <-> SINGLE and NONE <-> ALL-like values:
            // always a different byte, so the signature's committed hash no
            // longer matches what the verifier computes.
            *byte ^= 0x02;
            input.script_sig = ScriptBuf::from_bytes(bytes);
            return true;
        }
    }
    for input in &mut tx.input {
        let mut elements = input.witness.to_vec();
        let mut mutated = false;
        for element in &mut elements {
            if looks_like_der_sig(element) || element.len() == 65 {
                if let Some(byte) = element.last_mut() {
                    *byte ^= 0x02;
                    mutated = true;
                    break;
                }
            }
            if element.len() == 64 {
                // 64-byte Schnorr signatures use the implicit SIGHASH_DEFAULT;
                // appending an explicit non-default type re-binds the
                // signature to a hash it never committed to.
                element.push(0x03);
                mutated = true;
                break;
            }
        }
        if mutated {
            input.witness = Witness::from_slice(&elements);
            return true;
        }
    }
    false
}

fn tamper_witness(tx: &mut Transaction) -> bool {
    for input in &mut tx.input {
        let mut elements = input.witness.to_vec();
        if let Some(last) = elements.last_mut()
            && !last.is_empty()
        {
            let mid = last.len() / 2;
            if let Some(byte) = last.get_mut(mid) {
                *byte ^= 0x01;
                input.witness = Witness::from_slice(&elements);
                return true;
            }
        }
    }
    false
}

fn truncate_witness(tx: &mut Transaction) -> bool {
    for input in &mut tx.input {
        let mut elements = input.witness.to_vec();
        if elements.pop().is_some() {
            input.witness = Witness::from_slice(&elements);
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// On-disk fixture schema for `tests/vectors/scripts/*.json`. Provenance
/// fields (`txid`, `height`, `source`) are validated or recorded at load;
/// see the adjacent `README.md` manifest.
#[derive(Deserialize)]
struct FixtureFile {
    /// Human label for assertion messages.
    name: String,
    /// Script class the fixture exercises (e.g. `p2pkh`, `taproot_keypath`).
    class: String,
    /// Expected txid; the loader recomputes and cross-checks it.
    txid: String,
    /// Expected wtxid; the loader recomputes and cross-checks it. The txid
    /// alone authenticates only the witness-stripped serialization (ADV-W1);
    /// the wtxid commits to the witness bytes too. For pre-segwit
    /// transactions wtxid == txid — still recorded and still checked, so the
    /// schema stays uniform.
    wtxid: String,
    /// Mainnet height the spend confirmed at (documentation + messages).
    height: u32,
    /// Where the raw data was frozen from (auditable provenance).
    #[allow(dead_code, reason = "provenance lives in the JSON; read by humans")]
    source: String,
    /// Core-named verify flags active at `height`.
    flags: String,
    /// Whether the in-repo Rust interpreter natively supports this class
    /// (see module docs: single-input taproot key-path only).
    interpreter_parity: bool,
    /// Raw transaction hex.
    tx_hex: String,
    /// Every input's prevout, in input order.
    prevouts: Vec<PrevoutFile>,
}

/// One prevout in the on-disk fixture schema.
#[derive(Deserialize)]
struct PrevoutFile {
    /// scriptPubKey hex of the spent output.
    script_hex: String,
    /// Amount of the spent output in satoshis.
    amount_sat: u64,
}

/// A loaded, validated fixture.
struct Fixture {
    /// Human label for assertion messages.
    name: String,
    /// Script class the fixture exercises.
    class: String,
    /// Mainnet height of the spend.
    height: u32,
    /// Whether interpreter-vs-kernel parity is asserted for this fixture.
    interpreter_parity: bool,
    /// The decoded pristine transaction.
    tx: Transaction,
    /// Every input's prevout, in input order.
    prevouts: Vec<TxOut>,
    /// Parsed verify flags active at `height`.
    flags: VerifyFlags,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/scripts")
}

/// Loads and validates the committed fixture corpus. Every failure is loud:
/// a missing directory, unparseable JSON, a txid mismatch, or a prevout-count
/// mismatch is an error, never a skip.
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
    let tx: Transaction = encode::deserialize(&decode_hex(&file.tx_hex)?)
        .map_err(|error| format!("{}: tx hex does not decode: {error}", path.display()))?;
    let computed_txid = tx.compute_txid().to_string();
    if computed_txid != file.txid {
        return Err(format!(
            "{}: txid mismatch: manifest says {} but tx hex hashes to {computed_txid}",
            path.display(),
            file.txid
        )
        .into());
    }
    let computed_wtxid = tx.compute_wtxid().to_string();
    if computed_wtxid != file.wtxid {
        return Err(format!(
            "{}: wtxid mismatch: manifest says {} but tx hex hashes to {computed_wtxid} \
             (witness bytes are not what was frozen)",
            path.display(),
            file.wtxid
        )
        .into());
    }
    if file.prevouts.len() != tx.input.len() {
        return Err(format!(
            "{}: {} prevouts for {} inputs; every input needs its prevout \
             (the kernel taproot path requires all of them)",
            path.display(),
            file.prevouts.len(),
            tx.input.len()
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
                script_pubkey: ScriptBuf::from_bytes(decode_hex(&prevout.script_hex)?),
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
    if !hex.len().is_multiple_of(2) {
        return Err("hex string has odd length".into());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let digits = hex.as_bytes();
    for pair in digits.chunks_exact(2) {
        let value = u8::from_str_radix(str::from_utf8(pair)?, 16)?;
        bytes.push(value);
    }
    Ok(bytes)
}

/// Rejects an empty fixture set so the verdict loop cannot pass vacuously.
/// The loop below iterates fixtures, so zero fixtures means zero assertions —
/// success while testing nothing. This guard stays red-on-empty.
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

// ---------------------------------------------------------------------------
// Test 1: per-input script verdicts over the committed corpus.
// ---------------------------------------------------------------------------

/// Pins kernel script verdicts over every fixture and mutation, and asserts
/// interpreter-vs-kernel parity for the classes the Rust interpreter natively
/// supports (see module docs for the honest scoping).
///
/// This is explicitly **not** block-acceptance parity: it ignores coinbase
/// subsidy, BIP30/34 rules, merkle/witness commitments, the sigop budget, and
/// chain context. It pins the one surface both engines share — per-input
/// script verification — which is exactly the surface the kernel build's
/// apply path delegates to Core.
#[test]
fn script_verdict_parity() -> TestResult {
    let fixtures = load_fixtures()?;
    require_non_empty(&fixtures)?;

    let mut interpreter_scoped = 0usize;
    for fixture in &fixtures {
        let pristine_bytes = encode::serialize(&fixture.tx);
        let mut reject_mutations = 0usize;

        for mutation in Mutation::ALL {
            let Some(tx) = mutation.apply(&fixture.tx) else {
                continue;
            };
            if mutation != Mutation::Pristine {
                assert_ne!(
                    encode::serialize(&tx),
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
            // ADV-W3: a rejection only counts when a script actually executed
            // and failed. `Verdict::of` maps *any* error to `Reject`, so a
            // kernel parse/precompute failure (`ConsensusError::Kernel`) would
            // otherwise satisfy the rejection assertion without exercising the
            // mutation at all. Infrastructure failures must fail the test.
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

// ---------------------------------------------------------------------------
// Test 2: the differential cannot be kernel-vs-kernel (ADV-1 pin).
// ---------------------------------------------------------------------------

/// Proves [`script_verdict_parity`]'s Rust side is not the kernel in disguise
/// by asserting the engines *disagree* on two inputs where they are known to
/// differ. If anyone re-routes [`interpreter_result`] through the production
/// `verify_transaction` (which dispatches to the kernel under this feature),
/// both checks collapse into agreement and this test goes red.
///
/// Known divergences used:
/// 1. An `OP_TRUE` output spent with a non-empty scriptSig: the kernel
///    executes it and accepts; the interpreter's non-taproot path in this
///    binary (no `bitcoinconsensus`) only accepts the empty-scriptSig
///    `OP_TRUE` form and rejects everything else.
/// 2. The committed taproot **script-path** fixture: the kernel accepts the
///    pristine spend; the interpreter supports only key-path witnesses and
///    rejects script-path spends by construction.
#[test]
fn differential_is_non_vacuous() -> TestResult {
    // (1) Crafted divergence, independent of the committed corpus.
    let tx = op_true_spend_with_push_script_sig();
    let prevouts = vec![TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    }];
    let kernel = kernel_result(&tx, &prevouts, VerifyFlags::NONE);
    let interpreter = interpreter_result(&tx, &prevouts, VerifyFlags::NONE);
    assert_eq!(
        Verdict::of(&kernel),
        Verdict::Accept,
        "kernel must accept OP_TRUE spent with a push-only scriptSig: {kernel:?}"
    );
    assert_eq!(
        Verdict::of(&interpreter),
        Verdict::Reject,
        "interpreter must reject the non-empty-scriptSig OP_TRUE spend; if it \
         accepted, the Rust side of the differential is reaching the kernel"
    );

    // (2) Fixture-grounded divergence on a real mainnet spend.
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
        Verdict::Reject,
        "interpreter must reject the script-path spend (key-path-only support); \
         agreement here means the differential collapsed to kernel-vs-kernel"
    );
    Ok(())
}

/// A minimal transaction spending an `OP_TRUE` output with `scriptSig =
/// OP_PUSHNUM_1`. Not consensus-valid as a chain transaction (null prevout);
/// it only needs to drive per-input script verification.
fn op_true_spend_with_push_script_sig() -> Transaction {
    use bitcoin::{Sequence, TxIn, absolute, transaction};

    Transaction {
        version: transaction::Version(1),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x51]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

// ---------------------------------------------------------------------------
// Catalog self-test: keeps the mutation catalog honest.
// ---------------------------------------------------------------------------

/// Guards the mutation catalog itself: `Pristine` must be a byte-exact no-op
/// (so the "engines accept the genuine article" pin is meaningful) and `ALL`
/// must contain it exactly once.
#[test]
fn pristine_mutation_is_identity() -> TestResult {
    let tx = op_true_spend_with_push_script_sig();
    let before = encode::serialize(&tx);
    let after_tx = Mutation::Pristine
        .apply(&tx)
        .ok_or("Pristine must always apply")?;
    assert_eq!(
        before,
        encode::serialize(&after_tx),
        "Pristine mutation must be a byte-exact identity"
    );

    let pristine_count = Mutation::ALL
        .iter()
        .filter(|mutation| matches!(mutation, Mutation::Pristine))
        .count();
    assert_eq!(
        pristine_count, 1,
        "catalog must contain Pristine exactly once"
    );
    Ok(())
}
