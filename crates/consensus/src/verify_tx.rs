use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::Instant;

use bitcoin_rs_primitives::{Amount, OutPoint, Sequence, Tx, TxOut};

use crate::block_view::BlockView;
use crate::sigops::transaction_sigop_cost;
use bitcoin_rs_script::Interpreter;
use bitcoin_rs_script::VerifyFlags;
use rayon::prelude::*;

use crate::ScriptEngine;
use crate::UtxoView;
use crate::{ConsensusError, MAX_BLOCK_SIGOPS_COST, ValidationEngine};

const LOCKTIME_THRESHOLD: u32 = 500_000_000;
const SEQUENCE_FINAL: u32 = 0xffff_ffff;
const MIN_COINBASE_SCRIPT_SIG_SIZE: usize = 2;
const MAX_COINBASE_SCRIPT_SIG_SIZE: usize = 100;

/// Number of blocks after a coinbase that its outputs become spendable.
pub const COINBASE_MATURITY: u32 = 100;

// Width of the script-verification pool. 16 was chosen on the belief that SMT
// siblings slow secp256k1 down past that width. A full-verification replay of
// mainnet 0..150_000 reading local block files measures otherwise on this host
// (2x medians, `taskset -c 0-31`, wall and CPU together):
//
//    8 threads   130.6s wall   474.2s CPU
//   16 threads    97.7s wall   521.3s CPU
//   24 threads    83.7s wall   590.9s CPU
//   32 threads    78.4s wall   652.3s CPU
//
// Wall falls monotonically with width while CPU rises sublinearly, so unlike
// the threshold below this genuinely trades: 32 buys 1.67x the wall of 8 for
// 1.38x the CPU, and wall is what a syncing node is waiting on. 32 equals the
// core count here, and an earlier sweep found no gain from exceeding it.
//
// Re-measured after the block source was matched to Core's; the numbers this
// rationale first carried (157.8s at 32, 173.1s at 16) came from the contended
// REST harness. Same conclusion, sounder evidence — see CONCEPTS.md
// → *Contended-harness tuning artefact*. Kept as a cap rather than raised to
// verification against the rest of the apply pipeline; widen only against a
// fresh measurement on the target hardware.
const MAX_SCRIPT_VERIFY_THREADS: usize = 32;
// Blocks with fewer checks than this verify serially. Measured on a
// full-verification replay of mainnet 0..150_000 reading local block files,
// `taskset -c 0-31`, three interleaved rounds, wall and CPU together:
//
//   threshold    4    84.4s wall   946.6s CPU
//   threshold   16    80.1s wall   773.2s CPU
//   threshold   32    75.5s wall   649.6s CPU   <- both optima
//   threshold   64    78.4s wall   533.6s CPU
//   threshold  128    94.0s wall   390.7s CPU
//
// 32 is the wall minimum and also beats every smaller value on CPU, so it
// dominates rather than trades. CPU keeps falling above it, but wall turns
// sharply at 128, and a node that finishes later has not saved anything.
//
// This replaced a value of 4, which an earlier sweep picked while the harness
// fetched every block over REST from a second bitcoind competing for the same
// cores. That contention inflated the serial path and made ever-finer fan-out
// look free. Re-measured against local block files the ordering inverts, and 4
// is now the worst point tested on both axes. Do not tune this against a
// harness that shares CPU with the node, and do not tune it on wall alone.
const MIN_PARALLEL_SCRIPT_CHECKS: usize = 32;
static SCRIPT_VERIFY_POOL: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    rayon::ThreadPoolBuilder::new()
        .num_threads(available.min(MAX_SCRIPT_VERIFY_THREADS))
        .thread_name(|index| format!("script-verify-{index}"))
        .build()
        .unwrap_or_else(|error| panic!("failed to build script verification pool: {error}"))
});

/// Returns `true` iff the transaction is locktime-final at `block_height` and
/// the timestamp cutoff.
#[must_use]
pub fn is_final_tx(tx: &Tx, block_height: u32, locktime_cutoff: u32) -> bool {
    let lock_time = tx.lock_time.to_consensus();
    if lock_time == 0 {
        return true;
    }

    let threshold = if lock_time < LOCKTIME_THRESHOLD {
        block_height
    } else {
        locktime_cutoff
    };
    if lock_time < threshold {
        return true;
    }

    tx.inputs
        .iter()
        .all(|input| input.sequence == Sequence::from_consensus(SEQUENCE_FINAL))
}

/// Verifies that a coinbase transaction's scriptSig length is within consensus
/// bounds.
pub fn verify_coinbase_script_sig_size(tx: &Tx) -> Result<(), ConsensusError> {
    if let Some(input) = tx.inputs.first().filter(|_| is_coinbase(tx)) {
        let len = input.script_sig.len();
        if !(MIN_COINBASE_SCRIPT_SIG_SIZE..=MAX_COINBASE_SCRIPT_SIG_SIZE).contains(&len) {
            return Err(ConsensusError::CoinbaseScriptSigSize { len });
        }
    }
    Ok(())
}

/// Returns `true` for the one-input, null-prevout coinbase shape.
pub(crate) fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null()
}

/// Checks whether a transaction may spend a coinbase output at `spend_height`.
pub fn check_coinbase_maturity(
    coinbase: bool,
    created_height: u32,
    spend_height: u32,
) -> Result<(), ConsensusError> {
    let depth = spend_height.saturating_sub(created_height);
    if coinbase && depth < COINBASE_MATURITY {
        return Err(ConsensusError::Bip {
            bip: "COINBASE_MATURITY",
            reason: format!(
                "spent coinbase output created at height {created_height} cannot be spent at height {spend_height} (depth {depth} < {COINBASE_MATURITY})"
            ),
        });
    }
    Ok(())
}

/// Verifies non-contextual and input-script transaction rules for a
/// transaction.
pub fn verify_transaction(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    engine: ValidationEngine,
) -> Result<(), ConsensusError> {
    verify_transaction_with_locktime_cutoff(
        tx,
        prevouts,
        height,
        locktime_cutoff,
        flags,
        engine,
        false,
    )
}

/// Verifies non-script transaction rules for a transaction with a caller-
/// selected timestamp cutoff.
pub fn verify_transaction_non_script(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_with_locktime_cutoff(
        tx,
        prevouts,
        height,
        locktime_cutoff,
        flags,
        ValidationEngine::Native,
        true,
    )
}

fn verify_transaction_with_locktime_cutoff(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    engine: ValidationEngine,
    skip_scripts: bool,
) -> Result<(), ConsensusError> {
    // A coinbase skips dispatch, so selection must be checked before preparation.
    if !engine.is_supported() {
        return Err(ConsensusError::UnsupportedEngine { engine });
    }
    let Some(prep) = prepare_tx_checks(tx, height, locktime_cutoff, |_, outpoint| {
        prevouts.lookup(outpoint)
    })?
    else {
        return Ok(());
    };

    if !skip_scripts {
        crate::kernel::verify_tx_scripts(tx, &prep.prevouts, flags, engine)?;
    }

    finalize_tx_value_and_sigops(tx, &prep, flags)
}

struct TxPrep {
    prevouts: Vec<(OutPoint, TxOut)>,
    input_value: u64,
    output_value: u64,
}

/// Rejects null or repeated input outpoints outside coinbase transactions.
pub fn verify_transaction_input_outpoints(tx: &Tx) -> Result<(), ConsensusError> {
    if is_coinbase(tx) {
        return Ok(());
    }
    let mut seen = HashSet::new();
    for (input_index, input) in tx.inputs.iter().enumerate() {
        if input.previous_output.is_null() {
            return Err(ConsensusError::NullPrevout { input_index });
        }
        if !seen.insert(input.previous_output) {
            return Err(ConsensusError::DuplicateInput { input_index });
        }
    }
    Ok(())
}

fn prepare_tx_checks(
    tx: &Tx,
    height: u32,
    locktime_cutoff: u32,
    mut lookup: impl FnMut(usize, &OutPoint) -> Option<TxOut>,
) -> Result<Option<TxPrep>, ConsensusError> {
    if !is_final_tx(tx, height, locktime_cutoff) {
        return Err(ConsensusError::Bip {
            bip: "BIP113",
            reason: format!(
                "non-final transaction at height {height} locktime cutoff \
                 {locktime_cutoff}: locktime {}",
                tx.lock_time
            ),
        });
    }

    if tx.inputs.is_empty() {
        return Err(ConsensusError::EmptyInputs);
    }
    if tx.outputs.is_empty() {
        return Err(ConsensusError::EmptyOutputs);
    }

    let output_value = total_output_value(tx)?;
    if is_coinbase(tx) {
        verify_coinbase_script_sig_size(tx)?;
        return Ok(None);
    }

    verify_transaction_input_outpoints(tx)?;

    let mut input_value = 0u64;
    let mut prevouts = Vec::with_capacity(tx.inputs.len());
    for (input_index, input) in tx.inputs.iter().enumerate() {
        let prevout = lookup(input_index, &input.previous_output)
            .ok_or(ConsensusError::MissingPrevout { input_index })?;
        input_value = input_value
            .checked_add(prevout.value.to_sat())
            .ok_or(ConsensusError::OutputValueOverflow)?;
        prevouts.push((input.previous_output, prevout));
    }

    Ok(Some(TxPrep {
        prevouts,
        input_value,
        output_value,
    }))
}

fn finalize_tx_value_and_sigops(
    tx: &Tx,
    prep: &TxPrep,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    if prep.input_value < prep.output_value {
        return Err(ConsensusError::InputsLessThanOutputs {
            input_value: prep.input_value,
            output_value: prep.output_value,
        });
    }

    let sigop_cost = transaction_sigop_cost(tx, &prep.prevouts, flags);
    if sigop_cost > MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusError::SigopsLimit {
            cost: sigop_cost,
            max: MAX_BLOCK_SIGOPS_COST,
        });
    }
    Ok(())
}

pub(crate) fn verify_input_script_native(
    input_index: usize,
    spent_outputs: &[TxOut],
    tx: &Tx,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    let input = &tx.inputs[input_index];
    let prevout = &spent_outputs[input_index];
    Interpreter
        .execute_with_prevouts(
            &prevout.script_pubkey,
            &input.script_sig,
            &input.witness,
            flags,
            spent_outputs,
            tx,
            input_index,
        )
        .map_err(|error| ConsensusError::Script {
            input_index,
            reason: error.to_string(),
            engine: ScriptEngine::Native,
        })?;
    Ok(())
}

struct PreparedTx<'b> {
    tx: &'b Tx,
    spent_outputs: Vec<TxOut>,
    pre_error: Option<ConsensusError>,
    post_error: Option<ConsensusError>,
    checks_start: usize,
    checks_len: usize,
    script_state: Option<crate::kernel::PreparedTx<'b>>,
}

struct InputCheck {
    prepared_index: usize,
    input_index: usize,
}

/// Sub-stage durations of [`verify_block_input_scripts`], reported to the
/// caller.
#[derive(Clone, Copy, Default)]
pub struct ScriptStageTimings {
    /// Serial per-transaction preparation (`prepare_block_input_checks`), in
    /// seconds.
    pub prepare_seconds: f64,
    /// Input-check fan-out (rayon pool install plus join, or the serial fallback
    /// for small blocks), excluding the ordered error scan, in seconds.
    pub parallel_seconds: f64,
}

/// Verifies every input script across a block in one flat, block-ordered pass.
pub fn verify_block_input_scripts(
    view: &mut BlockView<'_>,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    timings: &mut ScriptStageTimings,
    parsed: &crate::kernel::BlockParse,
) -> Result<(), ConsensusError> {
    let prepare_started = Instant::now();
    let unit = prepare_block_script_checks(view, height, locktime_cutoff, flags, parsed)?;
    timings.prepare_seconds = prepare_started.elapsed().as_secs_f64();

    let parallel_started = Instant::now();
    let mut set_parallel_seconds = || {
        timings.parallel_seconds = parallel_started.elapsed().as_secs_f64();
    };
    let mut before_serial_scan = || {};
    let verdict = verify_prepared_units_with_hooks(
        core::slice::from_ref(&unit),
        &mut set_parallel_seconds,
        &mut before_serial_scan,
    );
    verdict.map_err(|failure| failure.error)
}

/// One block's script checks, prepared but not executed.
pub struct BlockScriptChecks<'b> {
    prepared: Vec<PreparedTx<'b>>,
    checks: Vec<InputCheck>,
    flags: VerifyFlags,
}

/// Which unit failed, and how.
#[derive(Debug)]
pub struct BatchScriptFailure {
    /// Position of the failing unit.
    pub unit: usize,
    /// The failure, identical to what the single-block path would report.
    pub error: ConsensusError,
}

/// Resolves one block's order-sensitive transaction state without executing any
/// script.
pub fn prepare_block_script_checks<'tx, 'checks>(
    view: &mut BlockView<'tx>,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    parsed: &'checks crate::kernel::BlockParse,
) -> Result<BlockScriptChecks<'checks>, ConsensusError>
where
    'tx: 'checks,
{
    let (txs, resolved) = view.parts_mut();
    if txs.len() != resolved.len() {
        return Err(ConsensusError::PrevoutMatrixSize {
            expected: txs.len(),
            actual: resolved.len(),
        });
    }
    let (prepared, checks) =
        prepare_block_input_checks(txs, resolved, height, locktime_cutoff, flags, parsed);
    Ok(BlockScriptChecks {
        prepared,
        checks,
        flags,
    })
}

fn verify_prepared_units_with_hooks<AfterParallel, BeforeSerialScan>(
    units: &[BlockScriptChecks<'_>],
    after_parallel: &mut AfterParallel,
    before_serial_scan: &mut BeforeSerialScan,
) -> Result<(), BatchScriptFailure>
where
    AfterParallel: FnMut(),
    BeforeSerialScan: FnMut(),
{
    // Fixed offsets keep result slices independent of scan order.
    let mut offsets = Vec::with_capacity(units.len());
    let mut total = 0_usize;
    for unit in units {
        offsets.push(total);
        let Some(next) = total.checked_add(unit.checks.len()) else {
            return Err(layout_failure(0));
        };
        total = next;
    }

    let run = |(unit_index, check): &(usize, &InputCheck)| {
        let unit = &units[*unit_index];
        check_input(&unit.prepared, check, unit.flags)
    };
    let flat: Vec<(usize, &InputCheck)> = units
        .iter()
        .enumerate()
        .flat_map(|(index, unit)| unit.checks.iter().map(move |check| (index, check)))
        .collect();
    let results: Vec<Result<(), ConsensusError>> = if total < MIN_PARALLEL_SCRIPT_CHECKS {
        flat.iter().map(run).collect()
    } else {
        SCRIPT_VERIFY_POOL.install(|| flat.par_iter().map(run).collect())
    };

    // Timing must stop here: the ordered scan below is serial attribution work,
    // not parallel script execution.
    after_parallel();
    before_serial_scan();

    for (unit_index, unit) in units.iter().enumerate() {
        let from = offsets[unit_index];
        let Some(to) = from.checked_add(unit.checks.len()) else {
            return Err(layout_failure(unit_index));
        };
        let Some(slice) = results.get(from..to) else {
            return Err(layout_failure(unit_index));
        };
        match first_prepared_error(&unit.prepared, slice) {
            Ok(Some(error)) => {
                return Err(BatchScriptFailure {
                    unit: unit_index,
                    error,
                });
            }
            Ok(None) => {}
            Err(()) => return Err(layout_failure(unit_index)),
        }
    }
    Ok(())
}

/// Executes prepared script checks and reports the first failure in unit order.
pub fn verify_prepared_units(units: &[BlockScriptChecks<'_>]) -> Result<(), BatchScriptFailure> {
    let mut after = || {};
    let mut before = || {};
    verify_prepared_units_with_hooks(units, &mut after, &mut before)
}

/// Reports an internal prepared-check layout mismatch.
fn layout_failure(unit: usize) -> BatchScriptFailure {
    BatchScriptFailure {
        unit,
        error: ConsensusError::Kernel(
            "internal: prepared script-check layout does not match its results".to_owned(),
        ),
    }
}

/// First failure within one prepared block, in transaction order with phase
/// `pre < script < post`.
fn first_prepared_error(
    prepared: &[PreparedTx<'_>],
    results: &[Result<(), ConsensusError>],
) -> Result<Option<ConsensusError>, ()> {
    for prep in prepared {
        if let Some(error) = &prep.pre_error {
            return Ok(Some(error.clone()));
        }
        let Some(to) = prep.checks_start.checked_add(prep.checks_len) else {
            return Err(());
        };
        let Some(slice) = results.get(prep.checks_start..to) else {
            return Err(());
        };
        for result in slice {
            if let Err(error) = result {
                return Ok(Some(error.clone()));
            }
        }
        if let Some(error) = &prep.post_error {
            return Ok(Some(error.clone()));
        }
    }
    Ok(None)
}

/// Resolves order-sensitive transaction state before script checks fan out.
fn prepare_block_input_checks<'b>(
    txs: &'b [Tx],
    resolved: &mut [Vec<Option<TxOut>>],
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    parsed: &'b crate::kernel::BlockParse,
) -> (Vec<PreparedTx<'b>>, Vec<InputCheck>) {
    let mut prepared = Vec::with_capacity(txs.len());
    let mut checks = Vec::new();
    for (tx_index, tx) in txs.iter().enumerate() {
        let resolved_inputs = &mut resolved[tx_index];
        let prep = match prepare_tx_checks(tx, height, locktime_cutoff, |input_index, _| {
            resolved_inputs.get_mut(input_index).and_then(Option::take)
        }) {
            Ok(Some(prep)) => prep,
            Ok(None) => {
                prepared.push(PreparedTx {
                    tx,
                    spent_outputs: Vec::new(),
                    pre_error: None,
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    script_state: None,
                });
                continue;
            }
            Err(pre_error) => {
                prepared.push(PreparedTx {
                    tx,
                    spent_outputs: Vec::new(),
                    pre_error: Some(pre_error),
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    script_state: None,
                });
                break;
            }
        };

        // Every input needs the complete spent-output set for BIP341.
        let spent_outputs: Vec<TxOut> = prep
            .prevouts
            .iter()
            .map(|(_, spent)| spent.clone())
            .collect();

        let script_state = match parsed.prepare_tx(tx_index, tx.inputs.len(), &prep.prevouts) {
            Ok(state) => state,
            Err(setup_error) => {
                prepared.push(PreparedTx {
                    tx,
                    spent_outputs,
                    pre_error: Some(setup_error),
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    script_state: None,
                });
                break;
            }
        };

        let prepared_index = prepared.len();
        let checks_start = checks.len();
        for input_index in 0..tx.inputs.len() {
            checks.push(InputCheck {
                prepared_index,
                input_index,
            });
        }
        let checks_len = tx.inputs.len();

        let post_error = finalize_tx_value_and_sigops(tx, &prep, flags).err();
        let stop_after_tx = post_error.is_some();
        prepared.push(PreparedTx {
            tx,
            spent_outputs,
            pre_error: None,
            post_error,
            checks_start,
            checks_len,
            script_state: Some(script_state),
        });
        // This tx's scripts still outrank its post error; that post error makes
        // every later transaction irrelevant to the ordered verdict.
        if stop_after_tx {
            break;
        }
    }
    (prepared, checks)
}

fn check_input(
    prepared: &[PreparedTx<'_>],
    check: &InputCheck,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    let prep = &prepared[check.prepared_index];
    let script_state = prep.script_state.as_ref().ok_or_else(|| {
        ConsensusError::Kernel("clean non-coinbase tx lost prepared script state".to_owned())
    })?;
    crate::kernel::verify_prepared_input(
        script_state,
        &prep.spent_outputs,
        prep.tx,
        check.input_index,
        flags,
    )
}

fn total_output_value(tx: &Tx) -> Result<u64, ConsensusError> {
    tx.outputs.iter().try_fold(0u64, |sum, output| {
        let next = sum
            .checked_add(output.value.to_sat())
            .ok_or(ConsensusError::OutputValueOverflow)?;
        if Amount::from_sat(next) > Amount::MAX_MONEY {
            Err(ConsensusError::OutputValueOverflow)
        } else {
            Ok(next)
        }
    })
}

#[cfg(test)]
mod tests {

    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script,
        Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes, deserialize,
    };
    #[cfg(not(feature = "kernel"))]
    use bitcoin_rs_primitives::{Sighash, SighashCache};
    use bitcoin_rs_script::opcode::{OP_EQUAL, OP_HASH160};
    use bitcoin_rs_script::push_data;
    use bitcoin_rs_script::{VerifyFlags, push_int};

    use super::{
        ScriptStageTimings, is_final_tx, verify_coinbase_script_sig_size, verify_transaction,
    };
    use crate::ValidationEngine;

    fn parsed_block_for(txs: &[Tx], engine: ValidationEngine) -> crate::kernel::BlockParse {
        let block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: CompactTarget::from_consensus(0x2000_ffff),
                nonce: 0,
            },
            txs: txs.to_vec(),
        };
        crate::kernel::BlockParse::parse(&consensus_bytes(&block), engine)
            .unwrap_or_else(|error| panic!("synthetic block must parse: {error}"))
    }

    #[cfg(feature = "kernel")]
    const TEST_ENGINE: ValidationEngine = ValidationEngine::Kernel;
    #[cfg(not(feature = "kernel"))]
    const TEST_ENGINE: ValidationEngine = ValidationEngine::Native;

    fn test_block_parse(txs: &[Tx]) -> crate::kernel::BlockParse {
        parsed_block_for(txs, TEST_ENGINE)
    }

    fn block_view_for(
        txs: &[Tx],
        resolved: Vec<Vec<Option<TxOut>>>,
    ) -> crate::block_view::BlockView<'_> {
        let mut view = crate::block_view::BlockView::new(txs, txs.iter().map(Tx::txid).collect());
        view.set_resolved(resolved);
        view
    }
    use crate::{ConsensusError, ScriptEngine, UtxoView};

    impl UtxoView for hashbrown::HashMap<OutPoint, TxOut> {
        fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
            self.get(outpoint).cloned()
        }
    }

    // Activation contract: BIP141, "Sigops" (https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#sigops),
    // as implemented by Bitcoin Core v31.1 in src/validation.cpp:
    // https://github.com/bitcoin/bitcoin/blob/v31.1/src/validation.cpp
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
                sequence: Sequence::from_consensus(u32::MAX),
                witness: Witness::from_stack(vec![vec![0xac; usize::try_from(cost)?]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::from_consensus(0),
        };
        let prevouts = hashbrown::HashMap::from([(
            outpoint,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes([vec![0x00, 0x20], vec![1; 32]].concat()),
            },
        )]);
        // The assume-valid path skips script execution, not sigop accounting.
        // Active flags remain explicit even though script execution is skipped.
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
        // Batched preparation binds the same flags used by execution, so its
        // cached post-error cannot come from a different activation context.
        let txs = vec![tx];
        let block = test_block_parse(&txs);
        let resolved = vec![vec![prevouts.get(&outpoint).cloned()]];
        let inactive = super::prepare_block_script_checks(
            &mut block_view_for(&txs, resolved.clone()),
            0,
            0,
            VerifyFlags::P2SH,
            &block,
        )?;
        assert!(inactive.prepared[0].post_error.is_none());
        assert!(super::verify_prepared_units(core::slice::from_ref(&inactive)).is_ok());
        let active = super::prepare_block_script_checks(
            &mut block_view_for(&txs, resolved),
            0,
            0,
            VerifyFlags::MANDATORY,
            &block,
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
                verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY, TEST_ENGINE),
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
                TEST_ENGINE
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
                TEST_ENGINE
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
            let secret =
                SecretKey::from_slice(&[seed; 32]).unwrap_or_else(|_| panic!("secret key"));
            let keypair = Keypair::from_secret_key(&secp, &secret);
            // BIP341 key-only tweak: t = TaggedHash("TapTweak", x_only_pubkey || [0u8; 32])
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
            tweak_hash.update([0u8; 32]); // empty merkle root
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
            script_pubkey.push(0x51); // OP_1
            script_pubkey.push(0x20); // push 32 bytes
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
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            outputs: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: push_int(1).into(),
            }],
        };

        for (input_idx, keypair) in keypairs.iter().enumerate() {
            let mut cache = SighashCache::new(&tx);
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
            verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY, TEST_ENGINE),
            Ok(())
        );
    }

    #[test]
    #[cfg(feature = "kernel")]
    fn kernel_accepts_non_taproot_spend_with_script_sig_data() {
        let outpoint = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[7; 32])),
            vout: 0,
        };
        let tx = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: [push_int(7), push_int(7)].concat().into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            }],
        };
        let mut utxos = hashbrown::HashMap::new();
        utxos.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: vec![OP_EQUAL].into(),
            },
        );

        assert_eq!(
            verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY, TEST_ENGINE),
            Ok(())
        );
    }

    #[test]
    #[cfg(feature = "kernel")]
    fn kernel_rejects_script_sig_mismatch_with_kernel_verdict() {
        let outpoint = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[8; 32])),
            vout: 0,
        };
        let tx = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: [push_int(7), push_int(8)].concat().into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            }],
        };
        let mut utxos = hashbrown::HashMap::new();
        utxos.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: vec![OP_EQUAL].into(),
            },
        );

        let result = verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY, TEST_ENGINE);

        // Pins the client-facing bytes: the kernel verdict still arrives
        // behind the unchanged prefix. Classification uses the engine field.
        let Err(ConsensusError::Script {
            input_index,
            reason,
            engine,
        }) = result
        else {
            panic!("a kernel script rejection is expected");
        };
        assert_eq!(input_index, 0);
        assert_eq!(engine, ScriptEngine::Kernel);
        assert!(
            reason
                .strip_prefix(crate::kernel::KERNEL_SCRIPT_REJECT_PREFIX)
                .is_some_and(|verdict| !verdict.is_empty()),
            "the reject reason lost its kernel prefix: {reason}"
        );
    }

    #[test]
    #[cfg(feature = "kernel")]
    fn kernel_skip_scripts_entry_accepts_invalid_script() {
        let outpoint = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[9; 32])),
            vout: 0,
        };
        let tx = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: [push_int(7), push_int(8)].concat().into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            }],
        };
        let mut utxos = hashbrown::HashMap::new();
        utxos.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: vec![OP_EQUAL].into(),
            },
        );

        assert_eq!(
            super::verify_transaction_non_script(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
        assert!(matches!(
            verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY, TEST_ENGINE),
            Err(ConsensusError::Script { input_index: 0, .. })
        ));
    }

    #[test]
    fn locktime_finality_uses_the_height_and_the_caller_supplied_cutoff() {
        const TIMESTAMP: u32 = 500_000_100;
        // (locktime, height, cutoff, final)
        let cases: [(u32, u32, u32, bool); 8] = [
            (0, 0, 0, true),
            (200, 100, 0, false),
            (200, 200, 0, false),
            (200, 201, 0, true),
            (TIMESTAMP, 1, TIMESTAMP - 1, false),
            (TIMESTAMP, 1, TIMESTAMP, false),
            (TIMESTAMP, 1, TIMESTAMP + 1, true),
            // A height cutoff cannot retire a timestamp locktime.
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

            // A final sequence on every input overrides the locktime.
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
        // Fails on its second transaction, not its first.
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
        block: &'b crate::kernel::BlockParse,
        flags: VerifyFlags,
    ) -> super::BlockScriptChecks<'b> {
        let mut view = block_view_for(txs, resolved);
        match super::prepare_block_script_checks(&mut view, 0, 0, flags, block) {
            Ok(unit) => unit,
            Err(error) => panic!("test fixture prevout matrix is malformed: {error}"),
        }
    }

    fn true_spending_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
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
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
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

    fn mismatch_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: [push_int(7), push_int(8)].concat().into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
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
        // Backend reason text differs; both must report input zero.
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
        assert!(hex.len().is_multiple_of(2), "hex string has odd length");
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digits = std::str::from_utf8(pair).unwrap_or_else(|_| panic!("hex ascii"));
                u8::from_str_radix(digits, 16).unwrap_or_else(|_| panic!("hex digit"))
            })
            .collect()
    }

    fn load_taproot_scriptpath_fixture() -> TaprootScriptPathFixture {
        let json = include_str!("../tests/vectors/scripts/taproot_scriptpath_spend.json");
        let file: TaprootScriptPathFile = serde_json::from_str(json)
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
                TEST_ENGINE
            ),
            Ok(())
        );
    }

    #[test]
    fn parallel_timing_is_captured_before_ordered_error_scan() {
        use std::cell::Cell;

        let shared_tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: Vec::new(),
            outputs: Vec::new(),
        };
        let prepared: Vec<super::PreparedTx<'_>> = (0..10)
            .map(|_| super::PreparedTx {
                tx: &shared_tx,
                spent_outputs: Vec::new(),
                pre_error: None,
                post_error: None,
                checks_start: 0,
                checks_len: 0,
                script_state: None,
            })
            .collect();
        let unit = super::BlockScriptChecks {
            prepared,
            checks: Vec::new(),
            flags: VerifyFlags::MANDATORY,
        };
        let scan_started = Cell::new(false);
        let mut before_serial_scan = || scan_started.set(true);
        let mut after_parallel = || {
            assert!(
                !scan_started.get(),
                "parallel timing hook must run before the serial error scan"
            );
        };
        let result = super::verify_prepared_units_with_hooks(
            core::slice::from_ref(&unit),
            &mut after_parallel,
            &mut before_serial_scan,
        );
        assert!(result.is_ok());
        assert!(scan_started.get(), "the serial error scan must have run");
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
}
