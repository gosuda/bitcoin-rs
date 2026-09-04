use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::Instant;

use bitcoin_rs_primitives::{Amount, OutPoint, Sequence, Tx, TxOut, Txid};

use crate::block_view::BlockView;
#[cfg(not(feature = "kernel"))]
use bitcoin_rs_script::Interpreter;
use bitcoin_rs_script::script::instructions;
use bitcoin_rs_script::{
    Instruction, VerifyFlags, count_segwit, count_tx_legacy, is_p2sh, is_witness_program, opcode,
};
use rayon::prelude::*;

use crate::rust_path::UtxoView;
use crate::{ConsensusError, MAX_BLOCK_SIGOPS_COST};

const LOCKTIME_THRESHOLD: u32 = 500_000_000;
const SEQUENCE_FINAL: u32 = 0xffff_ffff;
const MIN_COINBASE_SCRIPT_SIG_SIZE: usize = 2;
const MAX_COINBASE_SCRIPT_SIG_SIZE: usize = 100;

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

/// Returns `true` iff the transaction is locktime-final at `block_height` and the timestamp cutoff.
///
/// Implements Bitcoin Core's `IsFinalTx`:
///   - locktime == 0: always final.
///   - locktime < `LOCKTIME_THRESHOLD`: height-based; final iff locktime < `block_height`.
///   - locktime >= `LOCKTIME_THRESHOLD`: timestamp-based; final iff locktime < `locktime_cutoff`.
///   - all inputs have sequence == `SEQUENCE_FINAL`: final regardless of locktime.
///
/// Callers choose the timestamp cutoff: block header time before BIP113, previous-tip MTP after.
#[must_use]
pub fn is_final_tx(tx: &Tx, block_height: u32, locktime_cutoff: u32) -> bool {
    is_final_tx_with_locktime_cutoff(tx, block_height, locktime_cutoff)
}

/// Verifies that a coinbase transaction's scriptSig length is within consensus bounds.
pub fn verify_coinbase_script_sig_size(tx: &Tx) -> Result<(), ConsensusError> {
    if let Some(input) = tx.inputs.first().filter(|_| is_coinbase(tx)) {
        let len = input.script_sig.len();
        if !(MIN_COINBASE_SCRIPT_SIG_SIZE..=MAX_COINBASE_SCRIPT_SIG_SIZE).contains(&len) {
            return Err(ConsensusError::CoinbaseScriptSigSize { len });
        }
    }
    Ok(())
}

fn is_coinbase(tx: &Tx) -> bool {
    tx.inputs.len() == 1 && is_null_outpoint(&tx.inputs[0].previous_output)
}

/// Core's `OutPoint::IsNull`: null hash plus `NULL_INDEX` (`u32::MAX`), the
/// coinbase marker. The derived all-zero outpoint (`vout` 0) is not null.
fn is_null_outpoint(outpoint: &OutPoint) -> bool {
    outpoint.txid == Txid::default() && outpoint.vout == u32::MAX
}

/// Returns `true` iff the transaction is locktime-final at `block_height` and `locktime_cutoff`.
///
/// Callers choose the timestamp cutoff: block header time before BIP113, previous-tip MTP after.
#[must_use]
fn is_final_tx_with_locktime_cutoff(tx: &Tx, block_height: u32, locktime_cutoff: u32) -> bool {
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

/// Verifies non-contextual and input-script transaction rules for a transaction.
///
/// `locktime_cutoff` is the caller-selected timestamp cutoff: block header time before
/// BIP113 activation and previous-tip MTP after. A `locktime_cutoff` of `0` retains the
/// old non-contextual behavior for callers that do not have an MTP.
pub fn verify_transaction(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_with_locktime_cutoff(tx, prevouts, height, locktime_cutoff, flags, false)
}

/// Verifies non-script transaction rules for a transaction with a caller-selected
/// timestamp cutoff.
///
/// Checks finality, empty inputs/outputs, coinbase scriptSig size, duplicate inputs, null
/// prevouts, missing prevouts, input/output value balance, and sigop limits. Skips
/// kernel/script script execution. This is the assume-valid entry.
pub fn verify_transaction_non_script(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
) -> Result<(), ConsensusError> {
    verify_transaction_with_locktime_cutoff(
        tx,
        prevouts,
        height,
        locktime_cutoff,
        VerifyFlags::NONE,
        true,
    )
}

fn verify_transaction_with_locktime_cutoff(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    skip_scripts: bool,
) -> Result<(), ConsensusError> {
    let Some(prep) = prepare_tx_checks(tx, height, locktime_cutoff, |_, outpoint| {
        prevouts.lookup(outpoint)
    })?
    else {
        // Coinbase: fully checked by the pre-phase; no inputs to verify.
        return Ok(());
    };

    if !skip_scripts {
        // Under the kernel feature every script class routes through Core's
        // engine — one transaction parse plus one sighash precompute shared across
        // inputs. Without it, the native interpreter in bitcoin-rs-script runs.
        #[cfg(feature = "kernel")]
        crate::kernel::verify_tx_scripts(tx, &prep.prevouts, flags)?;
        #[cfg(not(feature = "kernel"))]
        {
            // One clone of the spent outputs per transaction, shared by every
            // input check; BIP341 sighashes commit to the full ordered set.
            let spent_outputs: Vec<TxOut> = prep
                .prevouts
                .iter()
                .map(|(_, prevout)| prevout.clone())
                .collect();
            for input_index in 0..tx.inputs.len() {
                verify_input_script_portable(input_index, &spent_outputs, tx, flags)?;
            }
        }
    }

    finalize_tx_value_and_sigops(tx, &prep)
}

/// Resolved per-transaction state carried from the pre-phase into the script and
/// post phases.
struct TxPrep {
    prevouts: Vec<(OutPoint, TxOut)>,
    input_value: u64,
    output_value: u64,
}

/// Runs a transaction's non-script pre-checks: finality, empty in/out, total
/// output value, coinbase scriptSig size, duplicate/null inputs, and ordered
/// prevout resolution with input-value overflow. `lookup(input_index, outpoint)`
/// resolves each input's prevout. Returns `Ok(None)` for an accepted coinbase
/// (no inputs to verify) and `Ok(Some(prep))` for a clean non-coinbase tx.
fn prepare_tx_checks(
    tx: &Tx,
    height: u32,
    locktime_cutoff: u32,
    mut lookup: impl FnMut(usize, &OutPoint) -> Option<TxOut>,
) -> Result<Option<TxPrep>, ConsensusError> {
    if !is_final_tx_with_locktime_cutoff(tx, height, locktime_cutoff) {
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

    let mut seen = HashSet::new();
    for (input_index, input) in tx.inputs.iter().enumerate() {
        if is_null_outpoint(&input.previous_output) {
            return Err(ConsensusError::NullPrevout { input_index });
        }
        if !seen.insert(input.previous_output) {
            return Err(ConsensusError::DuplicateInput { input_index });
        }
    }

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

/// Runs a transaction's deferred post-checks: input/output value balance and the
/// sigop-cost limit, reusing the resolved prevouts.
fn finalize_tx_value_and_sigops(tx: &Tx, prep: &TxPrep) -> Result<(), ConsensusError> {
    if prep.input_value < prep.output_value {
        return Err(ConsensusError::InputsLessThanOutputs {
            input_value: prep.input_value,
            output_value: prep.output_value,
        });
    }

    let _ = 0usize;
    let sigop_cost = total_sigop_cost(tx, &prep.prevouts);
    if sigop_cost > MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusError::SigopsLimit {
            cost: sigop_cost,
            max: MAX_BLOCK_SIGOPS_COST,
        });
    }
    Ok(())
}

/// Portable per-input script verdict: the native interpreter covers every
/// consensus spend class (legacy, P2SH, `SegWit` v0, Taproot key-path and
/// script-path).
#[cfg(not(feature = "kernel"))]
fn verify_input_script_portable(
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
        })?;
    Ok(())
}

/// Per-transaction state retained across the flat block verify phases.
struct PreparedTx<'b> {
    #[cfg(not(feature = "kernel"))]
    /// Borrowed from the parse-once [`BlockView`]; every input check of this
    /// transaction reads the same decoded transaction without re-indexing.
    tx: &'b Tx,
    #[cfg(feature = "kernel")]
    prevouts: Vec<(OutPoint, TxOut)>,
    /// The prevouts of `prevouts` as a plain slice, cloned once per
    /// transaction instead of once per input check; the portable interpreter
    /// commits to every spent output in its sighashes.
    #[cfg(not(feature = "kernel"))]
    spent_outputs: Vec<TxOut>,
    pre_error: Option<ConsensusError>,
    post_error: Option<ConsensusError>,
    checks_start: usize,
    checks_len: usize,
    #[cfg(feature = "kernel")]
    kernel_state: Option<crate::kernel::PreparedKernelTx<bitcoinkernel::TransactionRef<'b>>>,
}

/// One deferred per-input script check, indexing back into the prepared txs.
struct InputCheck {
    prepared_index: usize,
    input_index: usize,
}

/// Sub-stage durations of [`verify_block_input_scripts`], reported to the caller.
///
/// The node layer uses these to attribute the script stage to its serial
/// preparation and parallel execution without adding a `metrics` dependency to
/// this crate. Both fields are written before the verdict is returned, so the
/// caller records them on the success and error paths.
#[derive(Clone, Copy, Default)]
pub struct ScriptStageTimings {
    /// Serial per-transaction preparation (`prepare_block_input_checks`), in
    /// seconds.
    pub prepare_seconds: f64,
    /// Input-check fan-out (rayon pool install plus join, or the serial
    /// fallback for small blocks), excluding the ordered error scan, in
    /// seconds.
    pub parallel_seconds: f64,
}

/// Verifies every input script across a block in one flat, block-ordered pass.
///
/// `resolved[i]` holds transaction `i`'s prevouts in input order (empty for the
/// coinbase). The node resolves them serially in block order so same-block
/// spends and overlay semantics stay authoritative. Prevout resolution is order
/// sensitive; script verification is not, so the per-input checks run
/// concurrently, yet the first failure is returned in block order (tx ascending,
/// phase `pre < script < post`, input ascending) — byte-identical to applying
/// the single-tx path tx by tx in block order.
///
/// `timings` receives the durations of the serial preparation and the parallel
/// input-check fan-out (in seconds). Both are written before the verdict is
/// returned, so the caller records them on the success and error paths. This
/// crate has no `metrics` dependency, so the caller owns the histogram recording.
pub fn verify_block_input_scripts(
    view: &mut BlockView<'_>,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    timings: &mut ScriptStageTimings,
    kernel_block: &crate::kernel::KernelBlock,
) -> Result<(), ConsensusError> {
    let prepare_started = Instant::now();
    let unit = prepare_block_script_checks(view, height, locktime_cutoff, kernel_block)?;
    timings.prepare_seconds = prepare_started.elapsed().as_secs_f64();

    let parallel_started = Instant::now();
    let mut set_parallel_seconds = || {
        timings.parallel_seconds = parallel_started.elapsed().as_secs_f64();
    };
    let mut before_serial_scan = || {};
    let verdict = verify_prepared_units_with_hooks(
        core::slice::from_ref(&unit),
        &[flags],
        &mut set_parallel_seconds,
        &mut before_serial_scan,
    );
    verdict.map_err(|failure| failure.error)
}

/// One block's script checks, prepared but not executed.
///
/// Holds borrows into the caller's parse-once [`BlockView`] transactions and
/// parsed kernel block, so both must outlive every unit built from them.
pub struct BlockScriptChecks<'b> {
    prepared: Vec<PreparedTx<'b>>,
    checks: Vec<InputCheck>,
}

/// Which unit failed, and how.
///
/// The index is the position in the slice handed to [`verify_prepared_units`],
/// so a caller batching several blocks learns which one to re-run through the
/// ordinary path to reproduce the error in its documented position.
#[derive(Debug)]
pub struct BatchScriptFailure {
    /// Position of the failing unit.
    pub unit: usize,
    /// The failure, identical to what the single-block path would report.
    pub error: ConsensusError,
}

/// Resolves one block's order-sensitive transaction state without executing
/// any script.
///
/// # Errors
///
/// Returns [`ConsensusError::PrevoutMatrixSize`] when `resolved` does not
/// cover every transaction. Consensus failures found during preparation are
/// not errors here: they are retained in transaction order and reported by
/// [`verify_prepared_units`], because reporting them now would let a later
/// transaction's cheap failure outrank an earlier one.
pub fn prepare_block_script_checks<'tx, 'checks>(
    view: &mut BlockView<'tx>,
    height: u32,
    locktime_cutoff: u32,
    kernel_block: &'checks crate::kernel::KernelBlock,
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
        prepare_block_input_checks(txs, resolved, height, locktime_cutoff, kernel_block);
    Ok(BlockScriptChecks { prepared, checks })
}

fn verify_prepared_units_with_hooks<AfterParallel, BeforeSerialScan>(
    units: &[BlockScriptChecks<'_>],
    flags_per_unit: &[VerifyFlags],
    after_parallel: &mut AfterParallel,
    before_serial_scan: &mut BeforeSerialScan,
) -> Result<(), BatchScriptFailure>
where
    AfterParallel: FnMut(),
    BeforeSerialScan: FnMut(),
{
    if units.len() != flags_per_unit.len() {
        return Err(BatchScriptFailure {
            unit: 0,
            error: ConsensusError::Kernel(format!(
                "batch verify needs one flag set per unit: {} units, {} flag sets",
                units.len(),
                flags_per_unit.len()
            )),
        });
    }

    // Offsets are precomputed rather than accumulated during the scan. With a
    // running counter, reversing the scan order misaligns every slice instead
    // of simply reporting a different unit, which hides an ordering bug behind
    // an unrelated symptom and lets an ordering test pass for the wrong reason.
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
        check_input(&unit.prepared, check, flags_per_unit[*unit_index])
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
///
/// # Errors
///
/// Returns the first [`BatchScriptFailure`] in the supplied unit order, or an
/// internal layout failure when the unit and flag slices do not correspond.
pub fn verify_prepared_units(
    units: &[BlockScriptChecks<'_>],
    flags_per_unit: &[VerifyFlags],
) -> Result<(), BatchScriptFailure> {
    let mut after = || {};
    let mut before = || {};
    verify_prepared_units_with_hooks(units, flags_per_unit, &mut after, &mut before)
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
///
/// Shared by the single-block and batched entry points on purpose: a second
/// copy of this ordering is how the two paths would silently disagree about
/// which error a block produces. A result slice that does not cover a
/// transaction's checks means this function and its caller disagree about the
/// layout. That cannot happen from any input, only from a bug here, but it must
/// never be answered with "no error found": that reports success for scripts
/// nobody ran.
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
///
/// Preparation stops at the first pre-script failure so no later transaction
/// can outrank it during the final ordered error scan.
fn prepare_block_input_checks<'b>(
    txs: &'b [Tx],
    resolved: &mut [Vec<Option<TxOut>>],
    height: u32,
    locktime_cutoff: u32,
    // Unused by the portable backend, which verifies the view's transactions
    // directly; kept in the signature so both backends share one call shape.
    #[cfg_attr(
        not(feature = "kernel"),
        expect(unused_variables, reason = "kernel-only")
    )]
    kernel_block: &'b crate::kernel::KernelBlock,
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
                    #[cfg(not(feature = "kernel"))]
                    tx,
                    #[cfg(feature = "kernel")]
                    prevouts: Vec::new(),
                    #[cfg(not(feature = "kernel"))]
                    spent_outputs: Vec::new(),
                    pre_error: None,
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    #[cfg(feature = "kernel")]
                    kernel_state: None,
                });
                continue;
            }
            Err(pre_error) => {
                prepared.push(PreparedTx {
                    #[cfg(not(feature = "kernel"))]
                    tx,
                    #[cfg(feature = "kernel")]
                    prevouts: Vec::new(),
                    #[cfg(not(feature = "kernel"))]
                    spent_outputs: Vec::new(),
                    pre_error: Some(pre_error),
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    #[cfg(feature = "kernel")]
                    kernel_state: None,
                });
                break;
            }
        };

        // Build retained kernel state before checks so setup failure cannot
        // leave an InputCheck without its PreparedKernelTx.
        #[cfg(feature = "kernel")]
        let kernel_state = match kernel_block.transaction(tx_index).and_then(|kernel_tx| {
            crate::kernel::prepare_kernel_tx(kernel_tx, tx.inputs.len(), &prep.prevouts)
        }) {
            Ok(state) => state,
            Err(setup_error) => {
                prepared.push(PreparedTx {
                    #[cfg(not(feature = "kernel"))]
                    tx,
                    prevouts: prep.prevouts,
                    pre_error: Some(setup_error),
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    kernel_state: None,
                });
                break;
            }
        };

        // One clone of the spent outputs per transaction, not per input: the
        // portable interpreter commits to every spent output, so each input
        // check needs the full ordered set.
        #[cfg(not(feature = "kernel"))]
        let spent_outputs: Vec<TxOut> = prep
            .prevouts
            .iter()
            .map(|(_, spent)| spent.clone())
            .collect();

        let prepared_index = prepared.len();
        let checks_start = checks.len();
        for input_index in 0..tx.inputs.len() {
            checks.push(InputCheck {
                prepared_index,
                input_index,
            });
        }
        let checks_len = tx.inputs.len();

        let post_error = finalize_tx_value_and_sigops(tx, &prep).err();
        let stop_after_tx = post_error.is_some();
        prepared.push(PreparedTx {
            #[cfg(not(feature = "kernel"))]
            tx,
            #[cfg(feature = "kernel")]
            prevouts: prep.prevouts,
            #[cfg(not(feature = "kernel"))]
            spent_outputs,
            pre_error: None,
            post_error,
            checks_start,
            checks_len,
            #[cfg(feature = "kernel")]
            kernel_state: Some(kernel_state),
        });
        // This tx's scripts still outrank its post error; that post error makes
        // every later transaction irrelevant to the ordered verdict.
        if stop_after_tx {
            break;
        }
    }
    (prepared, checks)
}

/// Runs one deferred input's script verdict against its retained state. Forks on
/// `cfg(kernel)` between the kernel and portable engines, sharing `&prepared` and
/// `&txs` by shared reference only.
fn check_input(
    prepared: &[PreparedTx<'_>],
    check: &InputCheck,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    let prep = &prepared[check.prepared_index];
    #[cfg(feature = "kernel")]
    {
        let (_, prevout) = &prep.prevouts[check.input_index];
        let kernel_state = prep.kernel_state.as_ref().ok_or_else(|| {
            ConsensusError::Kernel("clean non-coinbase tx lost prepared kernel state".to_owned())
        })?;
        crate::kernel::verify_prepared_input(kernel_state, prevout, check.input_index, flags)
    }
    #[cfg(not(feature = "kernel"))]
    {
        verify_input_script_portable(check.input_index, &prep.spent_outputs, prep.tx, flags)
    }
}

fn cached_prevout_lookup(
    prevouts: &[(OutPoint, TxOut)],
    cursor: &mut usize,
    outpoint: &OutPoint,
) -> Option<TxOut> {
    if prevouts.is_empty() {
        return None;
    }
    if *cursor >= prevouts.len() {
        *cursor = 0;
    }
    if let Some((cached_outpoint, txout)) = prevouts.get(*cursor)
        && cached_outpoint == outpoint
    {
        *cursor = (*cursor).saturating_add(1);
        return Some(txout.clone());
    }
    let (index, txout) =
        prevouts
            .iter()
            .enumerate()
            .find_map(|(index, (cached_outpoint, txout))| {
                (cached_outpoint == outpoint).then_some((index, txout))
            })?;
    *cursor = index.saturating_add(1);
    Some(txout.clone())
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

fn total_sigop_cost(tx: &Tx, prevouts: &[(OutPoint, TxOut)]) -> u32 {
    let mut cost = count_tx_legacy(tx).saturating_mul(4);
    let mut cursor = 0_usize;
    for input in &tx.inputs {
        let Some(prevout) = cached_prevout_lookup(prevouts, &mut cursor, &input.previous_output)
        else {
            continue;
        };
        let redeem_script = last_push(&input.script_sig);
        if is_p2sh(&prevout.script_pubkey) {
            if let Some(redeem) = redeem_script {
                cost = cost.saturating_add(count_accurate(redeem).saturating_mul(4));
            }
        }
        let witness_program = if is_witness_program(&prevout.script_pubkey) {
            Some(prevout.script_pubkey.as_slice())
        } else {
            redeem_script.filter(|script| is_witness_program(script))
        };
        if let Some(program) = witness_program {
            cost = cost.saturating_add(count_segwit(program, &input.witness));
        }
    }
    cost
}

fn last_push(script: &[u8]) -> Option<&[u8]> {
    let mut last = None;
    for instruction in instructions(script) {
        match instruction.ok()? {
            Instruction::PushBytes(bytes) => last = Some(bytes),
            Instruction::Op(_) => last = None,
        }
    }
    last
}

fn count_accurate(script: &[u8]) -> u32 {
    let mut count = 0_u32;
    let mut pushed_number = None;
    for instruction in instructions(script) {
        match instruction {
            Ok(Instruction::Op(opcode::OP_CHECKSIG | opcode::OP_CHECKSIGVERIFY)) => {
                count = count.saturating_add(1);
                pushed_number = None;
            }
            Ok(Instruction::Op(opcode::OP_CHECKMULTISIG | opcode::OP_CHECKMULTISIGVERIFY)) => {
                count = count.saturating_add(u32::from(pushed_number.unwrap_or(20)));
                pushed_number = None;
            }
            Ok(Instruction::Op(op)) => pushed_number = opcode::decode_pushnum(op),
            Ok(Instruction::PushBytes(_)) => pushed_number = None,
            Err(_) => break,
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    #[cfg(feature = "kernel")]
    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script,
        Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes, deserialize,
    };
    #[cfg(not(feature = "kernel"))]
    use bitcoin_rs_primitives::{Sighash, SighashCache};
    #[cfg(feature = "kernel")]
    use bitcoin_rs_script::opcode::{OP_EQUAL, OP_HASH160};
    #[cfg(feature = "kernel")]
    use bitcoin_rs_script::push_data;
    use bitcoin_rs_script::{VerifyFlags, push_int};

    use super::{
        ScriptStageTimings, is_final_tx_with_locktime_cutoff, verify_coinbase_script_sig_size,
        verify_transaction,
    };

    /// Wraps `txs` in a block and parses it the way production does, so tests
    /// exercise the real one-shot parse rather than a stand-in.
    fn kernel_block_for(txs: &[Tx]) -> crate::kernel::KernelBlock {
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
        crate::kernel::KernelBlock::parse(&consensus_bytes(&block))
            .unwrap_or_else(|error| panic!("synthetic block must parse: {error}"))
    }

    /// Wraps `txs` and its resolved prevouts in the parse-once view the node
    /// hands to verification, with identities computed once from the same
    /// transactions.
    fn block_view_for(
        txs: &[Tx],
        resolved: Vec<Vec<Option<TxOut>>>,
    ) -> crate::block_view::BlockView<'_> {
        let mut view = crate::block_view::BlockView::new(txs, txs.iter().map(Tx::txid).collect());
        view.set_resolved(resolved);
        view
    }
    use crate::{ConsensusError, rust_path::UtxoView};

    impl UtxoView for hashbrown::HashMap<OutPoint, TxOut> {
        fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
            self.get(outpoint).cloned()
        }
    }

    #[test]
    fn coinbase_transaction_skips_prevout_lookup() {
        let tx = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
                script_sig: vec![1, 1].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            }],
        };
        let utxos = hashbrown::HashMap::new();
        assert_eq!(
            verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
    }

    #[test]
    fn coinbase_script_sig_size_rejects_invalid_lengths() {
        for len in [0, 1, 101] {
            let tx = coinbase_transaction_with_script_sig_len(len);
            let utxos = hashbrown::HashMap::new();
            let expected = Err(ConsensusError::CoinbaseScriptSigSize { len });

            assert_eq!(verify_coinbase_script_sig_size(&tx), expected);
            assert_eq!(
                verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY),
                expected
            );
        }
    }

    #[test]
    fn coinbase_script_sig_size_accepts_valid_boundaries() {
        let utxos = hashbrown::HashMap::new();
        for len in [2, 100] {
            let tx = coinbase_transaction_with_script_sig_len(len);

            assert_eq!(verify_coinbase_script_sig_size(&tx), Ok(()));
            assert_eq!(
                verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY),
                Ok(())
            );
        }
    }

    #[test]
    fn duplicate_non_coinbase_input_is_rejected() {
        let outpoint = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[1; 32])),
            vout: 0,
        };
        let tx = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![spending_input(outpoint), spending_input(outpoint)],
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
                script_pubkey: push_int(1).into(),
            },
        );
        assert_eq!(
            verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::NONE),
            Err(ConsensusError::DuplicateInput { input_index: 1 })
        );
    }

    #[test]
    fn verify_transaction_accepts_multi_input_true_scripts() {
        let first = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[1; 32])),
            vout: 0,
        };
        let second = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[2; 32])),
            vout: 0,
        };
        let tx = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![true_spending_input(first), true_spending_input(second)],
            outputs: vec![TxOut {
                value: Amount::from_sat(75),
                script_pubkey: Script::new(),
            }],
        };
        let mut utxos = hashbrown::HashMap::new();
        utxos.insert(
            first,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: push_int(1).into(),
            },
        );
        utxos.insert(
            second,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: push_int(1).into(),
            },
        );

        assert_eq!(
            verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
    }

    #[test]
    fn verify_transaction_reuses_prevouts_for_sigop_counting() {
        let first = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[11; 32])),
            vout: 0,
        };
        let second = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[12; 32])),
            vout: 0,
        };
        let tx = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![true_spending_input(first), true_spending_input(second)],
            outputs: vec![TxOut {
                value: Amount::from_sat(75),
                script_pubkey: Script::new(),
            }],
        };
        let mut utxos = hashbrown::HashMap::new();
        utxos.insert(
            first,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: push_int(1).into(),
            },
        );
        utxos.insert(
            second,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: push_int(1).into(),
            },
        );
        let view = CountingUtxoView::new(utxos);

        assert_eq!(
            verify_transaction(&tx, &view, 0, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
        assert_eq!(view.lookup_count(), tx.inputs.len());
    }

    #[test]
    #[cfg(not(feature = "kernel"))]
    fn verify_transaction_routes_taproot_spends_to_interpreter() {
        let first = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[5; 32])),
            vout: 0,
        };
        let second = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[6; 32])),
            vout: 0,
        };
        let tx = Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![true_spending_input(first), true_spending_input(second)],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            }],
        };
        let mut utxos = hashbrown::HashMap::new();
        utxos.insert(
            first,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: p2tr_script_pubkey().into(),
            },
        );
        utxos.insert(
            second,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: push_int(1).into(),
            },
        );

        let result = verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY);

        assert_eq!(
            result,
            Err(ConsensusError::Script {
                input_index: 0,
                reason: "script failed: WITNESS_PROGRAM_WITNESS_EMPTY".to_owned(),
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
            verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY),
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
            verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
    }

    /// R2 pin: in the kernel build the script verdict carries the kernel
    /// dispatch marker, proving the Rust interpreter (whose call site is
    /// `cfg(not(feature = "kernel"))`) did not produce it.
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

        let result = verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY);

        assert!(matches!(
            result,
            Err(ConsensusError::Script {
                input_index: 0,
                reason
            }) if reason.starts_with("kernel script verification failed:")
        ));
    }

    /// Assume-valid semantics: the non-script entry must accept a transaction
    /// whose script the kernel would reject — no kernel invocation when
    /// scripts are skipped.
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
            super::verify_transaction_non_script(&tx, &utxos, 0, 0),
            Ok(())
        );
        assert!(matches!(
            verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY),
            Err(ConsensusError::Script { input_index: 0, .. })
        ));
    }

    #[test]
    fn verify_transaction_rejects_non_final_height_lock() {
        let tx = Tx {
            version: 1,
            lock_time: LockTime::from_consensus(200),
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Script::new(),
            }],
        };
        let utxos = hashbrown::HashMap::new();

        let result = verify_transaction(&tx, &utxos, 100, 0, VerifyFlags::MANDATORY);

        assert!(matches!(
            result,
            Err(ConsensusError::Bip { bip: "BIP113", .. })
        ));
    }

    #[test]
    fn timestamp_locktime_uses_caller_supplied_cutoff() {
        let tx = Tx {
            version: 1,
            lock_time: LockTime::from_consensus(500_000_100),
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Script::new(),
            }],
        };

        assert!(!is_final_tx_with_locktime_cutoff(&tx, 1, 500_000_100));
        assert!(is_final_tx_with_locktime_cutoff(&tx, 1, 500_000_101));
    }

    #[test]
    fn transaction_paths_share_locktime_and_coinbase_rules() {
        let coinbase = coinbase_transaction_with_script_sig_len(2);
        let utxos = hashbrown::HashMap::new();

        assert_eq!(
            verify_transaction(&coinbase, &utxos, 0, 0, VerifyFlags::MANDATORY),
            Ok(())
        );

        let non_final = Tx {
            version: 1,
            lock_time: LockTime::from_consensus(500_000_100),
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: Script::new(),
                sequence: Sequence::from_consensus(0),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Script::new(),
            }],
        };

        assert!(matches!(
            verify_transaction(&non_final, &utxos, 1, 500_000_100, VerifyFlags::MANDATORY),
            Err(ConsensusError::Bip { bip: "BIP113", .. })
        ));
    }

    fn spending_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: push_int(1).into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    /// Batching is pointless unless a run of units reports the SAME first error
    /// the per-block path would. These three tests are what make the offset
    /// table load-bearing; without them a running counter passes by accident.
    #[test]
    #[cfg(feature = "kernel")]
    fn batched_units_report_the_earliest_failing_unit() {
        let good_txs = vec![coinbase_transaction_with_script_sig_len(2)];
        let good_block = kernel_block_for(&good_txs);

        // Unit 0 fails on its SECOND transaction, unit 2 on its first. Block
        // order must win over position within a block.
        let first_txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![true_spending_input(outpoint(1))], 50),
            spend_tx(vec![mismatch_input(outpoint(2))], 50),
        ];
        let first_block = kernel_block_for(&first_txs);
        let last_txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![mismatch_input(outpoint(3))], 50),
        ];
        let last_block = kernel_block_for(&last_txs);

        let units = [
            prepared_unit(
                &first_txs,
                vec![
                    Vec::new(),
                    vec![Some(op1_txout(50))],
                    vec![Some(op_equal_txout(50))],
                ],
                &first_block,
            ),
            prepared_unit(&good_txs, vec![Vec::new()], &good_block),
            prepared_unit(
                &last_txs,
                vec![Vec::new(), vec![Some(op_equal_txout(50))]],
                &last_block,
            ),
        ];
        let flags = [VerifyFlags::MANDATORY; 3];

        match super::verify_prepared_units(&units, &flags) {
            Err(failure) => assert_eq!(
                failure.unit, 0,
                "the earliest failing unit must win, got unit {}",
                failure.unit
            ),
            Ok(()) => panic!("a unit with a mismatched script must fail"),
        }
    }

    /// Pins the offsets themselves, not just the order they are visited. The
    /// failing unit is LAST and every earlier unit passes, so the verdict is
    /// decided purely by whether each unit reads its own slice of results.
    #[test]
    #[cfg(feature = "kernel")]
    fn each_unit_reads_its_own_slice_of_results() {
        let clean_txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![true_spending_input(outpoint(11))], 50),
            spend_tx(vec![true_spending_input(outpoint(12))], 50),
        ];
        let clean_block = kernel_block_for(&clean_txs);
        let clean_resolved = vec![
            Vec::new(),
            vec![Some(op1_txout(50))],
            vec![Some(op1_txout(50))],
        ];
        let bad_txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![mismatch_input(outpoint(13))], 50),
        ];
        let bad_block = kernel_block_for(&bad_txs);

        let units = [
            prepared_unit(&clean_txs, clean_resolved.clone(), &clean_block),
            prepared_unit(&clean_txs, clean_resolved, &clean_block),
            prepared_unit(
                &bad_txs,
                vec![Vec::new(), vec![Some(op_equal_txout(50))]],
                &bad_block,
            ),
        ];
        let flags = [VerifyFlags::MANDATORY; 3];

        match super::verify_prepared_units(&units, &flags) {
            Err(failure) => assert_eq!(
                failure.unit, 2,
                "only the last unit fails, so misaligned offsets would blame another"
            ),
            Ok(()) => panic!("the last unit has a mismatched script and must fail"),
        }
    }

    /// A batched unit must produce the identical error the single-block entry
    /// point produces for the same block, or batching changes consensus.
    #[test]
    #[cfg(feature = "kernel")]
    fn a_batched_unit_matches_the_single_block_path() {
        let txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![mismatch_input(outpoint(7))], 50),
        ];
        let block = kernel_block_for(&txs);
        let resolved = vec![Vec::new(), vec![Some(op_equal_txout(50))]];

        let mut timings = super::ScriptStageTimings::default();
        let single = super::verify_block_input_scripts(
            &mut block_view_for(&txs, resolved.clone()),
            0,
            0,
            VerifyFlags::MANDATORY,
            &mut timings,
            &block,
        );
        let units = [prepared_unit(&txs, resolved, &block)];
        let batched = super::verify_prepared_units(&units, &[VerifyFlags::MANDATORY]);

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

    /// Flags differ per block across softfork activation heights, so a unit
    /// must be checked under its own.
    #[test]
    #[cfg(feature = "kernel")]
    fn each_unit_is_checked_under_its_own_flags() {
        let first_txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![true_spending_input(outpoint(9))], 50),
        ];
        let first_block = kernel_block_for(&first_txs);
        let first_resolved = vec![Vec::new(), vec![Some(op1_txout(50))]];

        let redeem_script = [0_u8];
        let redeem_hash = bitcoin::hashes::hash160::Hash::hash(&redeem_script);
        let p2sh_output = TxOut {
            value: Amount::from_sat(50),
            script_pubkey: [
                vec![OP_HASH160],
                push_data(&redeem_hash.to_byte_array()),
                vec![OP_EQUAL],
            ]
            .into()
            .concat()
            .into(),
        };
        let second_txs = vec![
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
        let second_block = kernel_block_for(&second_txs);
        let second_resolved = vec![Vec::new(), vec![Some(p2sh_output)]];

        let units = [
            prepared_unit(&first_txs, first_resolved, &first_block),
            prepared_unit(&second_txs, second_resolved, &second_block),
        ];
        assert!(
            super::verify_prepared_units(&units[1..], &[VerifyFlags::MANDATORY],).is_err(),
            "the second fixture must require its permissive flag set"
        );
        assert!(
            super::verify_prepared_units(&units, &[VerifyFlags::MANDATORY, VerifyFlags::NONE],)
                .is_ok(),
            "each unit must use the flag set at its own index"
        );
    }

    #[cfg(feature = "kernel")]
    fn prepared_unit<'b>(
        txs: &'b [Tx],
        resolved: Vec<Vec<Option<TxOut>>>,
        block: &'b crate::kernel::KernelBlock,
    ) -> super::BlockScriptChecks<'b> {
        let mut view = block_view_for(txs, resolved);
        match super::prepare_block_script_checks(&mut view, 0, 0, block) {
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

    struct CountingUtxoView {
        utxos: hashbrown::HashMap<OutPoint, TxOut>,
        lookups: Cell<usize>,
    }

    impl CountingUtxoView {
        fn new(utxos: hashbrown::HashMap<OutPoint, TxOut>) -> Self {
            Self {
                utxos,
                lookups: Cell::new(0),
            }
        }

        fn lookup_count(&self) -> usize {
            self.lookups.get()
        }
    }

    impl UtxoView for CountingUtxoView {
        fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
            self.lookups.set(self.lookups.get().saturating_add(1));
            self.utxos.get(outpoint).cloned()
        }
    }

    #[cfg(not(feature = "kernel"))]
    fn p2tr_script_pubkey() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(34);
        bytes.push(0x51);
        bytes.push(0x20);
        bytes.extend_from_slice(&[7; 32]);
        bytes
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

    #[cfg(feature = "kernel")]
    fn op1_txout(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: push_int(1).into(),
        }
    }

    #[cfg(feature = "kernel")]
    fn op_equal_txout(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![OP_EQUAL].into(),
        }
    }

    /// Input spending an `OP_EQUAL` prevout with a mismatched `7 8` scriptSig:
    /// rejected by the kernel.
    #[cfg(feature = "kernel")]
    fn mismatch_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: [push_int(7), push_int(8)].concat().into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    #[cfg(feature = "kernel")]
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

    #[cfg(feature = "kernel")]
    fn outpoint(seed: u8) -> OutPoint {
        OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[seed; 32])),
            vout: 0,
        }
    }

    #[test]
    fn block_input_scripts_rejects_mismatched_prevout_matrix() {
        let txs = vec![coinbase_transaction_with_script_sig_len(2)];
        assert_eq!(
            super::verify_block_input_scripts(
                &mut block_view_for(&txs, Vec::new()),
                0,
                0,
                VerifyFlags::MANDATORY,
                &mut ScriptStageTimings::default(),
                &kernel_block_for(&txs)
            ),
            Err(ConsensusError::PrevoutMatrixSize {
                expected: 1,
                actual: 0,
            })
        );
    }

    /// The assignment's required case: an earlier transaction's script failure
    /// must outrank a later transaction's missing prevout, because prep emits the
    /// earlier tx's input checks before it breaks on the missing-prevout pre-error.
    #[test]
    #[cfg(feature = "kernel")]
    fn earlier_tx_script_error_beats_later_tx_missing_prevout() {
        let txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![mismatch_input(outpoint(1))], 50),
            spend_tx(vec![true_spending_input(outpoint(2))], 50),
        ];
        let resolved = vec![Vec::new(), vec![Some(op_equal_txout(100))], vec![None]];
        let result = super::verify_block_input_scripts(
            &mut block_view_for(&txs, resolved),
            0,
            0,
            VerifyFlags::MANDATORY,
            &mut ScriptStageTimings::default(),
            &kernel_block_for(&txs),
        );
        assert!(
            matches!(result, Err(ConsensusError::Script { input_index: 0, .. })),
            "expected tx1 Script error, got {result:?}"
        );
    }

    /// The deferred post-error (value balance) must not outrank the same tx's
    /// script failure: script is phase 1, post is phase 2 in the intra-tx order.
    #[test]
    #[cfg(feature = "kernel")]
    fn intra_tx_script_error_beats_value_and_sigop() {
        let txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![mismatch_input(outpoint(1))], 100),
        ];
        let resolved = vec![Vec::new(), vec![Some(op_equal_txout(50))]];
        let result = super::verify_block_input_scripts(
            &mut block_view_for(&txs, resolved),
            0,
            0,
            VerifyFlags::MANDATORY,
            &mut ScriptStageTimings::default(),
            &kernel_block_for(&txs),
        );
        assert!(
            matches!(result, Err(ConsensusError::Script { input_index: 0, .. })),
            "expected Script error over InputsLessThanOutputs, got {result:?}"
        );
    }

    /// A later transaction's pre-error must not outrank an earlier transaction's
    /// deferred post-error: the scan walks in block order and returns tx1 first.
    #[test]
    #[cfg(feature = "kernel")]
    fn later_pre_error_does_not_outrank_earlier_post_error() {
        let txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![true_spending_input(outpoint(1))], 100),
            spend_tx(
                vec![
                    true_spending_input(outpoint(2)),
                    true_spending_input(outpoint(2)),
                ],
                50,
            ),
        ];
        let resolved = vec![
            Vec::new(),
            vec![Some(op1_txout(50))],
            vec![Some(op1_txout(50)), Some(op1_txout(50))],
        ];
        let result = super::verify_block_input_scripts(
            &mut block_view_for(&txs, resolved),
            0,
            0,
            VerifyFlags::MANDATORY,
            &mut ScriptStageTimings::default(),
            &kernel_block_for(&txs),
        );
        assert_eq!(
            result,
            Err(ConsensusError::InputsLessThanOutputs {
                input_value: 50,
                output_value: 100,
            })
        );
    }

    /// Parallel script checks still report the earliest block-ordered failure.
    #[test]
    #[cfg(feature = "kernel")]
    fn parallel_script_checks_report_first_error() {
        let mut txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![mismatch_input(outpoint(1))], 50),
        ];
        let mut resolved = vec![Vec::new(), vec![Some(op_equal_txout(100))]];
        for seed in 2..=u8::try_from(super::MIN_PARALLEL_SCRIPT_CHECKS).unwrap_or(u8::MAX) {
            txs.push(spend_tx(vec![mismatch_input(outpoint(seed))], 50));
            resolved.push(vec![Some(op_equal_txout(100))]);
        }

        let result = super::verify_block_input_scripts(
            &mut block_view_for(&txs, resolved),
            0,
            0,
            VerifyFlags::MANDATORY,
            &mut ScriptStageTimings::default(),
            &kernel_block_for(&txs),
        );
        assert!(
            matches!(result, Err(ConsensusError::Script { input_index: 0, .. })),
            "expected first Script error, got {result:?}"
        );
    }

    /// A same-block spend (tx2 consuming tx1's output) verifies when the node
    /// resolves it into `resolved`; a bad script in the producing tx surfaces that
    /// earlier transaction's Script error.
    #[test]
    #[cfg(feature = "kernel")]
    fn same_block_spend_resolves_and_verifies() {
        let tx1 = spend_tx(vec![true_spending_input(outpoint(1))], 100);
        let tx1_out = OutPoint {
            txid: tx1.txid(),
            vout: 0,
        };
        let tx2 = spend_tx(vec![true_spending_input(tx1_out)], 90);
        let tx1_output = tx1.outputs[0].clone();
        let txs = vec![coinbase_transaction_with_script_sig_len(2), tx1, tx2];
        let resolved = vec![
            Vec::new(),
            vec![Some(op1_txout(100))],
            vec![Some(tx1_output)],
        ];
        assert_eq!(
            super::verify_block_input_scripts(
                &mut block_view_for(&txs, resolved),
                0,
                0,
                VerifyFlags::MANDATORY,
                &mut ScriptStageTimings::default(),
                &kernel_block_for(&txs)
            ),
            Ok(())
        );

        let bad_tx1 = spend_tx(vec![mismatch_input(outpoint(1))], 100);
        let bad_out = OutPoint {
            txid: bad_tx1.txid(),
            vout: 0,
        };
        let bad_tx2 = spend_tx(vec![true_spending_input(bad_out)], 90);
        let bad_tx1_output = bad_tx1.outputs[0].clone();
        let bad_txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            bad_tx1,
            bad_tx2,
        ];
        let bad_resolved = vec![
            Vec::new(),
            vec![Some(op_equal_txout(100))],
            vec![Some(bad_tx1_output)],
        ];
        let bad = super::verify_block_input_scripts(
            &mut block_view_for(&bad_txs, bad_resolved),
            0,
            0,
            VerifyFlags::MANDATORY,
            &mut ScriptStageTimings::default(),
            &kernel_block_for(&txs),
        );
        assert!(
            matches!(bad, Err(ConsensusError::Script { input_index: 0, .. })),
            "expected producing tx Script error, got {bad:?}"
        );
    }

    // ---- Taproot script-path public-seam regression ---------------------------
    //
    // The committed `taproot_scriptpath_spend.json` fixture is a real mainnet
    // BIP342 script-path spend. Both the kernel path and the native interpreter
    // accept it. These two tests pin `verify_transaction`'s public seam for
    // both builds against this fixture.

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

    /// Decodes a hex string to bytes; panics on malformed input. The fixture is
    /// committed and validated, so a malformed hex is a corpus regression, not
    /// a runtime condition.
    fn decode_hex(hex: &str) -> Vec<u8> {
        assert!(hex.len().is_multiple_of(2), "hex string has odd length");
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digits = std::str::from_utf8(pair).unwrap_or_else(|_| panic!("hex ascii"));
                u8::from_str_radix(digits, 16).unwrap_or_else(|_| panic!("hex digit"))
            })
            .collect()
    }

    /// Loads and decodes the committed mainnet Taproot script-path fixture.
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

    /// Public-seam regression: under `feature = "kernel"`, `verify_transaction`
    /// routes the real mainnet Taproot script-path spend to the kernel, which
    /// accepts it.
    #[test]
    #[cfg(feature = "kernel")]
    fn verify_transaction_accepts_mainnet_taproot_scriptpath_spend() {
        let fixture = load_taproot_scriptpath_fixture();
        let mut utxos = hashbrown::HashMap::new();
        for (index, prevout) in fixture.prevouts.iter().enumerate() {
            utxos.insert(fixture.tx.inputs[index].previous_output, prevout.clone());
        }
        assert_eq!(
            verify_transaction(&fixture.tx, &utxos, fixture.height, 0, fixture.flags),
            Ok(())
        );
    }

    /// Public-seam regression: without the kernel, `verify_transaction` routes
    /// the Taproot script-path spend to the portable interpreter, which now
    /// implements BIP342 script-path verification and accepts the spend.
    #[test]
    #[cfg(not(feature = "kernel"))]
    fn verify_transaction_accepts_mainnet_taproot_scriptpath_under_portable() {
        let fixture = load_taproot_scriptpath_fixture();
        let mut utxos = hashbrown::HashMap::new();
        for (index, prevout) in fixture.prevouts.iter().enumerate() {
            utxos.insert(fixture.tx.inputs[index].previous_output, prevout.clone());
        }
        let result = verify_transaction(&fixture.tx, &utxos, fixture.height, 0, fixture.flags);
        assert!(
            result.is_ok(),
            "expected portable taproot script-path acceptance, got {result:?}"
        );
    }

    #[test]
    #[cfg(feature = "kernel")]
    fn parallel_timing_is_captured_before_ordered_error_scan() {
        use std::cell::Cell;

        let prepared: Vec<super::PreparedTx> = (0..10)
            .map(|_| super::PreparedTx {
                prevouts: Vec::new(),
                pre_error: None,
                post_error: None,
                checks_start: 0,
                checks_len: 0,
                kernel_state: None,
            })
            .collect();
        let unit = super::BlockScriptChecks {
            prepared,
            checks: Vec::new(),
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
            &[VerifyFlags::MANDATORY],
            &mut after_parallel,
            &mut before_serial_scan,
        );
        assert!(result.is_ok());
        assert!(scan_started.get(), "the serial error scan must have run");
    }
}
