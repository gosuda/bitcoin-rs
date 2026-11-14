use std::collections::HashSet;
use std::time::Instant;

use crate::primitives::{Amount, OutPoint, Sequence, Tx, TxOut, TxView, Wtxid};

use crate::block_view::{BlockView, BlockViewSource};
use crate::script::PreparedTransaction;
use crate::script::VerifyFlags;
use crate::sigops::transaction_sigop_cost_view;
use rayon::prelude::*;

use crate::ScriptEngine;
use crate::UtxoView;
use crate::{ConsensusError, MAX_BLOCK_SIGOPS_COST, ValidationEngine};

use crate::primitives::{LOCKTIME_THRESHOLD, SEQUENCE_FINAL};
const MIN_COINBASE_SCRIPT_SIG_SIZE: usize = 2;
const MAX_COINBASE_SCRIPT_SIG_SIZE: usize = 100;

pub(crate) const COINBASE_MATURITY: u32 = 100;

const MIN_PARALLEL_SCRIPT_CHECKS: usize = 32;

#[must_use]
pub fn is_final_tx_view(tx: TxView<'_>, block_height: u32, locktime_cutoff: u32) -> bool {
    let lock_time = tx.lock_time().to_consensus();
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

    for i in 0..tx.input_count() {
        if tx.input_sequence(i) != Sequence::from_consensus(SEQUENCE_FINAL) {
            return false;
        }
    }
    true
}

#[must_use]
pub fn is_final_tx(tx: &Tx, block_height: u32, locktime_cutoff: u32) -> bool {
    is_final_tx_view(tx.into(), block_height, locktime_cutoff)
}

pub fn verify_coinbase_script_sig_size_view(tx: TxView<'_>) -> Result<(), ConsensusError> {
    if tx.is_coinbase() && tx.input_count() > 0 {
        let len = tx.input_script_sig(0).len();
        if !(MIN_COINBASE_SCRIPT_SIG_SIZE..=MAX_COINBASE_SCRIPT_SIG_SIZE).contains(&len) {
            return Err(ConsensusError::CoinbaseScriptSigSize { len });
        }
    }
    Ok(())
}

pub fn verify_coinbase_script_sig_size(tx: &Tx) -> Result<(), ConsensusError> {
    verify_coinbase_script_sig_size_view(tx.into())
}

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

pub fn verify_transaction(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    engine: ValidationEngine,
    signature_cache: Option<&crate::script::SignatureCache>,
) -> Result<(), ConsensusError> {
    verify_transaction_with_locktime_cutoff(
        tx.into(),
        prevouts,
        height,
        locktime_cutoff,
        flags,
        Some(engine),
        signature_cache,
    )
}

pub fn verify_transaction_non_script(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_with_locktime_cutoff(
        tx.into(),
        prevouts,
        height,
        locktime_cutoff,
        flags,
        None,
        None,
    )
}

pub fn verify_transaction_non_script_view(
    tx: TxView<'_>,
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
        None,
        None,
    )
}

fn verify_transaction_with_locktime_cutoff(
    tx: TxView<'_>,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    engine: Option<ValidationEngine>,
    signature_cache: Option<&crate::script::SignatureCache>,
) -> Result<(), ConsensusError> {
    if let Some(engine) = engine
        && !engine.is_supported()
    {
        return Err(ConsensusError::UnsupportedEngine { engine });
    }
    let Some(prep) = prepare_tx_checks(tx, height, locktime_cutoff, |_, outpoint| {
        prevouts.lookup(outpoint)
    })?
    else {
        return Ok(());
    };

    if let Some(engine) = engine {
        crate::kernel::verify_tx_scripts_view(tx, &prep.prevouts, flags, engine, signature_cache)?;
    }

    finalize_tx_value_and_sigops(tx, &prep, flags)
}

struct TxPrep {
    prevouts: Vec<(OutPoint, TxOut)>,
    input_value: u64,
    output_value: u64,
}

pub fn verify_transaction_input_outpoints_view(tx: TxView<'_>) -> Result<(), ConsensusError> {
    if tx.is_coinbase() {
        return Ok(());
    }
    let mut seen = HashSet::new();
    for input_index in 0..tx.input_count() {
        let outpoint = tx.input_outpoint(input_index);
        if outpoint.is_null() {
            return Err(ConsensusError::NullPrevout { input_index });
        }
        if !seen.insert(outpoint) {
            return Err(ConsensusError::DuplicateInput { input_index });
        }
    }
    Ok(())
}

pub fn verify_transaction_input_outpoints(tx: &Tx) -> Result<(), ConsensusError> {
    verify_transaction_input_outpoints_view(tx.into())
}

pub(crate) fn verify_transaction_structure_view(tx: TxView<'_>) -> Result<u64, ConsensusError> {
    if tx.input_count() == 0 {
        return Err(ConsensusError::EmptyInputs);
    }
    if tx.output_count() == 0 {
        return Err(ConsensusError::EmptyOutputs);
    }
    let output_value = total_output_value_view(tx)?;
    if tx.is_coinbase() {
        verify_coinbase_script_sig_size_view(tx)?;
    } else {
        verify_transaction_input_outpoints_view(tx)?;
    }
    Ok(output_value)
}

pub(crate) fn verify_transaction_structure(tx: &Tx) -> Result<u64, ConsensusError> {
    verify_transaction_structure_view(tx.into())
}

fn total_output_value_view(tx: TxView<'_>) -> Result<u64, ConsensusError> {
    let mut sum = 0u64;
    for i in 0..tx.output_count() {
        let next = sum
            .checked_add(tx.output_value(i).to_sat())
            .ok_or(ConsensusError::OutputValueOverflow)?;
        if Amount::from_sat(next) > Amount::MAX_MONEY {
            return Err(ConsensusError::OutputValueOverflow);
        }
        sum = next;
    }
    Ok(sum)
}

fn prepare_tx_checks(
    tx: TxView<'_>,
    height: u32,
    locktime_cutoff: u32,
    mut lookup: impl FnMut(usize, &OutPoint) -> Option<TxOut>,
) -> Result<Option<TxPrep>, ConsensusError> {
    if !is_final_tx_view(tx, height, locktime_cutoff) {
        return Err(ConsensusError::Bip {
            bip: "BIP113",
            reason: format!(
                "non-final transaction at height {height} locktime cutoff \
                 {locktime_cutoff}: locktime {}",
                tx.lock_time()
            ),
        });
    }

    let output_value = verify_transaction_structure_view(tx)?;
    if tx.is_coinbase() {
        return Ok(None);
    }

    let mut input_value = 0u64;
    let mut prevouts = Vec::with_capacity(tx.input_count());
    for input_index in 0..tx.input_count() {
        let prevout = lookup(input_index, &tx.input_outpoint(input_index))
            .ok_or(ConsensusError::MissingPrevout { input_index })?;
        input_value = input_value
            .checked_add(prevout.value.to_sat())
            .ok_or(ConsensusError::OutputValueOverflow)?;
        prevouts.push((tx.input_outpoint(input_index), prevout));
    }

    Ok(Some(TxPrep {
        prevouts,
        input_value,
        output_value,
    }))
}

fn finalize_tx_value_and_sigops(
    tx: TxView<'_>,
    prep: &TxPrep,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    if prep.input_value < prep.output_value {
        return Err(ConsensusError::InputsLessThanOutputs {
            input_value: prep.input_value,
            output_value: prep.output_value,
        });
    }

    let sigop_cost = transaction_sigop_cost_view(tx, &prep.prevouts, flags);
    if sigop_cost > MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusError::SigopsLimit {
            cost: sigop_cost,
            max: MAX_BLOCK_SIGOPS_COST,
        });
    }
    Ok(())
}

pub(crate) fn verify_input_script_native(
    prepared: &PreparedTransaction<'_>,
    input_index: usize,
    flags: VerifyFlags,
    signature_cache: Option<&crate::script::SignatureCache>,
) -> Result<(), ConsensusError> {
    prepared
        .verify_input(input_index, flags, signature_cache)
        .map_err(|error| ConsensusError::Script {
            input_index,
            reason: error.to_string(),
            engine: ScriptEngine::Native,
        })?;
    Ok(())
}

struct PreparedTx<'b> {
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

#[derive(Clone, Copy, Default)]
pub struct ScriptStageTimings {
    pub prepare_seconds: f64,
    pub parallel_seconds: f64,
}

pub fn verify_block_input_scripts<'tx, 'checks>(
    view: &mut BlockView<'tx>,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    timings: &mut ScriptStageTimings,
    script_source: &'checks crate::kernel::BlockScriptSource,
    script_cache: Option<&crate::script_cache::ScriptExecutionCache>,
) -> Result<(), ConsensusError>
where
    'tx: 'checks,
{
    let prepare_started = Instant::now();
    let mut takes = script_cache.map(crate::script_cache::WindowCacheTakes::new);
    let unit = prepare_block_script_checks(
        view,
        height,
        locktime_cutoff,
        flags,
        script_source,
        takes.as_mut(),
    )?;
    timings.prepare_seconds = prepare_started.elapsed().as_secs_f64();

    let unit_slice = core::slice::from_ref(&unit);
    let parallel_started = Instant::now();
    let results = run_prepared_checks(unit_slice);
    timings.parallel_seconds = parallel_started.elapsed().as_secs_f64();
    first_unit_failure(unit_slice, &results).map_err(|failure| failure.error)
}

pub struct BlockScriptChecks<'b> {
    prepared: Vec<PreparedTx<'b>>,
    checks: Vec<InputCheck>,
    flags: VerifyFlags,
}

#[derive(Debug)]
pub struct BatchScriptFailure {
    pub unit: usize,
    pub error: ConsensusError,
}

pub fn prepare_block_script_checks<'tx, 'checks>(
    view: &mut BlockView<'tx>,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    script_source: &'checks crate::kernel::BlockScriptSource,
    takes: Option<&mut crate::script_cache::WindowCacheTakes<'_>>,
) -> Result<BlockScriptChecks<'checks>, ConsensusError>
where
    'tx: 'checks,
{
    let wtxids: Vec<Wtxid> = if takes.is_some() {
        match view.facts().wtxids().map(<[Wtxid]>::to_vec) {
            Some(wtxids) => wtxids,
            None if view.facts().has_witness() => view.witness_ids().to_vec(),
            None => view.txids().iter().map(|txid| Wtxid(txid.0)).collect(),
        }
    } else {
        Vec::new()
    };
    let (source, resolved) = view.parts_mut();
    let tx_count = match source {
        BlockViewSource::Txs(txs) => txs.len(),
        BlockViewSource::Image(img) => img.tx_count(),
    };
    if tx_count != resolved.len() {
        return Err(ConsensusError::PrevoutMatrixSize {
            expected: tx_count,
            actual: resolved.len(),
        });
    }
    if takes.is_some() && tx_count != wtxids.len() {
        return Err(ConsensusError::PrevoutMatrixSize {
            expected: tx_count,
            actual: wtxids.len(),
        });
    }
    let (prepared, checks) = prepare_block_input_checks(
        source,
        resolved,
        &wtxids,
        height,
        locktime_cutoff,
        flags,
        script_source,
        takes,
    );
    Ok(BlockScriptChecks {
        prepared,
        checks,
        flags,
    })
}

fn run_prepared_checks(units: &[BlockScriptChecks<'_>]) -> Vec<Result<(), ConsensusError>> {
    let run = |(unit_index, check): &(usize, &InputCheck)| check_input(&units[*unit_index], check);
    let flat: Vec<(usize, &InputCheck)> = units
        .iter()
        .enumerate()
        .flat_map(|(index, unit)| unit.checks.iter().map(move |check| (index, check)))
        .collect();
    if flat.len() < MIN_PARALLEL_SCRIPT_CHECKS {
        flat.iter().map(run).collect()
    } else {
        flat.par_iter().map(run).collect()
    }
}

fn first_unit_failure(
    units: &[BlockScriptChecks<'_>],
    results: &[Result<(), ConsensusError>],
) -> Result<(), BatchScriptFailure> {
    let mut offsets = Vec::with_capacity(units.len());
    let mut total = 0_usize;
    for unit in units {
        offsets.push(total);
        let Some(next) = total.checked_add(unit.checks.len()) else {
            return Err(layout_failure(0));
        };
        total = next;
    }

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

pub fn verify_prepared_units(units: &[BlockScriptChecks<'_>]) -> Result<(), BatchScriptFailure> {
    let results = run_prepared_checks(units);
    first_unit_failure(units, &results)
}

fn layout_failure(unit: usize) -> BatchScriptFailure {
    BatchScriptFailure {
        unit,
        error: ConsensusError::Kernel(
            "internal: prepared script-check layout does not match its results".to_owned(),
        ),
    }
}

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

fn prepare_block_input_checks<'b>(
    source: BlockViewSource<'b>,
    resolved: &mut [Vec<Option<TxOut>>],
    wtxids: &[Wtxid],
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    script_source: &'b crate::kernel::BlockScriptSource,
    mut takes: Option<&mut crate::script_cache::WindowCacheTakes<'_>>,
) -> (Vec<PreparedTx<'b>>, Vec<InputCheck>) {
    let tx_count = match source {
        BlockViewSource::Txs(txs) => txs.len(),
        BlockViewSource::Image(img) => img.tx_count(),
    };
    let mut prepared = Vec::with_capacity(tx_count);
    let mut checks = Vec::new();
    for tx_index in 0..tx_count {
        let tx = match source {
            BlockViewSource::Txs(txs) => TxView::Owned(&txs[tx_index]),
            BlockViewSource::Image(img) => TxView::View(img.tx(tx_index)),
        };
        let resolved_inputs = &mut resolved[tx_index];
        let prep = match prepare_tx_checks(tx, height, locktime_cutoff, |input_index, _| {
            resolved_inputs.get_mut(input_index).and_then(Option::take)
        }) {
            Ok(Some(prep)) => prep,
            Ok(None) => {
                prepared.push(PreparedTx {
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
                    pre_error: Some(pre_error),
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    script_state: None,
                });
                break;
            }
        };

        if takes
            .as_mut()
            .is_some_and(|takes| takes.take(wtxids[tx_index], flags))
        {
            let post_error = finalize_tx_value_and_sigops(tx, &prep, flags).err();
            let stop_after_tx = post_error.is_some();
            prepared.push(PreparedTx {
                pre_error: None,
                post_error,
                checks_start: checks.len(),
                checks_len: 0,
                script_state: None,
            });
            if stop_after_tx {
                break;
            }
            continue;
        }

        let post_error = finalize_tx_value_and_sigops(tx, &prep, flags).err();
        let script_state = match script_source.prepare_tx(tx_index, tx, prep.prevouts) {
            Ok(state) => state,
            Err(setup_error) => {
                prepared.push(PreparedTx {
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
        for input_index in 0..tx.input_count() {
            checks.push(InputCheck {
                prepared_index,
                input_index,
            });
        }
        let checks_len = tx.input_count();

        let stop_after_tx = post_error.is_some();
        prepared.push(PreparedTx {
            pre_error: None,
            post_error,
            checks_start,
            checks_len,
            script_state: Some(script_state),
        });
        if stop_after_tx {
            break;
        }
    }
    (prepared, checks)
}

fn check_input(unit: &BlockScriptChecks<'_>, check: &InputCheck) -> Result<(), ConsensusError> {
    let prep = &unit.prepared[check.prepared_index];
    let script_state = prep.script_state.as_ref().ok_or_else(|| {
        ConsensusError::Kernel("clean non-coinbase tx lost prepared script state".to_owned())
    })?;
    crate::kernel::verify_prepared_input(script_state, check.input_index, unit.flags)
}

#[cfg(test)]
mod tests;
