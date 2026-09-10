from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}")
    file.write_text(text.replace(old, new, 1))


def replace_between(path: str, start_marker: str, end_marker: str, replacement: str) -> None:
    file = Path(path)
    text = file.read_text()
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    file.write_text(text[:start] + replacement + text[end:])


# Share the already-resolved ordered coin set with admission instead of
# sending it back through UtxoView for a second resolution pass.  The indexed
# closure validates that every supplied outpoint belongs to the corresponding
# transaction input before any script work consumes its TxOut.
replace_between(
    "crates/consensus/src/verify_tx.rs",
    "fn verify_transaction_with_locktime_cutoff(",
    "\n/// Resolved per-transaction state carried from the pre-phase into the script and\n",
    r'''fn verify_transaction_with_locktime_cutoff(
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
    verify_prepared_transaction(tx, &prep, flags, skip_scripts)
}

/// Verifies a transaction from an immutable, input-ordered set of already
/// resolved previous coins.
///
/// This is the admission-side counterpart to block script preparation.  It
/// never re-reads chainstate or the mempool: each `(OutPoint, TxOut)` is read
/// only at the corresponding transaction input index.  A missing, short,
/// misordered, or mismatched entry fails closed as `MissingPrevout` before
/// signature or value checks can consume the wrong coin.
pub fn verify_transaction_resolved(
    tx: &Tx,
    prevouts: &[(OutPoint, TxOut)],
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    let Some(prep) = prepare_tx_checks(tx, height, locktime_cutoff, |input_index, outpoint| {
        let (resolved_outpoint, prevout) = prevouts.get(input_index)?;
        (*resolved_outpoint == *outpoint).then(|| prevout.clone())
    })?
    else {
        return Ok(());
    };
    verify_prepared_transaction(tx, &prep, flags, false)
}

/// Executes script and post checks from one immutable preparation result.
fn verify_prepared_transaction(
    tx: &Tx,
    prep: &TxPrep,
    flags: VerifyFlags,
    skip_scripts: bool,
) -> Result<(), ConsensusError> {
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
            let sighash = native_sighash_cache(tx, &spent_outputs, flags);
            for input_index in 0..tx.inputs.len() {
                verify_input_script_portable(
                    input_index,
                    &spent_outputs,
                    tx,
                    flags,
                    sighash.clone(),
                )?;
            }
        }
    }

    finalize_tx_value_and_sigops(tx, prep, flags)
}
''',
)

# Make the resolved entry point part of the consensus surface used by the
# mempool gateway.
replace_once(
    "crates/consensus/src/lib.rs",
    """    ScriptStageTimings, is_final_tx, verify_block_input_scripts, verify_coinbase_script_sig_size,
    verify_transaction, verify_transaction_non_script,
""",
    """    ScriptStageTimings, is_final_tx, verify_block_input_scripts, verify_coinbase_script_sig_size,
    verify_transaction, verify_transaction_non_script, verify_transaction_resolved,
""",
)

# Admission still needs one layered lookup (mempool first, then chain) to build
# its immutable ordered snapshot. Index the chain subset once so a multi-input
# transaction does not linearly rescan every confirmed coin for every input.
replace_once(
    "crates/mempool/src/gateway.rs",
    """use bitcoin_rs_consensus::{ConsensusError, UtxoView, total_sigop_cost, verify_transaction};
""",
    """use bitcoin_rs_consensus::{
    ConsensusError, UtxoView, total_sigop_cost, verify_transaction_resolved,
};
""",
)
replace_once(
    "crates/mempool/src/gateway.rs",
    "use hashbrown::HashSet;\n",
    "use hashbrown::{HashMap, HashSet};\n",
)
replace_once(
    "crates/mempool/src/gateway.rs",
    """struct PrevoutMap<'a>(&'a [(OutPoint, TxOut)]);

impl UtxoView for PrevoutMap<'_> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.0
            .iter()
            .find(|(op, _)| op == outpoint)
            .map(|(_, txout)| txout.clone())
    }
}
""",
    """struct PrevoutMap<'a> {
    by_outpoint: HashMap<OutPoint, &'a TxOut>,
}

impl<'a> PrevoutMap<'a> {
    fn new(prevouts: &'a [(OutPoint, TxOut)]) -> Self {
        Self {
            by_outpoint: prevouts
                .iter()
                .map(|(outpoint, txout)| (*outpoint, txout))
                .collect(),
        }
    }
}

impl UtxoView for PrevoutMap<'_> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.by_outpoint.get(outpoint).map(|txout| (*txout).clone())
    }
}
""",
)
replace_once(
    "crates/mempool/src/gateway.rs",
    "        let chain_view = PrevoutMap(&request.prevouts);\n",
    "        let chain_view = PrevoutMap::new(&request.prevouts);\n",
)

# At this point `resolved` is already input ordered and owns stable TxOut
# copies.  Verify exactly those facts; do not perform a second layered lookup.
file = Path("crates/mempool/src/gateway.rs")
text = file.read_text()
old = """        if let Err(error) = verify_transaction(
            &request.tx,
            &view,
            finality_height,
            request.locktime_cutoff,
"""
new = """        if let Err(error) = verify_transaction_resolved(
            &request.tx,
            &resolved,
            finality_height,
            request.locktime_cutoff,
"""
count = text.count(old)
if count != 1:
    raise SystemExit(f"gateway.rs: expected one admission verification call, found {count}")
file.write_text(text.replace(old, new, 1))

# Strengthen T07's order/mismatch and lifetime tests so their names correspond
# to actual prepared verification behavior rather than identity-only checks.
test = Path("crates/consensus/tests/overhaul_prepared_inputs.rs")
text = test.read_text()
old = r'''/// Prepared facts are owned copies: replacing the source record after
/// preparation cannot corrupt the prepared coin facts.
#[test]
fn prepared_facts_survive_source_record_replacement() {
    let (tx, view) = two_input_tx();
    // Resolve and drop the source view entirely; the resolved prevouts used
    // for sighash computation are owned facts held by the verification
    // pipeline, not borrows into the view.
    drop(view);
    let bytes = consensus_bytes(&tx);
    let reparsed: Tx = bitcoin_rs_primitives::deserialize(&bytes).expect("round trip");
    assert_eq!(reparsed.inputs.len(), 2);
    assert_eq!(reparsed.inputs[0].previous_output, outpoint(1));
}
'''
new = r'''/// The immutable resolved API owns the verification facts for the duration of
/// the call: changing a separate source record cannot alter which coins are
/// consumed, and mismatched replacement identities fail before script work.
#[test]
fn prepared_facts_survive_source_record_replacement() {
    let (tx, mut view) = two_input_tx();
    let resolved: Vec<(OutPoint, TxOut)> = tx
        .inputs
        .iter()
        .map(|input| {
            let coin = view.utxos.get(&input.previous_output).expect("resolved");
            (input.previous_output, coin.clone())
        })
        .collect();

    // Replace the source records after taking the immutable snapshot.  The
    // prepared verification entry below must consume only `resolved`.
    view.utxos.insert(
        outpoint(1),
        TxOut {
            value: 1,
            script_pubkey: vec![0x6a],
        },
    );
    let flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    let stable = bitcoin_rs_consensus::verify_transaction_resolved(&tx, &resolved, 0, 0, flags);
    assert_eq!(stable, Ok(()), "source replacement must not affect prepared facts");

    let mut mismatched = resolved;
    mismatched[0].0 = outpoint(0xEE);
    assert_eq!(
        bitcoin_rs_consensus::verify_transaction_resolved(&tx, &mismatched, 0, 0, flags),
        Err(bitcoin_rs_consensus::ConsensusError::MissingPrevout { input_index: 0 }),
        "replacement identity mismatch must fail closed before verification"
    );
}
'''
if text.count(old) != 1:
    raise SystemExit("overhaul_prepared_inputs.rs: prepared lifetime test anchor changed")
text = text.replace(old, new, 1)
old = r'''/// Input order and outpoint identity are load-bearing: swapping two inputs'
/// prevout references changes the resolved coin facts and the resulting
/// verification context, never silently reusing the first input's facts.
#[test]
fn input_order_and_outpoint_mismatch_changes_resolution() {
    let (mut tx, _view) = two_input_tx();
    // Swap the two inputs' previous outputs.
    let first = tx.inputs[0].previous_output;
    tx.inputs[0].previous_output = tx.inputs[1].previous_output;
    tx.inputs[1].previous_output = first;

    // Duplicate outpoints across inputs (double spend) must fail closed.
    let (mut dup, view) = two_input_tx();
    dup.inputs[1].previous_output = dup.inputs[0].previous_output;
    let flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    let verdict = bitcoin_rs_consensus::verify_transaction(&dup, &view, 0, 0, flags);
    assert!(verdict.is_err(), "duplicate-input spend must fail closed");
}
'''
new = r'''/// Input order and outpoint identity are load-bearing: swapping prepared coins
/// cannot silently feed one input another input's amount or script.
#[test]
fn input_order_and_outpoint_mismatch_changes_resolution() {
    let (tx, view) = two_input_tx();
    let flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    let mut resolved: Vec<(OutPoint, TxOut)> = tx
        .inputs
        .iter()
        .map(|input| {
            let coin = view.utxos.get(&input.previous_output).expect("resolved");
            (input.previous_output, coin.clone())
        })
        .collect();
    resolved.swap(0, 1);
    assert_eq!(
        bitcoin_rs_consensus::verify_transaction_resolved(&tx, &resolved, 0, 0, flags),
        Err(bitcoin_rs_consensus::ConsensusError::MissingPrevout { input_index: 0 }),
        "misordered prepared coins must fail closed"
    );

    let (mut dup, view) = two_input_tx();
    dup.inputs[1].previous_output = dup.inputs[0].previous_output;
    let verdict = bitcoin_rs_consensus::verify_transaction(&dup, &view, 0, 0, flags);
    assert!(verdict.is_err(), "duplicate-input spend must fail closed");
}
'''
if text.count(old) != 1:
    raise SystemExit("overhaul_prepared_inputs.rs: order test anchor changed")
test.write_text(text.replace(old, new, 1))

# Exercise eager cache population against the already oracle-tested lazy path
# on an actual multi-input transaction.  This prevents future refactors from
# silently cloning empty caches and calling the optimization complete.
path = Path("crates/primitives/src/sighash.rs")
text = path.read_text()
insert = r'''

    #[test]
    fn precomputed_multi_input_cache_matches_lazy_sighashes() {
        let mut tx = synthetic_tx(2);
        let mut second = tx.inputs[0].clone();
        second.previous_output.vout = 1;
        tx.inputs.push(second);
        let prevouts = vec![
            crate::TxOut {
                value: 50_000,
                script_pubkey: vec![0x51],
            },
            crate::TxOut {
                value: 60_000,
                script_pubkey: vec![0x51],
            },
        ];

        let mut lazy_segwit = SighashCache::new(&tx);
        let expected_segwit = lazy_segwit
            .segwit_v0_signature_hash(1, &[0x51], 60_000, Sighash::All)
            .expect("lazy BIP143 sighash");
        let mut prepared = SighashCache::new(&tx);
        prepared.precompute_segwit_v0();
        assert_eq!(
            prepared
                .clone()
                .segwit_v0_signature_hash(1, &[0x51], 60_000, Sighash::All),
            Ok(expected_segwit),
            "cloned prepared BIP143 cache must preserve the oracle-tested digest"
        );

        let mut lazy_taproot = SighashCache::new(&tx);
        let expected_taproot = lazy_taproot
            .taproot_signature_hash(1, &prevouts, None, None, Sighash::All)
            .expect("lazy BIP341 sighash");
        let mut prepared = SighashCache::new(&tx);
        prepared.precompute_taproot(&prevouts);
        assert_eq!(
            prepared
                .clone()
                .taproot_signature_hash(1, &prevouts, None, None, Sighash::All),
            Ok(expected_taproot),
            "cloned prepared BIP341 cache must preserve the oracle-tested digest"
        );
    }
'''
module_end = text.rfind("\n}")
if module_end == -1:
    raise SystemExit("sighash.rs: tests module end not found")
path.write_text(text[:module_end] + insert + text[module_end:])
