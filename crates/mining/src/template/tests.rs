//! Coinbase-budget rule: what selection holds back, what `admits` checks, and
//! the identity qualifier. Pools hold real transactions; the size and weight
//! of a finished block are measured from its serialization, and a pool-shaped
//! coinbase is parsed back by rust-bitcoin, rather than read from the
//! candidate's own bookkeeping.
use super::*;
use bitcoin_rs_mempool::{MempoolEntry, MempoolLimits};
use bitcoin_rs_primitives::{Amount, LockTime, OutPoint, Script, Sequence, TxIn, TxOut};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PAYOUT: &[u8] = &[0x51];

#[derive(Clone, Copy)]
struct Limits {
    weight: u64,
    size: u64,
    sigops: u64,
}

const GENEROUS: Limits = Limits {
    weight: 4_000_000,
    size: 4_000_000,
    sigops: 80_000,
};

const BUDGET: CoinbaseBudget = CoinbaseBudget {
    additional_size: 1_000,
    additional_sigops: 7,
};

fn context(segwit_active: bool, limits: Limits) -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0x11; 32]),
        height: 100,
        version: 0x2000_0000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        min_time: 1,
        current_time: 2,
        locktime_cutoff: 1,
        staged_parent_mtp: 1,
        network: Network::Regtest,
        csv_active: true,
        segwit_active,
        max_weight: limits.weight,
        max_size: limits.size,
        max_sigops: limits.sigops,
    }
}

/// A transaction with a 200-byte witness, so its weight is not four times its size.
fn witnessed_tx(label: u8) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[label; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: vec![vec![label; 200]].into(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![0x51].into(),
        }],
    }
}

/// A pool holding the witnessed transaction with the given admitted sigop cost.
fn pool_with_tx(sigop_cost: u32) -> Result<Mempool, Box<dyn std::error::Error>> {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let tx = witnessed_tx(1);
    let vsize = u32::try_from(tx.vsize())?;
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx),
        vsize,
        10_000,
        0,
        0,
        sigop_cost,
    ))?;
    Ok(pool)
}

fn assemble(
    context: &CandidateContext,
    pool: &Mempool,
    budget: Option<CoinbaseBudget>,
) -> Result<Candidate, MiningError> {
    let body = select_template_body(pool, context, PAYOUT, budget)?;
    finish_candidate(context, &body, PAYOUT)
}

/// A v2 child spending the given parent outpoint with the given version and
/// sequence.
fn lock_child(parent: Txid, vout: u32, version: u32, sequence: u32) -> Tx {
    Tx {
        version,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent, vout),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: vec![vec![0x51; 10]].into(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(900),
            script_pubkey: vec![0x51].into(),
        }],
    }
}

fn insert_staged(pool: &mut Mempool, tx: Tx) -> Txid {
    let txid = tx.txid();
    let vsize = u32::try_from(tx.vsize()).unwrap_or_else(|_| panic!("fixture vsize fits"));
    pool.insert_entry(MempoolEntry::new(Arc::new(tx), vsize, 10_000, 0, 0, 0))
        .unwrap_or_else(|error| panic!("fixture insert stages: {error:?}"));
    txid
}

/// Relative locks of staged-confirmation parents evaluate at the staged
/// confirmation height instead of being skipped: a height lock met exactly
/// at the staged height selects, a lock needing one more block refuses, a
/// version-1 child stays exempt, and a time lock follows the staged
/// predecessor MTP against the candidate cutoff. Skipping would select
/// every child below.
/// BIP68 time-flag bit (`1 << 22`): the consensus flag constant is
/// crate-private, so the test names the bit it sets.
const TIME_FLAG: u32 = 1 << 22;

#[test]
fn projected_staged_parent_locks_evaluate_at_the_staged_height() -> TestResult {
    let mut pool = Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    });
    let parent = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0x77; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: vec![vec![0x51; 10]].into(),
        }],
        outputs: (0..4)
            .map(|_| TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x51].into(),
            })
            .collect(),
    };
    let parent_txid = insert_staged(&mut pool, parent.clone());
    let height_met = insert_staged(&mut pool, lock_child(parent_txid, 0, 2, 1));
    let _height_unmet = insert_staged(&mut pool, lock_child(parent_txid, 1, 2, 2));
    let unsigned = insert_staged(&mut pool, lock_child(parent_txid, 2, 1, 2));
    let timed = insert_staged(&mut pool, lock_child(parent_txid, 3, 2, TIME_FLAG | 1));

    let block = Block {
        header: Header::default(),
        txs: vec![parent],
    };
    let plan = pool.plan_block_removals(&block);
    assert_eq!(plan.removals.len(), 1, "only the parent stages");

    // Candidate at height 100: the staged parent confirms at 99. The exact
    // body set proves both directions: the met lock and the unsigned child
    // select, the unmet height and time locks refuse.
    let base = context(true, GENEROUS);
    let selected = select_template_body_after(&pool, &plan, &base, PAYOUT)?;
    let body: Vec<Txid> = selected.transactions.iter().map(|tx| tx.txid).collect();
    assert_eq!(body.len(), 2, "only two children survive: {body:?}");
    assert!(body.contains(&height_met), "the met height lock selects");
    assert!(body.contains(&unsigned), "the unsigned child selects");

    // Time lock with predecessor MTP 1_000: satisfied at cutoff 1_512,
    // refused at 1_511. The cutoff alone never stands in for the MTP.
    let met_time = CandidateContext {
        locktime_cutoff: 1_512,
        staged_parent_mtp: 1_000,
        ..base
    };
    let selected = select_template_body_after(&pool, &plan, &met_time, PAYOUT)?;
    assert!(
        selected.transactions.iter().any(|tx| tx.txid == timed),
        "a time lock met by the staged predecessor MTP selects"
    );
    let unmet_time = CandidateContext {
        locktime_cutoff: 1_511,
        staged_parent_mtp: 1_000,
        ..base
    };
    let selected = select_template_body_after(&pool, &plan, &unmet_time, PAYOUT)?;
    assert!(
        selected.transactions.iter().all(|tx| tx.txid != timed),
        "a time lock unmet by the staged predecessor MTP refuses"
    );
    Ok(())
}

/// Weight, serialized size, and sigop cost of the finished block, measured from
/// its block serialization rather than from the candidate's own bookkeeping.
fn used(candidate: &Candidate) -> Result<(u64, u64, u64), Box<dyn std::error::Error>> {
    let block = candidate.into_unsolved_block()?;
    let sigops = u64::from(transaction_sigop_cost(
        &candidate.coinbase,
        &[],
        VerifyFlags::NONE,
    )) + candidate
        .transactions
        .iter()
        .map(|tx| u64::from(tx.sigop_cost))
        .sum::<u64>();
    Ok((block.weight(), u64::try_from(block.total_size())?, sigops))
}

/// Serialized growth a pool coinbase needs for `budget` when the owner coinbase
/// is `candidate`'s and the pool's outputs do not widen the output count: the
/// declared output bytes plus the scriptSig headroom to the 100-byte limit.
fn growth_size(
    candidate: &Candidate,
    budget: CoinbaseBudget,
) -> Result<u64, Box<dyn std::error::Error>> {
    let script_sig = candidate.coinbase.inputs[0].script_sig.len();
    Ok(u64::from(budget.additional_size) + u64::try_from(100 - script_sig)?)
}

#[test]
fn growth_binds_each_dimension_exactly_and_the_selector_drops_what_no_longer_fits() -> TestResult {
    for segwit_active in [true, false] {
        let pool = pool_with_tx(50)?;
        let plain = assemble(&context(segwit_active, GENEROUS), &pool, None)?;
        assert_eq!(plain.transactions.len(), 1);
        let (weight, size, sigops) = used(&plain)?;
        assert_eq!(weight, plain.weight);
        let growth = growth_size(&plain, BUDGET)?;
        let cases = [
            (
                "weight",
                Limits {
                    weight: weight + 4 * growth,
                    ..GENEROUS
                },
            ),
            (
                "size",
                Limits {
                    size: size + growth,
                    ..GENEROUS
                },
            ),
            (
                "sigops",
                Limits {
                    sigops: sigops
                        + u64::from(BUDGET.additional_sigops)
                        + u64::try_from(100 - plain.coinbase.inputs[0].script_sig.len())? * 80,
                    ..GENEROUS
                },
            ),
        ];
        for (field, exact) in cases {
            // At the exact limit the transaction stays and the budget fits.
            let fit = assemble(&context(segwit_active, exact), &pool, Some(BUDGET))?;
            assert_eq!(fit.transactions.len(), 1, "{field}");
            fit.admits(BUDGET)?;
            assert_eq!(
                fit.weight, plain.weight,
                "{field}: the block never contains the growth"
            );
            // One unit tighter: the ordinary candidate still fits the context
            // but refuses the budget, in exactly this dimension.
            let tight = match field {
                "weight" => Limits {
                    weight: exact.weight - 1,
                    ..exact
                },
                "size" => Limits {
                    size: exact.size - 1,
                    ..exact
                },
                _ => Limits {
                    sigops: exact.sigops - 1,
                    ..exact
                },
            };
            let tight = context(segwit_active, tight);
            let ordinary = assemble(&tight, &pool, None)?;
            assert_eq!(ordinary.transactions.len(), 1, "{field}");
            assert!(
                matches!(
                    ordinary.admits(BUDGET),
                    Err(MiningError::CapacityExhausted { field: refused }) if refused == field
                ),
                "{field}"
            );
            // The budgeted selector drops the transaction that no longer fits
            // instead of producing a candidate its consumer must refuse.
            let selected = assemble(&tight, &pool, Some(BUDGET))?;
            assert!(selected.transactions.is_empty(), "{field}");
            selected.admits(BUDGET)?;
        }
    }
    Ok(())
}

/// The owner coinbase with a pool's scriptSig and outputs, as a pool builds it.
fn pool_coinbase(candidate: &Candidate, extra: Vec<TxOut>) -> Tx {
    let mut coinbase = candidate.coinbase.clone();
    let mut script = coinbase.inputs[0].script_sig.as_bytes().to_vec();
    script.resize(100, 0xae);
    coinbase.inputs[0].script_sig = script.into();
    coinbase.outputs.extend(extra);
    coinbase
}

/// `count` outputs of exactly `serialized` bytes each; the first carries one
/// legacy sigop (`OP_CHECKSIG`) when `sigop` is set.
fn outputs_of(count: usize, serialized: usize, sigop: bool) -> Vec<TxOut> {
    (0..count)
        .map(|index| {
            // 8-byte value, 1-byte script length, then the script itself.
            let mut script = vec![0x51_u8; serialized - 9];
            if sigop && index == 0 {
                script[0] = 0xac;
            }
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: script.into(),
            }
        })
        .collect()
}

#[test]
fn a_pool_shaped_coinbase_fits_the_derived_envelope_exactly() -> TestResult {
    // (budget, pool outputs): the outputs total exactly `additional_size` bytes.
    // 251 empty-script outputs push the output count to 253, widening its
    // CompactSize by two bytes for a segwit owner coinbase.
    let cases = [
        (BUDGET, outputs_of(10, 100, true)),
        (
            CoinbaseBudget {
                additional_size: 251 * 9,
                additional_sigops: 0,
            },
            outputs_of(251, 9, false),
        ),
    ];
    for segwit_active in [true, false] {
        for (budget, extra) in &cases {
            let pool = pool_with_tx(0)?;
            let plain = assemble(&context(segwit_active, GENEROUS), &pool, None)?;
            let (weight, size, sigops) = used(&plain)?;
            let total_outputs = plain.coinbase.outputs.len() + extra.len();
            let count_growth = if total_outputs >= 253 { 2 } else { 0 };
            let growth = growth_size(&plain, *budget)? + count_growth;
            let exact = Limits {
                weight: weight + 4 * growth,
                size: size + growth,
                sigops: sigops
                    + u64::from(budget.additional_sigops)
                    + u64::try_from(100 - plain.coinbase.inputs[0].script_sig.len())? * 80,
            };
            let fit = assemble(&context(segwit_active, exact), &pool, Some(*budget))?;
            fit.admits(*budget)?;

            let mut block = fit.into_unsolved_block()?;
            block.txs[0] = pool_coinbase(&fit, extra.clone());
            let bytes = consensus_bytes(&block);
            let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)?;
            assert_eq!(oracle.weight().to_wu(), exact.weight, "weight is exact");
            assert_eq!(
                u64::try_from(oracle.total_size())?,
                exact.size,
                "size is exact"
            );
            let coinbase_sigops = u64::try_from(oracle.txdata[0].total_sigop_cost(|_| None))?;
            let body_sigops = fit
                .transactions
                .iter()
                .map(|tx| u64::from(tx.sigop_cost))
                .sum::<u64>();
            assert!(coinbase_sigops + body_sigops <= exact.sigops);
        }
    }
    Ok(())
}

#[test]
fn an_infeasible_budget_names_its_first_exhausted_dimension() -> TestResult {
    let pool = pool_with_tx(50)?;
    let empty = Mempool::new(MempoolLimits::default());
    let base = assemble(&context(true, GENEROUS), &empty, None)?;
    let (weight, size, sigops) = used(&base)?;
    let at_base = Limits {
        weight,
        size,
        sigops,
    };
    // `Some(0, 0)` still reserves the coinbase's own growth, so it is a
    // different request from `None`: the empty block at its exact limits
    // holds the ordinary template but not even the empty budget.
    let nothing = CoinbaseBudget {
        additional_size: 0,
        additional_sigops: 0,
    };
    let one_sigop = CoinbaseBudget {
        additional_size: 0,
        additional_sigops: 1,
    };
    assert!(select_template_body(&pool, &context(true, at_base), PAYOUT, None).is_ok());
    let cases = [
        ("weight", at_base, nothing),
        (
            "size",
            Limits {
                weight: 4_000_000,
                ..at_base
            },
            nothing,
        ),
        (
            "sigops",
            Limits {
                weight: 4_000_000,
                size: 4_000_000,
                ..at_base
            },
            one_sigop,
        ),
    ];
    for (field, limits, budget) in cases {
        let limited = context(true, limits);
        let refused = select_template_body(&pool, &limited, PAYOUT, Some(budget));
        assert!(
            matches!(
                &refused,
                Err(MiningError::CapacityExhausted { field: actual }) if *actual == field
            ),
            "{field}: {refused:?}"
        );
        // The finished-candidate rule agrees with the selection rule: the
        // ordinary empty block at these limits refuses the same budget in the
        // same dimension.
        let ordinary = assemble(&limited, &pool, None)?;
        assert!(ordinary.transactions.is_empty(), "{field}");
        assert!(
            matches!(
                ordinary.admits(budget),
                Err(MiningError::CapacityExhausted { field: actual }) if actual == field
            ),
            "{field}"
        );
    }
    // A budget no block could ever hold is refused in weight first and does
    // not overflow any scalar on the way.
    let huge = CoinbaseBudget {
        additional_size: u32::MAX,
        additional_sigops: u16::MAX,
    };
    assert!(matches!(
        select_template_body(&pool, &context(true, GENEROUS), PAYOUT, Some(huge)),
        Err(MiningError::CapacityExhausted { field: "weight" })
    ));
    assert!(matches!(
        base.admits(huge),
        Err(MiningError::CapacityExhausted { field: "weight" })
    ));
    Ok(())
}

#[test]
fn ordinary_identity_is_unchanged_and_the_qualifier_parses_strictly() {
    let previous = Hash256::from_le_bytes(&[0x22; 32]);
    for fee_revision in [0, 3] {
        let ordinary = TemplateId::with_fee_revision(&previous, 7, fee_revision);
        assert_eq!(ordinary.clone().qualified(None), ordinary);
        assert_eq!(
            CoinbaseBudget::split_qualifier(ordinary.as_str()),
            Some((ordinary.as_str(), None))
        );
        let qualified = ordinary.clone().qualified(Some(BUDGET));
        assert_ne!(qualified, ordinary);
        assert!(qualified.as_str().starts_with(ordinary.as_str()));
        assert_eq!(
            CoinbaseBudget::split_qualifier(qualified.as_str()),
            Some((ordinary.as_str(), Some(BUDGET)))
        );
        // `Some(0, 0)` reserves growth, so it differs from the ordinary id.
        let zero = CoinbaseBudget {
            additional_size: 0,
            additional_sigops: 0,
        };
        assert_ne!(ordinary.clone().qualified(Some(zero)), ordinary);
    }
    let extremes = CoinbaseBudget {
        additional_size: u32::MAX,
        additional_sigops: u16::MAX,
    };
    let id = TemplateId::new(&previous, 1).qualified(Some(extremes));
    let split = CoinbaseBudget::split_qualifier(id.as_str());
    assert_eq!(split.map(|(_, budget)| budget), Some(Some(extremes)));
    for malformed in [
        "x@cb",
        "x@cb1",
        "x@cb1.",
        "x@cb.1",
        "x@cb01.1",
        "x@cb1.01",
        "x@cb+1.1",
        "x@cb1.1 ",
        "x@cb4294967296.1",
        "x@cb1.65536",
        "x@cb1.1@cb2.2",
        "x@CB1.1",
        "x@",
    ] {
        assert!(
            CoinbaseBudget::split_qualifier(malformed).is_none(),
            "must reject {malformed}"
        );
    }
}
