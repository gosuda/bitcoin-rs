use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bitcoin_rs_chain::compact_is_met_by;
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_consensus::bip34::check_bip34;
use bitcoin_rs_consensus::verify_block::verify_block_rules;
use bitcoin_rs_mempool::{
    AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolGateway,
    MempoolLimits, SubmitOutcome,
};
use bitcoin_rs_mining::pool::{
    BIP320_VERSION_MASK, BlockStatus, Extranonce, ExtranonceLayout, Job, JobBook, JobBookConfig,
    JobError, JobId, Session, SessionId, ShareClass, ShareError, ShareOutcome, ShareSubmission,
    ShareTarget, ShareWork, StaleReason, fetch_template,
};
use bitcoin_rs_mining::{
    BlockTemplate, BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult,
    BlockValidationResult, Candidate, CandidateContext, CoinbaseBudget, GenerateRequest,
    GeneratedBlock, MiningControl, MiningControlError, MiningError, MiningInfo, assemble_candidate,
};
use bitcoin_rs_primitives::{
    Amount, BlockHash, BlockPayload, CompactTarget, Hash256, Header, LockTime, Network, OutPoint,
    Script, Sequence, Tx, TxIn, TxOut, Txid, Witness, encode::consensus_bytes,
};
use bitcoin_rs_script::VerifyFlags;
use compact_str::CompactString;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn Error>>;

const PAYOUT: &[u8] = &[0x51];
static ROLLED: [u8; 4] = [7, 7, 7, 7];

fn context(height: u32, parent: u8) -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[parent; 32]),
        height,
        version: 0x2000_0000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        min_time: 1_700_000_001,
        current_time: 1_700_000_600,
        locktime_cutoff: 1_700_000_000,
        staged_parent_mtp: 1_700_000_000,
        network: Network::Regtest,
        csv_active: true,
        segwit_active: true,
        max_weight: 4_000_000,
        max_size: 4_000_000,
        max_sigops: 80_000,
    }
}

const COIN_VALUE_SAT: u64 = 1_000_000;
const ADMISSION_TIME: u64 = 1_700_000_000;

fn wsh_true_script() -> Vec<u8> {
    let program: [u8; 32] = Sha256::digest([0x51_u8]).into();
    let mut script = vec![0x00, 0x20];
    script.extend_from_slice(&program);
    script
}

fn p2wpkh_script(label: u8) -> Vec<u8> {
    let mut script = vec![0x00, 0x14];
    script.extend_from_slice(&[label; 20]);
    script
}

fn coin_outpoint(label: u8) -> OutPoint {
    let mut bytes = [0xc0_u8; 32];
    bytes[0] = label;
    OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0)
}

fn spend(label: u8) -> Tx {
    let mut tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: coin_outpoint(label),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0x51]]),
        }],
        outputs: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: Script::from_bytes(p2wpkh_script(label)),
        }],
        lock_time: LockTime::ZERO,
    };
    let fee = tx.vsize() * (2 + u64::from(label));
    tx.outputs[0].value = Amount::from_sat(COIN_VALUE_SAT - fee);
    tx
}

struct Coins(HashMap<OutPoint, TxOut>);

impl AdmissionChain for Coins {
    fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
        let prevouts = tx
            .inputs
            .iter()
            .filter_map(|input| {
                self.0
                    .get(&input.previous_output)
                    .map(|output| (input.previous_output, output.clone()))
            })
            .collect();
        Some(ChainAdmissionSnapshot {
            prevouts,
            height: 1,
            locktime_cutoff: 0,
            csv_active: false,
            next_block_script_flags: VerifyFlags::STANDARD,
            confirmed: false,
            ..ChainAdmissionSnapshot::default()
        })
    }
}

fn admitted_gateway(count: u8) -> Result<MempoolGateway, Box<dyn Error>> {
    let gateway = MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        None,
        ValidationEngine::Native,
        None,
    );
    let script = wsh_true_script();
    let coins = Coins(
        (1..=count)
            .map(|label| {
                (
                    coin_outpoint(label),
                    TxOut {
                        value: Amount::from_sat(COIN_VALUE_SAT),
                        script_pubkey: Script::from_bytes(script.clone()),
                    },
                )
            })
            .collect(),
    );
    for label in 1..=count {
        let outcome = gateway.submit_transaction(
            Arc::new(spend(label)),
            AdmissionOrigin::Rpc,
            None,
            ADMISSION_TIME,
            &coins,
        )?;
        if !matches!(outcome, SubmitOutcome::Committed(_)) {
            return Err(
                format!("fixture transaction {label} was not committed: {outcome:?}").into(),
            );
        }
    }
    Ok(gateway)
}

fn assemble(context: &CandidateContext, txs: u8) -> Result<Candidate, Box<dyn Error>> {
    let gateway = admitted_gateway(txs)?;
    let pool = gateway.read();
    Ok(assemble_candidate(context, &pool, PAYOUT)?)
}

fn build_candidate(height: u32, parent: u8, txs: u8) -> Result<Arc<Candidate>, Box<dyn Error>> {
    let candidate = assemble(&context(height, parent), txs)?;
    assert_eq!(candidate.transactions.len(), usize::from(txs));
    assert!(
        candidate
            .transactions
            .iter()
            .all(|entry| Hash256::from(entry.txid) != Hash256::from(entry.wtxid)),
        "fixture transactions carry witness data"
    );
    Ok(Arc::new(candidate))
}

fn budget() -> CoinbaseBudget {
    CoinbaseBudget {
        additional_size: 200,
        additional_sigops: 100,
    }
}

fn config() -> JobBookConfig {
    JobBookConfig {
        budget: budget(),
        extranonce: ExtranonceLayout::new(4, 4),
        coinbase_tag: b"/pool/".to_vec(),
        version_mask: BIP320_VERSION_MASK,
        ntime_forward_secs: 600,
        max_jobs: 8,
        max_sessions: 16,
        max_shares_per_job: 64,
    }
}

struct Fixture {
    book: JobBook,
    session: Session,
    job: Arc<Job>,
    candidate: Arc<Candidate>,
}

fn fixture(config: JobBookConfig, height: u32, txs: u8) -> Result<Fixture, Box<dyn Error>> {
    let candidate = build_candidate(height, 0xab, txs)?;
    let mut book = JobBook::new(config)?;
    let session = book.open_session()?;
    let installed = book.install(Arc::clone(&candidate), Vec::new())?;
    Ok(Fixture {
        book,
        session,
        job: installed.job,
        candidate,
    })
}

fn submit_for(session: &Session, job: &Job, nonce: u32) -> ShareSubmission<'static> {
    ShareSubmission {
        session: session.id(),
        job: job.id(),
        rolled_extranonce: &ROLLED,
        ntime: job.ntime(),
        nonce,
        version: job.version(),
    }
}

fn nonces(
    session: &Session,
    job: &Job,
    want_block: bool,
    count: usize,
) -> Result<Vec<u32>, Box<dyn Error>> {
    let extranonce = Extranonce {
        session: session.extranonce_prefix(),
        rolled: &ROLLED,
    };
    let mut found = Vec::new();
    for nonce in 0..=u32::MAX {
        let header = job.header(extranonce, job.ntime(), job.version(), nonce)?;
        let hash = Hash256::from(header.compute_hash());
        if compact_is_met_by(job.bits(), hash) == want_block {
            found.push(nonce);
            if found.len() == count {
                return Ok(found);
            }
        }
    }
    Err("nonce space exhausted".into())
}

fn header_hash(session: &Session, job: &Job, nonce: u32) -> Result<Hash256, Box<dyn Error>> {
    let extranonce = Extranonce {
        session: session.extranonce_prefix(),
        rolled: &ROLLED,
    };
    let header = job.header(extranonce, job.ntime(), job.version(), nonce)?;
    Ok(Hash256::from(header.compute_hash()))
}

fn easy() -> Result<ShareTarget, JobError> {
    ShareTarget::from_le_bytes([0xff; 32])
}

fn tiny_target_bytes() -> [u8; 32] {
    let mut value = [0_u8; 32];
    value[0] = 1;
    value
}

fn minus_one(mut little_endian: [u8; 32]) -> [u8; 32] {
    for byte in &mut little_endian {
        if *byte == 0 {
            *byte = 0xff;
        } else {
            *byte -= 1;
            break;
        }
    }
    little_endian
}

#[test]
fn branch_root_equals_node_merkle_root_for_every_tree_shape() -> TestResult {
    let mut plain = config();
    plain.extranonce = ExtranonceLayout::new(0, 0);
    plain.coinbase_tag = Vec::new();
    plain.max_sessions = 1;
    for txs in [0_u8, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
        let candidate = build_candidate(100, 0xab, txs)?;
        let mut book = JobBook::new(plain.clone())?;
        let installed = book.install(Arc::clone(&candidate), Vec::new())?;
        let expected = candidate.into_unsolved_block()?.header.merkle_root;
        let empty = Extranonce {
            session: &[],
            rolled: &[],
        };
        assert_eq!(
            installed.job.merkle_root(empty)?,
            expected,
            "{txs} transactions"
        );
        let leaves = usize::from(txs) + 1;
        let depth = usize::try_from((leaves - 1).bit_width())?;
        assert_eq!(
            installed.job.merkle_branch().len(),
            depth,
            "{txs} transactions"
        );
    }
    Ok(())
}

#[test]
fn coinbase_split_reproduces_the_txid_serialization() -> TestResult {
    let candidate = build_candidate(800_000, 0xab, 3)?;
    let mut book = JobBook::new(config())?;
    let session = book.open_session()?;
    let installed = book.install(Arc::clone(&candidate), Vec::new())?;
    let job = &installed.job;
    let rolled = [1_u8, 2, 3, 4];
    let extranonce = Extranonce {
        session: session.extranonce_prefix(),
        rolled: &rolled,
    };

    let base = candidate.coinbase.inputs[0].script_sig.as_bytes().to_vec();
    let mut script = base.clone();
    script.extend_from_slice(b"/pool/");
    script.extend_from_slice(session.extranonce_prefix());
    script.extend_from_slice(&rolled);
    let mut expected = candidate.coinbase.clone();
    expected.inputs[0].script_sig = Script::from_bytes(script);
    check_bip34(800_000, expected.inputs[0].script_sig.as_bytes())?;

    assert_eq!(job.coinbase_txid(extranonce)?, expected.txid());
    assert_eq!(job.coinbase_prefix().len(), 42 + base.len() + 6);

    let mut stripped = expected.clone();
    stripped.inputs[0].witness = Witness::new();
    let mut joined = job.coinbase_prefix().to_vec();
    joined.extend_from_slice(session.extranonce_prefix());
    joined.extend_from_slice(&rolled);
    joined.extend_from_slice(job.coinbase_suffix());
    assert_eq!(joined, consensus_bytes(&stripped));

    let other = [9_u8, 9, 9, 9];
    assert_ne!(
        job.coinbase_txid(extranonce)?,
        job.coinbase_txid(Extranonce {
            session: session.extranonce_prefix(),
            rolled: &other,
        })?
    );
    Ok(())
}

#[test]
fn block_candidate_passes_consensus_and_reproduces_the_share() -> TestResult {
    let mut fx = fixture(config(), 100, 3)?;
    let nonce = nonces(&fx.session, &fx.job, true, 1)?[0];
    let submission = submit_for(&fx.session, &fx.job, nonce);
    let target = ShareTarget::from_pool_difficulty(1)?;

    let ShareOutcome::Block(found) = fx.book.validate(&submission, &target)? else {
        return Err("a network-target hash must classify as a block".into());
    };
    assert_eq!(found.share.class, ShareClass::Block);
    verify_block_rules(&found.block)?;
    assert_eq!(found.raw, consensus_bytes(&found.block));
    assert_eq!(found.block.block_hash(), found.share.hash);
    assert!(compact_is_met_by(
        fx.candidate.bits,
        Hash256::from(found.share.hash)
    ));
    assert_eq!(found.block.txs.len(), 4);
    assert_eq!(found.coinbase_txid, found.block.txs[0].txid());
    assert_eq!(found.coinbase_value, fx.candidate.coinbase_value);
    let paid: u64 = found.block.txs[0]
        .outputs
        .iter()
        .map(|output| output.value.to_sat())
        .sum();
    assert_eq!(paid, fx.candidate.coinbase_value);
    assert!(found.block.weight() <= fx.candidate.max_weight);
    let network = ShareTarget::from_compact(fx.job.bits())?;
    assert_eq!(found.share.target, target);
    assert_eq!(found.share.work, network.work());
    assert_eq!(found.share.height, 100);
    assert_eq!(found.share.job, fx.job.id());

    let mut extranonce = fx.session.extranonce_prefix().to_vec();
    extranonce.extend_from_slice(&ROLLED);
    assert_eq!(found.share.extranonce, extranonce);
    let script_sig = found.block.txs[0].inputs[0].script_sig.as_bytes();
    assert_eq!(
        &script_sig[2..],
        [b"/pool/".as_slice(), extranonce.as_slice()]
            .concat()
            .as_slice()
    );

    let replay = fx.book.validate(&submission, &target);
    assert!(
        matches!(replay, Err(ShareError::Duplicate { first_job, .. }) if first_job == fx.job.id())
    );
    Ok(())
}

#[test]
fn unburn_releases_duplicate_key_for_retry() -> TestResult {
    let mut fx = fixture(config(), 100, 2)?;
    let target = easy()?;
    let job = Arc::clone(&fx.job);
    let first = fx
        .book
        .validate(&submit_for(&fx.session, &job, 41), &target)?;
    let hash = first.share().hash;
    let replay = fx
        .book
        .validate(&submit_for(&fx.session, &job, 41), &target);
    assert!(
        matches!(replay, Err(ShareError::Duplicate { first_job, .. }) if first_job == job.id())
    );
    assert!(
        !fx.book
            .unburn(&BlockHash::from(Hash256::from_le_bytes(&[0xcc; 32])))
    );
    assert!(fx.book.unburn(&hash));
    assert!(!fx.book.unburn(&hash));
    let retry = fx
        .book
        .validate(&submit_for(&fx.session, &job, 41), &target)?;
    assert_eq!(retry.share().hash, hash);
    let replay = fx
        .book
        .validate(&submit_for(&fx.session, &job, 41), &target);
    assert!(
        matches!(replay, Err(ShareError::Duplicate { first_job, .. }) if first_job == job.id())
    );
    Ok(())
}

#[test]
fn scriptsig_may_grow_to_exactly_the_consensus_limit() -> TestResult {
    let mut wide = config();
    wide.extranonce = ExtranonceLayout::new(1, 95);
    wide.coinbase_tag = Vec::new();
    wide.max_sessions = 4;
    let candidate = build_candidate(800_000, 0xab, 1)?;
    let mut book = JobBook::new(wide.clone())?;
    let session = book.open_session()?;
    let installed = book.install(Arc::clone(&candidate), Vec::new())?;
    let rolled = [0x00_u8; 95];
    let extranonce = Extranonce {
        session: session.extranonce_prefix(),
        rolled: &rolled,
    };
    let mut nonce = 0_u32;
    loop {
        let header = installed.job.header(
            extranonce,
            installed.job.ntime(),
            installed.job.version(),
            nonce,
        )?;
        if compact_is_met_by(installed.job.bits(), Hash256::from(header.compute_hash())) {
            break;
        }
        nonce += 1;
    }
    let submission = ShareSubmission {
        session: session.id(),
        job: installed.job.id(),
        rolled_extranonce: &rolled,
        ntime: installed.job.ntime(),
        nonce,
        version: installed.job.version(),
    };
    let ShareOutcome::Block(found) = book.validate(&submission, &easy()?)? else {
        return Err("expected a block".into());
    };
    assert_eq!(found.block.txs[0].inputs[0].script_sig.len(), 100);
    verify_block_rules(&found.block)?;

    wide.extranonce = ExtranonceLayout::new(1, 96);
    let mut over = JobBook::new(wide)?;
    assert_eq!(
        over.install(candidate, Vec::new()).err(),
        Some(JobError::ExtranonceExceedsScriptSig {
            room: 96,
            needed: 97
        })
    );
    Ok(())
}

#[test]
fn share_classes_and_target_boundaries() -> TestResult {
    let probe = fixture(config(), 100, 3)?;
    let share_nonce = nonces(&probe.session, &probe.job, false, 1)?[0];
    let block_nonce = nonces(&probe.session, &probe.job, true, 1)?[0];
    let hash = header_hash(&probe.session, &probe.job, share_nonce)?;

    let mut fx = fixture(config(), 100, 3)?;
    let outcome = fx
        .book
        .validate(&submit_for(&fx.session, &fx.job, share_nonce), &easy()?)?;
    let ShareOutcome::Share(accepted) = outcome else {
        return Err("a hash above the network target is a share".into());
    };
    assert_eq!(accepted.class, ShareClass::Share);
    assert_eq!(accepted.hash, BlockHash::from(hash));
    assert_eq!(accepted.work.as_u128(), Some(1));
    assert_eq!(accepted.header.nonce, share_nonce);

    let mut fx = fixture(config(), 100, 3)?;
    let at_target = ShareTarget::from_le_bytes(hash.to_le_bytes())?;
    let outcome = fx
        .book
        .validate(&submit_for(&fx.session, &fx.job, share_nonce), &at_target)?;
    assert!(matches!(outcome, ShareOutcome::Share(_)));

    let mut fx = fixture(config(), 100, 3)?;
    let below = ShareTarget::from_le_bytes(minus_one(hash.to_le_bytes()))?;
    let verdict = fx
        .book
        .validate(&submit_for(&fx.session, &fx.job, share_nonce), &below);
    assert!(matches!(verdict, Err(ShareError::BelowTarget { .. })));

    let mut fx = fixture(config(), 100, 3)?;
    let tightest = ShareTarget::from_le_bytes(tiny_target_bytes())?;
    let verdict = fx
        .book
        .validate(&submit_for(&fx.session, &fx.job, block_nonce), &tightest)?;
    assert!(
        matches!(verdict, ShareOutcome::Block(_)),
        "network target takes precedence over the share target"
    );
    Ok(())
}

#[test]
fn fallback_block_work_is_capped_at_the_network_target() -> TestResult {
    let mut fx = fixture(config(), 100, 3)?;
    let network = ShareTarget::from_compact(fx.job.bits())?;
    let harder = ShareTarget::from_le_bytes(tiny_target_bytes())?;
    let mut block_nonce = None;
    for candidate in nonces(&fx.session, &fx.job, true, 5)? {
        let hash = header_hash(&fx.session, &fx.job, candidate)?;
        if !harder.meets(hash) {
            block_nonce = Some((candidate, hash));
            break;
        }
    }
    let (nonce, hash) = block_nonce.ok_or("a fallback block nonce exists")?;
    assert!(compact_is_met_by(fx.job.bits(), hash));
    assert!(!harder.meets(hash));
    let ShareOutcome::Block(found) = fx
        .book
        .validate(&submit_for(&fx.session, &fx.job, nonce), &harder)?
    else {
        return Err("a network-valid hash from a harder channel target is a block".into());
    };
    assert_eq!(found.share.target, harder);
    assert_eq!(found.share.work, network.work());
    assert_ne!(found.share.work, harder.work());
    Ok(())
}

fn assert_malformed_session_and_job_inputs(
    book: &mut JobBook,
    session: &Session,
    job: &Arc<Job>,
    target: &ShareTarget,
) {
    let verdict = book.validate(
        &ShareSubmission {
            session: SessionId::new(999),
            ..submit_for(session, job, 0)
        },
        target,
    );
    assert_eq!(
        verdict.err(),
        Some(ShareError::UnknownSession(SessionId::new(999)))
    );
    for unknown in [JobId::new(0), JobId::new(77)] {
        let verdict = book.validate(
            &ShareSubmission {
                job: unknown,
                ..submit_for(session, job, 0)
            },
            target,
        );
        assert_eq!(verdict.err(), Some(ShareError::UnknownJob(unknown)));
    }

    let first = book.validate(&submit_for(session, job, 41), target);
    assert!(first.is_ok());
    let second = book.validate(&submit_for(session, job, 41), target);
    assert!(matches!(
        second,
        Err(ShareError::Duplicate { first_job, .. }) if first_job == job.id()
    ));

    assert!(book.close_session(session.id()));
    let verdict = book.validate(&submit_for(session, job, 42), target);
    assert_eq!(
        verdict.err(),
        Some(ShareError::UnknownSession(session.id()))
    );
}

#[test]
fn malformed_shares_are_rejected_for_their_own_reason() -> TestResult {
    let mut fx = fixture(config(), 100, 2)?;
    let target = easy()?;
    let job = Arc::clone(&fx.job);

    let short = [1_u8, 2, 3];
    let verdict = fx.book.validate(
        &ShareSubmission {
            rolled_extranonce: &short,
            ..submit_for(&fx.session, &job, 0)
        },
        &target,
    );
    assert!(matches!(
        verdict,
        Err(ShareError::ExtranonceLength {
            expected: 4,
            actual: 3
        })
    ));

    let outside = job.version() ^ 0x0000_0001;
    let verdict = fx.book.validate(
        &ShareSubmission {
            version: outside,
            ..submit_for(&fx.session, &job, 0)
        },
        &target,
    );
    assert_eq!(
        verdict.err(),
        Some(ShareError::VersionOutsideMask {
            version: outside,
            job_version: job.version(),
            mask: BIP320_VERSION_MASK
        })
    );

    let rolled_version = job.version_from_rolled_bits(0x0000_2000)?;
    assert_eq!(rolled_version, job.version() | 0x0000_2000);
    assert!(
        fx.book
            .validate(
                &ShareSubmission {
                    version: rolled_version,
                    ..submit_for(&fx.session, &job, 0)
                },
                &target
            )
            .is_ok()
    );
    assert!(matches!(
        job.version_from_rolled_bits(0x0000_0001),
        Err(ShareError::VersionOutsideMask { .. })
    ));

    let verdict = fx.book.validate(
        &ShareSubmission {
            ntime: job.min_ntime() - 1,
            ..submit_for(&fx.session, &job, 0)
        },
        &target,
    );
    assert_eq!(
        verdict.err(),
        Some(ShareError::TimeTooEarly {
            ntime: job.min_ntime() - 1,
            min_ntime: job.min_ntime()
        })
    );
    for edge in [job.min_ntime(), job.max_ntime()] {
        let verdict = fx.book.validate(
            &ShareSubmission {
                ntime: edge,
                ..submit_for(&fx.session, &job, 0)
            },
            &target,
        );
        assert!(verdict.is_ok(), "ntime {edge} is inside the window");
    }
    let verdict = fx.book.validate(
        &ShareSubmission {
            ntime: job.max_ntime() + 1,
            ..submit_for(&fx.session, &job, 0)
        },
        &target,
    );
    assert_eq!(
        verdict.err(),
        Some(ShareError::TimeTooLate {
            ntime: job.max_ntime() + 1,
            max_ntime: job.max_ntime()
        })
    );

    assert_malformed_session_and_job_inputs(&mut fx.book, &fx.session, &job, &target);
    Ok(())
}

#[test]
fn rejected_input_cannot_fill_the_duplicate_set_and_capacity_never_refuses_a_block() -> TestResult {
    let mut tiny = config();
    tiny.max_shares_per_job = 1;
    let probe = fixture(tiny.clone(), 100, 1)?;
    let shares = nonces(&probe.session, &probe.job, false, 2)?;
    let block = nonces(&probe.session, &probe.job, true, 1)?[0];

    let mut fx = fixture(tiny, 100, 1)?;
    let tight = ShareTarget::from_le_bytes(tiny_target_bytes())?;
    for _ in 0..4 {
        let verdict = fx
            .book
            .validate(&submit_for(&fx.session, &fx.job, shares[0]), &tight);
        assert!(matches!(verdict, Err(ShareError::BelowTarget { .. })));
    }
    let target = easy()?;
    assert!(
        fx.book
            .validate(&submit_for(&fx.session, &fx.job, shares[0]), &target)
            .is_ok()
    );
    let verdict = fx
        .book
        .validate(&submit_for(&fx.session, &fx.job, shares[1]), &target);
    assert_eq!(
        verdict.err(),
        Some(ShareError::JobShareCapacity {
            job: fx.job.id(),
            capacity: 1
        })
    );
    let outcome = fx
        .book
        .validate(&submit_for(&fx.session, &fx.job, block), &target)?;
    assert!(matches!(outcome, ShareOutcome::Block(_)));
    Ok(())
}

#[test]
fn block_candidate_at_job_capacity_is_remembered_as_duplicate_on_replay() -> TestResult {
    let mut tiny = config();
    tiny.max_shares_per_job = 1;
    let mut fx = fixture(tiny, 100, 1)?;
    let target = easy()?;
    let share = nonces(&fx.session, &fx.job, false, 1)?[0];
    fx.book
        .validate(&submit_for(&fx.session, &fx.job, share), &target)?;
    let block = nonces(&fx.session, &fx.job, true, 1)?[0];
    let outcome = fx
        .book
        .validate(&submit_for(&fx.session, &fx.job, block), &target)?;
    assert!(matches!(outcome, ShareOutcome::Block(_)));
    let replay = fx
        .book
        .validate(&submit_for(&fx.session, &fx.job, block), &target);
    assert!(
        matches!(replay, Err(ShareError::Duplicate { .. })),
        "a block accepted at capacity must be remembered: {replay:?}"
    );
    Ok(())
}

#[test]
fn extra_outputs_are_funded_from_the_payout_and_stay_valid() -> TestResult {
    let candidate = build_candidate(100, 0xab, 2)?;
    let extra = vec![TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: Script::from_bytes(vec![0x51, 0x51]),
    }];
    let mut book = JobBook::new(config())?;
    let session = book.open_session()?;
    let installed = book.install(Arc::clone(&candidate), extra.clone())?;
    assert_eq!(installed.job.extra_outputs(), extra.as_slice());
    let nonce = nonces(&session, &installed.job, true, 1)?[0];
    let ShareOutcome::Block(found) = book.validate(
        &submit_for(&session, &installed.job, nonce),
        &ShareTarget::from_pool_difficulty(1)?,
    )?
    else {
        return Err("expected a block".into());
    };
    verify_block_rules(&found.block)?;
    let outputs = &found.block.txs[0].outputs;
    assert_eq!(outputs.len(), 3);
    assert_eq!(outputs[0].value.to_sat(), candidate.coinbase_value - 1_000);
    assert_eq!(
        outputs[0].script_pubkey,
        candidate.coinbase.outputs[0].script_pubkey
    );
    assert_eq!(outputs[1], extra[0]);
    assert_eq!(outputs[2], candidate.coinbase.outputs[1]);
    let paid: u64 = outputs.iter().map(|output| output.value.to_sat()).sum();
    assert_eq!(paid, candidate.coinbase_value);
    Ok(())
}

#[test]
fn out_of_budget_jobs_are_refused() -> TestResult {
    let candidate = build_candidate(100, 0xab, 1)?;
    let mut book = JobBook::new(config())?;

    let oversize = vec![TxOut {
        value: Amount::from_sat(1),
        script_pubkey: Script::from_bytes(vec![0x51; 300]),
    }];
    assert_eq!(
        book.install(Arc::clone(&candidate), oversize).err(),
        Some(JobError::ExtraOutputsSize {
            used: 8 + 3 + 300,
            budget: 200
        })
    );

    let sigop_heavy = vec![TxOut {
        value: Amount::from_sat(1),
        script_pubkey: Script::from_bytes(vec![0xac; 30]),
    }];
    assert!(matches!(
        book.install(Arc::clone(&candidate), sigop_heavy).err(),
        Some(JobError::ExtraOutputsSigops { used, budget: 100 }) if used > 100
    ));

    let overspend = vec![TxOut {
        value: Amount::from_sat(candidate.coinbase_value + 1),
        script_pubkey: Script::from_bytes(vec![0x51]),
    }];
    assert_eq!(
        book.install(Arc::clone(&candidate), overspend).err(),
        Some(JobError::ExtraOutputsValue {
            extra: candidate.coinbase_value + 1,
            available: candidate.coinbase_value
        })
    );

    let roomy = build_candidate(100, 0xab, 0)?;
    let snug = assemble(
        &CandidateContext {
            max_weight: roomy.weight,
            ..context(100, 0xab)
        },
        0,
    )?;
    assert_eq!(
        book.install(Arc::new(snug), Vec::new()).err(),
        Some(JobError::Budget(MiningError::CapacityExhausted {
            field: "weight"
        }))
    );

    assert_eq!(book.current().map(|job| job.id()), None);
    Ok(())
}

#[test]
fn sessions_get_unique_bounded_prefixes_and_reuse_oldest_freed_first() -> TestResult {
    let mut small = config();
    small.extranonce = ExtranonceLayout::new(1, 4);
    small.max_sessions = 3;
    let mut book = JobBook::new(small)?;
    let first = book.open_session()?;
    let second = book.open_session()?;
    let third = book.open_session()?;
    assert_eq!(first.extranonce_prefix(), &[0]);
    assert_eq!(second.extranonce_prefix(), &[1]);
    assert_eq!(third.extranonce_prefix(), &[2]);
    assert_eq!(
        book.open_session().err(),
        Some(JobError::SessionCapacity { capacity: 3 })
    );
    assert!(book.close_session(second.id()));
    assert!(!book.close_session(second.id()));
    assert!(book.session(second.id()).is_none());
    let reopened = book.open_session()?;
    assert_eq!(reopened.extranonce_prefix(), &[1]);
    assert_ne!(reopened.id(), second.id());
    assert_eq!(book.session_count(), 3);

    let mut single = config();
    single.extranonce = ExtranonceLayout::new(0, 4);
    single.max_sessions = 1;
    let mut book = JobBook::new(single.clone())?;
    assert_eq!(book.open_session()?.extranonce_prefix(), &[0_u8; 0]);
    assert!(book.open_session().is_err());

    single.max_sessions = 2;
    assert!(matches!(
        JobBook::new(single).err(),
        Some(JobError::InvalidConfig(_))
    ));
    Ok(())
}

#[test]
fn unusable_configurations_are_refused() {
    let broken = [
        JobBookConfig {
            max_jobs: 0,
            ..config()
        },
        JobBookConfig {
            max_sessions: 0,
            ..config()
        },
        JobBookConfig {
            max_shares_per_job: 0,
            ..config()
        },
        JobBookConfig {
            version_mask: 0x8000_0000,
            ..config()
        },
        JobBookConfig {
            ntime_forward_secs: 7_201,
            ..config()
        },
        JobBookConfig {
            extranonce: ExtranonceLayout::new(4, 90),
            ..config()
        },
    ];
    for candidate in broken {
        assert!(
            matches!(
                JobBook::new(candidate).err(),
                Some(JobError::InvalidConfig(_))
            ),
            "configuration must be refused"
        );
    }
}

#[test]
fn install_reports_exact_parent_and_staleness_facts() -> TestResult {
    let mut book = JobBook::new(config())?;
    let session = book.open_session()?;
    let target = easy()?;

    let first = book.install(build_candidate(100, 1, 0)?, Vec::new())?;
    assert!(first.fresh && first.clean_jobs && !first.parent_changed);
    assert_eq!(first.invalidated.len(), 0);

    let unchanged = book.install(Arc::clone(first.job.candidate()), Vec::new())?;
    assert!(!unchanged.fresh && !unchanged.clean_jobs && !unchanged.parent_changed);
    assert!(Arc::ptr_eq(&unchanged.job, &first.job));

    let refreshed = book.install(build_candidate(100, 1, 1)?, Vec::new())?;
    assert!(refreshed.fresh && !refreshed.clean_jobs && !refreshed.parent_changed);
    assert_eq!(refreshed.invalidated.len(), 0);
    assert!(
        book.validate(&submit_for(&session, &first.job, 5), &target)
            .is_ok(),
        "a same-parent refresh does not stale earlier jobs"
    );

    let extended = book.install(build_candidate(101, 2, 0)?, Vec::new())?;
    assert!(extended.clean_jobs && extended.parent_changed);
    assert_eq!(
        extended.invalidated,
        vec![first.job.id(), refreshed.job.id()]
    );
    let verdict = book.validate(&submit_for(&session, &refreshed.job, 6), &target);
    assert_eq!(
        verdict.err(),
        Some(ShareError::Stale {
            job: refreshed.job.id(),
            reason: StaleReason::PreviousBlockChanged
        })
    );

    let competing = book.install(build_candidate(100, 3, 0)?, Vec::new())?;
    assert!(competing.clean_jobs && competing.parent_changed);
    assert_eq!(competing.invalidated, vec![extended.job.id()]);

    assert_eq!(book.invalidate_active(), vec![competing.job.id()]);
    assert!(book.current().is_none());
    let verdict = book.validate(&submit_for(&session, &competing.job, 7), &target);
    assert_eq!(
        verdict.err(),
        Some(ShareError::Stale {
            job: competing.job.id(),
            reason: StaleReason::Invalidated
        })
    );

    let resumed = book.install(build_candidate(100, 3, 1)?, Vec::new())?;
    assert!(resumed.clean_jobs && !resumed.parent_changed);
    assert_eq!(resumed.invalidated.len(), 0);

    let back = book.install(build_candidate(101, 1, 0)?, Vec::new())?;
    assert!(back.clean_jobs && back.parent_changed);
    let verdict = book.validate(&submit_for(&session, &first.job, 8), &target);
    assert!(
        matches!(verdict, Err(ShareError::Stale { .. })),
        "a stale job is never revived when its parent returns"
    );
    assert_eq!(book.current().map(|job| job.id()), Some(back.job.id()));
    Ok(())
}

#[test]
fn retention_is_bounded_and_retired_jobs_are_stale() -> TestResult {
    let mut small = config();
    small.max_jobs = 2;
    let mut book = JobBook::new(small)?;
    let session = book.open_session()?;
    let first = book.install(build_candidate(100, 1, 0)?, Vec::new())?;
    let second = book.install(build_candidate(100, 1, 1)?, Vec::new())?;
    let third = book.install(build_candidate(100, 1, 2)?, Vec::new())?;
    assert!(book.job(first.job.id()).is_none());
    assert!(book.job(second.job.id()).is_some());
    assert!(book.job(third.job.id()).is_some());
    let target = easy()?;
    assert_eq!(
        book.validate(&submit_for(&session, &first.job, 1), &target)
            .err(),
        Some(ShareError::Stale {
            job: first.job.id(),
            reason: StaleReason::Retired
        })
    );
    assert!(
        book.validate(&submit_for(&session, &second.job, 1), &target)
            .is_ok()
    );
    Ok(())
}

#[test]
fn pool_difficulty_targets_and_work_are_exact() -> TestResult {
    let one = ShareTarget::from_pool_difficulty(1)?;
    let mut expected = [0_u8; 32];
    expected[4] = 0xff;
    expected[5] = 0xff;
    assert_eq!(one.to_be_bytes(), expected);
    let mut little = expected;
    little.reverse();
    assert_eq!(one.to_le_bytes(), little);
    assert_eq!(ShareTarget::from_be_bytes(expected)?, one);
    assert_eq!(one.work().as_u128(), Some(4_295_032_833));

    let two = ShareTarget::from_pool_difficulty(2)?;
    let mut halved = [0_u8; 32];
    halved[4] = 0x7f;
    halved[5] = 0xff;
    halved[6] = 0x80;
    assert_eq!(two.to_be_bytes(), halved);
    assert!(two.work() > one.work());

    let half = ShareTarget::from_pool_difficulty_decimal("0.5")?;
    let mut doubled = [0_u8; 32];
    doubled[3] = 0x01;
    doubled[4] = 0xff;
    doubled[5] = 0xfe;
    assert_eq!(half.to_be_bytes(), doubled);
    assert_eq!(ShareTarget::from_pool_difficulty_ratio(1, 2)?, half);
    assert_eq!(ShareTarget::from_pool_difficulty_ratio(3, 6)?, half);
    assert_eq!(ShareTarget::from_pool_difficulty_decimal("2")?, two);
    assert_eq!(ShareTarget::from_pool_difficulty_decimal("2.000")?, two);
    assert_eq!(ShareTarget::from_pool_difficulty_decimal("2.")?, two);

    let everything = ShareTarget::from_le_bytes([0xff; 32])?;
    assert_eq!(
        ShareTarget::from_pool_difficulty_ratio(1, u64::MAX)?,
        everything
    );
    assert_eq!(everything.work().as_u128(), Some(1));
    let total = one
        .work()
        .checked_add(two.work())
        .and_then(ShareWork::as_u128);
    assert_eq!(
        total,
        one.work()
            .as_u128()
            .zip(two.work().as_u128())
            .map(|(a, b)| a + b)
    );

    assert_eq!(
        ShareTarget::from_le_bytes([0; 32]),
        Err(JobError::ZeroTarget)
    );
    assert_eq!(
        ShareTarget::from_pool_difficulty(0),
        Err(JobError::ZeroTarget)
    );
    assert_eq!(
        ShareTarget::from_pool_difficulty_ratio(1, 0),
        Err(JobError::ZeroTarget)
    );
    for zero in ["0", "0.0", "000.000"] {
        assert_eq!(
            ShareTarget::from_pool_difficulty_decimal(zero),
            Err(JobError::ZeroTarget),
            "{zero}"
        );
    }
    for malformed in [
        "",
        "-1",
        "1e3",
        ".5",
        "1.2.3",
        " 1",
        "12345678901234567890",
        "1,5",
    ] {
        assert_eq!(
            ShareTarget::from_pool_difficulty_decimal(malformed),
            Err(JobError::InvalidDifficulty),
            "{malformed:?}"
        );
    }
    Ok(())
}

struct RecordingControl {
    template: Option<BlockTemplate>,
    verdict: Mutex<Result<BlockValidationResult, MiningControlError>>,
    requests: Mutex<Vec<BlockTemplateRequest>>,
    submitted: Mutex<Vec<BlockPayload>>,
}

impl RecordingControl {
    fn new(
        template: Option<BlockTemplate>,
        verdict: Result<BlockValidationResult, MiningControlError>,
    ) -> Self {
        Self {
            template,
            verdict: Mutex::new(verdict),
            requests: Mutex::new(Vec::new()),
            submitted: Mutex::new(Vec::new()),
        }
    }

    fn set_verdict(&self, verdict: Result<BlockValidationResult, MiningControlError>) {
        *lock(&self.verdict) = verdict;
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unused() -> MiningControlError {
    MiningControlError::Unavailable(CompactString::from("not used by these tests"))
}

impl MiningControl for RecordingControl {
    fn get_block_template(
        &self,
        request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError> {
        lock(&self.requests).push(request);
        match &self.template {
            Some(template) => Ok(BlockTemplateResult::Template(template.clone())),
            None => Ok(BlockTemplateResult::Proposal(
                BlockValidationResult::Accepted,
            )),
        }
    }

    fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
        Err(unused())
    }

    fn network_hash_ps(&self, _lookup: i64, _height: i64) -> Result<f64, MiningControlError> {
        Err(unused())
    }

    fn submit_block(
        &self,
        payload: BlockPayload,
    ) -> Result<BlockValidationResult, MiningControlError> {
        lock(&self.submitted).push(payload);
        lock(&self.verdict).clone()
    }

    fn submit_header(&self, _header: Header) -> Result<(), MiningControlError> {
        Err(unused())
    }

    fn publish_generation(&self) {}

    fn publish_fee_delta_generation(&self, _fee_delta_sequence: u64) {}

    fn generate(
        &self,
        _request: GenerateRequest,
    ) -> Result<Vec<GeneratedBlock>, MiningControlError> {
        Err(unused())
    }
}

fn template_around(candidate: &Arc<Candidate>) -> BlockTemplate {
    BlockTemplate {
        candidate: Arc::clone(candidate),
        rules: Vec::new(),
        version_bits_available: Vec::new(),
        version_bits_required: 0,
        capabilities: Vec::new(),
        mutable: Vec::new(),
        submit_old: None,
        signet: None,
    }
}

#[test]
fn found_blocks_reach_the_authoritative_submit_path_and_receipts_map_verdicts() -> TestResult {
    let mut fx = fixture(config(), 100, 2)?;
    let nonce = nonces(&fx.session, &fx.job, true, 1)?[0];
    let ShareOutcome::Block(found) = fx.book.validate(
        &submit_for(&fx.session, &fx.job, nonce),
        &ShareTarget::from_pool_difficulty(1)?,
    )?
    else {
        return Err("expected a block".into());
    };

    let control = RecordingControl::new(None, Ok(BlockValidationResult::Accepted));
    let receipt = found.submit(&control)?;
    assert_eq!(receipt.status(), BlockStatus::Applied);
    assert_eq!(receipt.hash, found.share.hash);
    assert_eq!(receipt.height, 100);
    assert_eq!(receipt.coinbase_txid, found.coinbase_txid);
    assert_eq!(receipt.coinbase_value, fx.candidate.coinbase_value);
    assert_eq!(receipt.session, fx.session.id());
    assert_eq!(receipt.job, fx.job.id());
    {
        let submitted = lock(&control.submitted);
        assert_eq!(submitted.len(), 1);
        assert_eq!(submitted[0].block(), &found.block);
        assert_eq!(submitted[0].bytes().as_ref(), found.raw.as_slice());
    }

    let cases = [
        (BlockValidationResult::Duplicate, BlockStatus::Applied),
        (
            BlockValidationResult::DuplicateInvalid,
            BlockStatus::Rejected,
        ),
        (
            BlockValidationResult::Rejected(CompactString::from("bad-txnmrklroot")),
            BlockStatus::Rejected,
        ),
        (
            BlockValidationResult::Inconclusive,
            BlockStatus::Undetermined,
        ),
        (
            BlockValidationResult::DuplicateInconclusive,
            BlockStatus::Undetermined,
        ),
    ];
    for (verdict, status) in cases {
        control.set_verdict(Ok(verdict.clone()));
        let receipt = found.submit(&control)?;
        assert_eq!(receipt.result, verdict);
        assert_eq!(receipt.status(), status);
    }

    control.set_verdict(Err(unused()));
    assert_eq!(found.submit(&control).err(), Some(unused()));
    control.set_verdict(Ok(BlockValidationResult::Accepted));
    assert_eq!(found.submit(&control)?.status(), BlockStatus::Applied);
    Ok(())
}

#[test]
fn templates_are_requested_with_the_declared_budget() -> TestResult {
    let candidate = build_candidate(100, 0xab, 1)?;
    let control = RecordingControl::new(
        Some(template_around(&candidate)),
        Ok(BlockValidationResult::Accepted),
    );
    let template = fetch_template(&control, budget(), Some("previous-generation"))?;
    assert!(Arc::ptr_eq(&template.candidate, &candidate));
    {
        let requests = lock(&control.requests);
        assert_eq!(requests.len(), 1);
        assert!(matches!(requests[0].mode, BlockTemplateMode::Template));
        assert_eq!(requests[0].coinbase_budget, Some(budget()));
        assert_eq!(
            requests[0].long_poll_id.as_deref(),
            Some("previous-generation")
        );
    }

    let mut book = JobBook::new(config())?;
    let installed = book.install(Arc::clone(&template.candidate), Vec::new())?;
    assert!(installed.fresh && installed.clean_jobs);

    let proposal_only = RecordingControl::new(None, Ok(BlockValidationResult::Accepted));
    assert!(matches!(
        fetch_template(&proposal_only, budget(), None),
        Err(MiningControlError::Failed(_))
    ));
    Ok(())
}

#[test]
fn accepted_block_retirement_makes_second_same_job_nonce_stale() -> TestResult {
    let mut fx = fixture(config(), 100, 2)?;
    let target = ShareTarget::from_pool_difficulty(1)?;
    let winning = nonces(&fx.session, &fx.job, true, 2)?;
    let outcome = fx
        .book
        .validate(&submit_for(&fx.session, &fx.job, winning[0]), &target)?;
    assert!(
        matches!(outcome, ShareOutcome::Block(_)),
        "first known winning nonce is accepted"
    );
    fx.book.invalidate_active();
    assert!(fx.book.current().is_none());
    let err = fx
        .book
        .validate(&submit_for(&fx.session, &fx.job, winning[1]), &target)
        .err();
    assert_eq!(
        err,
        Some(ShareError::Stale {
            job: fx.job.id(),
            reason: StaleReason::Invalidated
        }),
        "second winning nonce on the same job is stale and never resubmitted"
    );
    let replay = fx
        .book
        .validate(&submit_for(&fx.session, &fx.job, winning[0]), &target)
        .err();
    assert!(
        matches!(replay, Some(ShareError::Duplicate { .. })),
        "exact replay of an accepted share keeps duplicate identity, not stale"
    );
    let next = fx
        .book
        .install(build_candidate(101, 0xcd, 0)?, Vec::new())?;
    assert!(next.clean_jobs, "new parent job is fresh");
    let share = nonces(&fx.session, &next.job, false, 1)?[0];
    assert!(
        fx.book
            .validate(&submit_for(&fx.session, &next.job, share), &easy()?)
            .is_ok(),
        "new parent job accepts shares"
    );
    Ok(())
}
