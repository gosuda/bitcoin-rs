#![cfg(any(feature = "redb", feature = "fjall"))]

use std::{path::Path, sync::Arc};

use bitcoin_rs_mining::pool::ledger as pool_ledger;
use bitcoin_rs_mining::pool::ledger::{
    Balance, Ledger, MinerId, PayoutPolicy, PoolConfig, RoundState, ShareCredit, ShareReceipt,
};
use bitcoin_rs_mining::pool::stratum::sv1::{AccountResolver, Password};
use bitcoin_rs_mining::pool::{
    AcceptedShare, BlockReceipt, FoundBlock, JobId, LedgerUnavailable, RecordOutcome, SessionId,
    ShareClass, ShareLedger, ShareTarget, WorkerIdentity,
};
use bitcoin_rs_mining::{BlockValidationResult, MiningControlError};
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Header, Txid};
use bitcoin_rs_rpc::context::PoolOperator;
use bitcoin_rs_storage::KvStore;

use super::ledger::LedgerHost;

type OpenStore = fn(&Path) -> Result<Arc<dyn KvStore>, Box<dyn std::error::Error>>;
type TestResult = Result<(), Box<dyn std::error::Error>>;
const EPOCH: u32 = 17;

fn config() -> PoolConfig {
    PoolConfig::new(1_000, vec![0x51])
}

fn payout_policy() -> PayoutPolicy {
    PayoutPolicy {
        min_payout_sat: 1_000,
        max_outputs: 10,
    }
}

fn registered_host(
    open: OpenStore,
    path: &Path,
    epoch: u32,
) -> Result<LedgerHost, Box<dyn std::error::Error>> {
    let ledger = Arc::new(Ledger::create(open(path)?, config())?);
    ledger.set_payout_script(MinerId(42), &[0x51])?;
    Ok(LedgerHost::new(ledger, epoch, payout_policy()))
}

fn worker() -> WorkerIdentity {
    WorkerIdentity {
        account: "42".to_owned(),
        worker: "rig".to_owned(),
    }
}

fn share() -> Result<AcceptedShare, Box<dyn std::error::Error>> {
    let header = Header {
        version: 4,
        nonce: 0x1234_5678,
        time: 1_700_000_000,
        ..Header::default()
    };
    let target = ShareTarget::from_le_bytes([0xff; 32])?;
    Ok(AcceptedShare {
        session: SessionId::new(9),
        job: JobId::new(0x0102_0304),
        hash: header.compute_hash(),
        header,
        height: 101,
        previous_block_hash: BlockHash::from(Hash256::from_le_bytes(&[3; 32])),
        extranonce: vec![0, 1, 0x80, 0xff, 7],
        target,
        work: target.work(),
        class: ShareClass::Share,
    })
}

fn expected_credit(share: &AcceptedShare, epoch: u32) -> ShareCredit {
    ShareCredit {
        header_hash: Hash256::from(share.hash).to_le_bytes(),
        job: (u64::from(epoch) << 32) | u64::from(share.job.get()),
        account: MinerId(42),
        extranonce: share.extranonce.clone(),
        nonce: share.header.nonce,
        version: share.header.version,
        ntime: share.header.time,
        work: 1,
    }
}

fn found_block() -> Result<FoundBlock, Box<dyn std::error::Error>> {
    let mut share = share()?;
    share.class = ShareClass::Block;
    Ok(FoundBlock {
        block: Block {
            header: share.header,
            txs: Vec::new(),
        },
        raw: Vec::new(),
        coinbase_txid: Txid::from(Hash256::from_le_bytes(&[5; 32])),
        coinbase_value: 5_000_000_000,
        share,
    })
}

fn registered_account_gating(open: OpenStore) -> TestResult {
    let directory = tempfile::tempdir()?;
    let host = registered_host(open, directory.path(), EPOCH)?;
    let password = Password::new("not-an-account-registration-secret");
    for login in ["43", "43.rig", "address.rig", "", "42."] {
        assert!(host.resolve(login, &password).is_err(), "{login:?}");
    }
    assert_eq!(
        host.resolve("42.rig", &password)
            .unwrap_or_else(|_| panic!("registered login 42.rig refused")),
        worker()
    );
    assert_eq!(
        host.resolve("42", &password)
            .unwrap_or_else(|_| panic!("registered bare login refused"))
            .worker,
        "default"
    );
    let unregistered = WorkerIdentity {
        account: "43".to_owned(),
        worker: "rig".to_owned(),
    };
    assert!(host.record_share(&unregistered, &share()?).is_err());
    assert_eq!(host.ledger().share_count()?, 0);
    host.ledger().set_payout_script(MinerId(43), &[0x51])?;
    assert!(host.resolve("43.rig", &password).is_ok());
    Ok(())
}

fn exact_share_survives_reopen(open: OpenStore) -> TestResult {
    let directory = tempfile::tempdir()?;
    let share = share()?;
    {
        let host = registered_host(open, directory.path(), EPOCH)?;
        assert_eq!(
            host.record_share(&worker(), &share)
                .unwrap_or_else(|_| panic!("first share record unavailable")),
            RecordOutcome::Recorded
        );
        assert_eq!(
            host.record_share(&worker(), &share)
                .unwrap_or_else(|_| panic!("replay share record unavailable")),
            RecordOutcome::AlreadyRecorded
        );
    }
    let ledger = Ledger::open(open(directory.path())?, config())?;
    let credit = expected_credit(&share, EPOCH);
    assert_eq!(ledger.share_count()?, 1);
    assert_eq!(ledger.current_window()?, vec![(MinerId(42), 1)]);
    let (seq, work) = ledger
        .share_by_hash(&credit.header_hash)?
        .ok_or("recorded share missing after reopen")?;
    assert_eq!(work, credit.work);
    assert_eq!(
        ledger.record_share(&credit)?,
        ShareReceipt::Duplicate { seq }
    );
    assert_eq!(ledger.payout_script(MinerId(42))?, Some(vec![0x51]));
    Ok(())
}

fn restart_epoch_separates_reused_wire_job(open: OpenStore) -> TestResult {
    let directory = tempfile::tempdir()?;
    let first = share()?;
    let first_epoch;
    {
        let ledger = Arc::new(Ledger::create(open(directory.path())?, config())?);
        ledger.set_payout_script(MinerId(42), &[0x51])?;
        first_epoch = ledger.allocate_run_epoch()?;
        let host = LedgerHost::new(ledger, first_epoch, payout_policy());
        host.record_share(&worker(), &first)
            .map_err(|_| "first-epoch share record unavailable")?;
    }
    let ledger = Arc::new(Ledger::open(open(directory.path())?, config())?);
    let second_epoch = ledger.allocate_run_epoch()?;
    assert!(second_epoch > first_epoch);
    let host = LedgerHost::new(Arc::clone(&ledger), second_epoch, payout_policy());
    let mut second = first.clone();
    second.header.time += 1;
    second.hash = second.header.compute_hash();
    assert_eq!(
        host.record_share(&worker(), &second)
            .unwrap_or_else(|_| panic!("second-epoch share record unavailable")),
        RecordOutcome::Recorded
    );
    assert_eq!(ledger.share_count()?, 2);
    assert_eq!(ledger.current_window()?, vec![(MinerId(42), 2)]);
    for (share, epoch) in [(&first, first_epoch), (&second, second_epoch)] {
        assert!(matches!(
            ledger.record_share(&expected_credit(share, epoch))?,
            ShareReceipt::Duplicate { .. }
        ));
    }
    Ok(())
}

fn failed_block_receipt_stays_pending(open: OpenStore) -> TestResult {
    let directory = tempfile::tempdir()?;
    let found = found_block()?;
    {
        let host = registered_host(open, directory.path(), EPOCH)?;
        let receipt = Err(MiningControlError::Rejected("invalid candidate".into()));
        host.record_block(&worker(), &found, &receipt)
            .map_err(|_| "failed-submission block record unavailable")?;
        assert_eq!(host.ledger().share_count()?, 1);
    }
    let ledger = Ledger::open(open(directory.path())?, config())?;
    let hash = Hash256::from(found.share.hash).to_le_bytes();
    assert_eq!(
        ledger
            .round_for_block(&hash)?
            .ok_or("failed submission round missing")?
            .state,
        RoundState::Pending
    );
    assert!(ledger.share_by_hash(&hash)?.is_some());
    assert_eq!(ledger.balance(MinerId(42))?, Balance::default());
    Ok(())
}

fn rejected_block_receipt_stays_pending(open: OpenStore) -> TestResult {
    let directory = tempfile::tempdir()?;
    let found = found_block()?;
    {
        let host = registered_host(open, directory.path(), EPOCH)?;
        let receipt = BlockReceipt {
            hash: found.share.hash,
            height: found.share.height,
            previous_block_hash: found.share.previous_block_hash,
            coinbase_txid: found.coinbase_txid,
            coinbase_value: found.coinbase_value,
            session: found.share.session,
            job: found.share.job,
            result: BlockValidationResult::DuplicateInvalid,
        };
        host.record_block(&worker(), &found, &Ok(receipt))
            .map_err(|_| "rejected-receipt block record unavailable")?;
    }
    let ledger = Ledger::open(open(directory.path())?, config())?;
    let credit = expected_credit(&found.share, EPOCH);
    assert_eq!(
        ledger
            .round_for_block(&credit.header_hash)?
            .ok_or("rejected receipt round missing")?
            .state,
        RoundState::Pending
    );
    assert_eq!(ledger.balance(MinerId(42))?, Balance::default());
    assert_eq!(ledger.share_count()?, 1);
    assert!(matches!(
        ledger.record_share(&credit)?,
        ShareReceipt::Duplicate { .. }
    ));
    Ok(())
}

fn sv2_permanent_share_conflict_is_rejected(open: OpenStore) -> TestResult {
    let directory = tempfile::tempdir()?;
    let host = registered_host(open, directory.path(), EPOCH)?;
    let account = MinerId(42);
    let first = share()?;
    assert_eq!(
        host.record_accepted_share(account, &first)
            .unwrap_or_else(|_| panic!("first SV2 share record unavailable")),
        RecordOutcome::Recorded
    );
    let mut same_hash = first.clone();
    same_hash.header.nonce = same_hash.header.nonce.wrapping_add(1);
    assert_eq!(
        host.record_accepted_share(account, &same_hash)
            .unwrap_or_else(|error| panic!("share conflict surfaced as unavailable: {error:?}")),
        RecordOutcome::Rejected
    );
    let mut same_identity = first.clone();
    same_identity.hash = BlockHash::from(Hash256::from_le_bytes(&[9; 32]));
    assert_eq!(
        host.record_accepted_share(account, &same_identity)
            .unwrap_or_else(|error| panic!("identity conflict surfaced as unavailable: {error:?}")),
        RecordOutcome::Rejected
    );
    assert_eq!(host.ledger().share_count()?, 1);
    Ok(())
}

fn sv2_non_conflict_ledger_error_is_unavailable(open: OpenStore) -> TestResult {
    let directory = tempfile::tempdir()?;
    let host = registered_host(open, directory.path(), EPOCH)?;
    let mut bad = share()?;
    bad.extranonce = vec![0u8; pool_ledger::MAX_EXTRANONCE_LEN + 1];
    assert!(
        matches!(
            host.record_accepted_share(MinerId(42), &bad),
            Err(LedgerUnavailable)
        ),
        "non-conflict ledger refusal must stay unavailable"
    );
    assert_eq!(host.ledger().share_count()?, 0);
    Ok(())
}

fn block_record_reservations_are_bounded_and_released(open: OpenStore) -> TestResult {
    let directory = tempfile::tempdir()?;
    let host = Arc::new(registered_host(open, directory.path(), EPOCH)?);
    let mut permits = Vec::new();
    for _ in 0..8 {
        permits.push(
            host.try_reserve_block_slot()
                .ok_or("slot refused below capacity")?,
        );
    }
    assert!(host.try_reserve_block_slot().is_none());
    drop(
        permits
            .pop()
            .ok_or("permit vector exhausted below capacity")?,
    );
    permits.push(
        host.try_reserve_block_slot()
            .ok_or("released slot not re-reservable")?,
    );
    assert!(host.try_reserve_block_slot().is_none());
    drop(permits);
    let permits: Vec<_> = (0..8)
        .map(|_| {
            host.try_reserve_block_slot()
                .ok_or_else(|| std::io::Error::other("full release did not restore capacity"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert!(host.try_reserve_block_slot().is_none());
    drop(permits);
    Ok(())
}

fn durable_undetermined_keeps_reservation_until_waiter_removed(open: OpenStore) -> TestResult {
    use super::ledger::{BlockRecordOutcome, DeferredCharge};
    use bitcoin_rs_mining::pool::BlockStatus;

    let directory = tempfile::tempdir()?;
    let host = Arc::new(registered_host(open, directory.path(), EPOCH)?);
    let mut charges = Vec::new();
    for index in 0..8 {
        let mut found = found_block()?;
        let lane = u32::try_from(index).map_err(|_| "lane exceeds u32")?;
        found.share.header.nonce = found.share.header.nonce.wrapping_add(lane);
        found.share.hash = found.share.header.compute_hash();
        found.block.header = found.share.header;
        let receipt = BlockReceipt {
            hash: found.share.hash,
            height: found.share.height,
            previous_block_hash: found.share.previous_block_hash,
            coinbase_txid: found.coinbase_txid,
            coinbase_value: found.coinbase_value,
            session: found.share.session,
            job: found.share.job,
            result: BlockValidationResult::Inconclusive,
        };
        assert_eq!(
            receipt.status(),
            BlockStatus::Undetermined,
            "test receipt must stay Undetermined"
        );
        let permit = host
            .try_reserve_block_slot()
            .ok_or("slot refused below capacity")?;
        let (outcome, charge) = permit.record_or_enqueue(MinerId(42), &found, &Ok(receipt));
        assert!(
            matches!(outcome, BlockRecordOutcome::Durable),
            "good block must record durably"
        );
        let charge = charge.ok_or("durable Undetermined must retain its charge")?;
        assert!(
            matches!(charge, DeferredCharge::Permit(_)),
            "durable waiter must transfer its permit"
        );
        charges.push(charge);
        assert!(
            host.ledger()
                .round_for_block(&Hash256::from(found.share.hash).to_le_bytes())?
                .is_some(),
            "durable record must exist"
        );
    }
    assert!(
        host.try_reserve_block_slot().is_none(),
        "eight deferred charges must exhaust shared capacity"
    );
    let dropped = charges.pop().ok_or("eight charges expected")?;
    drop(dropped);
    assert!(
        host.try_reserve_block_slot().is_some(),
        "dropping one waiter must re-admit capacity"
    );
    drop(charges);
    Ok(())
}

#[test]
fn protocol_admissions_share_total_capacity_and_release_it_on_drop() -> TestResult {
    let shared = Arc::new(bitcoin_rs_mining::pool::stratum::sv1::ConnectionLimiter::new(1, 1)?);
    let sv1 = Arc::clone(&shared);
    let sv2 = Arc::clone(&shared);
    let first = sv1
        .try_admit("192.0.2.1".parse()?)
        .map_err(|reason| std::io::Error::other(format!("sv1 admission refused: {reason:?}")))?;
    assert!(matches!(
        sv2.try_admit("192.0.2.2".parse()?),
        Err(bitcoin_rs_mining::pool::stratum::sv1::RefusalReason::ConnectionLimit)
    ));
    assert_eq!(shared.active(), 1);
    drop(first);
    let second = sv2.try_admit("192.0.2.2".parse()?).map_err(|reason| {
        std::io::Error::other(format!("sv2 admission after release refused: {reason:?}"))
    })?;
    assert_eq!(shared.active(), 1);
    drop(second);
    assert_eq!(shared.active(), 0);
    Ok(())
}

#[test]
fn protocol_admissions_share_per_ip_capacity_without_consuming_refused_slots() -> TestResult {
    let shared = Arc::new(bitcoin_rs_mining::pool::stratum::sv1::ConnectionLimiter::new(3, 1)?);
    let sv1 = Arc::clone(&shared);
    let sv2 = Arc::clone(&shared);
    let same_ip = "192.0.2.1".parse()?;
    let first = sv1.try_admit(same_ip).map_err(|reason| {
        std::io::Error::other(format!("per-IP sv1 admission refused: {reason:?}"))
    })?;
    assert!(matches!(
        sv2.try_admit(same_ip),
        Err(bitcoin_rs_mining::pool::stratum::sv1::RefusalReason::PerIpLimit)
    ));
    let other = sv2.try_admit("192.0.2.2".parse()?).map_err(|reason| {
        std::io::Error::other(format!("second-IP admission refused: {reason:?}"))
    })?;
    assert_eq!(shared.active(), 2);
    drop(first);
    let replacement = sv2.try_admit(same_ip).map_err(|reason| {
        std::io::Error::other(format!(
            "released per-IP slot not re-admittable: {reason:?}"
        ))
    })?;
    assert_eq!(shared.active(), 2);
    drop((replacement, other));
    assert_eq!(shared.active(), 0);
    Ok(())
}

macro_rules! backend_tests {
    ($module:ident, $store:path) => {
        mod $module {
            use super::*;

            fn open(path: &Path) -> Result<Arc<dyn KvStore>, Box<dyn std::error::Error>> {
                Ok(Arc::new(<$store>::open(path)?))
            }

            #[test]
            fn block_record_capacity_is_bounded_and_permit_drop_releases_it() -> TestResult {
                block_record_reservations_are_bounded_and_released(open)
            }

            #[test]
            fn durable_undetermined_keeps_shared_reservation_until_waiter_removed() -> TestResult {
                durable_undetermined_keeps_reservation_until_waiter_removed(open)
            }

            #[test]
            fn only_explicitly_registered_accounts_can_authenticate_or_credit_shares() -> TestResult
            {
                registered_account_gating(open)
            }

            #[test]
            fn accepted_share_has_exact_durable_identity_and_idempotent_replay() -> TestResult {
                exact_share_survives_reopen(open)
            }

            #[test]
            fn restart_epoch_prevents_reused_wire_job_identity_collision() -> TestResult {
                restart_epoch_separates_reused_wire_job(open)
            }

            #[test]
            fn sv2_permanent_share_conflict_reports_rejected() -> TestResult {
                sv2_permanent_share_conflict_is_rejected(open)
            }

            #[test]
            fn sv2_non_conflict_ledger_error_stays_unavailable() -> TestResult {
                sv2_non_conflict_ledger_error_is_unavailable(open)
            }

            #[test]
            fn rejected_block_receipt_persists_pending_round_without_funds() -> TestResult {
                rejected_block_receipt_stays_pending(open)
            }

            #[test]
            fn failed_block_submission_persists_pending_round_without_funds() -> TestResult {
                failed_block_receipt_stays_pending(open)
            }
        }
    };
}

#[cfg(feature = "redb")]
backend_tests!(redb, bitcoin_rs_storage::RedbStore);
#[cfg(feature = "fjall")]
backend_tests!(fjall, bitcoin_rs_storage::FjallStore);

#[test]
fn composed_core_bounds_pin_the_contract_literals() -> TestResult {
    let composed = super::composed_core_config(128)?;
    assert_eq!(
        composed.book.max_jobs, 64,
        "retained job bound must stay 64"
    );
    assert_eq!(
        composed.book.max_sessions, 256,
        "session bound must stay twice the connection cap"
    );
    assert_eq!(
        composed.book.max_shares_per_job, 65_536,
        "per-job duplicate-tracking bound must stay 65,536"
    );
    assert_eq!(
        composed.outbox_items, 1024,
        "deferred share-ledger outbox must stay 1024 records"
    );
    assert_eq!(
        composed.outbox_bytes,
        8 * 1024 * 1024,
        "deferred share-ledger outbox must stay 8 MiB"
    );
    Ok(())
}

#[test]
fn pool_directory_lock_is_exclusive_while_prepare_resources_live() -> TestResult {
    let directory = tempfile::tempdir()?;
    let datadir = directory.path().join("pool");
    std::fs::create_dir_all(&datadir)?;
    let guard = crate::state::lock_pool_directory(&datadir)?;
    assert!(
        crate::state::lock_pool_directory(&datadir).is_err(),
        "a second pool prepare must not acquire the dedicated directory lock"
    );
    drop(guard);
    let _released = crate::state::lock_pool_directory(&datadir)?;
    Ok(())
}

fn ledger_create_open_and_epoch_under_guard(
    backend: bitcoin_rs_storage::StorageBackend,
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let datadir = directory.path().join("pool");
    std::fs::create_dir_all(&datadir)?;
    let guard = crate::state::lock_pool_directory(&datadir)?;
    let ledger_path = datadir.join("ledger");
    let policy = || pool_ledger::PoolConfig::new(1_000, vec![0x51]);
    let (_ledger, first): (pool_ledger::Ledger, u32) = crate::storage_backend::open_generic(
        "pool",
        backend,
        &ledger_path,
        None,
        &guard,
        super::LedgerComposer { config: policy() },
    )?;
    drop(_ledger);
    let (_ledger, second): (pool_ledger::Ledger, u32) = crate::storage_backend::open_generic(
        "pool",
        backend,
        &ledger_path,
        None,
        &guard,
        super::LedgerComposer { config: policy() },
    )?;
    assert!(
        second > first,
        "run-epoch allocation must advance across restarts while the directory lock is held"
    );
    drop(_ledger);
    let mismatch = pool_ledger::PoolConfig::new(2_000, vec![0x51]);
    let outcome = crate::storage_backend::open_generic(
        "pool",
        backend,
        &ledger_path,
        None,
        &guard,
        super::LedgerComposer { config: mismatch },
    )
    .map(|_: (pool_ledger::Ledger, u32)| ());
    let error = outcome.unwrap_err();
    assert!(
        matches!(
            error.downcast_ref::<pool_ledger::LedgerError>(),
            Some(pool_ledger::LedgerError::ConfigMismatch)
        ),
        "a changed policy must fail rather than reinterpret history: {error:?}"
    );
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn pool_prepare_create_open_and_epoch_run_under_the_directory_lock_redb() -> TestResult {
    ledger_create_open_and_epoch_under_guard(bitcoin_rs_storage::StorageBackend::Redb)
}

#[cfg(feature = "fjall")]
#[test]
fn pool_prepare_create_open_and_epoch_run_under_the_directory_lock_fjall() -> TestResult {
    ledger_create_open_and_epoch_under_guard(bitcoin_rs_storage::StorageBackend::Fjall)
}

#[test]
fn node_chain_view_reports_missing_index_observer_errors() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut config = crate::config::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = directory.path().to_owned();
    config.rpc.bind = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    config.rpc.auth = crate::Auth::basic("user", "password");
    config.indexes.txindex = false;
    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
    config.p2p.listen.clear();
    config.observability.metrics_bind = None;
    let state = crate::state::NodeState::open(config, None)?;
    assert!(state.derived_index_query().is_none());
    assert!(state.script_index_query().is_none());
    let view = super::ledger::NodeChainView::new(
        state.chainstate(),
        state.stable_read(),
        state.mempool_reader(),
        state.derived_index_query(),
        state.script_index_query(),
    )?;
    let txid = [0x07; 32];
    match pool_ledger::ChainView::tx_status(&view, &txid) {
        Err(error) => assert!(
            error.0.contains("txindex"),
            "missing txindex must be reported, not treated as evidence: {error}"
        ),
        Ok(_) => panic!("unknown payout must not resolve without a txindex"),
    }
    let outpoint = pool_ledger::OutPoint {
        txid: [0x09; 32],
        vout: 0,
    };
    match pool_ledger::ChainView::confirmed_spender(&view, &outpoint) {
        Err(error) => assert!(
            error.0.contains("script index"),
            "missing script index must be reported, not treated as evidence: {error}"
        ),
        Ok(_) => panic!("no spend can be observed without a script index"),
    }
    Ok(())
}

#[test]
fn pool_prepare_holds_directory_lock_for_service_lifetime() -> TestResult {
    let directory = tempfile::tempdir()?;
    let pool_datadir = directory.path().join("pool");
    let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = probe.local_addr()?.port();
    drop(probe);
    let mut config = crate::config::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = directory.path().join("node");
    config.rpc.bind = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    config.rpc.auth = crate::Auth::basic("user", "password");
    config.indexes.txindex = false;
    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;
    config.p2p.listen.clear();
    config.observability.metrics_bind = None;
    #[cfg(feature = "redb")]
    {
        config.storage.backend = bitcoin_rs_storage::StorageBackend::Redb;
    }
    #[cfg(all(not(feature = "redb"), feature = "fjall"))]
    {
        config.storage.backend = bitcoin_rs_storage::StorageBackend::Fjall;
    }
    config.mining.payout_script = vec![0x51];
    config.pool = Some(crate::config::PoolConfig {
        datadir: pool_datadir.clone(),
        v1_bind: Some(std::net::SocketAddr::from(([127, 0, 0, 1], port))),
        sv2_bind: None,
        sv2_authority_key: None,
        allow_non_loopback: false,
        max_connections: 128,
        max_connections_per_ip: 8,
        share_difficulty: "1".to_owned(),
        share_target: bitcoin_rs_mining::pool::ShareTarget::from_pool_difficulty_decimal("1")?,
        window_work: 1_000,
        fee_bps: 0,
        reward_script: vec![0x51],
        maturity: 100,
        payout_confirmations: 6,
        reorg_watch_depth: 1_000,
        min_payout_sat: 1_000,
        max_payout_outputs: 10,
    });
    let state = crate::state::NodeState::open(config, None)?;
    let control = Arc::new(bitcoin_rs_mining::FakeMiningControl::default());
    let service =
        super::PoolService::prepare(&state, control)?.expect("enabled pool must prepare a service");
    assert!(
        crate::state::lock_pool_directory(&pool_datadir).is_err(),
        "pool datadir must stay locked while the prepared service lives"
    );
    drop(service);
    let _released = crate::state::lock_pool_directory(&pool_datadir)?;
    Ok(())
}
