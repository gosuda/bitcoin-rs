use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bitcoin_rs_rpc::mining::pool::ledger as pool_ledger;
use bitcoin_rs_rpc::mining::pool::stratum::sv1::{
    ConnectionLimiter, DifficultyPolicy, Server, ServerConfig, ServerDeps,
};
use bitcoin_rs_rpc::mining::pool::{ExtranonceLayout, JobBookConfig, PoolCore};
use bitcoin_rs_rpc::mining::{CoinbaseBudget, MiningControl};
use bitcoin_rs_storage::KvStore;

use crate::run::RunError;

#[cfg(feature = "pool-sv2")]
pub(crate) mod authority;
pub mod ledger;
#[cfg(feature = "pool-sv2")]
mod sv2;
#[cfg(test)]
mod tests {
    use std::{path::Path, sync::Arc};

    use bitcoin_rs_consensus::primitives::{Block, BlockHash, Hash256, Header, Txid};
    use bitcoin_rs_rpc::context::PoolOperator;
    use bitcoin_rs_rpc::mining::pool::ledger as pool_ledger;
    use bitcoin_rs_rpc::mining::pool::ledger::{
        Balance, MinerId, PayoutPolicy, PoolConfig, RoundState, ShareCredit, ShareReceipt,
    };
    use bitcoin_rs_rpc::mining::pool::stratum::sv1::{AccountResolver, Password};
    use bitcoin_rs_rpc::mining::pool::{
        AcceptedShare, BlockReceipt, FoundBlock, JobId, LedgerUnavailable, RecordOutcome,
        SessionId, ShareClass, ShareLedger, ShareTarget, WorkerIdentity,
    };
    use bitcoin_rs_rpc::mining::{BlockValidationResult, MiningControlError};
    use bitcoin_rs_storage::KvStore;

    use super::ledger::{Ledger, LedgerHost};
    use crate::run::RunError;
    use crate::test_support::TestError;

    type OpenStore = fn(&Path) -> Result<Arc<dyn KvStore>, bitcoin_rs_storage::StorageError>;
    type TestResult = Result<(), TestError>;
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

    fn registered_host(open: OpenStore, path: &Path, epoch: u32) -> Result<LedgerHost, TestError> {
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

    fn share() -> Result<AcceptedShare, TestError> {
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

    fn found_block() -> Result<FoundBlock, TestError> {
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
        host.ledger().set_payout_script(MinerId(43), vec![0x51])?;
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
            .ok_or(TestError::Missing("recorded share after reopen"))?;
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
            host.record_share(&worker(), &first)?;
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
            host.record_block(&worker(), &found, &receipt)?;
            assert_eq!(host.ledger().share_count()?, 1);
        }
        let ledger = Ledger::open(open(directory.path())?, config())?;
        let hash = Hash256::from(found.share.hash).to_le_bytes();
        assert_eq!(
            ledger
                .round_for_block(&hash)?
                .ok_or(TestError::Missing("failed submission round"))?
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
                .map_err(|_| TestError::ExpectationFailed("block record available"))?;
        }
        let ledger = Ledger::open(open(directory.path())?, config())?;
        let credit = expected_credit(&found.share, EPOCH);
        assert_eq!(
            ledger
                .round_for_block(&credit.header_hash)?
                .ok_or(TestError::Missing("rejected receipt round"))?
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
                .unwrap_or_else(|error| panic!(
                    "share conflict surfaced as unavailable: {error:?}"
                )),
            RecordOutcome::Rejected
        );
        let mut same_identity = first;
        same_identity.hash = BlockHash::from(Hash256::from_le_bytes(&[9; 32]));
        assert_eq!(
            host.record_accepted_share(account, &same_identity)
                .unwrap_or_else(|error| panic!(
                    "identity conflict surfaced as unavailable: {error:?}"
                )),
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
                    .ok_or(TestError::Missing("slot below capacity"))?,
            );
        }
        assert!(host.try_reserve_block_slot().is_none());
        drop(
            permits
                .pop()
                .ok_or(TestError::Missing("permit below capacity"))?,
        );
        permits.push(
            host.try_reserve_block_slot()
                .ok_or(TestError::Missing("released slot"))?,
        );
        assert!(host.try_reserve_block_slot().is_none());
        drop(permits);
        let permits: Vec<_> = (0..8)
            .map(|_| {
                host.try_reserve_block_slot()
                    .ok_or(TestError::ExpectationFailed(
                        "full release restores capacity",
                    ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert!(host.try_reserve_block_slot().is_none());
        drop(permits);
        Ok(())
    }

    fn durable_undetermined_keeps_reservation_until_waiter_removed(open: OpenStore) -> TestResult {
        use super::ledger::{BlockRecordOutcome, DeferredCharge};
        use bitcoin_rs_rpc::mining::pool::BlockStatus;

        let directory = tempfile::tempdir()?;
        let host = Arc::new(registered_host(open, directory.path(), EPOCH)?);
        let mut charges = Vec::new();
        for index in 0..8 {
            let mut found = found_block()?;
            let lane = u32::try_from(index)?;
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
                .ok_or(TestError::Missing("slot below capacity"))?;
            let (outcome, charge) = permit.record_or_enqueue(MinerId(42), &found, &Ok(receipt));
            assert!(
                matches!(outcome, BlockRecordOutcome::Durable),
                "good block must record durably"
            );
            let charge = charge.ok_or(TestError::Missing("deferred charge"))?;
            assert!(
                matches!(charge, DeferredCharge::Permit(_)),
                "durable waiter must transfer its permit"
            );
            charges.push(charge);
            assert!(
                host.ledger_store()
                    .round_for_block(&Hash256::from(found.share.hash).to_le_bytes())?
                    .is_some(),
                "durable record must exist"
            );
        }
        assert!(
            host.try_reserve_block_slot().is_none(),
            "eight deferred charges must exhaust shared capacity"
        );
        let dropped = charges.pop().ok_or(TestError::Missing("deferred charge"))?;
        drop(dropped);
        assert!(
            host.try_reserve_block_slot().is_some(),
            "dropping one waiter must re-admit capacity"
        );
        drop(charges);
        Ok(())
    }

    // POOL-03
    #[test]
    fn protocol_admissions_share_total_capacity_and_release_it_on_drop() -> TestResult {
        let shared =
            Arc::new(bitcoin_rs_rpc::mining::pool::stratum::sv1::ConnectionLimiter::new(1, 1)?);
        let sv1 = Arc::clone(&shared);
        let sv2 = Arc::clone(&shared);
        let first = sv1
            .try_admit("192.0.2.1".parse()?)
            .map_err(|_| TestError::ExpectationFailed("sv1 admits"))?;
        assert!(matches!(
            sv2.try_admit("192.0.2.2".parse()?),
            Err(bitcoin_rs_rpc::mining::pool::stratum::sv1::RefusalReason::ConnectionLimit)
        ));
        assert_eq!(shared.active(), 1);
        drop(first);
        let second = sv2
            .try_admit("192.0.2.2".parse()?)
            .map_err(|_| TestError::ExpectationFailed("sv2 admits after release"))?;
        assert_eq!(shared.active(), 1);
        drop(second);
        assert_eq!(shared.active(), 0);
        Ok(())
    }

    #[test]
    fn protocol_admissions_share_per_ip_capacity_without_consuming_refused_slots() -> TestResult {
        let shared =
            Arc::new(bitcoin_rs_rpc::mining::pool::stratum::sv1::ConnectionLimiter::new(3, 1)?);
        let sv1 = Arc::clone(&shared);
        let sv2 = Arc::clone(&shared);
        let same_ip = "192.0.2.1".parse()?;
        let first = sv1
            .try_admit(same_ip)
            .map_err(|_| TestError::ExpectationFailed("per-IP sv1 admits"))?;
        assert!(matches!(
            sv2.try_admit(same_ip),
            Err(bitcoin_rs_rpc::mining::pool::stratum::sv1::RefusalReason::PerIpLimit)
        ));
        let other = sv2
            .try_admit("192.0.2.2".parse()?)
            .map_err(|_| TestError::ExpectationFailed("second-IP sv2 admits"))?;
        assert_eq!(shared.active(), 2);
        drop(first);
        let replacement = sv2
            .try_admit(same_ip)
            .map_err(|_| TestError::ExpectationFailed("released per-IP slot re-admits"))?;
        assert_eq!(shared.active(), 2);
        drop((replacement, other));
        assert_eq!(shared.active(), 0);
        Ok(())
    }

    macro_rules! backend_tests {
    ($module:ident, $store:path) => {
        mod $module {
            use super::*;

            fn open(path: &Path) -> Result<Arc<dyn KvStore>, bitcoin_rs_storage::StorageError> {
                Ok(Arc::new(<$store>::open_with_cache(path, 0)?))
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

    backend_tests!(rocksdb, bitcoin_rs_storage::RocksDbStore);

    // POOL-03
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

    // POOL-02
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
        let (ledger, first): (Ledger, u32) = crate::storage_backend::open_generic(
            "pool",
            backend,
            &ledger_path,
            None,
            &guard,
            super::LedgerComposer { config: policy() },
        )?;
        drop(ledger);
        let (ledger, second): (Ledger, u32) = crate::storage_backend::open_generic(
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
        drop(ledger);
        let mismatch = pool_ledger::PoolConfig::new(2_000, vec![0x51]);
        let outcome = crate::storage_backend::open_generic(
            "pool",
            backend,
            &ledger_path,
            None,
            &guard,
            super::LedgerComposer { config: mismatch },
        )
        .map(|_: (Ledger, u32)| ());
        let Err(error) = outcome else {
            panic!("outcome must be error");
        };
        assert!(
            matches!(
                error,
                RunError::PoolLedger(pool_ledger::LedgerError::ConfigMismatch)
            ),
            "a changed policy must fail rather than reinterpret history: {error:?}"
        );
        Ok(())
    }

    // POOL-02
    #[test]
    fn pool_prepare_create_open_and_epoch_run_under_the_directory_lock_rocksdb() -> TestResult {
        ledger_create_open_and_epoch_under_guard(bitcoin_rs_storage::StorageBackend::RocksDb)
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
        config.storage.backend = bitcoin_rs_storage::StorageBackend::RocksDb;
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
            share_target: bitcoin_rs_rpc::mining::pool::ShareTarget::from_pool_difficulty_decimal(
                "1",
            )?,
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
        let control: Arc<dyn bitcoin_rs_rpc::mining::MiningControl> =
            Arc::new(bitcoin_rs_rpc::mining::FakeMiningControl::default());
        let Some(service) = super::PoolService::prepare(&state, &control)? else {
            panic!("enabled pool must prepare a service");
        };
        assert!(
            crate::state::lock_pool_directory(&pool_datadir).is_err(),
            "pool datadir must stay locked while the prepared service lives"
        );
        drop(service);
        let _released = crate::state::lock_pool_directory(&pool_datadir)?;
        Ok(())
    }
}

pub(crate) struct PoolService {
    config: crate::config::PoolConfig,
    host: Arc<ledger::LedgerHost>,
    core: Arc<PoolCore>,
    #[cfg(feature = "pool-sv2")]
    control: Arc<dyn MiningControl>,
    chain: Arc<ledger::NodeChainView>,
    cancel: bitcoin_rs_consensus::latch::LatchWriter,
    worker: Option<JoinHandle<()>>,
    v1: Option<Server>,
    #[cfg(feature = "pool-sv2")]
    v2: Option<sv2::Sv2Service>,
}

struct LedgerComposer {
    config: pool_ledger::PoolConfig,
}
impl crate::storage_backend::StoreConsumer for LedgerComposer {
    type Output = (ledger::store::Ledger, u32);
    type Error = RunError;
    fn consume<S: KvStore>(self, store: Arc<S>) -> Result<Self::Output, Self::Error> {
        let store: Arc<dyn KvStore> = store;
        let ledger = match ledger::store::Ledger::create(Arc::clone(&store), self.config.clone()) {
            Ok(ledger) => ledger,
            Err(pool_ledger::LedgerError::PathExists) => {
                ledger::store::Ledger::open(Arc::clone(&store), self.config)?
            }
            Err(error) => return Err(error.into()),
        };
        let epoch = ledger.allocate_run_epoch()?;
        Ok((ledger, epoch))
    }
}

struct ComposedCore {
    book: JobBookConfig,
    outbox_items: usize,
    outbox_bytes: usize,
}

const MAX_RETAINED_JOBS: usize = 64;
const SESSION_SLOTS_PER_CONNECTION: usize = 2;
const MAX_SHARES_PER_JOB: usize = 65_536;
const MAX_OUTBOX_RECORDS: usize = 1024;
const MAX_OUTBOX_BYTES: usize = 8 * 1024 * 1024;

fn composed_core_config(max_connections: u32) -> Result<ComposedCore, RunError> {
    let sessions = usize::try_from(max_connections)?
        .checked_mul(SESSION_SLOTS_PER_CONNECTION)
        .ok_or(RunError::PoolSessionBoundOverflow)?;
    Ok(ComposedCore {
        book: JobBookConfig {
            budget: CoinbaseBudget {
                additional_size: 0,
                additional_sigops: 0,
            },
            extranonce: ExtranonceLayout::new(4, 4),
            coinbase_tag: b"/btcrs/".to_vec(),
            version_mask: bitcoin_rs_rpc::mining::pool::BIP320_VERSION_MASK,
            ntime_forward_secs: bitcoin_rs_rpc::mining::pool::MAX_NTIME_FORWARD_SECS,
            max_jobs: MAX_RETAINED_JOBS,
            max_sessions: sessions,
            max_shares_per_job: MAX_SHARES_PER_JOB,
        },
        outbox_items: MAX_OUTBOX_RECORDS,
        outbox_bytes: MAX_OUTBOX_BYTES,
    })
}

impl PoolService {
    pub(crate) fn prepare(
        state: &crate::state::NodeState,
        control: &Arc<dyn MiningControl>,
    ) -> Result<Option<Self>, RunError> {
        let Some(config) = state.config().pool.as_ref() else {
            return Ok(None);
        };
        std::fs::create_dir_all(&config.datadir)
            .map_err(|source| RunError::PoolDataDirCreate { source })?;
        let guard = crate::state::lock_pool_directory(&config.datadir)?;
        let accounting = config.ledger_config();
        let (ledger, epoch) = crate::storage_backend::open_generic(
            "pool",
            state.config().storage.backend,
            &config.datadir.join("ledger"),
            None,
            &guard,
            LedgerComposer { config: accounting },
        )?;
        let host = Arc::new(ledger::LedgerHost::new(
            Arc::new(ledger),
            epoch,
            pool_ledger::PayoutPolicy {
                min_payout_sat: config.min_payout_sat,
                max_outputs: usize::try_from(config.max_payout_outputs)?,
            },
        ));
        let composed = composed_core_config(config.max_connections)?;
        let core = Arc::new(
            PoolCore::new(composed.book, Arc::clone(control), host.clone())?
                .with_ledger_retry(1, Duration::ZERO)
                .with_outbox(composed.outbox_items, composed.outbox_bytes),
        );
        let chain = Arc::new(ledger::NodeChainView::new(
            state.chainstate(),
            state.stable_read(),
            state.mempool_reader(),
            state.derived_index_query(),
            state.script_index_query(),
        )?);
        Ok(Some(Self {
            config: config.clone(),
            host,
            core,
            #[cfg(feature = "pool-sv2")]
            control: Arc::clone(control),
            chain,
            cancel: bitcoin_rs_consensus::latch::LatchWriter::new(),
            worker: None,
            v1: None,
            #[cfg(feature = "pool-sv2")]
            v2: None,
        }))
    }

    pub(crate) fn handles(&self) -> bitcoin_rs_rpc::context::PoolHandles {
        bitcoin_rs_rpc::context::PoolHandles {
            operator: Some(self.host.clone()),
        }
    }

    pub(crate) fn start(&mut self) -> Result<(), RunError> {
        self.core
            .refresh(None, Vec::new())
            .map_err(|source| RunError::PoolInitialTemplate { source })?;
        let limiter = Arc::new(ConnectionLimiter::new(
            usize::try_from(self.config.max_connections)?,
            usize::try_from(self.config.max_connections_per_ip)?,
        )?);
        if let Some(bind) = self.config.v1_bind {
            let text = &self.config.share_difficulty;
            let difficulty_debug = match DifficultyPolicy::new(text, text, text) {
                Ok(policy) => policy,
                Err(error) => {
                    return Err(RunError::PoolDifficulty {
                        difficulty_debug: format!("{error:?}"),
                    });
                }
            };
            let mut config = ServerConfig::new(difficulty_debug);
            config.max_connections = usize::try_from(self.config.max_connections)?;
            config.max_connections_per_ip = usize::try_from(self.config.max_connections_per_ip)?;
            self.v1 = Some(Server::bind_with_limiter(
                bind,
                config,
                ServerDeps {
                    pool: Arc::clone(&self.core),
                    accounts: self.host.clone(),
                    observer: None,
                },
                Arc::clone(&limiter),
            )?);
        }
        #[cfg(feature = "pool-sv2")]
        if self.config.sv2_bind.is_some() {
            self.v2 = Some(sv2::start(
                &self.config,
                Arc::clone(&self.core),
                Arc::clone(&self.host),
                Arc::clone(&self.control),
                self.cancel.reader(),
                Arc::clone(&limiter),
            )?);
        }
        let core = Arc::clone(&self.core);
        let host = Arc::clone(&self.host);
        let chain = Arc::clone(&self.chain);
        let cancel = self.cancel.reader();
        self.worker = Some(
            std::thread::Builder::new()
                .name("pool-reconcile".into())
                .spawn(move || {
                    let current = std::thread::current();
                    let _guard = cancel.on_cancel(move || current.unpark());
                    while !cancel.is_triggered() {
                        if let Err(error) = core.refresh(None, Vec::new()) {
                            core.invalidate_active();
                            tracing::warn!(%error, "pool template refresh unavailable");
                        }
                        if let Err(error) = host.reconcile(&chain) {
                            tracing::error!(%error, "pool chain reconciliation failed");
                        }
                        core.drain_outbox();
                        std::thread::park_timeout(Duration::from_millis(250));
                    }
                    core.drain_outbox();
                    while matches!(host.drain_one_block_record(), Ok(true)) {}
                })?,
        );
        Ok(())
    }

    pub(crate) fn shutdown(&mut self, deadline: Instant) -> Result<(), RunError> {
        self.cancel.trigger();
        let mut failure = None;
        if let Some(server) = self.v1.as_mut() {
            match server.shutdown_until(deadline) {
                Ok(report) => {
                    if report.sessions_panicked != 0 {
                        failure = Some(RunError::PoolSv1SessionPanicked);
                    }
                    self.v1.take();
                }
                Err(error) => failure = Some(error.into()),
            }
        }
        #[cfg(feature = "pool-sv2")]
        if let Some(server) = self.v2.as_mut() {
            match server.stop_join(deadline) {
                Ok(()) => {
                    self.v2.take();
                }
                Err(error) => failure = Some(error),
            }
        }
        if let Some(worker) = self.worker.as_ref() {
            worker.thread().unpark();
            while !worker.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if !worker.is_finished() {
                failure = Some(RunError::PoolShutdownDeadlineExceeded);
            } else if let Some(worker) = self.worker.take() {
                if worker.join().is_err() {
                    failure = Some(RunError::PoolReconciliationPanicked);
                }
            }
        }
        if Instant::now() < deadline {
            self.core.drain_outbox();
        }
        while Instant::now() < deadline {
            match self.host.drain_one_block_record() {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    failure = Some(error.into());
                    break;
                }
            }
        }
        if self.host.pending_block_records() != 0 {
            failure = Some(RunError::PoolUnrecordedFoundBlocks);
        }
        if self.core.pending_ledger_writes() != 0 {
            failure = Some(RunError::PoolUnrecordedAccountingWork);
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }
}

impl Drop for PoolService {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown(Instant::now() + Duration::from_secs(10)) {
            tracing::error!(%error, "pool shutdown failed");
        }
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            if worker.join().is_err() {
                tracing::error!("pool reconciliation worker panicked during final join");
            }
        }
    }
}
