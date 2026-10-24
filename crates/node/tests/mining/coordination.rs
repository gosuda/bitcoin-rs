use std::str::FromStr as _;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use bitcoin_rs_mining::{BlockTemplate, MempoolSequenceWake, MiningControl, MiningControlError};
use bitcoin_rs_node::{
    MiningCoordinator, MiningOverrides, Network, NetworkSelection, UserConfig, resolve,
    state::NodeState,
};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use compact_str::CompactString;
use crossbeam_channel::bounded;
use parking_lot::Mutex;

use super::preparation_barrier::{
    BarrierNode, barrier_bound, fresh_tip_child, open_barrier_node, seed_fresh_chain,
};
use super::support::{
    HIGH_FEE_SATS, LATE_FEE_SATS, LOW_FEE_SATS, PRIORITY_DELTA_SATS, PRIORITY_SEED_BLOCKS, PROMPT,
    PendingPoll, REGTEST_SUBSIDY_SATS, admit_to_mempool, advance_mempool_sequence, coordinator,
    current_tip, expect_template, live_long_poll_id, mined_child, open_at_genesis,
    priority_fixture, regtest_mining, rpc_handler, seed_coinbase_spend_at, template_request,
    to_lower_hex, txid_strings,
};
use sonic_rs::{JsonValueTrait as _, json};

#[test]
fn cache_reuses_candidate_for_identical_generation_key() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();

    let first = expect_template(mining.get_block_template(template_request(None))?);
    let second = expect_template(mining.get_block_template(template_request(None))?);
    assert_eq!(
        first.candidate.template_id.as_str(),
        second.candidate.template_id.as_str()
    );
    assert!(
        Arc::ptr_eq(&first.candidate, &second.candidate),
        "identical generation must reuse the cached candidate arc"
    );
    Ok(())
}

#[test]
fn watch_only_payout_lands_in_candidate_coinbase() -> Result<()> {
    const ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let dir = tempfile::tempdir()?;
    let layer = UserConfig {
        network: Some(NetworkSelection::Regtest),
        mining: MiningOverrides {
            payout_address: Some(ADDRESS.to_owned()),
        },
        ..Default::default()
    };
    let mut config = resolve(&[&layer])?;
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    std::mem::forget(dir);
    let state = NodeState::open(config, None)?;
    let _ = state.apply_block(&Network::Regtest.genesis_block())?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let template = expect_template(mining.get_block_template(template_request(None))?);
    let expected = bitcoin::Address::from_str(ADDRESS)?
        .require_network(bitcoin::Network::Regtest)?
        .script_pubkey()
        .as_bytes()
        .to_vec();
    assert_eq!(
        template.candidate.coinbase.outputs[0].script_pubkey, expected,
        "configured watch-only payout must be the candidate coinbase script"
    );
    Ok(())
}

#[test]
fn network_hash_ps_answers_on_the_applied_tip() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let genesis_rate = mining.network_hash_ps(120, -1)?;
    assert!(
        genesis_rate.abs() < f64::EPSILON,
        "genesis has no lookback window, got {genesis_rate}"
    );
    let genesis_height_rate = mining.network_hash_ps(120, 0)?;
    assert!(
        genesis_height_rate.abs() < f64::EPSILON,
        "Core reports 0 at the genesis height, got {genesis_height_rate}"
    );
    Ok(())
}

#[test]
// CONTRACT: docs/contracts/external-api.md#API-06
fn network_hash_ps_rejects_core_invalid_windows() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    match mining.network_hash_ps(0, -1) {
        Err(MiningControlError::InvalidRequest(message)) => {
            assert_eq!(
                message.as_str(),
                "Invalid nblocks. Must be a positive number or -1."
            );
        }
        other => panic!("nblocks 0 must be invalid, got {other:?}"),
    }
    match mining.network_hash_ps(-2, -1) {
        Err(MiningControlError::InvalidRequest(message)) => {
            assert_eq!(
                message.as_str(),
                "Invalid nblocks. Must be a positive number or -1."
            );
        }
        other => panic!("nblocks -2 must be invalid, got {other:?}"),
    }
    match mining.network_hash_ps(120, -10) {
        Err(MiningControlError::InvalidRequest(message)) => {
            assert_eq!(message.as_str(), "Block does not exist at specified height");
        }
        other => panic!("height -10 must be invalid, got {other:?}"),
    }
    match mining.network_hash_ps(120, 1) {
        Err(MiningControlError::InvalidRequest(message)) => {
            assert_eq!(message.as_str(), "Block does not exist at specified height");
        }
        other => panic!("height above the tip must be invalid, got {other:?}"),
    }
    Ok(())
}

#[test]
fn key_invalidation_rebuilds_after_mempool_sequence_change() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let first = expect_template(mining.get_block_template(template_request(None))?);

    advance_mempool_sequence(&state)?;
    mining.publish_generation();
    let second = expect_template(mining.get_block_template(template_request(None))?);
    assert_ne!(
        first.candidate.template_id.as_str(),
        second.candidate.template_id.as_str(),
        "mempool sequence change must invalidate the generation key"
    );
    assert!(!Arc::ptr_eq(&first.candidate, &second.candidate));
    Ok(())
}

#[test]
fn concurrent_requests_share_single_flight_assembly() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let mining = Arc::new(mining);
    mining.publish_generation();

    let barrier = Arc::new(std::sync::Barrier::new(8));
    let candidates = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let mining = Arc::clone(&mining);
        let barrier = Arc::clone(&barrier);
        let candidates = Arc::clone(&candidates);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let template = expect_template(
                mining
                    .get_block_template(template_request(None))
                    .unwrap_or_else(|error| panic!("template failed: {error}")),
            );
            candidates.lock().push(Arc::clone(&template.candidate));
        }));
    }
    for handle in handles {
        handle.join().unwrap_or_else(|_| panic!("worker panicked"));
    }
    let candidates = candidates.lock();
    let first = &candidates[0];
    assert!(
        candidates
            .iter()
            .all(|candidate| Arc::ptr_eq(candidate, first)),
        "all concurrent waiters must observe the same single-flight candidate"
    );
    Ok(())
}

#[test]
fn long_poll_wakes_on_tip_change() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    let mining = Arc::new(mining);
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
    let (started_tx, started_rx) = bounded::<()>(1);
    let mining_wait = Arc::clone(&mining);
    let waiter = thread::spawn(move || {
        started_tx
            .send(())
            .unwrap_or_else(|error| panic!("start signal failed: {error}"));
        mining_wait.get_block_template(template_request(Some(long_poll_id)))
    });
    started_rx.recv_timeout(Duration::from_secs(2))?;
    thread::sleep(Duration::from_millis(50));
    let genesis = Network::Regtest.genesis_block();
    let child = mined_child(genesis.block_hash())?;
    let _ = state.apply_block(&child)?;
    mining.publish_generation();
    let result = waiter
        .join()
        .unwrap_or_else(|_| panic!("long-poll waiter panicked"))
        .unwrap_or_else(|error| panic!("long poll failed: {error}"));
    let template = expect_template(result);
    assert_ne!(
        template.candidate.template_id.as_str(),
        current.candidate.template_id.as_str()
    );
    let child_hash = Hash256::from_le_bytes(child.block_hash().as_bytes());
    assert_eq!(template.candidate.previous_block_hash, child_hash);
    assert_eq!(template.submit_old, Some(false));
    assert_eq!(
        template.rules.iter().any(|rule| rule.as_str() == "csv"),
        template.candidate.csv_active
    );
    assert_eq!(
        template.rules.iter().any(|rule| rule.as_str() == "segwit"),
        template.candidate.segwit_active
    );
    Ok(())
}

#[test]
fn long_poll_wakes_on_mempool_sequence_change() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    let mining = Arc::new(mining);
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
    let (started_tx, started_rx) = bounded::<()>(1);
    let mining_wait = Arc::clone(&mining);
    let waiter = thread::spawn(move || {
        started_tx
            .send(())
            .unwrap_or_else(|error| panic!("start signal failed: {error}"));
        mining_wait.get_block_template(template_request(Some(long_poll_id)))
    });
    started_rx.recv_timeout(Duration::from_secs(2))?;
    thread::sleep(Duration::from_millis(50));
    advance_mempool_sequence(&state)?;
    mining.publish_generation();
    let result = waiter
        .join()
        .unwrap_or_else(|_| panic!("mempool long-poll waiter panicked"))
        .unwrap_or_else(|error| panic!("mempool long poll failed: {error}"));
    let template = expect_template(result);
    assert_ne!(
        template.candidate.mempool_sequence,
        current.candidate.mempool_sequence
    );
    assert_eq!(
        template.candidate.previous_block_hash,
        current.candidate.previous_block_hash
    );
    assert_eq!(template.submit_old, Some(true));
    Ok(())
}

#[test]
fn shutdown_ends_long_poll_without_wake() -> Result<()> {
    let state = open_at_genesis(Network::Regtest)?;
    let shutdown = state.chainstate().shutdown_handle();
    let mining = Arc::new(MiningCoordinator::new(
        state.mempool_reader(),
        state.chainstate(),
        state.stable_read(),
        state.chain_followers(),
        state.config().mining.payout_script.clone(),
    ));
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
    let mining_wait = Arc::clone(&mining);
    let waiter =
        thread::spawn(move || mining_wait.get_block_template(template_request(Some(long_poll_id))));
    thread::sleep(Duration::from_millis(50));
    // Bounded wait slices must observe the flag even without a direct wake:
    // correctness does not depend on a wake notification, so the coordinator
    // carries none.
    shutdown.store(true, Ordering::Release);
    let outcome = waiter
        .join()
        .unwrap_or_else(|_| panic!("shutdown waiter panicked"));
    let Err(err) = outcome else {
        panic!("shutdown wait unexpectedly succeeded");
    };
    assert!(matches!(err, MiningControlError::Unavailable(_)));
    Ok(())
}

#[test]
fn mining_info_reports_default_signet_challenge() -> Result<()> {
    let state = open_at_genesis(Network::Signet)?;
    let mining = coordinator(&state);
    let info = mining.mining_info()?;
    let Some(signet) = info.signet.as_ref() else {
        panic!("default Signet did not expose challenge metadata");
    };
    assert_eq!(
        to_lower_hex(&signet.challenge),
        concat!(
            "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430",
            "210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae",
        )
    );
    Ok(())
}

#[test]
fn mining_info_omits_signet_on_regtest() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let info = mining.mining_info()?;
    assert!(info.signet.is_none());
    Ok(())
}

#[test]
fn mining_info_reports_network_hashps_after_genesis() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let info = mining.mining_info()?;
    assert_eq!(info.blocks, 0);
    assert!(
        info.network_hashes_per_second.is_finite(),
        "hashps must be a finite projection"
    );
    Ok(())
}

#[test]
fn last_candidate_counts_include_the_coinbase() -> Result<()> {
    use bitcoin_rs_mempool::MempoolEntry;

    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let empty = expect_template(mining.get_block_template(template_request(None))?);
    let empty_info = mining.mining_info()?;
    assert!(empty.candidate.transactions.is_empty());
    assert_eq!(
        empty_info.last_candidate.map(|info| info.transactions),
        Some(1)
    );

    let tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x42; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    };
    {
        let mempool = state.mempool();
        let mut guard = mempool.write();
        guard.insert_entry(MempoolEntry::new(Arc::new(tx), 120, 10_000, 1, 1, 0))?;
    }
    mining.publish_generation();
    let one = expect_template(mining.get_block_template(template_request(None))?);
    let one_info = mining.mining_info()?;
    assert_eq!(one.candidate.transactions.len(), 1);
    assert_eq!(
        one_info.last_candidate.map(|info| info.transactions),
        Some(2)
    );
    Ok(())
}

/// Two threads looping `publish_generation` (tip path) and
/// `publish_generation_from` (mempool path) must not deadlock within a 200 ms
/// watchdog.
#[test]
fn concurrent_publish_generation_paths_do_not_deadlock() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let mining = Arc::new(mining);

    let stop = Arc::new(AtomicBool::new(false));

    let (tip_done_tx, tip_done_rx) = bounded::<()>(1);
    let mining_tip = Arc::clone(&mining);
    let stop_tip = Arc::clone(&stop);
    let tip_thread = thread::spawn(move || {
        while !stop_tip.load(Ordering::Relaxed) {
            mining_tip.publish_generation();
        }
        let _ = tip_done_tx.send(());
    });

    let (seq_done_tx, seq_done_rx) = bounded::<()>(1);
    let mining_seq = Arc::clone(&mining);
    let stop_seq = Arc::clone(&stop);
    let seq_thread = thread::spawn(move || {
        let mut seq = 1_u64;
        while !stop_seq.load(Ordering::Relaxed) {
            mining_seq.publish_generation_from(seq);
            seq = seq.wrapping_add(1);
        }
        let _ = seq_done_tx.send(());
    });

    // 200 ms watchdog — if either thread is stuck, the joins below time out.
    thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);

    tip_done_rx
        .recv_timeout(Duration::from_millis(500))
        .map_err(|_| anyhow::anyhow!("tip publish_generation thread deadlocked"))?;
    seq_done_rx
        .recv_timeout(Duration::from_millis(500))
        .map_err(|_| anyhow::anyhow!("sequence publish_generation_from thread deadlocked"))?;

    tip_thread
        .join()
        .unwrap_or_else(|_| panic!("tip publish_generation thread panicked"));
    seq_thread
        .join()
        .unwrap_or_else(|_| panic!("sequence publish_generation_from thread panicked"));
    Ok(())
}

/// `publish_generation_from` must not take the mempool read lock: holding the
/// pool write lock and calling it must return immediately, not deadlock.
#[test]
fn publish_generation_from_does_not_take_mempool_lock() -> Result<()> {
    let (state, mining) = regtest_mining()?;

    // Hold the mempool write lock for the duration of the call — a reentrant
    // read would deadlock (parking_lot RwLock is not reentrant).
    let mempool = state.mempool();
    let _write_guard = mempool.write();

    let (done_tx, done_rx) = bounded::<()>(1);
    let handle = thread::spawn(move || {
        mining.publish_generation_from(1);
        let _ = done_tx.send(());
    });

    done_rx
        .recv_timeout(Duration::from_millis(200))
        .map_err(|_| {
            anyhow::anyhow!(
                "publish_generation_from deadlocked under the mempool write lock \
                 — it must not take the mempool read lock"
            )
        })?;
    handle
        .join()
        .unwrap_or_else(|_| panic!("publish_generation_from thread panicked"));
    Ok(())
}

/// A long-poll waiter must return in well under 1 s after a mempool-sequence
/// wake, even when `mempool_update_wait` is non-zero. The waiter returns as
/// soon as the published generation key differs from the waited key — no
/// `LONG_POLL_SLICE` (1 s) recheck delay.
#[test]
fn long_poll_returns_quickly_on_mempool_sequence_wake() -> Result<()> {
    let state = open_at_genesis(Network::Regtest)?;

    // Non-zero cooldown: the old code would wait up to `mempool_update_wait`
    // before returning on a mempool-only change. The fix returns immediately.
    let mining = Arc::new(MiningCoordinator::new(
        state.mempool_reader(),
        state.chainstate(),
        state.stable_read(),
        state.chain_followers(),
        state.config().mining.payout_script.clone(),
    ));
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let long_poll_id = CompactString::from(current.candidate.template_id.as_str());

    let (started_tx, started_rx) = bounded::<()>(1);
    let (done_tx, done_rx) = bounded(1);
    let mining_wait = Arc::clone(&mining);
    let waiter = thread::spawn(move || {
        started_tx
            .send(())
            .unwrap_or_else(|error| panic!("start signal failed: {error}"));
        let result = mining_wait.get_block_template(template_request(Some(long_poll_id)));
        let _ = done_tx.send(result);
    });

    started_rx.recv_timeout(Duration::from_secs(2))?;
    // Scheduling aid only: the start signal does not prove entry into the wait.
    thread::sleep(Duration::from_millis(50));

    // Advance the mempool sequence and wake via the lock-free path.
    advance_mempool_sequence(&state)?;
    let seq = state.mempool().read().sequence_number();
    let wake_start = std::time::Instant::now();
    mining.publish_generation_from(seq);

    let result = done_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|error| anyhow::anyhow!("mempool long-poll waiter did not complete: {error}"))?;
    let elapsed = wake_start.elapsed();
    waiter
        .join()
        .unwrap_or_else(|_| panic!("mempool long-poll waiter panicked"));
    let result = result.unwrap_or_else(|error| panic!("mempool long poll failed: {error}"));

    assert!(
        elapsed < Duration::from_millis(800),
        "long-poll waiter returned in {elapsed:?}, expected well under 1 s"
    );
    let template = expect_template(result);
    assert_ne!(
        template.candidate.mempool_sequence,
        current.candidate.mempool_sequence
    );
    assert_eq!(
        template.candidate.previous_block_hash,
        current.candidate.previous_block_hash
    );
    assert_eq!(template.submit_old, Some(true));
    Ok(())
}

/// CONTRACT: API-06 — getmininginfo's networkhashps mirrors the default
/// getnetworkhashps window.
#[test]
fn network_hash_ps_matches_mining_info_default_window() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let info = mining.mining_info()?;
    let rate = mining.network_hash_ps(120, -1)?;
    assert!(
        (rate - info.network_hashes_per_second).abs() < f64::EPSILON,
        "default-window hash rate must match mining info: {rate} vs {}",
        info.network_hashes_per_second
    );
    Ok(())
}

// Priority-change generations.
//
// Every test below runs the real node, the real mempool gateway, the real
// `MiningCoordinator`, and the real RPC `prioritisetransaction` /
// `getblocktemplate` handlers; no coordinator or gateway is replaced. Two
// independent pooled spends rank `high` over `low` until `low` is prioritised.
//
// What each group can and cannot fail:
// - Template-content tests (`priority_change_replaces_the_cached_candidate...`)
//   fail when the candidate identity omits the fee-priority component: the
//   second template would be the cached, stale one.
// - Pending-long-poll tests park the poll causally (`park_long_poll`) before
//   anything is published, so a poll started after the change cannot pass.
//   Their content assertions fail when the reply is the stale generation.
//   They do not prove the notification: the coordinator re-derives the live
//   generation every 1 s wait slice, so a lost notify only delays the same
//   reply, and the 5 s ceiling is above that slice. No test here fails on a
//   suppressed notify by design; the limit is recorded, not hidden.

/// A priority change moves the fee-priority sequence but not the pool
/// membership sequence. The generation must still change: the cached candidate
/// of the old generation is not served, the template is rebuilt in the new
/// order, and the pooled fees themselves do not move.
#[test]
fn priority_change_replaces_the_cached_candidate_for_an_unchanged_pool() -> Result<()> {
    let fx = priority_fixture()?;
    let first = expect_template(fx.mining().get_block_template(template_request(None))?);
    let again = expect_template(fx.mining().get_block_template(template_request(None))?);
    assert!(
        Arc::ptr_eq(&first.candidate, &again.candidate),
        "precondition: an unchanged generation is served from the cache"
    );
    let ranked = |template: &bitcoin_rs_mining::BlockTemplate| {
        template
            .candidate
            .transactions
            .iter()
            .map(|tx| (tx.txid.to_string(), tx.fee))
            .collect::<Vec<_>>()
    };
    let high = || (fx.high.txid().to_string(), HIGH_FEE_SATS);
    let low = || (fx.low.txid().to_string(), LOW_FEE_SATS);
    assert_eq!(ranked(&first), vec![high(), low()]);

    fx.prioritise(&fx.low, PRIORITY_DELTA_SATS)?;

    let after = expect_template(fx.mining().get_block_template(template_request(None))?);
    assert!(
        !Arc::ptr_eq(&first.candidate, &after.candidate),
        "a priority change must not be answered from the stale cached candidate"
    );
    assert_ne!(
        first.candidate.template_id.as_str(),
        after.candidate.template_id.as_str(),
        "the generation identity must change with the fee-priority sequence"
    );
    assert_eq!(
        after.candidate.mempool_sequence, first.candidate.mempool_sequence,
        "prioritisation does not change pool membership"
    );
    assert_eq!(
        after.candidate.previous_block_hash,
        first.candidate.previous_block_hash
    );
    assert_eq!(
        ranked(&after),
        vec![low(), high()],
        "the prioritised transaction ranks first; actual fees are unchanged"
    );
    assert_eq!(
        after.candidate.template_id.as_str(),
        live_long_poll_id(&fx.state)?,
        "the candidate identity is the live generation's longpollid"
    );
    Ok(())
}

/// A long poll that is pending when `prioritisetransaction` succeeds returns
/// the reordered template under the new generation id. The poll is proven
/// parked before the change, so starting late cannot satisfy this test. It
/// does not prove the notification (see the group comment).
#[test]
fn priority_change_returns_a_pending_long_poll_with_the_reordered_template() -> Result<()> {
    let fx = priority_fixture()?;
    let (before, poll) = fx.park_long_poll()?;
    assert_eq!(
        before.txids,
        txid_strings(&[&fx.high, &fx.low]),
        "precondition: high ranks over low"
    );

    fx.prioritise(&fx.low, PRIORITY_DELTA_SATS)?;

    let after = poll.collect(PROMPT)??;
    assert_eq!(
        after.txids,
        txid_strings(&[&fx.low, &fx.high]),
        "the pending poll must return the reordered template, not the stale one"
    );
    assert_eq!(after.fees, [LOW_FEE_SATS, HIGH_FEE_SATS]);
    assert_eq!(
        after.coinbase_value, before.coinbase_value,
        "prioritisation never changes the fees the coinbase claims"
    );
    let (waited, answered) = (before.id()?, after.id()?);
    assert_eq!(answered.tip, waited.tip);
    assert_eq!(answered.mempool_sequence, waited.mempool_sequence);
    assert_ne!(
        answered.fee_delta_sequence, waited.fee_delta_sequence,
        "the fee-priority component must advance"
    );
    assert_eq!(after.long_poll_id, live_long_poll_id(&fx.state)?);
    Ok(())
}

/// An ordinary admission after a priority change still returns a pending long
/// poll, keeps the fee-priority component of the generation, and keeps the
/// prioritised ordering.
#[test]
fn admission_after_a_priority_change_returns_a_pending_long_poll_and_keeps_the_fee_component()
-> Result<()> {
    let fx = priority_fixture()?;
    let initial = fx.template()?.id()?;
    fx.prioritise(&fx.low, PRIORITY_DELTA_SATS)?;
    let (prioritised, poll) = fx.park_long_poll()?;
    let prioritised_id = prioritised.id()?;
    assert_ne!(
        prioritised_id.fee_delta_sequence, initial.fee_delta_sequence,
        "precondition: the priority change moved the fee component"
    );

    let late = fx.admit_late()?;

    let after = poll.collect(PROMPT)??;
    assert_eq!(
        after.txids,
        txid_strings(&[&fx.low, &fx.high, &late]),
        "the admission joins the template; the priority ordering survives it"
    );
    assert_eq!(after.fees, [LOW_FEE_SATS, HIGH_FEE_SATS, LATE_FEE_SATS]);
    assert_eq!(
        after.coinbase_value,
        REGTEST_SUBSIDY_SATS + LOW_FEE_SATS + HIGH_FEE_SATS + LATE_FEE_SATS
    );
    let answered = after.id()?;
    assert_eq!(answered.tip, prioritised_id.tip);
    assert_ne!(
        answered.mempool_sequence, prioritised_id.mempool_sequence,
        "an admission moves the membership sequence"
    );
    assert_eq!(
        answered.fee_delta_sequence, prioritised_id.fee_delta_sequence,
        "an ordinary admission must carry the priority component forward"
    );
    assert_eq!(after.long_poll_id, live_long_poll_id(&fx.state)?);
    Ok(())
}

/// A miner still holding the id of the generation before a priority change is
/// told at once: the pool changed, so its id is stale and the call must not
/// wait. Deterministic: no wake is involved, only the identity. A candidate
/// identity without the fee-priority component makes the stale id equal to the
/// live one, and the call blocks until the ceiling.
#[test]
fn long_poll_on_the_pre_priority_id_returns_the_new_generation_without_waiting() -> Result<()> {
    let fx = priority_fixture()?;
    let before = fx.template()?;
    fx.prioritise(&fx.low, PRIORITY_DELTA_SATS)?;

    let after = fx.poll(&before.long_poll_id).collect(PROMPT)??;

    assert_ne!(after.long_poll_id, before.long_poll_id);
    assert_eq!(
        after.txids,
        txid_strings(&[&fx.low, &fx.high]),
        "the stale id must be answered with the reordered template"
    );
    assert_eq!(after.long_poll_id, live_long_poll_id(&fx.state)?);
    Ok(())
}

/// A legacy `{tip}{mempool_sequence}` id parses as fee revision zero, and
/// every colon-form near miss fails at once instead of waiting on a
/// generation that can never match. Each call runs under the `PROMPT`
/// ceiling, so an id that wrongly parses (and would wait) fails the test
/// rather than hanging it.
#[test]
fn long_poll_legacy_id_parses_as_fee_zero_and_malformed_ids_are_rejected() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    let mining = Arc::new(mining);
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let id = current.candidate.template_id.as_str();
    // No prioritisation has run, so the live fee revision is zero and the
    // legacy shape without a suffix names the live generation exactly.
    assert!(
        !id.contains(':'),
        "precondition: the live id {id:?} carries no fee suffix"
    );
    let (tip, sequence) = id.split_at(64);
    let rejected = [
        format!("{tip}:"),
        format!("{tip}{sequence}:7:8"),
        format!("{tip}{sequence}x"),
        format!("{tip}-1:2"),
        format!("{tip}5:x"),
        // A multibyte character straddling the tip/counter split.
        format!("{}é:1", "a".repeat(63)),
    ];

    for rejected_id in rejected {
        let call_id = CompactString::from(rejected_id.as_str());
        let call_mining = Arc::clone(&mining);
        let outcome = PendingPoll::spawn(state.chainstate().shutdown_handle(), move || {
            call_mining.get_block_template(template_request(Some(call_id)))
        })
        .collect(PROMPT)?;
        match outcome {
            Err(MiningControlError::InvalidRequest(message)) => assert!(
                message.as_str().contains("malformed"),
                "id {rejected_id:?} was rejected with {message:?}"
            ),
            other => panic!("long-poll id {rejected_id:?} must be malformed, got {other:?}"),
        }
    }
    // The legacy shape parses as fee revision zero: after a mempool change,
    // polling the previous legacy id returns the new generation at once
    // instead of failing as malformed. No wait is involved, so the check is
    // synchronous.
    advance_mempool_sequence(&state)?;
    let membership = state.mempool().read().sequence_number();
    mining.publish_generation_from(membership);
    let stale = CompactString::from(id);
    let answered = expect_template(mining.get_block_template(template_request(Some(stale)))?);
    assert_ne!(
        answered.candidate.mempool_sequence, current.candidate.mempool_sequence,
        "a legacy id must resolve against the fee-zero generation, not fail as malformed"
    );
    Ok(())
}

/// `publish_fee_delta_generation` receives its sequence as an argument: like
/// `publish_generation_from`, it must not take the mempool read lock, because
/// the RPC handler and observers call it around pool mutations.
#[test]
fn publish_fee_delta_generation_does_not_take_mempool_lock() -> Result<()> {
    let (state, mining) = regtest_mining()?;

    // A reentrant read would deadlock (parking_lot RwLock is not reentrant).
    let mempool = state.mempool();
    let _write_guard = mempool.write();

    let (done_tx, done_rx) = bounded::<()>(1);
    let handle = thread::spawn(move || {
        mining.publish_fee_delta_generation(1);
        let _ = done_tx.send(());
    });

    done_rx
        .recv_timeout(Duration::from_millis(200))
        .map_err(|_| {
            anyhow::anyhow!(
                "publish_fee_delta_generation deadlocked under the mempool write lock \
                 — it must not take the mempool read lock"
            )
        })?;
    handle
        .join()
        .unwrap_or_else(|_| panic!("publish_fee_delta_generation thread panicked"));
    Ok(())
}

// Staged-template durability proofs.
//
// Every test below runs the real node, the real mempool gateway, the real
// `MiningCoordinator` attached through the production
// `attach_mining_coordinator` path, and the real disk backend. The body's
// store is the real store wrapped by the sync barrier
// (`super::preparation_barrier`): while the gate holds the one armed sync,
// the staged-tip hook has fired and the preparation worker can finish, but
// the durable head has not advanced and nothing is published. Releasing the
// gate lets the real sync and head batch complete. The guard lives inside
// the `thread::scope` body, so a failed assertion releases the apply thread
// before the scope joins it: no test here can hang another.
//
// A stale IBD latch would suppress staging, so the chains are seeded with
// fresh-time blocks (same height-encoding coinbases as `seed_chain`, wall
// clock timestamps): the first fresh tip latches IBD off, and every staged
// block after it reaches the coordinator.

/// Real node on a real disk backend with a fresh chain, two pooled mature
/// spends (`low` ranks below `high`), and the coordinator attached through
/// the production signal path.
struct BarrierSetup {
    node: BarrierNode,
    mining: Arc<MiningCoordinator>,
    low: Tx,
    high: Tx,
}

fn barrier_setup() -> Result<BarrierSetup> {
    let node = open_barrier_node()?;
    seed_fresh_chain(&node.state, PRIORITY_SEED_BLOCKS)?;
    let mining = Arc::new(coordinator(&node.state));
    node.state.attach_mining_coordinator(&mining);
    let low = seed_coinbase_spend_at(1, LOW_FEE_SATS);
    let high = seed_coinbase_spend_at(2, HIGH_FEE_SATS);
    admit_to_mempool(&node.state, &low)?;
    admit_to_mempool(&node.state, &high)?;
    Ok(BarrierSetup {
        node,
        mining,
        low,
        high,
    })
}

/// Transaction ids of a built template in candidate order.
fn txids_of(template: &BlockTemplate) -> Vec<String> {
    template
        .candidate
        .transactions
        .iter()
        .map(|entry| entry.txid.to_string())
        .collect()
}

/// A staged preparation must not publish before the durable commit: while the
/// body sync is held and the worker has finished the staged tip, the applied
/// tip and an ordinary template still reference the old parent.
#[test]
fn staged_preparation_does_not_publish_before_commit() -> Result<()> {
    let setup = barrier_setup()?;
    let state = &setup.node.state;
    let gate = &setup.node.gate;
    let mining = &setup.mining;
    let old_tip = current_tip(state)?;
    let baseline = expect_template(mining.get_block_template(template_request(None))?);
    assert_eq!(
        baseline.candidate.previous_block_hash, old_tip.hash,
        "precondition: the template builds on the applied tip"
    );
    assert_eq!(
        txids_of(&baseline),
        txid_strings(&[&setup.high, &setup.low]),
        "precondition: high fee ranks over low"
    );

    // The barrier block consumes `low`, leaving `high` for the next template.
    let block = fresh_tip_child(state, vec![setup.low.clone()])?;
    let new_hash = Hash256::from(block.block_hash());

    thread::scope(|scope| {
        let _release = gate.release_guard();
        gate.arm();
        let apply = scope.spawn(|| state.apply_block(&block));
        assert!(
            gate.wait_entered(barrier_bound()),
            "the commit never reached the body-store sync boundary"
        );
        assert!(
            mining
                .wait_for_prepared_candidate(new_hash, barrier_bound())
                .is_some(),
            "the preparation worker never finished the staged tip while sync was held"
        );

        let held_tip = current_tip(state)?;
        assert_eq!(
            held_tip.hash, old_tip.hash,
            "the applied tip must not advance before the durable commit"
        );
        let held = expect_template(mining.get_block_template(template_request(None))?);
        assert_eq!(
            held.candidate.previous_block_hash, old_tip.hash,
            "an ordinary template must still build on the old parent while sync is held"
        );
        assert_eq!(
            txids_of(&held),
            txid_strings(&[&setup.high, &setup.low]),
            "the held template must still carry both pooled spends"
        );
        let mempool = state.mempool();
        let pool = mempool.read();
        assert!(
            pool.contains_txid(&setup.low.txid()),
            "the consumed spend must stay pooled until the commit removes it"
        );
        drop(pool);

        gate.release();
        apply
            .join()
            .map_err(|_| anyhow::anyhow!("barrier apply thread panicked"))??;
        assert_eq!(
            current_tip(state)?.hash,
            new_hash,
            "releasing the sync must let the real commit land the new tip"
        );
        Ok(())
    })
}

/// After the held commit lands, the first template on the new tip installs
/// the prepared candidate `Arc`, and the survivors match the actual pool.
#[test]
fn prepared_candidate_installs_on_commit_with_arc_reuse() -> Result<()> {
    let setup = barrier_setup()?;
    let state = &setup.node.state;
    let gate = &setup.node.gate;
    let mining = &setup.mining;
    let block = fresh_tip_child(state, vec![setup.low.clone()])?;
    let new_hash = Hash256::from(block.block_hash());

    thread::scope(|scope| {
        let _release = gate.release_guard();
        gate.arm();
        let apply = scope.spawn(|| state.apply_block(&block));
        assert!(
            gate.wait_entered(barrier_bound()),
            "the commit never reached the body-store sync boundary"
        );
        let prepared = mining
            .wait_for_prepared_candidate(new_hash, barrier_bound())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "the preparation worker never finished the staged tip while sync was held"
                )
            })?;

        gate.release();
        apply
            .join()
            .map_err(|_| anyhow::anyhow!("barrier apply thread panicked"))??;
        assert_eq!(
            current_tip(state)?.hash,
            new_hash,
            "the commit must land the staged tip"
        );

        let first = expect_template(mining.get_block_template(template_request(None))?);
        assert_eq!(
            first.candidate.previous_block_hash, new_hash,
            "the first template must build on the committed tip"
        );
        assert!(
            Arc::ptr_eq(&first.candidate, &prepared),
            "the first template on the new tip must install the prepared candidate arc"
        );
        assert_eq!(
            txids_of(&first),
            txid_strings(&[&setup.high]),
            "the installed candidate must carry exactly the removal survivors"
        );
        let mempool = state.mempool();
        let pool = mempool.read();
        assert!(
            !pool.contains_txid(&setup.low.txid()),
            "the block's spend must leave the pool on commit"
        );
        assert!(
            pool.contains_txid(&setup.high.txid()),
            "the survivor must stay pooled after the commit"
        );
        drop(pool);
        assert_eq!(
            first.candidate.coinbase_value,
            REGTEST_SUBSIDY_SATS + HIGH_FEE_SATS,
            "the installed coinbase must claim the survivors' actual fees"
        );
        Ok(())
    })
}

/// A fee-priority mutation committed while the sync is held invalidates the
/// staged preparation: the post-commit template is a new candidate in the
/// prioritised order, never the stale `Arc`.
#[test]
fn fee_priority_race_discards_stale_preparation() -> Result<()> {
    let setup = barrier_setup()?;
    let state = &setup.node.state;
    let gate = &setup.node.gate;
    let mining = &setup.mining;
    // An empty tip child removes nothing, so only the fee race can refuse
    // the prepared install.
    let block = fresh_tip_child(state, Vec::new())?;
    let new_hash = Hash256::from(block.block_hash());

    thread::scope(|scope| {
        let _release = gate.release_guard();
        gate.arm();
        let apply = scope.spawn(|| state.apply_block(&block));
        assert!(
            gate.wait_entered(barrier_bound()),
            "the commit never reached the body-store sync boundary"
        );
        let prepared = mining
            .wait_for_prepared_candidate(new_hash, barrier_bound())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "the preparation worker never finished the staged tip while sync was held"
                )
            })?;
        let staged_order: Vec<String> = prepared
            .transactions
            .iter()
            .map(|entry| entry.txid.to_string())
            .collect();
        assert_eq!(
            staged_order,
            txid_strings(&[&setup.high, &setup.low]),
            "precondition: the staged candidate ranks high over low"
        );

        // The real `prioritisetransaction` path: gateway mutation plus the
        // fee-generation publish, committed while the sync is still held.
        let handler = rpc_handler(state, mining.clone());
        let accepted = handler.dispatch(
            "prioritisetransaction",
            &json!([setup.low.txid().to_string(), 0, PRIORITY_DELTA_SATS]),
        )?;
        assert_eq!(
            accepted.as_bool(),
            Some(true),
            "the raced prioritisation must commit, got {accepted}"
        );

        gate.release();
        apply
            .join()
            .map_err(|_| anyhow::anyhow!("barrier apply thread panicked"))??;
        assert_eq!(
            current_tip(state)?.hash,
            new_hash,
            "the commit must land the staged tip"
        );

        let first = expect_template(mining.get_block_template(template_request(None))?);
        assert_eq!(
            first.candidate.previous_block_hash, new_hash,
            "the first template must build on the committed tip"
        );
        assert!(
            !Arc::ptr_eq(&first.candidate, &prepared),
            "a fee race between staging and publish must discard the stale preparation"
        );
        assert_eq!(
            txids_of(&first),
            txid_strings(&[&setup.low, &setup.high]),
            "the post-commit template must reflect the committed priority"
        );
        assert_eq!(
            first.candidate.template_id.as_str(),
            live_long_poll_id(state)?,
            "the served generation must be the live one"
        );
        Ok(())
    })
}

/// Shutting down with staged work held neither installs nor publishes it and
/// never hangs: the apply settles, GBT answers unavailable, and the prepared
/// wait comes back empty.
#[test]
fn shutdown_with_staged_work_installs_nothing_and_answers_unavailable() -> Result<()> {
    let setup = barrier_setup()?;
    let state = &setup.node.state;
    let gate = &setup.node.gate;
    let mining = &setup.mining;
    let block = fresh_tip_child(state, Vec::new())?;
    let new_hash = Hash256::from(block.block_hash());

    thread::scope(|scope| {
        let _release = gate.release_guard();
        gate.arm();
        let apply = scope.spawn(|| state.apply_block(&block));
        assert!(
            gate.wait_entered(barrier_bound()),
            "the commit never reached the body-store sync boundary"
        );

        // Staging fired before the sync (the hook runs ahead of it); shut
        // down with that work still unpublished.
        state.request_shutdown();
        gate.release();
        // The commit tail owns the outcome past the UTXO commit: either the
        // durable commit lands or the tail refuses it after shutdown — both
        // are acceptable, and neither is asserted here. A worker panic is
        // still a failure, so only the join layer is classified.
        let inner = apply
            .join()
            .map_err(|_| anyhow::anyhow!("barrier apply thread panicked"))?;
        let _ = inner;

        match mining.get_block_template(template_request(None)) {
            Err(MiningControlError::Unavailable(_)) => {}
            other => panic!("getblocktemplate after shutdown must be unavailable, got {other:?}"),
        }
        assert!(
            mining
                .wait_for_prepared_candidate(new_hash, Duration::from_secs(2))
                .is_none(),
            "shutdown must release prepared waiters with nothing to install"
        );
        // Commit or refusal stays unasserted, but the staged work itself must
        // never have published: no template was served in this test, so any
        // recorded candidate is the staged install leaking through.
        assert!(
            mining.mining_info()?.last_candidate.is_none(),
            "shutdown with staged work held must install nothing"
        );
        Ok(())
    })
}
