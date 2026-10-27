//! Production public-Node consumer: no RPC client, test seam, or fake coordinator.
use super::*;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_mining::{
    BlockValidationResult, CoinbaseBudget, GenerateRequest, GenerateSelection, solve_block,
};
use bitcoin_rs_primitives::{
    Amount, Hash256, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness, consensus_bytes,
};
use std::time::Instant;
use stratum_apps::stratum_core::{bitcoin, template_distribution_sv2::SubmitSolutionOwned};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// An empty candidate on the parent `parent`; distinct parents have distinct identities.
pub(super) fn empty_candidate(parent: u8) -> Arc<Candidate> {
    use bitcoin_rs_mining::{CandidateContext, assemble_candidate};
    Arc::new(
        assemble_candidate(
            &CandidateContext {
                previous_block_hash: Hash256::from_le_bytes(&[parent; 32]),
                height: 1,
                version: 0x20000000,
                bits: bitcoin_rs_primitives::CompactTarget::from_consensus(0x207fffff),
                min_time: 1,
                current_time: 1,
                locktime_cutoff: 1,
                staged_parent_mtp: 1,
                network: Network::Regtest,
                csv_active: true,
                segwit_active: true,
                max_weight: 4_000_000,
                max_size: 4_000_000,
                max_sigops: 80_000,
            },
            &bitcoin_rs_mempool::Mempool::new(Default::default()),
            &[0x51],
        )
        .unwrap(),
    )
}

fn candidate(node: &Node) -> Arc<Candidate> {
    let result = node
        .mining_control()
        .unwrap()
        .get_block_template(BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: vec![],
            rules: vec![],
            long_poll_id: None,
            coinbase_budget: None,
        })
        .unwrap();
    let BlockTemplateResult::Template(template) = result else {
        panic!("template");
    };
    template.candidate
}

/// Waits for the worker's next wake, then does what a session does: asks the
/// mining owner for its own candidate and retains it.
async fn next(hub: &Hub, wakes: &mut watch::Receiver<u64>, node: &Node) -> Arc<TemplateState> {
    tokio::time::timeout(Duration::from_secs(5), wakes.changed())
        .await
        .unwrap()
        .unwrap();
    hub.issue(candidate(node))
}

#[tokio::test]
async fn embedded_templates_preserve_wire_data_commit_and_cancel_on_shutdown() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.rpc.bind = "127.0.0.1:0".parse()?;
    config.p2p.listen.clear();
    config.p2p.dns_seeds_enabled = false;
    config.storage.dbcache_mb = 16;
    let witness_hash = bitcoin::hashes::sha256::Hash::hash(&[0x51]);
    config.mining.payout_script = [vec![0, 32], witness_hash.to_byte_array().to_vec()].concat();
    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
    let node = Arc::new(
        tokio::task::spawn_blocking(move || {
            block_on(Node::start(
                config,
                RuntimeInputs::default().with_shutdown(shutdown_rx),
            ))
        })
        .await??,
    );
    let hub = Hub::new();
    let mut updates = hub.subscribe();
    let worker_node = Arc::clone(&node);
    let worker_hub = hub.clone();
    let worker = std::thread::spawn(move || {
        let mining = worker_node.mining_control().unwrap();
        let mut calls = 0;
        let mut last_id: Option<String> = None;
        let mut retry_started: Option<Instant> = None;
        template_loop(
            |request| {
                calls += 1;
                assert_eq!(request.long_poll_id.as_deref(), last_id.as_deref());
                assert_eq!(
                    request.coinbase_budget, None,
                    "the worker only learns that the generation moved"
                );
                if let Some(started) = retry_started.take() {
                    assert!(started.elapsed() >= TEMPLATE_RETRY_DELAY);
                }
                // Race once before the initial job and once during refresh.
                // Both must recover without losing the last published identity.
                if calls == 1 || calls == 3 {
                    retry_started = Some(Instant::now());
                    return Err(MiningControlError::Unavailable(
                        "generation key changed during candidate assembly".into(),
                    ));
                }
                let result = mining.get_block_template(request)?;
                if let BlockTemplateResult::Template(template) = &result {
                    last_id = Some(template.candidate.template_id.as_str().to_owned());
                }
                Ok(result)
            },
            worker_hub,
        )
    });
    let first = next(&hub, &mut updates, &node).await;
    let c = Arc::clone(&first.candidate);
    let wire = first.new_template_msg()?;
    assert_eq!(wire.coinbase_tx_value_remaining, c.coinbase_value);
    assert_eq!(
        wire.coinbase_prefix.as_ref(),
        c.coinbase.inputs[0].script_sig.as_bytes()
    );
    assert_eq!(
        wire.coinbase_tx_outputs.as_ref(),
        c.coinbase
            .outputs
            .iter()
            .skip(1)
            .flat_map(consensus_bytes)
            .collect::<Vec<_>>()
    );
    let ample = CoinbaseBudget {
        additional_size: 1000,
        additional_sigops: 100,
    };
    let unbounded = CoinbaseBudget {
        additional_size: u32::MAX,
        additional_sigops: u16::MAX,
    };
    assert!(first.candidate.admits(ample).is_ok());
    assert!(first.candidate.admits(unbounded).is_err());
    let mut solved = c.into_unsolved_block()?;
    solve_block(&mut solved, 1_000_000)?;
    let solution = SubmitSolutionOwned {
        template_id: first.id,
        version: solved.header.version as u32,
        header_timestamp: solved.header.time,
        header_nonce: solved.header.nonce,
        coinbase_tx: consensus_bytes(&solved.txs[0]).try_into().unwrap(),
    };
    let assembled = first.assemble_block(&solution)?;
    let reference: bitcoin::Block = bitcoin::consensus::deserialize(&consensus_bytes(&assembled))?;
    assert_eq!(
        reference.header.merkle_root,
        reference.compute_merkle_root().unwrap()
    );
    assert_eq!(consensus_bytes(&assembled), consensus_bytes(&solved));
    let submission_node = Arc::clone(&node);
    assert_eq!(
        tokio::task::spawn_blocking(move || submission_node
            .mining_control()
            .unwrap()
            .submit_block(assembled))
        .await??,
        BlockValidationResult::Accepted
    );
    let second = next(&hub, &mut updates, &node).await;
    assert_ne!(second.candidate.template_id, first.candidate.template_id);
    assert!(Arc::ptr_eq(&hub.lookup(first.id).unwrap(), &first));
    assert_eq!(
        node.mining_control()?
            .submit_block(first.assemble_block(&solution)?)?,
        BlockValidationResult::Duplicate
    );
    let funding = solved.txs[0].clone();
    let generating = Arc::clone(&node);
    let payout = funding.outputs[0].script_pubkey.as_bytes().to_vec();
    tokio::task::spawn_blocking(move || {
        generating
            .mining_control()
            .unwrap()
            .generate(GenerateRequest {
                payout,
                count: 100,
                max_tries: 1_000_000,
                selection: GenerateSelection::Mempool,
                submit: true,
            })
    })
    .await??;
    let tx = Tx {
        version: 2,
        lock_time: bitcoin_rs_primitives::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(funding.txid(), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0x51]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(first.candidate.coinbase_value - 2000),
            script_pubkey: funding.outputs[0].script_pubkey.clone(),
        }],
    };
    let txid = tx.txid();
    let expected_tx = consensus_bytes(&tx);
    let before = candidate(&node);
    let broadcasting = Arc::clone(&node);
    tokio::task::spawn_blocking(move || block_on(broadcasting.broadcast(tx))).await??;
    let after = candidate(&node);
    assert_eq!(before.previous_block_hash, after.previous_block_hash);
    assert_ne!(before.template_id, after.template_id);
    // The worker wakes once per generation; the template a session would be
    // given for the generation that admitted the transaction carries it.
    let with_tx = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let state = next(&hub, &mut updates, &node).await;
            if state
                .candidate
                .transactions
                .iter()
                .any(|entry| entry.txid == txid)
            {
                break state;
            }
        }
    })
    .await?;
    assert_eq!(with_tx.candidate.template_id, after.template_id);
    assert_eq!(with_tx.candidate.transactions[0].txid, txid);
    let data = with_tx.transaction_data()?.into_inner();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0].as_ref(), expected_tx);
    let reference_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(data[0].as_ref())?;
    assert_eq!(
        reference_tx.compute_txid().to_byte_array(),
        *txid.as_bytes()
    );
    let mut solved_with_tx = with_tx.candidate.into_unsolved_block()?;
    solve_block(&mut solved_with_tx, 1_000_000)?;
    let with_tx_solution = SubmitSolutionOwned {
        template_id: with_tx.id,
        version: solved_with_tx.header.version as u32,
        header_timestamp: solved_with_tx.header.time,
        header_nonce: solved_with_tx.header.nonce,
        coinbase_tx: consensus_bytes(&solved_with_tx.txs[0]).try_into().unwrap(),
    };
    let projected = with_tx.assemble_block(&with_tx_solution)?;
    let reference: bitcoin::Block = bitcoin::consensus::deserialize(&consensus_bytes(&projected))?;
    assert_eq!(
        reference.header.merkle_root,
        reference.compute_merkle_root().unwrap()
    );
    assert_eq!(
        consensus_bytes(&projected),
        consensus_bytes(&solved_with_tx)
    );
    // The superseded same-tip empty job is still valid after mempool admission.
    let mut old_job = before.into_unsolved_block()?;
    solve_block(&mut old_job, 1_000_000)?;
    assert_eq!(
        node.mining_control()?.submit_block(old_job)?,
        BlockValidationResult::Accepted
    );
    // Its competitor must now be rejected by normal chainstate admission.
    assert!(matches!(
        node.mining_control()?.submit_block(projected)?,
        BlockValidationResult::Rejected(_)
    ));

    shutdown_tx.send(())?;
    let ended = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || worker.join()),
    )
    .await??
    .unwrap();
    assert!(ended.is_err());
    let node = Arc::try_unwrap(node).map_err(|_| "live node borrower")?;
    tokio::task::spawn_blocking(move || block_on(node.shutdown())).await??;
    Ok(())
}

#[test]
fn equal_candidate_identities_share_one_job_and_history_stays_bounded() {
    let hub = Hub::new();
    let first = hub.issue(empty_candidate(1));
    // A second session given the same owner identity gets the same job.
    assert!(Arc::ptr_eq(&hub.issue(empty_candidate(1)), &first));
    assert!(Arc::ptr_eq(&hub.lookup(first.id).unwrap(), &first));
    for parent in (2..).take(RETAINED_TEMPLATES) {
        hub.issue(empty_candidate(parent));
    }
    assert_eq!(hub.issued.lock().unwrap().len(), RETAINED_TEMPLATES);
    assert!(hub.lookup(first.id).is_none());
    // Only a retained state deduplicates: an evicted identity is issued afresh.
    assert_ne!(hub.issue(empty_candidate(1)).id, first.id);
}

#[test]
fn worker_wake_reaches_every_subscriber_without_carrying_a_job() {
    let hub = Hub::new();
    let (mut a, mut b) = (hub.subscribe(), hub.subscribe());
    assert!(!a.has_changed().unwrap());
    hub.wake();
    hub.wake();
    // Wakes coalesce: sessions refresh from the owner's live generation.
    assert!(a.has_changed().unwrap() && b.has_changed().unwrap());
    assert_eq!((*a.borrow_and_update(), *b.borrow_and_update()), (2, 2));
    assert!(hub.issued.lock().unwrap().is_empty());
}

#[test]
fn template_errors_other_than_generation_races_are_terminal() {
    let errors = [
        MiningControlError::Unavailable("node is shutting down".into()),
        MiningControlError::Unavailable("applied tip is not available".into()),
        MiningControlError::InvalidRequest("invalid request".into()),
        MiningControlError::Failed("assembly failed".into()),
        MiningControlError::Rejected("rejected".into()),
    ];
    for error in errors {
        let hub = Hub::new();
        let mut calls = 0;
        let result = template_loop(
            |_| {
                calls += 1;
                assert_eq!(calls, 1, "terminal errors must not be retried");
                Err(error.clone())
            },
            hub.clone(),
        );
        assert_eq!(result, Err(error.to_string()));
        assert_eq!(*hub.subscribe().borrow(), 0, "a failed poll wakes nobody");
    }
}

#[test]
fn shutdown_during_generation_retry_is_terminal() {
    let started = Instant::now();
    let mut calls = 0;
    let result = template_loop(
        |_| {
            calls += 1;
            match calls {
                1 => Err(MiningControlError::Unavailable(
                    "generation key changed during candidate assembly".into(),
                )),
                // The owner observes its shutdown latch on the next acquisition.
                2 => Err(MiningControlError::Unavailable(
                    "node is shutting down".into(),
                )),
                _ => panic!("shutdown must not be retried"),
            }
        },
        Hub::new(),
    );
    assert_eq!(calls, 2);
    assert_eq!(result, Err("node is shutting down".into()));
    assert!(started.elapsed() >= TEMPLATE_RETRY_DELAY);
}
