use super::*;

#[expect(
    clippy::expect_used,
    reason = "all generated graph indices are bounded by four"
)]
fn graph(parents: &[Vec<usize>], fees: u32, nonfinal: u32, chain_state: u8) -> (Snapshot, Coins) {
    let mut rows: Vec<SavedTransaction> = Vec::new();
    let mut coins = Coins {
        outputs: Vec::new(),
        height: 100,
        coinbase: false,
    };
    for (index, inputs) in parents.iter().enumerate() {
        let mut funding = Vec::new();
        if inputs.is_empty() {
            let point = OutPoint::new(
                Txid(Hash256::from_le_bytes(
                    &[u8::try_from(index + 40).expect("small graph"); 32],
                )),
                0,
            );
            coins.outputs.push((point, output(100_000)));
            funding.push((point, 100_000));
        } else {
            for &parent in inputs {
                let slot = parents[..index]
                    .iter()
                    .filter(|edges| edges.contains(&parent))
                    .count();
                funding.push((
                    OutPoint::new(rows[parent].txid, u32::try_from(slot).expect("small graph")),
                    rows[parent].tx.outputs[slot].value.to_sat(),
                ));
            }
        }
        let available = funding.iter().map(|(_, value)| value).sum::<u64>()
            - if fees & (1 << index) == 0 { 0 } else { 2_000 };
        let outputs = parents
            .iter()
            .filter(|edges| edges.contains(&index))
            .count()
            + 1;
        let outputs = u64::try_from(outputs).expect("small graph");
        let mut tx = spend(funding[0].0, available);
        tx.inputs = funding
            .iter()
            .map(|(point, _)| {
                let mut input = tx.inputs[0].clone();
                input.previous_output = *point;
                input
            })
            .collect();
        tx.outputs = (0..outputs)
            .map(|slot| {
                output(available / outputs + if slot == 0 { available % outputs } else { 0 })
            })
            .collect();
        if nonfinal & (1 << index) != 0 {
            tx.lock_time = LockTime::from_consensus(150);
            tx.inputs[0].sequence = Sequence::ZERO;
        }
        rows.push(SavedTransaction {
            txid: tx.txid(),
            tx: Arc::new(tx),
            time: NOW - u64::try_from(index).expect("small graph"),
            unbroadcast: index % 2 == 0,
            sigop_cost: 0,
        });
    }
    if (1..=3).contains(&chain_state) {
        let root = &rows[0];
        coins
            .outputs
            .retain(|(point, _)| *point != root.tx.inputs[0].previous_output);
        if chain_state == 1 || chain_state == 3 {
            coins
                .outputs
                .extend(root.tx.outputs.iter().enumerate().map(|(slot, out)| {
                    (
                        OutPoint::new(root.txid, u32::try_from(slot).expect("small graph")),
                        out.clone(),
                    )
                }));
        }
    }
    if chain_state == 3 || chain_state == 4 {
        rows[0].time = NOW - MAX_AGE - 1;
    }
    (
        Snapshot {
            transactions: rows,
            deltas: Vec::new(),
        },
        coins,
    )
}

fn membership(gateway: &MempoolGateway, ids: &[Txid]) -> u32 {
    let pool = gateway.read();
    ids.iter().enumerate().fold(0, |mask, (index, id)| {
        mask | if pool.contains_txid(id) {
            1 << index
        } else {
            0
        }
    })
}

#[test]
fn generated_small_graphs_match_direct_gateway_maximal_subsets() -> TestResult {
    let shapes = [
        vec![vec![], vec![0]],
        vec![vec![], vec![0], vec![1]],
        vec![vec![], vec![0], vec![0]],
        vec![vec![], vec![], vec![0, 1]],
        vec![vec![], vec![0], vec![0], vec![1, 2]],
    ];
    let mut comparisons = 0;
    for (shape, parents) in shapes.iter().enumerate() {
        for fees in 0..1_u32 << parents.len() {
            for nonfinal in 0..1_u32 << parents.len() {
                for state in 0..5 {
                    let (mut snapshot, chain) = graph(parents, fees, nonfinal, state);
                    let ids: Vec<_> = snapshot.transactions.iter().map(|row| row.txid).collect();
                    for capacity in [0, snapshot.transactions[0].tx.vsize()] {
                        let mut best = vec![0_u32];
                        for mask in 1..1_u32 << parents.len() {
                            let control = gateway(
                                MempoolLimits {
                                    max_total_bytes: capacity,
                                    ..Default::default()
                                },
                                None,
                            );
                            let package: Vec<_> = snapshot
                                .transactions
                                .iter()
                                .enumerate()
                                .filter(|(index, _)| mask & (1 << index) != 0)
                                .filter(|(index, _)| !((state == 3 || state == 4) && *index == 0))
                                .map(|(_, row)| row.tx.as_ref().clone())
                                .collect();
                            if control
                                .submit_package_with_times(
                                    &package,
                                    LocalOrigin::Rpc,
                                    None,
                                    |_| NOW,
                                    &chain,
                                )
                                .is_ok()
                            {
                                let admitted = membership(&control, &ids);
                                match admitted.count_ones().cmp(&best[0].count_ones()) {
                                    std::cmp::Ordering::Greater => best = vec![admitted],
                                    std::cmp::Ordering::Equal => best.push(admitted),
                                    std::cmp::Ordering::Less => {}
                                }
                            }
                        }
                        for reversed in [false, true] {
                            if reversed {
                                snapshot.transactions.reverse();
                            }
                            let target = gateway(
                                MempoolLimits {
                                    max_total_bytes: capacity,
                                    ..Default::default()
                                },
                                None,
                            );
                            let report =
                                restore_candidates(&snapshot, &target, &chain, NOW, deadline())?;
                            assert!(!report.timed_out);
                            assert_eq!(report.limited, 0);
                            let actual = membership(&target, &ids);
                            assert!(
                                best.contains(&actual),
                                "shape={shape} fees={fees:b} nonfinal={nonfinal:b} state={state} capacity={capacity} reversed={reversed}: actual={actual:b} best={best:?}"
                            );
                            comparisons += 1;
                            if reversed {
                                snapshot.transactions.reverse();
                            }
                        }
                    }
                }
            }
        }
    }
    eprintln!("compared {comparisons} generated restore outcomes with direct gateway subsets");
    Ok(())
}

#[test]
fn search_limits_do_not_commit_a_parent_before_subset_search_finishes() -> TestResult {
    for (count, nonfinal_children) in [(8, true), (9, true), (25, false), (26, false)] {
        let funding = OutPoint::new(Txid(Hash256::from_le_bytes(&[32; 32])), 0);
        let chain = Coins {
            outputs: vec![(funding, output(100_000))],
            height: 100,
            coinbase: false,
        };
        let mut point = funding;
        let mut rows = Vec::new();
        for index in 0..count {
            let mut tx = spend(point, 95_000);
            if index != 0 && nonfinal_children {
                tx.lock_time = LockTime::from_consensus(150);
                tx.inputs[0].sequence = Sequence::ZERO;
            }
            point = OutPoint::new(tx.txid(), 0);
            rows.push(SavedTransaction {
                txid: tx.txid(),
                tx: Arc::new(tx),
                time: NOW,
                unbroadcast: true,
                sigop_cost: 0,
            });
        }
        let control = gateway(MempoolLimits::default(), None);
        admit(&control, &rows[0].tx, &chain)?;
        assert_eq!(control.read().len(), 1, "the parent can enter alone");
        let snapshot = Snapshot {
            transactions: rows,
            deltas: Vec::new(),
        };
        let seen = Arc::new(Seen::default());
        let target = gateway(MempoolLimits::default(), Some(Arc::clone(&seen)));
        let report = restore_candidates(&snapshot, &target, &chain, NOW, deadline())?;
        assert!(!report.timed_out);
        if count == 8 {
            assert_eq!((report.restored, report.limited), (1, 0));
            assert!(report.package_attempts <= 255);
            assert_eq!(seen.0.lock().len(), 1);
        } else if count == 25 {
            assert_eq!(
                (report.restored, report.limited, report.package_attempts),
                (25, 0, 1)
            );
            assert_eq!(seen.0.lock().len(), 1);
        } else {
            assert_eq!((report.restored, report.limited), (0, count));
            assert!(
                seen.0.lock().is_empty(),
                "failed searches publish no commits"
            );
            assert_eq!(target.read().sequence_number(), 0);
            assert_eq!(
                report.package_attempts,
                if count == 9 {
                    u64::try_from(MAX_SUBSET_ATTEMPTS)?
                } else {
                    0
                }
            );
        }
    }
    Ok(())
}

#[test]
fn deadline_exhaustion_leaves_the_current_family_uncommitted() -> TestResult {
    let rows = saved_ancestor_chain(3);
    let members: Vec<_> = rows.iter().collect();
    let target = gateway(MempoolLimits::default(), None);
    let (prefix_chain, prefix, _) = family();
    admit(&target, &prefix, &prefix_chain)?;
    let sequence = target.read().sequence_number();
    let chain = AncestorReads {
        calls: std::sync::atomic::AtomicUsize::new(0),
        expire_at: None,
    };
    let mut attempts = 0;
    let error = restore_family(&members, &target, &chain, Instant::now(), &mut attempts)
        .err()
        .ok_or("expired deadline must stop subset search")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(attempts, 0);
    assert_eq!(chain.calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(target.read().len(), 1);
    assert!(target.read().contains_txid(&prefix.txid()));
    assert_eq!(target.read().sequence_number(), sequence);
    Ok(())
}

#[test]
fn eight_member_rejection_exhausts_exactly_all_nonempty_subsets() -> TestResult {
    let snapshot = Snapshot {
        transactions: saved_ancestor_chain(8),
        deltas: Vec::new(),
    };
    let target = gateway(MempoolLimits::default(), None);
    let chain = Coins {
        outputs: Vec::new(),
        height: 100,
        coinbase: false,
    };
    let report = restore_candidates(&snapshot, &target, &chain, NOW, deadline())?;
    assert_eq!(
        (report.restored, report.limited, report.package_attempts),
        (0, 0, 255)
    );
    assert!(!report.timed_out);
    assert_eq!(target.read().sequence_number(), 0);
    Ok(())
}

#[test]
fn subset_selection_respects_an_already_committed_pool_prefix() -> TestResult {
    let (snapshot, mut chain) = graph(&[vec![], vec![0]], 1, 0, 0);
    let funding = OutPoint::new(Txid(Hash256::from_le_bytes(&[61; 32])), 0);
    chain.outputs.push((funding, output(100_000)));
    let prefix = spend(funding, 99_000);
    let ids: Vec<_> = snapshot.transactions.iter().map(|row| row.txid).collect();
    let family: Vec<_> = snapshot.transactions.iter().collect();
    let parent_size = family[0].tx.vsize();
    let child_size = family[1].tx.vsize();
    for budget in [parent_size, parent_size + child_size] {
        let capacity = prefix.vsize() + budget;
        let mut best = vec![0_u32];
        for mask in 1..4 {
            let control = gateway(
                MempoolLimits {
                    max_total_bytes: capacity,
                    ..Default::default()
                },
                None,
            );
            admit(&control, &prefix, &chain)?;
            let package: Vec<_> = family
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, row)| row.tx.as_ref().clone())
                .collect();
            if control
                .submit_package_with_times(&package, LocalOrigin::Rpc, None, |_| NOW, &chain)
                .is_ok()
            {
                let admitted = membership(&control, &ids);
                match admitted.count_ones().cmp(&best[0].count_ones()) {
                    std::cmp::Ordering::Greater => best = vec![admitted],
                    std::cmp::Ordering::Equal => best.push(admitted),
                    std::cmp::Ordering::Less => {}
                }
            }
        }
        let target = gateway(
            MempoolLimits {
                max_total_bytes: capacity,
                ..Default::default()
            },
            None,
        );
        admit(&target, &prefix, &chain)?;
        let mut attempts = 0;
        assert!(matches!(
            restore_family(&family, &target, &chain, deadline(), &mut attempts)?,
            FamilyRestore::Accepted(_)
        ));
        assert!(best.contains(&membership(&target, &ids)));
        assert!(
            target.read().contains_txid(&prefix.txid()),
            "restore must not evict its prefix"
        );
    }
    Ok(())
}
