use super::*;

fn values(rows: &[(i128, u32)]) -> Vec<FeeWeight> {
    rows.iter()
        .map(|&(fee, weight)| FeeWeight { fee, weight })
        .collect()
}

#[test]
fn core_311_diagram_vectors() -> Result<(), FeeDiagramError> {
    // Independent vectors: bitcoin/bitcoin 9be056a8a72b624dae9623b2f7bded92c2a21c91,
    // src/test/rbf_tests.cpp::feerate_chunks_utilities.
    let old = values(&[(950, 300), (100, 100)]);
    for (new, expected) in [
        (values(&[(1000, 300), (50, 100)]), Some(Ordering::Greater)),
        (values(&[(1000, 300), (0, 100)]), None),
        (values(&[(1100, 300)]), Some(Ordering::Greater)),
        (values(&[(1100, 100), (0, 100)]), Some(Ordering::Greater)),
        (values(&[(750, 100), (249, 250), (151, 650)]), None),
        (
            values(&[(750, 100), (250, 250), (150, 150)]),
            Some(Ordering::Greater),
        ),
        (old.clone(), Some(Ordering::Equal)),
    ] {
        assert_eq!(compare(&new, &old)?, expected, "{new:?}");
        assert_eq!(compare(&old, &new)?, expected.map(Ordering::reverse));
    }
    let smaller = values(&[(950, 300), (100, 99)]);
    assert_eq!(compare(&smaller, &old)?, Some(Ordering::Greater));
    assert_eq!(
        compare(&smaller, &values(&[(950, 300), (100, 100), (0, 1), (0, 1)]))?,
        Some(Ordering::Greater)
    );
    assert_eq!(
        compare(
            &smaller,
            &values(&[(950, 300), (100, 100), (0, 1), (0, 1), (1, 1)])
        )?,
        None
    );
    Ok(())
}

#[test]
fn exact_weights_negative_fees_and_horizontal_tails() -> Result<(), FeeDiagramError> {
    // Both sizes round to 101 vbytes; the weight-based curves are different.
    assert_eq!(
        compare(&values(&[(1000, 401)]), &values(&[(1000, 404)]))?,
        Some(Ordering::Greater)
    );
    assert_eq!(compare(&[], &values(&[(-1, 10)]))?, Some(Ordering::Greater));
    assert_eq!(compare(&values(&[(0, 10)]), &[])?, Some(Ordering::Equal));
    assert_eq!(
        compare(&values(&[(100, 10)]), &values(&[(200, 100)]))?,
        None
    );
    Ok(())
}

#[test]
fn shared_parent_requires_a_joint_chunk() -> Result<(), FeeDiagramError> {
    let fees = values(&[(0, 100), (90, 100), (90, 100)]);
    let chunks = linearize(&fees, &[vec![], vec![0], vec![0]])?;
    assert_eq!(
        chunks,
        vec![Chunk {
            members: vec![0, 1, 2],
            total: FeeWeight {
                fee: 180,
                weight: 300
            }
        }]
    );
    // Each child's ancestor package is only 90/200. Considering those
    // packages alone misses the valid 180/300 joint package.
    Ok(())
}

#[test]
fn equal_rates_have_minimal_topological_chunks() -> Result<(), FeeDiagramError> {
    let fees = values(&[(100, 100), (100, 100), (100, 100)]);
    let chunks = linearize(&fees, &[vec![], vec![0], vec![0]])?;
    assert_eq!(
        chunks
            .iter()
            .map(|chunk| chunk.members.clone())
            .collect::<Vec<_>>(),
        vec![vec![0], vec![1], vec![2]]
    );
    Ok(())
}

#[test]
fn negative_parent_and_independent_competitor() -> Result<(), FeeDiagramError> {
    let fees = values(&[(-100, 100), (300, 100), (110, 100)]);
    let chunks = linearize(&fees, &[vec![], vec![0], vec![]])?;
    assert_eq!(
        chunks
            .iter()
            .map(|chunk| chunk.members.clone())
            .collect::<Vec<_>>(),
        vec![vec![2], vec![0, 1]]
    );
    assert_eq!(
        chunks[1].total,
        FeeWeight {
            fee: 200,
            weight: 200
        }
    );
    Ok(())
}

#[test]
fn signed_priority_extremes_preserve_one_satoshi_and_parent_cancellation()
-> Result<(), FeeDiagramError> {
    let maximum = i128::from(i64::MAX);
    let before = values(&[(maximum + 1_000, 400)]);
    let after = values(&[(maximum + 1_001, 400)]);
    assert_eq!(compare(&after, &before)?, Some(Ordering::Greater));
    let fees = values(&[(i128::from(i64::MIN) + 1_000, 400), (maximum + 2_000, 400)]);
    let chunks = linearize(&fees, &[vec![], vec![0]])?;
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].members, vec![0, 1]);
    assert_eq!(chunks[0].total.fee, 2_999);
    Ok(())
}

#[test]
fn invalid_graphs_and_arithmetic_fail_explicitly() {
    assert_eq!(
        linearize(&values(&[(1, 0)]), &[vec![]]),
        Err(FeeDiagramError::Weight)
    );
    assert_eq!(
        linearize(&values(&[(1, 1)]), &[vec![1]]),
        Err(FeeDiagramError::Dependencies)
    );
    assert_eq!(
        linearize(&values(&[(1, 1), (1, 1)]), &[vec![1], vec![0]]),
        Err(FeeDiagramError::Dependencies)
    );
    assert_eq!(
        linearize(&values(&[(i128::MAX, 1), (1, 1)]), &[vec![], vec![]]),
        Err(FeeDiagramError::Arithmetic)
    );
    assert_eq!(
        compare(&values(&[(1, 0)]), &[]),
        Err(FeeDiagramError::Weight)
    );
    assert_eq!(
        compare(&values(&[(i128::MAX, 1), (1, 1)]), &[]),
        Err(FeeDiagramError::Arithmetic)
    );
}

#[test]
fn maximum_default_cluster_shared_parent() -> Result<(), FeeDiagramError> {
    let mut fees = vec![
        FeeWeight {
            fee: 100,
            weight: 100
        };
        64
    ];
    fees[0].fee = 0;
    let mut parents = vec![vec![0]; 64];
    parents[0].clear();
    let chunks = linearize(&fees, &parents)?;
    // k children with their zero-fee parent have rate k/(k+1), which
    // increases strictly through k=63: the only optimal chunk is the whole set.
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].members, (0..64).collect::<Vec<_>>());
    assert_eq!(
        chunks[0].total,
        FeeWeight {
            fee: 6300,
            weight: 6400
        }
    );
    Ok(())
}

fn next(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    *seed >> 32
}

#[test]
fn chunks_match_exhaustive_closed_subsets() -> Result<(), FeeDiagramError> {
    let mut seed = 639_u64;
    for nodes in 1..=8 {
        for _ in 0..80 {
            let fees: Vec<_> = (0..nodes)
                .map(|_| FeeWeight {
                    fee: i128::from(next(&mut seed) % 301) - 100,
                    weight: u32::try_from(next(&mut seed) % 31 + 1).unwrap_or(1),
                })
                .collect();
            let parents: Vec<Vec<usize>> = (0..nodes)
                .map(|child| {
                    (0..child)
                        .filter(|_| next(&mut seed).is_multiple_of(3))
                        .collect()
                })
                .collect();
            let chunks = linearize(&fees, &parents)?;
            let mut done = 0_usize;
            for chunk in chunks {
                let mut selected = 0_usize;
                for &member in &chunk.members {
                    assert_eq!((done | selected) & (1 << member), 0);
                    assert!(
                        parents[member]
                            .iter()
                            .all(|&parent| (done | selected) & (1 << parent) != 0)
                    );
                    selected |= 1 << member;
                }
                assert_eq!(sum_members(&fees, &chunk.members)?, chunk.total);
                // Independent exponential reference: enumerate every remaining
                // ancestor-closed subset and compare exact integer ratios.
                for subset in 1..(1 << nodes) {
                    if subset & done != 0 {
                        continue;
                    }
                    let members: Vec<_> = (0..nodes).filter(|&i| subset & (1 << i) != 0).collect();
                    if members
                        .iter()
                        .any(|&i| parents[i].iter().any(|&p| (subset | done) & (1 << p) == 0))
                    {
                        continue;
                    }
                    let fee: i128 = members.iter().map(|&i| fees[i].fee).sum();
                    let weight: i128 = members.iter().map(|&i| i128::from(fees[i].weight)).sum();
                    assert!(
                        fee * i128::from(chunk.total.weight) <= chunk.total.fee * weight,
                        "nonoptimal chunk {chunk:?}; subset {subset:b}; fees {fees:?}; parents {parents:?}"
                    );
                }
                done |= selected;
            }
            assert_eq!(done, (1 << nodes) - 1);
        }
    }
    Ok(())
}
