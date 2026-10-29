use super::*;
use bitcoin_rs_chain::NodeStatus;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Branched {
    tree: BlockTree,
    best: NodeId,
    applied: headers::HeaderCheckpointPoint,
    invalid: Vec<Hash256>,
}

fn fork_header(tree: &mut BlockTree, parent: NodeId, height: u32, salt: u32) -> TestResult<NodeId> {
    let prev = BlockHash(tree.node(parent)?.hash);
    let mut header = mined_regtest_header(prev, height)?;
    header.time = header.time.saturating_add(100 + salt);
    mine_header_to_declared_target(&mut header)?;
    let accepted = accept_headers(
        tree,
        core::slice::from_ref(&header),
        NETWORK,
        bitcoin_rs_chain::current_unix_seconds(),
        bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
    )?;
    Ok(accepted.ids[0])
}

fn active_header(tree: &mut BlockTree, parent: NodeId, height: u32) -> TestResult<NodeId> {
    let header = mined_regtest_header(BlockHash(tree.node(parent)?.hash), height)?;
    let accepted = accept_headers(
        tree,
        core::slice::from_ref(&header),
        NETWORK,
        bitcoin_rs_chain::current_unix_seconds(),
        bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
    )?;
    Ok(accepted.ids[0])
}

fn branched() -> TestResult<Branched> {
    let (mut tree, main4, _) = chain_with_applied_height(4, 4)?;
    let at = |tree: &BlockTree, height| {
        tree.node_at_height_from(main4, height)
            .ok_or("active height missing")
    };
    let main2 = at(&tree, 2)?;
    let main3 = at(&tree, 3)?;
    let a4 = fork_header(&mut tree, main3, 4, 0)?;
    fork_header(&mut tree, a4, 5, 0)?;
    let main5 = active_header(&mut tree, main4, 5)?;
    fork_header(&mut tree, main4, 5, 1)?;
    let c3 = fork_header(&mut tree, main2, 3, 2)?;
    fork_header(&mut tree, c3, 4, 2)?;
    let invalid = tree.invalidate_subtree(c3)?;
    let best = active_header(&mut tree, main5, 6)?;
    fork_header(&mut tree, main5, 6, 3)?;
    assert_eq!(
        tree.tip_id(),
        Some(best),
        "equal work never displaces the best tip"
    );
    assert_eq!(invalid.invalid.len(), 2);
    let best_node = tree.node(best)?;
    let applied = headers::HeaderCheckpointPoint {
        height: best_node.height,
        hash: best_node.hash,
    };
    Ok(Branched {
        tree,
        best,
        applied,
        invalid: invalid.invalid,
    })
}

fn side_leaf_hashes(tree: &BlockTree, best: Hash256) -> TestResult<Vec<Hash256>> {
    let mut leaves = Vec::new();
    for id in tree.leaf_node_ids() {
        let node = tree.node(id)?;
        if node.status != NodeStatus::Invalid && node.hash != best {
            leaves.push(node.hash);
        }
    }
    Ok(leaves)
}

fn publish(
    dir: &Path,
    tree: BlockTree,
    utxo: &UtxoSet,
    stats: CoinStats,
    applied: &TipSnapshot,
) -> TestResult {
    let published = super::super::write_checkpoint(
        dir,
        config(),
        &RwLock::new(tree),
        utxo,
        &CoinStatsListener::new(stats),
        Some(applied),
    )?;
    assert!(matches!(published, CheckpointWrite::Published { .. }));
    Ok(())
}

fn restore(dir: &Path) -> TestResult<super::super::RestoredChainstate> {
    match load_checkpoint(dir, config())? {
        CheckpointLoad::Complete(restored) => Ok(*restored),
        CheckpointLoad::Cold => Err("checkpoint did not restore".into()),
    }
}

fn applied_stats(height: u32) -> CoinStats {
    let mut stats = CoinStats::new();
    stats.height = height;
    stats
}

#[test]
fn valid_side_branches_survive_restart_in_learn_order() -> TestResult {
    let dir = tempfile::tempdir()?;
    let fixture = branched()?;
    let original = &fixture.tree;
    let best_hash = original.node(fixture.best)?.hash;
    let expected_leaves = side_leaf_hashes(original, best_hash)?;
    assert_eq!(
        expected_leaves.len(),
        3,
        "a5, b5, and d6 are the valid side leaves"
    );
    let mut expected_all = Vec::new();
    for id in original.leaf_node_ids() {
        let node = original.node(id)?;
        if node.status != NodeStatus::Invalid {
            expected_all.push(node.hash);
        }
    }
    let mut expected_nodes = Vec::new();
    for id in original.leaf_node_ids() {
        for ancestor in original.ancestor_chain(id)? {
            let node = original.node(ancestor)?;
            let parent = node
                .parent
                .map(|parent| original.node(parent).map(|parent| parent.hash))
                .transpose()?;
            expected_nodes.push((node.hash, node.height, node.chainwork, parent));
        }
    }
    let applied_tip = tip_snapshot(original, fixture.applied)?;
    let original_len = original.len();
    publish(
        dir.path(),
        fixture.tree,
        &UtxoSet::new(),
        applied_stats(fixture.applied.height),
        &applied_tip,
    )?;

    let super::super::RestoredChainstate {
        tree,
        utxo,
        coin_stats,
        applied_tip,
        ..
    } = restore(dir.path())?;
    publish(dir.path(), tree, &utxo, coin_stats, &applied_tip)?;
    let restored = restore(dir.path())?;
    let tree = &restored.tree;

    assert_eq!(tree.tip().map(|tip| tip.hash), Some(best_hash));
    assert_eq!(restored.applied_tip.hash, fixture.applied.hash);
    assert_eq!(tree.len(), original_len - fixture.invalid.len());
    for hash in &fixture.invalid {
        assert!(
            tree.lookup(*hash).is_none(),
            "invalid subtrees stay excluded"
        );
    }
    for (hash, height, chainwork, parent) in expected_nodes {
        if fixture.invalid.contains(&hash) {
            continue;
        }
        let node = tree.node_by_hash(hash).ok_or("retained node missing")?;
        let restored_parent = node
            .parent
            .map(|parent| tree.node(parent).map(|parent| parent.hash))
            .transpose()?;
        assert_eq!((node.height, node.chainwork), (height, chainwork));
        assert_eq!(restored_parent, parent);
        assert_ne!(node.status, NodeStatus::Invalid);
    }
    assert_eq!(
        side_leaf_hashes(tree, best_hash)?,
        expected_leaves,
        "side leaves keep their relative learn order across active-first restore"
    );
    let mut restored_all = Vec::new();
    for id in tree.leaf_node_ids() {
        restored_all.push(tree.node(id)?.hash);
    }
    assert_ne!(
        restored_all, expected_all,
        "active-first restore moves the best tip earlier while side-leaf order holds"
    );
    assert_ne!(
        tree.tip_id(),
        Some(fixture.best),
        "the fixture interleaves learning, so active-first restore moves slab positions"
    );
    Ok(())
}

#[test]
fn active_only_artifact_still_loads_without_side_branches() -> TestResult {
    let dir = tempfile::tempdir()?;
    let fixture = branched()?;
    let tree = &fixture.tree;
    let best_hash = tree.node(fixture.best)?.hash;
    let mut ancestry = tree.ancestor_chain(fixture.best)?;
    ancestry.reverse();
    let mut active_only = Vec::new();
    active_only.extend_from_slice(b"BRSHEAD\0");
    active_only.extend_from_slice(&headers::ACTIVE_ONLY_HEADER_VERSION.to_le_bytes());
    active_only.extend_from_slice(&NETWORK.magic());
    active_only.extend_from_slice(&NETWORK.genesis_block_hash().to_le_bytes());
    active_only.extend_from_slice(&u64::try_from(ancestry.len())?.to_le_bytes());
    for id in &ancestry {
        active_only.extend_from_slice(&headers::encode_header(&tree.node(*id)?.header)?);
    }
    let applied_tip = tip_snapshot(tree, fixture.applied)?;
    publish(
        dir.path(),
        fixture.tree,
        &UtxoSet::new(),
        applied_stats(fixture.applied.height),
        &applied_tip,
    )?;
    mutate_authenticated_artifact(dir.path(), HEADERS_FILE, |bytes| {
        *bytes = active_only;
    })?;
    mutate_authenticated_manifest(dir.path(), |manifest| {
        manifest.headers.version = headers::ACTIVE_ONLY_HEADER_VERSION;
    })?;

    let restored = restore(dir.path())?;
    assert_eq!(restored.tree.len(), ancestry.len());
    assert_eq!(restored.tree.tip().map(|tip| tip.hash), Some(best_hash));
    assert_eq!(restored.applied_tip.hash, fixture.applied.hash);
    Ok(())
}

#[test]
fn reader_rejects_malformed_side_sections() -> TestResult {
    let fixture = branched()?;
    let (bytes, written) = write_checkpoint(&fixture.tree, fixture.best, fixture.applied)?;
    let metadata = written.metadata;
    let active_end = headers::HEADER_PREFIX_LEN + 80 * 7;
    let side_start = active_end + 8;
    let side_count = u64::from_le_bytes(bytes[active_end..side_start].try_into()?);
    assert_eq!(side_count, 4, "a4, a5, b5, and d6 are retained");
    let read = |bytes: Vec<u8>, metadata| {
        headers::read_headers(&mut Cursor::new(bytes), config(), metadata)
    };

    let truncated = bytes[..bytes.len() - 1].to_vec();
    assert!(matches!(
        read(truncated, metadata),
        Err(headers::HeaderCheckpointError::InvalidFileLength { .. })
    ));
    let mut inflated = bytes.clone();
    inflated[active_end..side_start].copy_from_slice(&(side_count + 1).to_le_bytes());
    assert!(matches!(
        read(inflated, metadata),
        Err(headers::HeaderCheckpointError::InvalidFileLength { .. })
    ));
    assert!(matches!(
        read(bytes[..active_end].to_vec(), metadata),
        Err(headers::HeaderCheckpointError::InvalidFileLength { .. })
    ));

    let first_active = headers::HEADER_PREFIX_LEN + 80;
    let mut duplicate = bytes.clone();
    duplicate.copy_within(first_active..first_active + 80, side_start);
    assert!(matches!(
        read(duplicate, metadata),
        Err(headers::HeaderCheckpointError::MalformedSideBranch { index: 0 })
    ));
    let mut orphan = bytes.clone();
    orphan[side_start + 4] ^= 1;
    assert!(matches!(
        read(orphan, metadata),
        Err(headers::HeaderCheckpointError::Chain(_))
    ));

    let best_hash = BlockHash(fixture.tree.node(fixture.best)?.hash);
    let heavier = mined_regtest_header(best_hash, 7)?;
    let mut displacing = bytes.clone();
    displacing[active_end..side_start].copy_from_slice(&(side_count + 1).to_le_bytes());
    displacing.extend_from_slice(&headers::encode_header(&heavier)?);
    assert!(matches!(
        read(displacing, metadata),
        Err(headers::HeaderCheckpointError::SideBranchDisplacedBestTip)
    ));

    let active_only_metadata = headers::HeaderCheckpointMetadata {
        version: headers::ACTIVE_ONLY_HEADER_VERSION,
        ..metadata
    };
    assert!(matches!(
        read(bytes[..active_end].to_vec(), active_only_metadata),
        Err(headers::HeaderCheckpointError::VersionMismatch {
            manifest: 1,
            artifact: 2,
        })
    ));
    Ok(())
}
