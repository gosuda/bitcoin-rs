use std::sync::atomic::Ordering;
use std::thread;

use anyhow::Result;
use bitcoin_rs_chain::regtest_fixture;
use bitcoin_rs_chain::{NodeStatus, compact_is_met_by};
use bitcoin_rs_mining::{
    BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult, BlockValidationResult,
    MiningControl, MiningControlError,
};
use bitcoin_rs_node::Network;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, BlockPayload, CompactTarget, Hash256, Header, LockTime, OutPoint,
    Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};

use super::support::{
    WITNESS_COMMITMENT_PREFIX, WITNESS_RESERVED, coordinator, disconnect_applied,
    excess_coinbase_child, is_witness_commitment, mined_child, mined_child_labeled,
    mined_regtest_header, open_at_genesis, open_network, propose_block, regtest_mining,
    solved_template_block,
};

#[test]
fn proposal_has_no_side_effects() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let before = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing before proposal"));
    let before_seq = state.mempool().read().sequence_number();
    let before_blocks = state.block_log_reader().read().len();

    let genesis = Network::Regtest.genesis_block();
    let child = mined_child(genesis.block_hash())?;
    let result = mining.get_block_template(BlockTemplateRequest {
        mode: BlockTemplateMode::Proposal(child),
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id: None,
        coinbase_budget: None,
    })?;
    match result {
        BlockTemplateResult::Proposal(BlockValidationResult::Accepted) => {}
        other => panic!("valid proposal must be accepted, got {other:?}"),
    }

    let after = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing after proposal"));
    assert_eq!(before.hash, after.hash);
    assert_eq!(before_seq, state.mempool().read().sequence_number());
    assert_eq!(before_blocks, state.block_log_reader().read().len());
    Ok(())
}

#[test]
fn proposal_rejects_excess_coinbase_without_side_effects() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let before = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing before proposal"));
    let before_seq = state.mempool().read().sequence_number();
    let before_blocks = state.block_log_reader().read().len();

    let genesis = Network::Regtest.genesis_block();
    let child = excess_coinbase_child(genesis.block_hash())?;
    let result = mining.get_block_template(BlockTemplateRequest {
        mode: BlockTemplateMode::Proposal(child),
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id: None,
        coinbase_budget: None,
    })?;
    match result {
        BlockTemplateResult::Proposal(BlockValidationResult::Rejected(reason)) => {
            assert_eq!(reason.as_str(), "bad-cb-amount");
        }
        other => panic!("expected bad-cb-amount proposal rejection, got {other:?}"),
    }

    let after = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing after proposal"));
    assert_eq!(before.hash, after.hash);
    assert_eq!(before_seq, state.mempool().read().sequence_number());
    assert_eq!(before_blocks, state.block_log_reader().read().len());
    Ok(())
}

// CONTRACT: API-19
#[test]
fn proposal_without_coinbase_is_bad_cb_missing() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let mut block = mined_child(genesis.block_hash())?;
    let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) else {
        panic!("child missing coinbase input");
    };
    input.previous_output = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x11; 32])), 0);
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("test block has no merkle root"))?;
    match propose_block(&mining, block)? {
        BlockValidationResult::Rejected(reason) => {
            assert_eq!(reason.as_str(), "bad-cb-missing");
        }
        other => panic!("expected bad-cb-missing, got {other:?}"),
    }
    Ok(())
}

// CONTRACT: API-19
#[test]
fn proposal_merkle_mismatch_is_bad_txnmrklroot() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let mut block = mined_child(genesis.block_hash())?;
    block.header.merkle_root = Hash256::from_le_bytes(&[0x11; 32]);
    match propose_block(&mining, block)? {
        BlockValidationResult::Rejected(reason) => {
            assert_eq!(reason.as_str(), "bad-txnmrklroot");
        }
        other => panic!("expected bad-txnmrklroot, got {other:?}"),
    }
    Ok(())
}

/// A height-1 child of the signet genesis whose commitment carries no signet
/// section: the witness commitment, BIP34 push, reserved nonce, and
/// signet-difficulty proof of work all hold, so only BIP325 can refuse it.
fn signet_child_without_signet_section() -> Result<Block> {
    // One transaction, so the commitment root is the zeroed coinbase wtxid
    // and the commitment is `H(root || reserved)` over 64 zero bytes.
    let commitment = bitcoin_rs_primitives::encode::double_sha256(&[0_u8; 64]).to_le_bytes();
    let mut commitment_script = WITNESS_COMMITMENT_PREFIX.to_vec();
    commitment_script.extend_from_slice(&commitment);
    let genesis = Network::Signet.genesis_block();
    let coinbase = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            // BIP34 height-1 push plus the extranonce byte.
            script_sig: Script::from_bytes(vec![0x51, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![WITNESS_RESERVED.to_vec()]),
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(50 * 100_000_000),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: Script::from_bytes(commitment_script),
            },
        ],
    };
    let mut block = Block {
        header: Header {
            version: 0x2000_0000,
            prev_blockhash: genesis.block_hash(),
            merkle_root: Hash256::default(),
            time: genesis.header.time + 600,
            bits: genesis.header.bits,
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    block.header.merkle_root = block.txs[0].txid().into();
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

// CONTRACT: API-19, BIP325
#[test]
fn signet_submit_reports_bad_signet_blksig_and_proposal_skips_the_solution() -> Result<()> {
    let fixture = open_at_genesis(Network::Signet)?;
    let mining = coordinator(&fixture);
    mining.publish_generation();
    let block = signet_child_without_signet_section()?;

    // A proposal skips the solution, as Core skips it without fCheckPOW.
    assert_eq!(
        propose_block(&mining, block.clone())?,
        BlockValidationResult::Accepted
    );

    // The commit path checks the solution and reports the BIP22 reason.
    match mining.submit_block(BlockPayload::from_local(block))? {
        BlockValidationResult::Rejected(reason) => {
            assert_eq!(reason.as_str(), "bad-signet-blksig");
        }
        other => panic!("expected bad-signet-blksig, got {other:?}"),
    }

    // A refused solution never moves the tip.
    let tip = fixture
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing"));
    assert_eq!(
        tip.hash,
        Hash256::from(Network::Signet.genesis_block().block_hash())
    );
    assert!(
        fixture.mempool_gateway().stable_generation().is_some(),
        "a clean block rejection must settle the chain generation"
    );
    Ok(())
}

// CONTRACT: API-21
#[test]
fn proposal_commitment_without_witness_nonce_is_bad_witness_nonce_size() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();
    let mut block = solved_template_block(&mining)?;
    {
        let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) else {
            panic!("solved candidate missing coinbase input");
        };
        assert!(
            !input.witness.is_empty(),
            "assembled candidate must carry the reserved nonce"
        );
        input.witness.clear();
    }
    assert!(
        block.txs.first().is_some_and(|tx| tx
            .outputs
            .iter()
            .any(|output| is_witness_commitment(&output.script_pubkey))),
        "assembled candidate must carry a BIP141 commitment"
    );
    match propose_block(&mining, block)? {
        BlockValidationResult::Rejected(reason) => {
            assert_eq!(reason.as_str(), "bad-witness-nonce-size");
        }
        other => panic!("expected bad-witness-nonce-size, got {other:?}"),
    }
    Ok(())
}

// CONTRACT: API-21
#[test]
fn proposal_witness_without_commitment_is_unexpected_witness() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();
    let mut block = solved_template_block(&mining)?;
    {
        let Some(coinbase) = block.txs.first_mut() else {
            panic!("solved candidate missing coinbase");
        };
        assert!(
            coinbase
                .inputs
                .first()
                .is_some_and(|input| !input.witness.is_empty()),
            "assembled candidate must carry the reserved nonce"
        );
        coinbase
            .outputs
            .retain(|output| !is_witness_commitment(&output.script_pubkey));
        assert!(
            !coinbase.outputs.is_empty(),
            "coinbase must keep a payout output after stripping the commitment"
        );
    }
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("test block has no merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    match propose_block(&mining, block)? {
        BlockValidationResult::Rejected(reason) => {
            assert_eq!(reason.as_str(), "unexpected-witness");
        }
        other => panic!("expected unexpected-witness, got {other:?}"),
    }
    Ok(())
}

// CONTRACT: API-21
#[test]
fn proposal_wrong_witness_commitment_is_bad_witness_merkle_match() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();
    let mut block = solved_template_block(&mining)?;
    {
        let Some(output) = block.txs.first_mut().and_then(|tx| {
            tx.outputs
                .iter_mut()
                .rev()
                .find(|output| is_witness_commitment(&output.script_pubkey))
        }) else {
            panic!("solved candidate missing BIP141 commitment");
        };
        output.script_pubkey[6] ^= 0xff;
    }
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("test block has no merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    match propose_block(&mining, block)? {
        BlockValidationResult::Rejected(reason) => {
            assert_eq!(reason.as_str(), "bad-witness-merkle-match");
        }
        other => panic!("expected bad-witness-merkle-match, got {other:?}"),
    }
    Ok(())
}

#[test]
fn accepted_submission_is_visible_before_return() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let child = mined_child(genesis.block_hash())?;
    let child_hash = child.block_hash();
    let result = mining.submit_block(BlockPayload::from_local(child))?;
    assert_eq!(result, BlockValidationResult::Accepted);
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing after submit"));
    assert_eq!(tip.hash, Hash256::from(child_hash));
    assert_eq!(tip.height, 1);
    Ok(())
}

#[test]
fn truncated_payload_bytes_fail_construction_before_submit() -> Result<()> {
    use bitcoin_rs_primitives::{BlockPayload, DecodeError, consensus_bytes};
    use bytes::Bytes;
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let block = mined_child(genesis.block_hash())?;
    let raw = consensus_bytes(&block);
    // Malformed images never reach submit: both constructors refuse truncated
    // and empty images with the decode failure before any submit path runs.
    // This constructor gate replaces the removed split-pair bytes-gate
    // `Rejected` branch; consensus-failure `Rejected` mapping on the submit
    // path itself is proved by the high-hash and bad-prevblk tests below.
    let truncated = Bytes::from(raw[..raw.len() - 1].to_vec());
    assert!(matches!(
        BlockPayload::from_raw(truncated.clone()),
        Err(DecodeError::EndOfData { .. })
    ));
    assert!(matches!(
        BlockPayload::from_prefix(truncated),
        Err(DecodeError::EndOfData { .. })
    ));
    assert!(matches!(
        BlockPayload::from_raw(Bytes::new()),
        Err(DecodeError::EndOfData { .. })
    ));
    // The exact image keeps its raw length and submits on its own merits.
    let payload = BlockPayload::from_raw(Bytes::from(raw.clone()))?;
    assert_eq!(payload.bytes().len(), raw.len());
    assert_eq!(payload.block(), &block);
    assert_eq!(
        mining.submit_block(payload)?,
        BlockValidationResult::Accepted
    );
    Ok(())
}

#[test]
fn foreign_valid_bytes_apply_as_their_own_block() -> Result<()> {
    use bitcoin_rs_primitives::{BlockPayload, consensus_bytes};
    use bytes::Bytes;
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let other = mined_child_labeled(genesis.block_hash(), 2)?;
    let other_hash = Hash256::from(other.block_hash());
    // Foreign-but-valid bytes decode to their own exact payload — a different
    // block — and apply on their own merits, never as a mismatch against a
    // separately supplied block.
    let foreign = BlockPayload::from_raw(Bytes::from(consensus_bytes(&other)))?;
    assert_eq!(foreign.block(), &other);
    assert_eq!(
        mining.submit_block(foreign)?,
        BlockValidationResult::Accepted
    );
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing after foreign submit"));
    assert_eq!(tip.hash, other_hash);
    assert_eq!(tip.height, 1);
    Ok(())
}

#[test]
fn submit_block_fills_omitted_coinbase_witness() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let mut block = solved_template_block(&mining)?;
    let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) else {
        panic!("solved candidate missing coinbase input");
    };
    assert!(
        !input.witness.is_empty(),
        "assembled candidate must carry the reserved nonce"
    );
    input.witness.clear();
    let has_commitment = block.txs[0]
        .outputs
        .iter()
        .any(|output| is_witness_commitment(&output.script_pubkey));
    assert!(
        has_commitment,
        "assembled candidate must carry a BIP141 commitment"
    );
    let block_hash = block.block_hash();
    assert_eq!(
        mining.submit_block(BlockPayload::from_local(block))?,
        BlockValidationResult::Accepted
    );
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing after submit"));
    assert_eq!(tip.hash, Hash256::from(block_hash));
    Ok(())
}

#[test]
fn submit_block_accepts_prefill_image_when_fill_applies() -> Result<()> {
    use bitcoin_rs_primitives::{BlockPayload, consensus_bytes};
    use bytes::Bytes;
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let mut block = solved_template_block(&mining)?;
    let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) else {
        panic!("solved candidate missing coinbase input");
    };
    assert!(
        !input.witness.is_empty(),
        "assembled candidate must carry the reserved nonce"
    );
    input.witness.clear();
    let has_commitment = block.txs[0]
        .outputs
        .iter()
        .any(|output| is_witness_commitment(&output.script_pubkey));
    assert!(
        has_commitment,
        "assembled candidate must carry a BIP141 commitment"
    );
    // Prefill image: the exact encoding of the stripped block. The coordinator
    // runs its own read-only predicate and fill on this image and accepts; the
    // test never fills, so only the coordinator's fill can complete the block.
    let image = Bytes::from(consensus_bytes(&block));
    let payload = BlockPayload::from_raw(image.clone())?;
    assert_eq!(payload.bytes(), &image);
    // The fill restores only the witness nonce, so the applied tip carries the
    // stripped block's own header hash.
    let block_hash = Hash256::from(block.block_hash());
    assert_eq!(
        mining.submit_block(payload)?,
        BlockValidationResult::Accepted
    );
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing after prefill submit"));
    assert_eq!(tip.hash, block_hash);
    Ok(())
}

#[test]
fn submit_header_admits_a_mined_child_and_is_idempotent() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    let genesis = Network::Regtest.genesis_block();
    let child = mined_child(genesis.block_hash())?;
    let child_hash = Hash256::from(child.block_hash());
    mining.submit_header(child.header)?;
    mining.submit_header(child.header)?;
    assert!(
        state
            .chainstate()
            .block_tree_reader()
            .read()
            .lookup(child_hash)
            .is_some(),
        "submitted header must be in the tree"
    );
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing"));
    assert_eq!(
        tip.hash,
        Hash256::from(genesis.block_hash()),
        "header submission must not apply the block"
    );
    Ok(())
}

#[test]
fn submit_header_accepts_genesis_before_and_after_bootstrap() -> Result<()> {
    let state = open_network(Network::Regtest)?;
    let mining = coordinator(&state);
    let genesis = Network::Regtest.genesis_block();
    mining.submit_header(genesis.header)?;
    assert_eq!(
        state.chainstate().header_tip().map(|tip| tip.hash),
        Some(genesis.block_hash().into())
    );
    assert!(state.chainstate().applied_tip_snapshot().is_none());

    let _ = state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
        Network::Regtest.genesis_block(),
    ))?;
    let before = state.chainstate().snapshot();

    mining.submit_header(genesis.header)?;
    mining.submit_header(genesis.header)?;

    let after = state.chainstate().snapshot();
    assert_eq!(after.chain_tx_count, before.chain_tx_count);
    assert_eq!(
        after.applied.map(|tip| tip.hash),
        Some(genesis.block_hash().into())
    );
    Ok(())
}

#[test]
fn submit_header_rejects_an_invalid_parent_without_inserting_child() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    let genesis = Network::Regtest.genesis_block();
    let invalid = mined_child(genesis.block_hash())?;
    let child = mined_child(invalid.block_hash())?;
    let tree = state.chainstate().block_tree_reader();
    {
        let mut tree = tree.write();
        let genesis_id = tree
            .lookup(genesis.block_hash().into())
            .ok_or_else(|| anyhow::anyhow!("missing genesis"))?;
        tree.insert_node(
            Some(genesis_id),
            invalid.header,
            bitcoin_rs_chain::NodeStatus::Invalid,
        )?;
    }

    match mining.submit_header(child.header) {
        Err(MiningControlError::Rejected(reason)) => assert_eq!(reason.as_str(), "bad-prevblk"),
        other => panic!("expected invalid-parent rejection, got {other:?}"),
    }
    assert!(tree.read().lookup(child.block_hash().into()).is_none());
    Ok(())
}

#[test]
fn submit_header_requires_the_previous_header() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let orphan = mined_child(BlockHash::from(Hash256::from_le_bytes(&[0x11; 32])))?;
    for bits in [orphan.header.bits, CompactTarget::from_consensus(0)] {
        let header = Header {
            bits,
            ..orphan.header
        };
        match mining.submit_header(header) {
            Err(MiningControlError::Rejected(reason)) => {
                assert_eq!(
                    reason,
                    format!(
                        "Must submit previous header ({}) first",
                        header.prev_blockhash
                    ),
                    "missing-parent rejection must precede proof-of-work validation"
                );
            }
            other => panic!("expected missing-prev rejection, got {other:?}"),
        }
    }
    Ok(())
}

#[test]
fn submit_header_rejects_bad_diffbits() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let genesis = Network::Regtest.genesis_block();
    let mut child = mined_child(genesis.block_hash())?;
    child.header.bits = CompactTarget::from_consensus(0x207f_fffe);
    regtest_fixture::mine_block_to_declared_target(&mut child)?;
    match mining.submit_header(child.header) {
        Err(MiningControlError::Rejected(reason)) => {
            assert_eq!(reason.as_str(), "bad-diffbits");
        }
        other => panic!("expected bad-diffbits, got {other:?}"),
    }
    Ok(())
}

#[test]
fn submit_header_rejects_time_too_new() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let genesis = Network::Regtest.genesis_block();
    let mut child = mined_child(genesis.block_hash())?;
    child.header.time = u32::MAX;
    regtest_fixture::mine_block_to_declared_target(&mut child)?;
    match mining.submit_header(child.header) {
        Err(MiningControlError::Rejected(reason)) => {
            assert_eq!(reason.as_str(), "time-too-new");
        }
        other => panic!("expected time-too-new, got {other:?}"),
    }
    Ok(())
}

#[test]
fn submit_header_rejects_bad_version_after_bip34_activation() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let genesis = Network::Regtest.genesis_block();
    let base_time = genesis.header.time;
    let mut prev = genesis.block_hash();
    // Regtest enforces the BIP34 version floor from candidate height 500
    // (Core `DeploymentActiveAfter`), so heights 1..=499 still carry version 1.
    for height in 1..=499_u32 {
        let header = mined_regtest_header(prev, base_time + height * 600, 1);
        mining.submit_header(header)?;
        prev = header.compute_hash();
    }
    let rejected = mined_regtest_header(prev, base_time + 500 * 600, 1);
    match mining.submit_header(rejected) {
        Err(MiningControlError::Rejected(reason)) => {
            assert_eq!(reason.as_str(), "bad-version(0x00000001)");
        }
        other => panic!("expected bad-version rejection, got {other:?}"),
    }
    let accepted = mined_regtest_header(prev, base_time + 500 * 600, 2);
    mining.submit_header(accepted)?;
    Ok(())
}

#[test]
fn rejection_mapping_for_bad_prev_hash() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let mut block = mined_child(BlockHash::from(Hash256::from_le_bytes(&[0x11; 32])))?;
    // Ensure PoW still valid for the mutated prev hash by remine.
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("test block has no merkle root"))?;
    block.header.nonce = 0;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    let result = mining.submit_block(BlockPayload::from_local(block))?;
    match result {
        BlockValidationResult::Rejected(reason) => {
            assert!(
                reason.contains("inconclusive-not-best-prevblk") || reason.contains("prev"),
                "unexpected rejection reason: {reason}"
            );
        }
        other => panic!("expected rejection, got {other:?}"),
    }
    Ok(())
}

#[test]
fn concurrent_duplicate_submissions_leave_admission_open() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    let child = mined_child(Network::Regtest.genesis_block().block_hash())?;
    let start = std::sync::Barrier::new(3);
    let outcomes = thread::scope(|scope| {
        let submit = || {
            start.wait();
            mining.submit_block(BlockPayload::from_local(child.clone()))
        };
        let first = scope.spawn(submit);
        let second = scope.spawn(submit);
        start.wait();
        [
            first
                .join()
                .unwrap_or_else(|error| std::panic::resume_unwind(error)),
            second
                .join()
                .unwrap_or_else(|error| std::panic::resume_unwind(error)),
        ]
    });
    let [first, second] = outcomes;
    let results = [first?, second?];
    assert!(results.contains(&BlockValidationResult::Accepted));
    assert!(results.contains(&BlockValidationResult::Duplicate));
    assert!(state.mempool_gateway().stable_generation().is_some());
    assert_eq!(state.chainstate().chain_snapshot().tip_height, 1);
    let mut next = mined_child_labeled(child.block_hash(), 2)?;
    next.header.time = child.header.time + 1;
    regtest_fixture::mine_block_to_declared_target(&mut next)?;
    assert_eq!(
        mining.submit_block(BlockPayload::from_local(next))?,
        BlockValidationResult::Accepted,
        "a racing duplicate must not poison the next valid submission"
    );
    Ok(())
}

#[test]
fn unsolved_pow_is_rejected_by_proposal_and_submit() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let mut block = mined_child(genesis.block_hash())?;
    while compact_is_met_by(block.header.bits, block.block_hash().into()) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("nonce exhausted while invalidating PoW"))?;
    }
    let proposal = mining.get_block_template(BlockTemplateRequest {
        mode: BlockTemplateMode::Proposal(block.clone()),
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id: None,
        coinbase_budget: None,
    })?;
    match proposal {
        BlockTemplateResult::Proposal(BlockValidationResult::Accepted) => {}
        other => panic!("BIP22 proposal must omit unsolved PoW, got {other:?}"),
    }
    match mining.submit_block(BlockPayload::from_local(block))? {
        BlockValidationResult::Rejected(reason) => {
            assert!(reason.contains("high-hash"), "submit reason: {reason}");
        }
        other => panic!("expected submit high-hash, got {other:?}"),
    }
    assert!(
        state.mempool_gateway().stable_generation().is_some(),
        "a clean block rejection must settle the chain generation"
    );
    assert!(!state.chainstate().shutdown_handle().load(Ordering::Acquire));
    Ok(())
}

#[test]
fn duplicate_solved_submission_is_idempotent() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let child = mined_child(genesis.block_hash())?;
    assert_eq!(
        mining.submit_block(BlockPayload::from_local(child.clone()))?,
        BlockValidationResult::Accepted
    );
    let height = state
        .chainstate()
        .applied_tip_snapshot()
        .map_or(0, |tip| tip.height);
    assert_eq!(
        mining.submit_block(BlockPayload::from_local(child))?,
        BlockValidationResult::Duplicate
    );
    assert_eq!(
        state
            .chainstate()
            .applied_tip_snapshot()
            .map_or(0, |tip| tip.height),
        height,
        "duplicate solved submission must not reapply"
    );
    Ok(())
}

// CONTRACT: API-18
#[test]
fn proposal_of_an_applied_block_is_duplicate() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    assert_eq!(
        propose_block(&mining, genesis)?,
        BlockValidationResult::Duplicate
    );
    Ok(())
}

// CONTRACT: API-18
#[test]
fn proposal_of_an_invalid_header_is_duplicate_invalid() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = genesis.block_hash();
    let invalid = mined_child_labeled(genesis.block_hash(), 2)?;
    {
        let tree = state.chainstate().block_tree_reader();
        let genesis_id = tree
            .read()
            .lookup(Hash256::from(genesis_hash))
            .ok_or_else(|| anyhow::anyhow!("missing genesis"))?;
        tree.write()
            .insert_node(Some(genesis_id), invalid.header, NodeStatus::Invalid)?;
    }
    assert_eq!(
        propose_block(&mining, invalid)?,
        BlockValidationResult::DuplicateInvalid
    );
    Ok(())
}

// CONTRACT: API-18
#[test]
fn proposal_of_a_header_only_block_is_duplicate_inconclusive() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_bytes());
    let side = mined_child_labeled(genesis.block_hash(), 3)?;
    {
        let tree = state.chainstate().block_tree_reader();
        let genesis_id = tree
            .read()
            .lookup(genesis_hash)
            .ok_or_else(|| anyhow::anyhow!("missing genesis"))?;
        tree.write()
            .insert_node(Some(genesis_id), side.header, NodeStatus::HeaderValid)?;
    }
    assert_eq!(
        propose_block(&mining, side)?,
        BlockValidationResult::DuplicateInconclusive
    );
    Ok(())
}

// CONTRACT: API-18
#[test]
fn proposal_of_a_disconnected_scripts_valid_block_is_duplicate() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let child = mined_child(genesis.block_hash())?;
    let child_hash = Hash256::from(child.block_hash());
    assert_eq!(
        mining.submit_block(BlockPayload::from_local(child.clone()))?,
        BlockValidationResult::Accepted
    );
    disconnect_applied(&state, &child)?;
    let chain_tx_count = {
        let tree = state.chainstate().block_tree_reader();
        tree.read()
            .node_by_hash(child_hash)
            .ok_or_else(|| anyhow::anyhow!("disconnected child missing from tree"))?
            .chain_tx_count
    };
    assert_eq!(
        chain_tx_count.get(),
        Some(2),
        "disconnect must keep the scripts-valid chain_tx_count"
    );
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing after disconnect"));
    assert_eq!(tip.hash, Hash256::from(genesis.block_hash()));
    assert_eq!(
        propose_block(&mining, child)?,
        BlockValidationResult::Duplicate
    );
    Ok(())
}

// CONTRACT: API-18
#[test]
fn submit_of_a_disconnected_scripts_valid_block_is_duplicate() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let child = mined_child(genesis.block_hash())?;
    assert_eq!(
        mining.submit_block(BlockPayload::from_local(child.clone()))?,
        BlockValidationResult::Accepted
    );
    disconnect_applied(&state, &child)?;
    assert_eq!(
        mining.submit_block(BlockPayload::from_local(child))?,
        BlockValidationResult::Duplicate
    );
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing after duplicate submit"));
    assert_eq!(tip.hash, genesis_hash);
    Ok(())
}

// CONTRACT: API-18
#[test]
fn applied_ancestor_with_unset_chain_tx_count_is_duplicate() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let child = mined_child(genesis.block_hash())?;
    assert_eq!(
        mining.submit_block(BlockPayload::from_local(child))?,
        BlockValidationResult::Accepted
    );
    {
        let tree = state.chainstate().block_tree_reader();
        let mut tree = tree.write();
        let genesis_id = tree
            .lookup(genesis_hash)
            .ok_or_else(|| anyhow::anyhow!("missing genesis"))?;
        tree.restore_chain_tx_count(genesis_id, bitcoin_rs_chain::ChainTxCount::UNKNOWN)?;
    }
    assert_eq!(
        propose_block(&mining, genesis.clone())?,
        BlockValidationResult::Duplicate
    );
    assert_eq!(
        mining.submit_block(BlockPayload::from_local(genesis))?,
        BlockValidationResult::Duplicate
    );
    Ok(())
}

#[test]
fn submit_block_applies_a_header_already_in_the_tree() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let child = mined_child(genesis.block_hash())?;
    let child_hash = Hash256::from(child.block_hash());
    mining.submit_header(child.header)?;
    assert_eq!(
        mining.submit_block(BlockPayload::from_local(child))?,
        BlockValidationResult::Accepted
    );
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing after submit"));
    assert_eq!(tip.hash, child_hash);
    Ok(())
}

#[test]
fn active_ancestor_submit_is_duplicate() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();
    let genesis = Network::Regtest.genesis_block();
    let child = mined_child(genesis.block_hash())?;
    assert_eq!(
        mining.submit_block(BlockPayload::from_local(child))?,
        BlockValidationResult::Accepted
    );
    assert_eq!(
        mining.submit_block(BlockPayload::from_local(genesis))?,
        BlockValidationResult::Duplicate
    );
    Ok(())
}
