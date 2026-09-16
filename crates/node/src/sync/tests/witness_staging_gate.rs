//! Node-level body/header binding interaction tests (issue #1070).
//!
//! These exercise the `buffer_received_block_chunk` flow: the binding gate
//! pre-pass, `AlreadyStaged` priority over late malformed duplicates, and
//! recovery when a malformed body is followed by the correct one.

use super::*;
use bitcoin_rs_p2p::InboundBlock;
use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};

/// BIP141 witness commitment prefix: `OP_RETURN` `OP_PUSHBYTES_36` `commitment_header`.
const WITNESS_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// SHA256d(00*32 || 00*32): coinbase-only witness root and zero reserved value.
const ZERO_RESERVED_COMMITMENT: [u8; 32] = [
    0xe2, 0xf6, 0x1c, 0x3f, 0x71, 0xd1, 0xde, 0xfd, 0x3f, 0xa9, 0x99, 0xdf, 0xa3, 0x69, 0x53, 0x75,
    0x5c, 0x69, 0x06, 0x89, 0x79, 0x99, 0x62, 0xb4, 0x8b, 0xeb, 0xd8, 0x36, 0x97, 0x4e, 0x8c, 0xf9,
];

/// Builds a coinbase with a BIP141 commitment output. When `witness` is true
/// the coinbase input carries a single 32-byte zero witness element (the
/// reserved nonce); when false the witness is empty (stripped). Both variants
/// share the same txid — witness data is not committed to in the txid — so
/// they produce the same merkle root and block hash.
fn segwit_coinbase(height: u32, witness: bool) -> Tx {
    let mut script_sig = push_int(i64::from(height));
    script_sig.extend_from_slice(&push_int(1));
    let mut commitment_script = WITNESS_PREFIX.to_vec();
    commitment_script.extend_from_slice(&ZERO_RESERVED_COMMITMENT);
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(script_sig),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: if witness {
                Witness::from_stack(vec![vec![0; 32]])
            } else {
                Witness::new()
            },
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::new(),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: Script::from_bytes(commitment_script),
            },
        ],
        lock_time: LockTime::from_consensus(0),
    }
}

/// Mines a PoW-valid regtest block with a segwit commitment coinbase.
fn segwit_block(prev_blockhash: BlockHash, height: u32, witness: bool) -> Block {
    mined_block_with_prev_hash(
        prev_blockhash,
        height,
        vec![segwit_coinbase(height, witness)],
    )
}

/// Sets up a `BlockSync` with genesis applied, a single segwit block header in
/// the tree, and a default sync budget. Returns the sync, the block hash, and
/// both body variants (correct and stripped).
fn segwit_sync_fixture() -> Result<(BlockSync, Hash256, Block, Block), Box<dyn std::error::Error>> {
    let (sync, _peers, _applied_tip, _main, _blocks_tx) = sync_with_mined_chain(0)?;
    sync.ensure_genesis_tip();
    install_budget(&sync, super::super::default_sync_budget());

    let genesis = Network::Regtest.genesis_block();
    let prev_hash = genesis.block_hash();

    // Mine the correct block (with witness) — this also fixes the header.
    let correct_block = segwit_block(prev_hash, 1, true);
    let block_hash = Hash256::from_le_bytes(correct_block.block_hash().as_bytes());

    // Insert the header into the tree so the witness gate can derive
    // segwit_active from the parent (genesis) and the block height.
    let genesis_id = sync
        .handles
        .block_tree
        .read()
        .lookup(Hash256::from_le_bytes(genesis.block_hash().as_bytes()))
        .ok_or("missing genesis node")?;
    sync.handles.block_tree.write().insert_node(
        Some(genesis_id),
        correct_block.header,
        NodeStatus::HeaderValid,
    )?;

    // The stripped variant shares the same header/hash (witness does not
    // affect txid or block hash).
    let stripped_block = segwit_block(prev_hash, 1, false);
    assert_eq!(
        stripped_block.block_hash(),
        correct_block.block_hash(),
        "stripped and correct blocks must share the same hash"
    );

    Ok((sync, block_hash, correct_block, stripped_block))
}

/// (g) A malformed (witness-stripped) body arrives first and is rejected for
/// delivery; the correct body arrives later and is staged normally. The
/// window's source-aware `reject_delivery` is a no-op here (no pending, no
/// source), but the stager must remain clean so the correct body can stage.
#[test]
fn malformed_body_dropped_then_correct_body_staged() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, block_hash, correct_block, stripped_block) = segwit_sync_fixture()?;

    // Send the stripped (malformed) body first.
    let mut batch = vec![InboundBlock::from_decoded(stripped_block)];
    let received = sync.buffer_received_block_chunk(&mut batch, Some(block_hash));
    assert_eq!(received, 1, "malformed body should be processed (rejected)");
    assert!(
        batch.is_empty(),
        "buffer_received_block_chunk should drain the batch"
    );
    // The stager must NOT contain the malformed body.
    assert!(
        !sync.block_stager.lock().contains(&block_hash),
        "malformed body must not be staged"
    );
    // The window must not have the malformed body in its received state.
    assert_eq!(
        sync.download_window.lock().received_len(),
        0,
        "malformed body must not be in window received state"
    );

    // Now send the correct body.
    let mut batch = vec![InboundBlock::from_decoded(correct_block)];
    let received = sync.buffer_received_block_chunk(&mut batch, Some(block_hash));
    assert_eq!(received, 1, "correct body should be processed (staged)");
    // The stager must now contain the correct body.
    assert!(
        sync.block_stager.lock().contains(&block_hash),
        "correct body must be staged after malformed was rejected"
    );

    Ok(())
}

/// A body with altered non-witness transaction data retains the header hash
/// but fails the txid Merkle-root binding. It must not occupy the stager slot,
/// leaving the original body eligible to arrive later.
#[test]
fn altered_non_witness_body_dropped_then_correct_body_staged()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, block_hash, correct_block, _) = segwit_sync_fixture()?;
    let mut altered_block = correct_block.clone();
    altered_block.txs[0].outputs[0].value = Amount::from_sat(2);
    assert_eq!(
        Hash256::from_le_bytes(altered_block.block_hash().as_bytes()),
        block_hash,
        "altering body transaction bytes must retain the header-derived hash"
    );

    let mut batch = vec![InboundBlock::from_decoded(altered_block)];
    assert_eq!(
        sync.buffer_received_block_chunk(&mut batch, Some(block_hash)),
        1
    );
    assert!(!sync.block_stager.lock().contains(&block_hash));
    assert_eq!(sync.download_window.lock().received_len(), 0);

    let mut batch = vec![InboundBlock::from_decoded(correct_block)];
    assert_eq!(
        sync.buffer_received_block_chunk(&mut batch, Some(block_hash)),
        1
    );
    assert!(sync.block_stager.lock().contains(&block_hash));

    Ok(())
}

/// (h) A correct body is staged first; a late malformed duplicate for the
/// same hash must not displace it or corrupt the received/window state. The
/// already-staged precheck skips witness hashing for the duplicate, so no
/// `reject_delivery` or window manipulation occurs — the duplicate is a pure
/// `AlreadyStaged` credited as a duplicate delivery.
#[test]
fn correct_body_staged_then_malformed_duplicate_is_ignored()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, block_hash, correct_block, stripped_block) = segwit_sync_fixture()?;

    // Send the correct body first.
    let mut batch = vec![InboundBlock::from_decoded(correct_block)];
    let received = sync.buffer_received_block_chunk(&mut batch, Some(block_hash));
    assert_eq!(received, 1, "correct body should be staged");
    assert!(
        sync.block_stager.lock().contains(&block_hash),
        "correct body must be staged"
    );
    let staged_bytes = sync.block_stager.lock().received_bytes();
    let window_received = sync.download_window.lock().received_len();

    // Send the stripped (malformed) duplicate.
    let mut batch = vec![InboundBlock::from_decoded(stripped_block)];
    let received = sync.buffer_received_block_chunk(&mut batch, Some(block_hash));
    assert_eq!(received, 1, "duplicate should be processed (AlreadyStaged)");

    // The stager must still contain the correct body — not displaced.
    assert!(
        sync.block_stager.lock().contains(&block_hash),
        "correct body must still be staged after malformed duplicate"
    );
    assert_eq!(
        sync.block_stager.lock().received_bytes(),
        staged_bytes,
        "staged byte count must not change from a duplicate"
    );
    assert_eq!(
        sync.block_stager.lock().received_len(),
        1,
        "only one body should be staged"
    );
    // The already-staged precheck skips witness hashing, so no
    // reject_delivery touches the window — received state is unchanged.
    assert_eq!(
        sync.download_window.lock().received_len(),
        window_received,
        "window received state must not change from an already-staged duplicate"
    );

    Ok(())
}
