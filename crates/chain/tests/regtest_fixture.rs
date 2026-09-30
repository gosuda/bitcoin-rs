//! Contract tests for the shared regtest fixture: declared-target mining,
//! merkle binding, determinism, and the coinbase height push. Deterministic,
//! no wire.

use bitcoin::Target;
use bitcoin::hashes::Hash;
use bitcoin::script::Builder;
use bitcoin_rs_chain::regtest_fixture::{self, REGTEST_BITS};
use bitcoin_rs_chain::validate_pow;
use bitcoin_rs_primitives::{BlockHash, Hash256, Network};

fn genesis_parent() -> BlockHash {
    BlockHash::from(Network::Regtest.genesis_block_hash())
}

#[test]
fn mined_child_meets_declared_target() -> Result<(), Box<dyn std::error::Error>> {
    let child = regtest_fixture::mined_regtest_child_at(genesis_parent(), 1)?;
    assert_eq!(
        child.header.version, 4,
        "fixture headers carry a version the shared contextual header gate accepts past the BIP34 height"
    );
    assert_eq!(child.header.bits.to_consensus(), REGTEST_BITS);
    let hash = child.block_hash();
    // Differential: the `bitcoin` crate's own target check, independent of
    // the `compact_is_met_by` path the fixture grinds with.
    let target = Target::from_compact(bitcoin::CompactTarget::from_consensus(
        child.header.bits.to_consensus(),
    ));
    assert!(
        target.is_met_by(bitcoin::BlockHash::from_byte_array(*hash.as_bytes())),
        "the bitcoin target oracle rejects the fixture proof of work"
    );
    validate_pow(&child.header, Hash256::from(hash), Network::Regtest)?;
    let script_sig = &child.txs[0].inputs[0].script_sig;
    // The `bitcoin` crate's CScriptNum builder is the independent BIP34 oracle.
    let height_push = Builder::new().push_int(1).into_script();
    assert!(
        script_sig.as_bytes().starts_with(height_push.as_bytes())
            && (2..=100).contains(&script_sig.as_bytes().len()),
        "the coinbase scriptSig must carry the height push inside the consensus 2..=100 range"
    );
    Ok(())
}

#[test]
fn mined_child_merkle_root_binds() -> Result<(), Box<dyn std::error::Error>> {
    let child = regtest_fixture::mined_regtest_child_at(genesis_parent(), 2)?;
    assert_eq!(
        Some(child.header.merkle_root),
        regtest_fixture::merkle_root(&child.txs),
        "the header merkle root must equal the fixture fold over the block's transactions"
    );
    let txids = child
        .txs
        .iter()
        .map(|tx| bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
    let root =
        bitcoin::merkle_tree::calculate_root(txids).ok_or("fixture block has transactions")?;
    assert_eq!(
        child.header.merkle_root,
        Hash256::from_le_bytes(root.as_byte_array()),
        "the fixture fold must agree with the bitcoin crate's merkle computation"
    );
    Ok(())
}

#[test]
fn mined_block_merkle_root_binds_over_an_odd_tx_count() -> Result<(), Box<dyn std::error::Error>> {
    // Three transactions exercise the odd-leaf duplication both merkle folds
    // implement — the case where implementations diverge.
    let coinbase = regtest_fixture::coinbase(3);
    let mut tx2 = coinbase.clone();
    tx2.lock_time = bitcoin_rs_primitives::LockTime::from_consensus(1);
    let mut tx3 = coinbase.clone();
    tx3.lock_time = bitcoin_rs_primitives::LockTime::from_consensus(2);
    let block =
        regtest_fixture::mined_block_with_prev_hash(genesis_parent(), 3, vec![coinbase, tx2, tx3])?;
    assert_eq!(
        Some(block.header.merkle_root),
        regtest_fixture::merkle_root(&block.txs),
        "the header merkle root must equal the fixture fold over the block's transactions"
    );
    let txids = block
        .txs
        .iter()
        .map(|tx| bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
    let root =
        bitcoin::merkle_tree::calculate_root(txids).ok_or("fixture block has transactions")?;
    assert_eq!(
        block.header.merkle_root,
        Hash256::from_le_bytes(root.as_byte_array()),
        "the fixture fold must agree with the bitcoin crate's merkle computation on an odd leaf count"
    );
    Ok(())
}

#[test]
fn grind_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let first = regtest_fixture::mined_regtest_child_at(genesis_parent(), 3)?;
    let second = regtest_fixture::mined_regtest_child_at(genesis_parent(), 3)?;
    assert_eq!(
        first.header, second.header,
        "grinding the same parent twice must produce byte-identical headers"
    );
    assert_eq!(first.block_hash(), second.block_hash());
    Ok(())
}
