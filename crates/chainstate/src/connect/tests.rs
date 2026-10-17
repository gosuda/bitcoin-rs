use super::*;
use crate::test_fixtures::{MemoryBodies, handles};
use bitcoin_rs_chain::regtest_fixture;
use bitcoin_rs_primitives::{Amount, Network, TxOut, Witness, encode::double_sha256};
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_utxo::UtxoSet;

fn witness_child(
    parent: bitcoin_rs_primitives::BlockHash,
    height: u32,
) -> Result<Block, regtest_fixture::RegtestFixtureError> {
    let mut coinbase = regtest_fixture::coinbase(height);
    coinbase.inputs[0].witness = Witness::from_stack(vec![vec![0; 32]]);
    let commitment = double_sha256(&[0; 64]);
    coinbase.outputs.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: [
            vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed],
            commitment.as_byte_array().to_vec(),
        ]
        .concat()
        .into(),
    });
    regtest_fixture::mined_block_with_prev_hash(parent, height, vec![coinbase])
}

#[test]
fn preserved_witness_body_is_bound_before_commit_and_disconnect_keeps_exact_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    for engine in bitcoin_rs_consensus::ValidationEngine::ALL
        .iter()
        .copied()
        .filter(|e| e.is_supported())
    {
        let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        chain.validation_engine = engine;
        let bodies = Arc::new(MemoryBodies::default());
        chain.block_body_store = Some(bodies.clone());
        chain.set_capture_flags(false, true);
        let genesis = Network::Regtest.genesis_block();
        chain.apply_block(&genesis, None)?;
        let child = witness_child(genesis.block_hash(), 1)?;
        let raw = bytes::Bytes::from(consensus_bytes(&child));
        let before = chain.chain_snapshot();
        // A witness mutation leaves both txid and serialized length unchanged.
        // It must never be certified by the matching valid body's bytes.
        let mut changed = child.clone();
        changed.txs[0].inputs[0].witness = Witness::from_stack(vec![vec![1; 32]]);
        assert_eq!(changed.txs[0].txid(), child.txs[0].txid());
        assert_eq!(consensus_bytes(&changed).len(), raw.len());
        assert!(matches!(
            chain.apply_block(&changed, Some(raw.clone())),
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Kernel(_)
            ))
        ));
        assert_eq!(chain.chain_snapshot().tip_hash, before.tip_hash);
        assert!(bodies.load_block_body(1, child.block_hash().0)?.is_none());

        let outcome = chain.apply_block(&child, Some(raw.clone()))?;
        assert_eq!(outcome.block_bytes, raw);
        assert_eq!(
            bodies.load_block_body(1, child.block_hash().0)?.as_deref(),
            Some(raw.as_ref())
        );

        let mut bad_merkle = witness_child(child.block_hash(), 2)?;
        bad_merkle.txs[0].outputs[0].value = Amount::from_sat(1);
        let bad_raw = bytes::Bytes::from(consensus_bytes(&bad_merkle));
        assert!(chain.apply_block(&bad_merkle, Some(bad_raw)).is_err());
        assert_eq!(
            chain.applied_tip_snapshot().ok_or("missing tip")?.hash,
            child.block_hash().0
        );
        assert!(
            bodies
                .load_block_body(2, bad_merkle.block_hash().0)?
                .is_none()
        );

        chain.disconnect_block(&child)?;
        let replayed = chain.apply_block(&child, None)?;
        assert_eq!(replayed.block_bytes, raw);
        assert_eq!(
            bodies.load_block_body(1, child.block_hash().0)?.as_deref(),
            Some(raw.as_ref())
        );
    }
    Ok(())
}
