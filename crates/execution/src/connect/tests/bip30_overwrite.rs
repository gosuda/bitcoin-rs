use std::sync::Arc;

use bitcoin_rs_consensus::bip30::BIP30_DUPLICATE_TXID_EXCEPTIONS;
use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockHash, BlockImage, CompactTarget, Hash256, Header, LockTime, Network,
    OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness, deserialize,
};
use bitcoin_rs_storage::ColumnFamily;
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_storage::coins::CoinKey;
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};

use crate::connect::{ChangeRequest, build_block_changes_checked};
use crate::test_fixtures::{TestError, TestResult, handles};

fn coinbase_tx() -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    }
}

#[test]
fn exception_block_undo_removes_the_coin_it_overwrites() -> TestResult {
    let (exception_height, exception_hash) = BIP30_DUPLICATE_TXID_EXCEPTIONS[0];
    let coinbase = coinbase_tx();
    let txid = coinbase.txid();
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash(Hash256::default()),
            merkle_root: Hash256::default(),
            time: 1_300_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 1,
        },
        txs: vec![coinbase],
    };
    let image = BlockImage::from_local(block);

    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let prior = OwnedUtxoOut {
        vout: 0,
        value: 50_000,
        script_pubkey: vec![0x51],
        coinbase: true,
        height: 1,
    };
    let record = UtxoRecord::from_owned_outputs(txid.0, &[prior])
        .map_err(|_| TestError::Missing("prior coin record"))?;
    chain.commit_authority.store().put(
        ColumnFamily::Coins,
        CoinKey(txid.0.to_le_bytes()).as_bytes(),
        record.bytes(),
    )?;

    let txids = [txid];
    let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
    let resolved = Arc::new(crate::ResolvedUtxoView::resolve(
        &crate::connect::ChainstateUtxoSource::new(&chain),
        &image,
        &tx_plan,
    ));
    let Ok((_changes, undo, _totals)) = build_block_changes_checked(&ChangeRequest {
        image: &image,
        block_hash: exception_hash,
        height: exception_height,
        txids: &txids,
        tx_plan: &tx_plan,
        resolved: &resolved,
    }) else {
        return Err(TestError::Missing(
            "the BIP30 exception block must build its changes",
        ));
    };

    let overwritten = OutPoint::new(txid, 0);
    if undo
        .restores()
        .iter()
        .any(|restore| restore.outpoint == overwritten)
    {
        return Err(TestError::Missing(
            "the exception block's undo must not restore the coin it overwrites, as Bitcoin Core",
        ));
    }
    if !undo.removes().contains(&overwritten) {
        return Err(TestError::Missing(
            "the exception block's undo must remove the coin it overwrites",
        ));
    }
    Ok(())
}

#[test]
fn exception_block_disconnect_drops_the_overwritten_engine_coin() -> TestResult {
    let (exception_height, exception_hash) = BIP30_DUPLICATE_TXID_EXCEPTIONS[0];
    let coinbase = coinbase_tx();
    let txid = coinbase.txid();
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash(Hash256::default()),
            merkle_root: Hash256::default(),
            time: 1_300_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 1,
        },
        txs: vec![coinbase],
    };
    let image = BlockImage::from_local(block);

    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let prior = OwnedUtxoOut {
        vout: 0,
        value: 50_000,
        script_pubkey: vec![0x51],
        coinbase: true,
        height: 1,
    };
    let prior_record = UtxoRecord::from_owned_outputs(txid.0, &[prior])
        .map_err(|_| TestError::Missing("prior coin record"))?;
    let key = CoinKey(txid.0.to_le_bytes());
    chain.commit_authority.store().put(
        ColumnFamily::Coins,
        CoinKey(txid.0.to_le_bytes()).as_bytes(),
        prior_record.bytes(),
    )?;

    let txids = [txid];
    let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
    let resolved = Arc::new(crate::ResolvedUtxoView::resolve(
        &crate::connect::ChainstateUtxoSource::new(&chain),
        &image,
        &tx_plan,
    ));
    let Ok((changes, undo, _totals)) = build_block_changes_checked(&ChangeRequest {
        image: &image,
        block_hash: exception_hash,
        height: exception_height,
        txids: &txids,
        tx_plan: &tx_plan,
        resolved: &resolved,
    }) else {
        return Err(TestError::Missing(
            "the BIP30 exception block must build its changes",
        ));
    };

    let created: Vec<OwnedUtxoOut> = changes
        .adds()
        .iter()
        .filter(|add| add.outpoint.txid == txid)
        .map(|add| OwnedUtxoOut {
            vout: add.outpoint.vout,
            value: add.txout.value.to_sat(),
            script_pubkey: add.txout.script_pubkey.to_vec(),
            coinbase: add.coinbase,
            height: add.height,
        })
        .collect();
    let post_connect = UtxoRecord::from_owned_outputs(txid.0, &created)
        .map_err(|_| TestError::Missing("post-connect coin record"))?;
    chain.coins.wipe()?;
    chain.commit_authority.store().put(
        ColumnFamily::Coins,
        CoinKey(txid.0.to_le_bytes()).as_bytes(),
        post_connect.bytes(),
    )?;

    let delta = crate::disconnect::build_disconnect_delta(&chain.coins, &undo)?;
    let (_, remaining) = delta
        .records
        .iter()
        .find(|(record_key, _)| record_key.as_bytes() == key.as_bytes())
        .ok_or(TestError::Missing(
            "disconnect must rewrite the exception block's txid",
        ))?;
    if remaining.is_some() {
        return Err(TestError::Missing(
            "disconnect must drop the overwritten coin, as Bitcoin Core",
        ));
    }
    Ok(())
}
// CMT-06
#[test]
fn overwriting_block_disconnect_derives_removal_as_before() -> TestResult {
    let (exception_height, _) = BIP30_DUPLICATE_TXID_EXCEPTIONS[0];
    let coinbase = coinbase_tx();
    let txid = coinbase.txid();
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash(Hash256::default()),
            merkle_root: Hash256::default(),
            time: 1_300_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 1,
        },
        txs: vec![coinbase],
    };
    let block_hash = Hash256::from(block.block_hash());
    let image = BlockImage::from_local(block.clone());
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let prior = OwnedUtxoOut {
        vout: 0,
        value: 50_000,
        script_pubkey: vec![0x51],
        coinbase: true,
        height: 1,
    };
    let prior_record = UtxoRecord::from_owned_outputs(txid.0, &[prior])
        .map_err(|_| TestError::Missing("prior coin record"))?;
    let key = CoinKey(txid.0.to_le_bytes());
    chain.commit_authority.store().put(
        ColumnFamily::Coins,
        CoinKey(txid.0.to_le_bytes()).as_bytes(),
        prior_record.bytes(),
    )?;
    let txids = [txid];
    let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
    let resolved = Arc::new(crate::ResolvedUtxoView::resolve(
        &crate::connect::ChainstateUtxoSource::new(&chain),
        &image,
        &tx_plan,
    ));
    let Ok((changes, undo, _totals)) = build_block_changes_checked(&ChangeRequest {
        image: &image,
        block_hash,
        height: exception_height,
        txids: &txids,
        tx_plan: &tx_plan,
        resolved: &resolved,
    }) else {
        return Err(TestError::Missing(
            "the BIP30 exception block must build its changes",
        ));
    };
    let created: Vec<OwnedUtxoOut> = changes
        .adds()
        .iter()
        .filter(|add| add.outpoint.txid == txid)
        .map(|add| OwnedUtxoOut {
            vout: add.outpoint.vout,
            value: add.txout.value.to_sat(),
            script_pubkey: add.txout.script_pubkey.to_vec(),
            coinbase: add.coinbase,
            height: add.height,
        })
        .collect();
    let pre_bytes = prior_record.bytes().to_vec();
    if pre_bytes.is_empty() {
        return Err(TestError::Missing(
            "prior coin set must hold the overwritten coin",
        ));
    }
    let post_connect = UtxoRecord::from_owned_outputs(txid.0, &created)
        .map_err(|_| TestError::Missing("post-connect coin record"))?;
    chain.coins.wipe()?;
    chain.commit_authority.store().put(
        ColumnFamily::Coins,
        CoinKey(txid.0.to_le_bytes()).as_bytes(),
        post_connect.bytes(),
    )?;
    let encoded = bitcoin_rs_storage::utxo::contract::encode_undo_record(&undo, block_hash);
    let derived =
        bitcoin_rs_storage::utxo::contract::decode_undo_record_for_block(&encoded, &block)
            .map_err(|_| TestError::Missing("derived undo must decode"))?;
    if !derived.restores().is_empty() {
        return Err(TestError::Missing(
            "derived undo must hold no overwritten restore",
        ));
    }
    let overwritten = OutPoint::new(txid, 0);
    if !derived.removes().contains(&overwritten) {
        return Err(TestError::Missing(
            "derived undo must remove the created outpoint",
        ));
    }
    let delta = crate::disconnect::build_disconnect_delta(&chain.coins, &derived)?;
    let (_, remaining) = delta
        .records
        .iter()
        .find(|(record_key, _)| record_key.as_bytes() == key.as_bytes())
        .ok_or(TestError::Missing(
            "disconnect must rewrite the exception block's txid",
        ))?;
    if remaining.is_some() {
        return Err(TestError::Missing(
            "disconnect must drop the overwritten coin, as Bitcoin Core",
        ));
    }
    Ok(())
}

struct FakeBlockLoader {
    height: u32,
    hash: Hash256,
    body: Vec<u8>,
}

impl BlockBodyStore for FakeBlockLoader {
    fn persist_block_body(
        &self,
        _height: u32,
        _hash: Hash256,
        _body: &[u8],
    ) -> Result<(), StorageError> {
        Err(StorageError::backend("the fake block loader is read-only"))
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok((height == self.height && hash == self.hash).then(|| self.body.clone()))
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[test]
fn read_bip30_overwrite_undo_removes_the_overwritten_coin() -> TestResult {
    let (exception_height, exception_hash) = BIP30_DUPLICATE_TXID_EXCEPTIONS[0];
    let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    chain.block_body_store = Some(Arc::new(FakeBlockLoader {
        height: exception_height,
        hash: exception_hash,
        body: include_bytes!("../../../../consensus/tests/testdata/91842.bin").to_vec(),
    }));
    let body = chain
        .block_body_store
        .as_ref()
        .ok_or(TestError::Missing("the fake block loader is installed"))?
        .load_block_body(exception_height, exception_hash)?
        .ok_or(TestError::Missing("the loader serves the exception block"))?;
    let block = deserialize::<Block>(&body)
        .map_err(|_| TestError::Missing("the exception block must decode"))?;
    assert_eq!(
        Hash256::from(block.block_hash()),
        exception_hash,
        "the loaded block must be the BIP30 exception block"
    );
    let image = BlockImage::from_local(block.clone());
    let txids: Vec<_> = block.txs.iter().map(Tx::txid).collect();

    let prior = OwnedUtxoOut {
        vout: 0,
        value: 5_000_000_000,
        script_pubkey: vec![0x51],
        coinbase: true,
        height: 91_812,
    };
    let record = UtxoRecord::from_owned_outputs(txids[0].0, &[prior])
        .map_err(|_| TestError::Missing("prior coin record"))?;
    chain.commit_authority.store().put(
        ColumnFamily::Coins,
        CoinKey(txids[0].0.to_le_bytes()).as_bytes(),
        record.bytes(),
    )?;

    let tx_plan = crate::prepare::plan_block_transactions(&image, &txids);
    let resolved = Arc::new(crate::ResolvedUtxoView::resolve(
        &crate::connect::ChainstateUtxoSource::new(&chain),
        &image,
        &tx_plan,
    ));
    let Ok((_changes, undo, _totals)) = build_block_changes_checked(&ChangeRequest {
        image: &image,
        block_hash: exception_hash,
        height: exception_height,
        txids: &txids,
        tx_plan: &tx_plan,
        resolved: &resolved,
    }) else {
        return Err(TestError::Missing(
            "the BIP30 exception block must build its changes",
        ));
    };

    let overwritten = OutPoint::new(txids[0], 0);
    if undo
        .restores()
        .iter()
        .any(|entry| entry.outpoint == overwritten)
    {
        return Err(TestError::Missing(
            "the undo must not restore the engine coin the exception block overwrites, as Bitcoin Core",
        ));
    }
    if !undo.removes().contains(&overwritten) {
        return Err(TestError::Missing(
            "the undo must remove the engine coin the exception block overwrites",
        ));
    }
    Ok(())
}
