use std::str::FromStr;

use crate::support::primitives::TestError;
use bitcoin_rs_consensus::primitives::{
    Block as PrimitiveBlock, BlockHash, BlockImage, Txid, Wtxid, deserialize,
};
const HEIGHTS: &[(u32, &str)] = &[
    (
        0,
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    ),
    (
        1,
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
    ),
    (
        170,
        "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee",
    ),
    (
        91722,
        "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e",
    ),
    (
        91812,
        "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f",
    ),
    (
        91842,
        "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec",
    ),
    (
        91880,
        "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721",
    ),
    (
        173_818,
        "00000000000008a5097526239afca1d59e6e112aca135ab7dd5189b5fe9f0696",
    ),
    (
        363_731,
        "00000000000000000c28e23330c29046f19e817fe8fe039f4044b2b2882aef53",
    ),
    (
        481_823,
        "000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80",
    ),
    (
        481_824,
        "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893",
    ),
    (
        624_455,
        "0000000000000000000159c36c1e487714ef94d4e93419a2455eaa8cd0e05ddb",
    ),
    (
        709_632,
        "0000000000000000000687bca986194dc2c1f949318629b44bb54ec0a94d8244",
    ),
    (
        800_000,
        "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
    ),
    (
        880_000,
        "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
    ),
];

#[test]
fn golden_blocks_decode_and_hash_to_blockstream_txids() -> Result<(), TestError> {
    for (height, expected_hash) in HEIGHTS {
        let block_bytes = read_fixture(*height, "bin")?;
        let txid_text = String::from_utf8(read_fixture(*height, "txids.txt")?)?;
        let expected_txids = parse_txids(&txid_text)?;
        let wtxid_text = String::from_utf8(read_fixture(*height, "wtxids.txt")?)?;
        let expected_wtxids = parse_wtxids(&wtxid_text)?;
        let block = deserialize::<PrimitiveBlock>(&block_bytes)?;
        let expected_block_hash = expected_hash.parse::<BlockHash>()?;

        assert_eq!(
            block.block_hash(),
            expected_block_hash,
            "height {height} block hash"
        );
        assert_eq!(
            block.txs.len(),
            expected_txids.len(),
            "height {height} tx count"
        );

        assert_eq!(
            expected_wtxids.len(),
            expected_txids.len(),
            "height {height} wtxid golden count"
        );
        for (index, (tx, expected_txid)) in block.txs.iter().zip(expected_txids.iter()).enumerate()
        {
            assert_eq!(
                tx.txid(),
                *expected_txid,
                "height {height} tx index {index}"
            );
            let expected_wtxid = expected_wtxids[index];
            if !tx.has_witness() {
                assert_eq!(
                    tx.wtxid().0,
                    tx.txid().0,
                    "height {height} tx index {index}: pre-segwit wtxid must equal txid"
                );
            }
            assert_eq!(
                tx.wtxid(),
                expected_wtxid,
                "height {height} tx index {index}: golden wtxid"
            );
        }
        assert_eq!(
            bitcoin_rs_consensus::primitives::consensus_bytes(&block),
            block_bytes,
            "height {height} re-encode"
        );
    }
    Ok(())
}
// BLK-02, BLK-03, BLK-05, BLK-06
#[test]
fn golden_blocks_image_identities_and_views_match_core_vectors() -> Result<(), TestError> {
    for (height, expected_hash) in HEIGHTS {
        let block_bytes = read_fixture(*height, "bin")?;
        let txid_text = String::from_utf8(read_fixture(*height, "txids.txt")?)?;
        let expected_txids = parse_txids(&txid_text)?;
        let wtxid_text = String::from_utf8(read_fixture(*height, "wtxids.txt")?)?;
        let expected_wtxids = parse_wtxids(&wtxid_text)?;
        let expected_block_hash = expected_hash.parse::<BlockHash>()?;

        let raw = bytes::Bytes::from(block_bytes.clone());
        let image = BlockImage::from_raw(raw)?;

        assert_eq!(
            image.block_hash(),
            expected_block_hash,
            "height {height} block hash"
        );
        assert_eq!(
            image.tx_count(),
            expected_txids.len(),
            "height {height} tx count"
        );
        assert_eq!(
            image.identities().len(),
            expected_txids.len(),
            "height {height} identities count"
        );

        let decoded = deserialize::<PrimitiveBlock>(&block_bytes)?;
        for index in 0..image.tx_count() {
            let identity = image.identity(index);
            let tx_view = image.tx(index);
            let expected_txid = expected_txids[index];
            let expected_wtxid = expected_wtxids[index];
            let decoded_tx = &decoded.txs[index];

            assert_eq!(
                identity.txid(),
                expected_txid,
                "height {height} tx index {index}: identity txid"
            );
            assert_eq!(
                tx_view.txid(),
                expected_txid,
                "height {height} tx index {index}: tx_view txid"
            );

            if !tx_view.has_witness() {
                assert_eq!(
                    identity.wtxid(),
                    None,
                    "height {height} tx index {index}: legacy identity wtxid must be None"
                );
                assert_eq!(
                    tx_view.wtxid().0,
                    tx_view.txid().0,
                    "height {height} tx index {index}: legacy tx_view wtxid must equal txid"
                );
            } else {
                assert_eq!(
                    identity.wtxid(),
                    Some(expected_wtxid),
                    "height {height} tx index {index}: segwit identity wtxid"
                );
            }
            assert_eq!(
                tx_view.wtxid(),
                expected_wtxid,
                "height {height} tx index {index}: tx_view wtxid"
            );

            assert_eq!(
                usize::try_from(identity.total_size())?,
                decoded_tx.total_size(),
                "height {height} tx index {index}: total size"
            );
            assert_eq!(
                usize::try_from(identity.base_size())?,
                decoded_tx.base_size(),
                "height {height} tx index {index}: base size"
            );
            assert_eq!(
                tx_view.total_size(),
                decoded_tx.total_size(),
                "height {height} tx index {index}: view total size"
            );
            assert_eq!(
                tx_view.base_size(),
                decoded_tx.base_size(),
                "height {height} tx index {index}: view base size"
            );

            assert_eq!(
                tx_view.version(),
                decoded_tx.version,
                "height {height} tx index {index}: version"
            );
            assert_eq!(
                tx_view.lock_time(),
                decoded_tx.lock_time,
                "height {height} tx index {index}: lock_time"
            );
            assert_eq!(
                tx_view.is_coinbase(),
                decoded_tx.is_coinbase(),
                "height {height} tx index {index}: is_coinbase"
            );
            assert_eq!(
                tx_view.input_count(),
                decoded_tx.inputs.len(),
                "height {height} tx index {index}: input_count"
            );
            assert_eq!(
                tx_view.output_count(),
                decoded_tx.outputs.len(),
                "height {height} tx index {index}: output_count"
            );

            for (in_idx, expected_in) in decoded_tx.inputs.iter().enumerate() {
                assert_eq!(
                    tx_view.input_outpoint(in_idx),
                    expected_in.previous_output,
                    "height {height} tx {index} input {in_idx}: outpoint"
                );
                assert_eq!(
                    tx_view.input_script_sig(in_idx),
                    expected_in.script_sig.as_bytes(),
                    "height {height} tx {index} input {in_idx}: script_sig"
                );
                assert_eq!(
                    tx_view.input_sequence(in_idx),
                    expected_in.sequence,
                    "height {height} tx {index} input {in_idx}: sequence"
                );
                assert_eq!(
                    tx_view.witness_item_count(in_idx),
                    expected_in.witness.len(),
                    "height {height} tx {index} input {in_idx}: witness count"
                );
                for (item_idx, expected_item) in expected_in.witness.iter().enumerate() {
                    assert_eq!(
                        tx_view.witness_item(in_idx, item_idx),
                        expected_item,
                        "height {height} tx {index} input {in_idx} item {item_idx}"
                    );
                }
            }

            for (out_idx, expected_out) in decoded_tx.outputs.iter().enumerate() {
                assert_eq!(
                    tx_view.output_value(out_idx),
                    expected_out.value,
                    "height {height} tx {index} output {out_idx}: value"
                );
                assert_eq!(
                    tx_view.output_script(out_idx),
                    expected_out.script_pubkey.as_bytes(),
                    "height {height} tx {index} output {out_idx}: script"
                );
            }

            let materialized_tx = tx_view.materialize();
            assert_eq!(
                &materialized_tx, decoded_tx,
                "height {height} tx {index}: materialized tx"
            );
        }

        let materialized_block = image.materialize();
        assert_eq!(
            materialized_block, decoded,
            "height {height} materialized block"
        );
    }
    Ok(())
}

fn read_fixture(height: u32, extension: &'static str) -> Result<Vec<u8>, TestError> {
    let path = format!("tests/testdata/{height}.{extension}");
    match std::fs::read(&path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(TestError::MissingFixture { height, extension })
        }
        Err(error) => Err(error.into()),
    }
}

fn parse_wtxids(wtxid_text: &str) -> Result<Vec<Wtxid>, TestError> {
    wtxid_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Wtxid::from_str(line).map_err(Into::into))
        .collect()
}

fn parse_txids(txid_text: &str) -> Result<Vec<Txid>, bitcoin_rs_consensus::primitives::HashError> {
    txid_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(Txid::from_str)
        .collect()
}
