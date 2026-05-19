//! Golden block fixture tests for primitive block and transaction hashing.
use bitcoin_rs_primitives::{Block as PrimitiveBlock, Hash256, Tx};

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
fn golden_blocks_decode_and_hash_to_blockstream_txids() -> Result<(), Box<dyn std::error::Error>> {
    for (height, expected_hash) in HEIGHTS {
        let block_bytes = read_fixture(*height, "bin")?;
        let txid_text = String::from_utf8(read_fixture(*height, "txids.txt")?)?;
        let expected_txids = parse_txids(&txid_text)?;
        let bitcoin_block: bitcoin::Block = bitcoin::consensus::deserialize(&block_bytes)?;
        let block = PrimitiveBlock(bitcoin_block);
        let expected_block_hash = Hash256::from_str_be(expected_hash)?;

        assert_eq!(
            block.block_hash(),
            expected_block_hash,
            "height {height} block hash"
        );
        assert_eq!(
            block.0.txdata.len(),
            expected_txids.len(),
            "height {height} tx count"
        );

        for (index, (tx, expected_txid)) in
            block.0.txdata.iter().zip(expected_txids.iter()).enumerate()
        {
            assert_eq!(
                Tx(tx.clone()).txid(),
                *expected_txid,
                "height {height} tx index {index}"
            );
        }
    }
    Ok(())
}

fn read_fixture(height: u32, extension: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = format!("tests/testdata/{height}.{extension}");
    match std::fs::read(&path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(format!("missing {path}; run scripts/fetch-golden.sh to populate testdata").into())
        }
        Err(error) => Err(error.into()),
    }
}

fn parse_txids(txid_text: &str) -> Result<Vec<Hash256>, bitcoin_rs_primitives::HashError> {
    txid_text.lines().map(Hash256::from_str_be).collect()
}
