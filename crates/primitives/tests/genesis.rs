//! Native genesis blocks hash to the published per-network genesis identifiers
//! and round-trip the Core `CreateGenesisBlock` serializations compiled into
//! [`Network::genesis_block`].

use bitcoin_rs_primitives::{Network, consensus_bytes};

#[test]
fn native_genesis_matches_published_hash_and_compiled_bytes() {
    let times = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    let cases = [
        (
            Network::Mainnet,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            true,
        ),
        (
            Network::Testnet3,
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            true,
        ),
        (
            Network::Testnet4,
            "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            false,
        ),
        (
            Network::Signet,
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            true,
        ),
        (
            Network::Regtest,
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            true,
        ),
    ];
    for (network, published, has_times) in cases {
        let native = network.genesis_block();
        assert_eq!(
            format!("{}", native.block_hash()),
            published,
            "{network:?} genesis hash diverges from the published identifier"
        );
        assert_eq!(
            format!("{}", network.genesis_block_hash()),
            published,
            "{network:?} compiled genesis hash diverges"
        );
        let bytes = consensus_bytes(&native);
        assert_eq!(
            bitcoin_rs_primitives::Block::consensus_decode(&bytes)
                .unwrap_or_else(|error| panic!("{network:?} genesis must re-decode: {error}")),
            native,
            "{network:?} genesis must round-trip"
        );
        assert_eq!(native.txs.len(), 1, "{network:?} genesis is a single tx");
        assert!(
            native.txs[0].inputs[0].previous_output.is_null(),
            "{network:?} genesis coinbase prevout is null"
        );
        assert_eq!(
            native.txs[0].outputs[0].value, 5_000_000_000,
            "{network:?} genesis subsidy is 50 BTC"
        );
        if has_times {
            assert!(
                native.txs[0].inputs[0]
                    .script_sig
                    .windows(times.len())
                    .any(|window| window == times),
                "{network:?} genesis coinbase must carry the Times message"
            );
        }
    }
}
