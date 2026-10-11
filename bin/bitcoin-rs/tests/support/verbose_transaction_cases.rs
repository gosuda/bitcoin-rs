//! Transaction wire versions through actual accepted blocks and lookup consumers.
use bitcoin::consensus::{deserialize, encode::serialize_hex};
use bitcoin::hex::FromHex as _;
use bitcoin_rs_e2e::differential::{compare_reply, mine_common_chain};
use bitcoin_rs_e2e::helpers::funding_address;
use bitcoin_rs_e2e::{Kind, ProcessNode};
use serde_json::{Value, json};

use super::start;

fn submit_versioned_coinbase(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    version: u32,
) -> (String, String) {
    let template = core
        .rpc(
            "generateblock",
            &json!([funding_address().expect("address").to_string(), [], false]),
        )
        .expect("Core constructs an unsubmitted block");
    let bytes =
        Vec::<u8>::from_hex(template["hex"].as_str().expect("block hex")).expect("Core block hex");
    let mut block: bitcoin::Block = deserialize(&bytes).expect("Core block codec");
    block.txdata[0].version =
        bitcoin::transaction::Version(i32::from_le_bytes(version.to_le_bytes()));
    block.header.merkle_root = block.compute_merkle_root().expect("coinbase merkle root");
    let target = bitcoin::Target::from_compact(block.header.bits);
    assert!(
        (0..1_000_000_u32).any(|nonce| {
            block.header.nonce = nonce;
            target.is_met_by(block.block_hash())
        }),
        "regtest proof-of-work search is bounded"
    );
    let hash = block.block_hash().to_string();
    let txid = block.txdata[0].compute_txid().to_string();
    let raw = serialize_hex(&block);
    for process in [core, node] {
        assert!(
            process
                .rpc("submitblock", &json!([raw]))
                .expect("block submission")
                .is_null()
        );
        assert_eq!(
            process
                .rpc("getbestblockhash", &json!([]))
                .expect("applied tip"),
            hash
        );
    }
    (hash, txid)
}

fn versions(one: &Value, two: &Value, raw: &Value) -> Value {
    json!({
        "block_one_coinbase": one["coinbase_tx"]["version"],
        "block_two_coinbase": two["coinbase_tx"]["version"],
        "block_two_transaction": two["tx"][0]["version"],
        "raw_transaction": raw["version"]
    })
}

fn compare_confirmed_views(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    hash: &str,
    txid: &str,
    version: u32,
) {
    let core_one = core
        .rpc("getblock", &json!([hash, 1]))
        .expect("Core block 1");
    let node_one = node
        .rpc("getblock", &json!([hash, 1]))
        .expect("native block 1");
    let core_two = core
        .rpc("getblock", &json!([hash, 2]))
        .expect("Core block 2");
    let node_two = node
        .rpc("getblock", &json!([hash, 2]))
        .expect("native block 2");
    let core_raw = core
        .rpc("getrawtransaction", &json!([txid, 1, hash]))
        .expect("Core raw");
    let node_raw = node
        .rpc("getrawtransaction", &json!([txid, 1, hash]))
        .expect("native raw");
    let expected = json!({
        "block_one_coinbase": version,
        "block_two_coinbase": version,
        "block_two_transaction": version,
        "raw_transaction": version
    });
    assert_eq!(
        versions(&core_one, &core_two, &core_raw),
        expected,
        "independent Core wire-version observation"
    );
    assert_eq!(
        versions(&node_one, &node_two, &node_raw),
        expected,
        "all native public transaction-version fields"
    );
    for (reference, candidate) in [(&core_one, &node_one), (&core_two, &node_two)] {
        assert_eq!(
            candidate["version"], reference["version"],
            "block-header version keeps its own interpretation"
        );
        assert_eq!(
            candidate["tx"].as_array().expect("transaction array").len(),
            1
        );
        compare_reply(
            "coinbase summary",
            &reference["coinbase_tx"],
            &candidate["coinbase_tx"],
        )
        .expect("all summary fields retained");
    }
    // Coinbase has neither an undo fee nor input prevout. This comparison does
    // not certify the separately unimplemented non-coinbase undo projection.
    compare_reply(
        "nested coinbase transaction",
        &core_two["tx"][0],
        &node_two["tx"][0],
    )
    .expect("transaction identity, bytes and script fields match Core");
    compare_reply("confirmed raw transaction", &core_raw, &node_raw)
        .expect("all explicit-block chain fields match Core");
}

#[test]
fn verbose_transaction_versions_match_core_for_accepted_blocks() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    let funds = mine_common_chain(&mut core, &mut node, 102).expect("mature shared chain");
    let mut last = None;
    for version in [2_u32, 0x8000_0000, u32::MAX] {
        let (hash, txid) = submit_versioned_coinbase(&mut core, &mut node, version);
        compare_confirmed_views(&mut core, &mut node, &hash, &txid, version);
        last = Some((hash, txid));
    }

    let transaction = funds
        .signed_spend(1000, bitcoin::Sequence::MAX)
        .expect("standard control");
    assert_eq!(transaction.version, bitcoin::transaction::Version::TWO);
    let txid = transaction.compute_txid().to_string();
    let raw = serialize_hex(&transaction);
    for process in [&mut core, &mut node] {
        process
            .rpc("sendrawtransaction", &json!([raw]))
            .expect("standard mempool admission");
    }
    let core_unconfirmed = core
        .rpc("getrawtransaction", &json!([txid, 1]))
        .expect("Core mempool");
    let node_unconfirmed = node
        .rpc("getrawtransaction", &json!([txid, 1]))
        .expect("native mempool");
    compare_reply(
        "unconfirmed raw transaction",
        &core_unconfirmed,
        &node_unconfirmed,
    )
    .expect("mempool projection");
    for field in [
        "blockhash",
        "confirmations",
        "time",
        "blocktime",
        "in_active_chain",
    ] {
        assert!(
            node_unconfirmed.get(field).is_none(),
            "mempool omits {field}"
        );
    }

    let (hash, txid) = last.expect("high-bit block");
    for process in [&mut core, &mut node] {
        process
            .rpc("invalidateblock", &json!([hash]))
            .expect("disconnect high-bit block");
    }
    let core_stale = core
        .rpc("getrawtransaction", &json!([txid, 1, hash]))
        .expect("Core stale");
    let node_stale = node
        .rpc("getrawtransaction", &json!([txid, 1, hash]))
        .expect("native stale");
    compare_reply("stale explicit-block transaction", &core_stale, &node_stale)
        .expect("stale metadata retained");
    assert_eq!(node_stale["version"], u32::MAX);
    assert_eq!(node_stale["confirmations"], 0);
    assert_eq!(node_stale["in_active_chain"], false);
    assert!(node_stale.get("time").is_none());
    assert!(node_stale.get("blocktime").is_none());
    core.stop().expect("Core stop");
    node.stop().expect("native stop");
}
