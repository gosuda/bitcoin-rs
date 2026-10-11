//! BIP133 and delayed inventory observed over real bitcoin-rs and Core sockets.
use bitcoin::p2p::{message::NetworkMessage, message_blockdata::Inventory};
use bitcoin_rs_e2e::helpers::{
    coinbase_at, funding_address, funding_output, signed_spend, submit_genesis, tx_hex,
};
use bitcoin_rs_e2e::live_peer::LivePeer;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result};
use serde_json::json;
use std::time::{Duration, Instant};

fn seen(peer: &LivePeer, hash: &str) -> bool {
    peer.inventory_seen.iter().any(|item| match item {
        Inventory::Transaction(id) | Inventory::WitnessTransaction(id) => id.to_string() == hash,
        Inventory::WTx(id) => id.to_string() == hash,
        _ => false,
    })
}

fn scenario(kind: Kind) -> Result<()> {
    let mut node = ProcessNode::spawn(kind)?;
    if kind == Kind::Core {
        node.rpc("setmocktime", &json!([0]))?;
    }
    if kind == Kind::BitcoinRs {
        submit_genesis(&mut node)?;
    }
    node.rpc(
        "generatetoaddress",
        &json!([101, funding_address()?.to_string()]),
    )?;
    let (first, first_output) = funding_output(&coinbase_at(&mut node, 1)?)?;
    let (second, second_output) = funding_output(&coinbase_at(&mut node, 2)?)?;
    let mut peers = [
        LivePeer::connect_with_height(&node, "fee-filtered", 0)?,
        LivePeer::connect_with_height(&node, "fee-open", 0)?,
    ];
    peers[0].send(
        NetworkMessage::FeeFilter(20_000),
        Instant::now() + Duration::from_secs(2),
    )?;
    peers[1].send(
        NetworkMessage::FeeFilter(0),
        Instant::now() + Duration::from_secs(2),
    )?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let infos = node.rpc("getpeerinfo", &json!([]))?;
        if infos.as_array().is_some_and(|rows| {
            rows.iter()
                .any(|row| row["minfeefilter"].as_f64() == Some(0.0002))
        }) {
            break;
        }
        if Instant::now() >= deadline {
            return Err(Error::Assertion(
                "received feefilter was not applied".into(),
            ));
        }
        for peer in &mut peers {
            peer.pump(Duration::from_millis(20), &mut |_, _| {});
        }
    }
    let low = signed_spend(first, &first_output, 1_000, bitcoin::Sequence::MAX)?;
    let high = signed_spend(second, &second_output, 10_000, bitcoin::Sequence::MAX)?;
    let low_id = low.compute_txid().to_string();
    let high_id = high.compute_txid().to_string();
    node.rpc("sendrawtransaction", &json!([tx_hex(&low)]))?;
    node.rpc("sendrawtransaction", &json!([tx_hex(&high)]))?;
    let deadline = Instant::now() + Duration::from_secs(90);
    while !(seen(&peers[0], &high_id) && seen(&peers[1], &high_id) && seen(&peers[1], &low_id)) {
        for peer in &mut peers {
            peer.pump(Duration::from_millis(20), &mut |_, _| {});
        }
        if Instant::now() >= deadline {
            return Err(Error::Assertion(
                "fee-aware relay did not reach eligible peers".into(),
            ));
        }
    }
    // Keep observing after successful deliveries through another complete
    // native relay window (30-second ceiling plus polling allowance). Core uses
    // an uncapped exponential clock; this is a finite observation there too,
    // not a claim that Core has the same deadline or cannot relay later.
    let observation_deadline = Instant::now() + Duration::from_secs(31);
    loop {
        assert!(
            !seen(&peers[0], &low_id),
            "below-filter transaction was announced"
        );
        if Instant::now() >= observation_deadline {
            break;
        }
        for peer in &mut peers {
            peer.pump(Duration::from_millis(20), &mut |_, _| {});
            assert!(!peer.dropped, "relay observation peer disconnected");
        }
    }
    let info = node.rpc("getmempoolinfo", &json!([]))?;
    assert_eq!(info["size"], 2, "peer filters must not alter admission");
    let minimum = bitcoin::Amount::from_btc(
        info["minrelaytxfee"]
            .as_f64()
            .ok_or_else(|| Error::Assertion("missing minrelaytxfee".into()))?,
    )
    .map_err(|error| Error::Assertion(error.to_string()))?
    .to_sat();
    for peer in &peers {
        assert!(
            !peer.fee_filters_seen.is_empty(),
            "node never advertised its relay floor"
        );
        for rate in &peer.fee_filters_seen {
            let rate = u64::try_from(*rate).map_err(|error| Error::Assertion(error.to_string()))?;
            assert!(
                rate >= minimum,
                "advertised filter below configured minimum"
            );
        }
    }
    node.stop()
}

#[test]
fn fee_filter_relay_matches_core_at_the_wire_boundary() -> Result<()> {
    scenario(Kind::BitcoinRs)?;
    scenario(Kind::Core)
}
