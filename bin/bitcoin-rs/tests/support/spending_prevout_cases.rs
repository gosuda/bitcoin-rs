//! API-32: public wire observations against the checksum-pinned Core 31.1.

use bitcoin::Sequence;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin_rs_e2e::differential::{compare_rpc, mine_common_chain};
use bitcoin_rs_e2e::{Error, Kind};
use serde_json::{Value, json};

use super::start;

#[test]
fn gettxspendingprevout_tracks_admission_replacement_and_confirmation() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    let funds = mine_common_chain(&mut core, &mut node, 101).expect("common mature funds");
    let prevout = funds.common_outpoints[0];
    let queried_txid = prevout.txid.to_string().to_uppercase();
    let output = json!({"txid": queried_txid, "vout": prevout.vout});
    let unknown = json!({"txid": "00".repeat(32), "vout": 2_147_483_647});
    let outputs = json!([unknown, output, output]);
    assert_eq!(
        compare_rpc(
            &mut core,
            &mut node,
            "gettxspendingprevout",
            &json!([outputs])
        )
        .expect("unspent"),
        outputs,
    );
    for fee in [10_000, 20_000] {
        let tx = funds
            .signed_spend(fee, Sequence::MAX)
            .expect("valid signed spend");
        let raw = serialize_hex(&tx);
        let txid = tx.compute_txid().to_string();
        assert_eq!(
            compare_rpc(&mut core, &mut node, "sendrawtransaction", &json!([raw]))
                .expect("admit or replace"),
            json!(txid),
        );
        let expected = json!([
            unknown,
            {"txid": queried_txid, "vout": prevout.vout, "spendingtxid": txid},
            {"txid": queried_txid, "vout": prevout.vout, "spendingtxid": txid},
        ]);
        for params in [
            json!([outputs]),
            json!({"outputs": outputs}),
            json!({"args": [outputs]}),
            json!({"outputs": outputs, "args": null}),
            json!({"outputs": outputs, "args": 1}),
            json!({"outputs": outputs, "args": {}}),
        ] {
            assert_eq!(
                compare_rpc(&mut core, &mut node, "gettxspendingprevout", &params)
                    .expect("ordered and duplicate queries"),
                expected
            );
        }
        let with_raw = json!([{"txid": queried_txid, "vout": prevout.vout, "spendingtxid": txid, "spendingtx": raw}]);
        for params in [
            json!([[output], {"return_spending_tx": true, "mempool_only": false}]),
            json!({"outputs": [output], "options": {"return_spending_tx": true, "mempool_only": false}}),
            json!({"outputs": [output], "return_spending_tx": true, "mempool_only": false}),
            json!({"args": [[output]], "return_spending_tx": true, "mempool_only": false}),
        ] {
            assert_eq!(
                compare_rpc(&mut core, &mut node, "gettxspendingprevout", &params)
                    .expect("optional full transaction"),
                with_raw
            );
        }
    }
    mine_common_chain(&mut core, &mut node, 1).expect("confirm replacement");
    assert_eq!(
        compare_rpc(
            &mut core,
            &mut node,
            "gettxspendingprevout",
            &json!([outputs])
        )
        .expect("confirmed spender leaves mempool"),
        outputs
    );
    for process in [&mut core, &mut node] {
        let result = process.rpc(
            "gettxspendingprevout",
            &json!([[output], {"mempool_only": false}]),
        );
        assert!(
            matches!(result, Err(Error::Rpc { code: -1, ref message, .. }) if message.contains("txospenderindex is unavailable")),
            "{result:?}"
        );
    }
}

#[test]
fn gettxspendingprevout_parameter_errors_match_pinned_core() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    let txid = "ab".repeat(32);
    let out = json!({"txid": txid, "vout": 0});
    let cases = [
        json!([[]]),
        json!([null]),
        json!([1, []]),
        json!([1]),
        json!([{}]),
        json!([[null]]),
        json!([[1]]),
        json!([[[]]]),
        json!([[{}]]),
        json!([[{"vout": 0}]]),
        json!([[{"txid": txid}]]),
        json!([[{"txid": null, "vout": 0}]]),
        json!([[{"txid": 1, "vout": "bad"}]]),
        json!([[{"txid": txid, "vout": "0"}]]),
        json!([[{"txid": txid, "vout": 0, "extra": 1}]]),
        json!([[{"txid": "abc", "vout": 0}]]),
        json!([[{"txid": "z".repeat(64), "vout": 0}]]),
        json!([[{"txid": txid, "vout": -1}]]),
        json!([[{"txid": txid, "vout": 2_147_483_648_u64}]]),
        json!([[{"txid": txid, "vout": 1.0}]]),
        json!([[{"txid": txid, "vout": 1.5}]]),
        json!([[out], []]),
        json!([[out], true]),
        json!([[out], {"unknown": false}]),
        json!([[out], {"mempool_only": 1}]),
        json!([[out], {"mempool_only": null}]),
        json!([[out], {"return_spending_tx": "yes"}]),
        json!([[out], {"return_spending_tx": null}]),
        json!([[out], {"mempool_only": false}]),
        json!({"outputs": [out], "unknown": false}),
        json!({"outputs": [out], "options": {}, "mempool_only": true}),
        json!({"outputs": [out], "args": [[out]]}),
        json!({"args": [[out], {}], "return_spending_tx": true}),
    ];
    for params in cases {
        let error = |result| match result {
            Err(Error::Rpc { code, message, .. }) => json!({"code": code, "message": message}),
            result => panic!("expected RPC rejection for {params}: {result:?}"),
        };
        let reference: Value = error(core.rpc("gettxspendingprevout", &params));
        let candidate = error(node.rpc("gettxspendingprevout", &params));
        assert_eq!(reference, candidate, "params: {params}");
    }
}
