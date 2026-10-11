//! API-03: canonical POST bytes agree with pinned Core GET, including coins.
//! Core 31.1's POST parser prepends a string length and shifts the fields;
//! that independently observed mismatch is intentionally retained as a gap.

#![expect(
    clippy::expect_used,
    reason = "reference failures identify the exact wire contract"
)]

use std::path::Path;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::{BlockHash, OutPoint, Sequence, TxOut, Txid};
use bitcoin_rs_e2e::differential::{compare_rpc, mine_common_chain};
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions};
use serde_json::json;

fn start(kind: Kind) -> ProcessNode {
    let rest = if kind == Kind::Core {
        "-rest=1"
    } else {
        "--rest=true"
    };
    ProcessNode::spawn_with(
        kind,
        &SpawnOptions {
            binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
            extra_args: &[rest],
            ..Default::default()
        },
    )
    .expect("isolated REST node; Core binary must match the release digest")
}

fn request_body(check: bool, points: &[OutPoint]) -> Vec<u8> {
    // Write the intended protocol directly, independently of the candidate's
    // request parser. This vector is deliberately small enough for one byte.
    let mut body = vec![
        u8::from(check),
        u8::try_from(points.len()).expect("bounded count"),
    ];
    for point in points {
        body.extend_from_slice(&point.txid.to_byte_array());
        body.extend_from_slice(&point.vout.to_le_bytes());
    }
    body
}

fn expected_response(height: u32, tip: BlockHash, coins: &[Option<(u32, TxOut)>]) -> Vec<u8> {
    let mut body = height.to_le_bytes().to_vec();
    body.extend_from_slice(&tip.to_byte_array());
    let mut bitmap = vec![0_u8; coins.len().div_ceil(8)];
    for (i, coin) in coins.iter().enumerate() {
        if coin.is_some() {
            bitmap[i / 8] |= 1 << (i % 8);
        }
    }
    body.push(u8::try_from(bitmap.len()).expect("small bitmap"));
    body.extend(bitmap);
    body.push(u8::try_from(coins.iter().flatten().count()).expect("small coin count"));
    for (coin_height, output) in coins.iter().flatten() {
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.extend_from_slice(&coin_height.to_le_bytes());
        body.extend_from_slice(&output.value.to_sat().to_le_bytes());
        body.push(u8::try_from(output.script_pubkey.len()).expect("P2PKH script"));
        body.extend_from_slice(output.script_pubkey.as_bytes());
    }
    body
}

fn check_lookup(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    points: &[OutPoint],
    without_pool: &[Option<(u32, TxOut)>],
    with_pool: &[Option<(u32, TxOut)>],
) {
    let tip = compare_rpc(core, node, "getbestblockhash", &json!([])).expect("same applied tip");
    let hash: BlockHash = tip.as_str().expect("tip hex").parse().expect("block hash");
    let height = core
        .rpc("getblockcount", &json!([]))
        .expect("height")
        .as_u64()
        .expect("height number");
    for (check, coins) in [(false, without_pool), (true, with_pool)] {
        let expected = expected_response(u32::try_from(height).expect("height"), hash, coins);
        let path_points = points
            .iter()
            .map(|p| format!("{}-{}", p.txid, p.vout))
            .collect::<Vec<_>>()
            .join("/");
        for format in ["bin", "hex"] {
            let get_path = format!(
                "/rest/getutxos/{}{path_points}.{format}",
                if check { "checkmempool/" } else { "" }
            );
            let post_path = format!("/rest/getutxos.{format}");
            let canonical = request_body(check, points);
            let body = if format == "hex" {
                canonical.to_lower_hex_string().into_bytes()
            } else {
                canonical
            };
            let expected = if format == "hex" {
                format!("{}\n", expected.to_lower_hex_string()).into_bytes()
            } else {
                expected.clone()
            };
            let reference = core.http_get(&get_path).expect("Core GET");
            assert_eq!(reference.status, 200);
            assert_eq!(
                reference.body, expected,
                "independent coin/bitmap wire fixture"
            );
            let get = node.http_get(&get_path).expect("candidate GET");
            let post = node
                .http("POST", &post_path, &body, false)
                .expect("candidate POST");
            for response in [&get, &post] {
                assert_eq!(response.status, 200);
                assert_eq!(response.body, reference.body, "{get_path}");
                assert!(
                    !response
                        .headers
                        .iter()
                        .any(|(name, _)| name == "access-control-allow-origin")
                );
            }
            let broken = core
                .http("POST", &post_path, &body, false)
                .expect("pinned Core POST gap");
            assert_eq!(broken.status, 200);
            let bytes = if format == "hex" {
                Vec::<u8>::from_hex(broken.text().expect("hex text").trim()).expect("hex bytes")
            } else {
                broken.body
            };
            assert_eq!(
                &bytes[..36],
                &expected_response(u32::try_from(height).expect("height"), hash, &[])[..36]
            );
            assert_eq!(
                &bytes[36..],
                if check { &[1, 0, 0][..] } else { &[0, 0][..] },
                "Core 31.1 string prefix shifts bool/count"
            );
        }
    }
    assert_eq!(
        compare_rpc(core, node, "getbestblockhash", &json!([])).expect("unchanged tip"),
        tip
    );
}

#[test]
fn canonical_getutxos_post_matches_core_get_and_exposes_core_post_gap() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    let funds = mine_common_chain(&mut core, &mut node, 101).expect("same mature reference blocks");
    let (first, first_output) = funds.confirmed_output(0).expect("first coinbase");
    let (second, second_output) = funds.confirmed_output(1).expect("second coinbase");
    let unknown = OutPoint::new(Txid::from_byte_array([0x11; 32]), u32::MAX);
    let initial = [
        Some((1, first_output.clone())),
        None,
        Some((1, first_output)),
    ];
    check_lookup(
        &mut core,
        &mut node,
        &[first, unknown, first],
        &initial,
        &initial,
    );

    let spend = funds
        .signed_spend(10_000, Sequence::MAX)
        .expect("test funding spend");
    compare_rpc(
        &mut core,
        &mut node,
        "sendrawtransaction",
        &json!([serialize_hex(&spend)]),
    )
    .expect("same public admission");
    let created = OutPoint::new(spend.compute_txid(), 0);
    let created_output = spend.output[0].clone();
    let (_, first_output) = funds.confirmed_output(0).expect("first coinbase");
    let without_pool = [
        Some((1, first_output)),
        None,
        Some((2, second_output.clone())),
        None,
        None,
    ];
    let with_pool = [
        None,
        Some((0x7fff_ffff, created_output.clone())),
        Some((2, second_output.clone())),
        None,
        Some((0x7fff_ffff, created_output.clone())),
    ];
    let points = [first, created, second, unknown, created];
    check_lookup(&mut core, &mut node, &points, &without_pool, &with_pool);

    mine_common_chain(&mut core, &mut node, 1).expect("confirm spend in same block");
    let confirmed = [
        None,
        Some((102, created_output.clone())),
        Some((2, second_output)),
        None,
        Some((102, created_output)),
    ];
    check_lookup(&mut core, &mut node, &points, &confirmed, &confirmed);
    let json_get = node
        .http_get(&format!(
            "/rest/getutxos/checkmempool/{}-{}.json",
            created.txid, created.vout
        ))
        .expect("GET JSON");
    assert_eq!(json_get.status, 200);
    assert_eq!(
        json_get.json().expect("coins JSON")["utxos"][0]["height"],
        json!(102)
    );

    let fifteen = request_body(true, &[second; 15]);
    let response = node
        .http("POST", "/rest/getutxos.bin", &fifteen, false)
        .expect("15 points");
    assert_eq!(response.status, 200);
    assert_eq!(&response.body[36..39], &[2, 255, 127]);
    let core_gap = core
        .http("POST", "/rest/getutxos.bin", &fifteen, false)
        .expect("Core 15-point gap");
    assert_eq!(core_gap.status, 400);
    assert_eq!(core_gap.body, b"Parse error\r\n");
    for bad in [vec![0, 16], vec![0, 0, 0], vec![0; 2_049]] {
        assert_eq!(
            node.http("POST", "/rest/getutxos.bin", &bad, false)
                .expect("bad body")
                .status,
            400
        );
    }
    core.stop().expect("reap Core");
    node.stop().expect("reap candidate");
}
