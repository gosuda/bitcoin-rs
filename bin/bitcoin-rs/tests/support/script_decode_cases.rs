//! Public Core 31.1 script projections, using the existing process custody owner.
use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_e2e::Kind;
use bitcoin_rs_e2e::differential::compare_rpc;
use serde_json::json;

use super::start;

const KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const UNCOMPRESSED: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

fn script_vectors() -> Vec<String> {
    let mut scripts = vec![String::new()];
    scripts.extend((0..=255_u8).map(|opcode| format!("{opcode:02x}")));
    for bytes in [
        "00",
        "80",
        "01",
        "81",
        "0100",
        "0180",
        "000080",
        "ffffff7f",
        "ffffffff",
        "0100000000",
    ] {
        scripts.push(format!("{:02x}{bytes}", bytes.len() / 2));
        scripts.push(format!("4c{:02x}{bytes}", bytes.len() / 2));
    }
    scripts.extend(
        [
            "4c02ff",
            "4d0100",
            "4e01000000",
            "6a51",
            "6a76",
            "01004f5152",
            "0063016861",
        ]
        .map(str::to_owned),
    );
    for len in [520, 521] {
        scripts.push(format!(
            "4d{:02x}{:02x}{}",
            len & 255,
            len >> 8,
            "01".repeat(len)
        ));
    }
    scripts.extend(["61".repeat(10_000), "61".repeat(10_001)]);
    scripts.extend([
        format!("21{KEY}ac"),
        format!("41{UNCOMPRESSED}ac"),
        format!("21{}ac", "00".repeat(33)),
        format!("2102{}ac", "00".repeat(32)),
        format!("4106{}ac", &UNCOMPRESSED[2..]),
        format!("5121{KEY}51ae"),
        format!("5221{KEY}21{KEY}52ae"),
        format!("5221{KEY}41{UNCOMPRESSED}52ae"),
        format!("76a914{}88ac", "11".repeat(20)),
        format!("a914{}87", "22".repeat(20)),
        format!("0014{}", "33".repeat(20)),
        format!("0020{}", "44".repeat(32)),
        format!("5120{}", &KEY[2..]),
        format!("5120{}", "ff".repeat(32)),
        "51024e73".to_owned(),
        format!("5202{}", "55".repeat(2)),
        "00025555".to_owned(),
        format!("6321{KEY}ad670320a107b1756821{KEY}ac"),
        format!("21{KEY}ad5ab2"),
        format!("21{KEY}ad00"),
        format!("21{KEY}ad21{KEY}ac"),
        format!("21{KEY}ad5ab26903000040b2"),
        format!("21{KEY}ac736452b268"),
    ]);
    scripts
}

#[test]
fn decodescript_matches_core_opcode_and_wrapper_matrix() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    let scripts = script_vectors();
    eprintln!(
        "comparing {} script vectors against pinned Core",
        scripts.len()
    );
    for script in scripts {
        let prefix = &script[..script.len().min(96)];
        compare_rpc(&mut core, &mut node, "decodescript", &json!([script])).unwrap_or_else(
            |error| panic!("script {prefix} ({} bytes): {error}", script.len() / 2),
        );
    }
}

#[test]
fn decoded_transaction_uses_the_same_core_script_projection() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    // Strict-DER scalar encodings test formatting only; these are not signatures
    // over a transaction, so no signing or wallet is involved.
    for hash_type in [1_u8, 2, 3, 0x81, 0x82, 0x83, 0, 4] {
        let script_sig =
            bitcoin::ScriptBuf::from_hex(&format!("093006020101020101{hash_type:02x}"))
                .expect("fixed push");
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(
                        [1; 32],
                    )),
                    vout: 0,
                },
                script_sig,
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: script_vectors()
                .into_iter()
                .map(|script| bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1),
                    script_pubkey: bitcoin::ScriptBuf::from_hex(&script).expect("hex script"),
                })
                .collect(),
        };
        let hex = bitcoin::consensus::serialize(&tx).to_lower_hex_string();
        compare_rpc(&mut core, &mut node, "decoderawtransaction", &json!([hex])).unwrap_or_else(
            |error| panic!("transaction script projection sighash {hash_type}: {error}"),
        );
    }
}

#[test]
fn decodescript_addresses_follow_the_selected_network() {
    for (core_chain, network) in [("main", "mainnet"), ("test", "testnet3")] {
        let chain = format!("-chain={core_chain}");
        let mut core = bitcoin_rs_e2e::ProcessNode::spawn_with(
            Kind::Core,
            &bitcoin_rs_e2e::SpawnOptions {
                extra_args: &["-regtest=0", &chain],
                ..Default::default()
            },
        )
        .expect("isolated reference network");
        let config = format!(
            "network = \"{network}\"\np2p_listen = [\"127.0.0.1:0\"]\ndns_seeds_enabled = false\n"
        );
        let mut node = bitcoin_rs_e2e::ProcessNode::spawn_with(
            Kind::BitcoinRs,
            &bitcoin_rs_e2e::SpawnOptions {
                binary: Some(super::self_binary()),
                toml_override: Some(&config),
                ..Default::default()
            },
        )
        .expect("isolated candidate network");
        for script in [
            format!("76a914{}88ac", "11".repeat(20)),
            format!("0014{}", "11".repeat(20)),
            format!("5120{}", &KEY[2..]),
            format!("5121{KEY}51ae"),
            "51024e73".to_owned(),
        ] {
            compare_rpc(&mut core, &mut node, "decodescript", &json!([script]))
                .expect("network-specific address and descriptor");
        }
    }
}

#[test]
fn decodescript_parameter_forms_and_errors_follow_core() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    for params in [
        json!([""]),
        json!(["51"]),
        json!({"hexstring":"51"}),
        json!({"args":["51"]}),
        json!({"hexstring":"51","args":null}),
        json!({"hexstring":"51","args":7}),
        json!([null]),
        json!([false]),
        json!([1]),
        json!([[]]),
        json!([{}]),
        json!(["0"]),
        json!(["zz"]),
        json!([" 51"]),
        json!(["51 "]),
        json!(["0x51"]),
        json!({"hexstring":null}),
        json!({"hexstring":"51","args":["51"]}),
        json!({"hexstring":"51","unknown":0}),
        json!({"other":"51"}),
    ] {
        let request =
            json!({"jsonrpc":"1.0","id":"script-params","method":"decodescript","params":params});
        let reference = core.rpc_raw(&request).expect("Core reply");
        let candidate = node.rpc_raw(&request).expect("candidate reply");
        bitcoin_rs_e2e::differential::compare_reply(
            &format!("decodescript {params}"),
            &reference,
            &candidate,
        )
        .expect("same result or exact parameter error");
    }
    // The compact usage body is an explicit registry deviation. Code and
    // method signature retain Core's invalid-arity behavior.
    for params in [
        json!([]),
        json!(null),
        json!({}),
        json!(["51", 0]),
        json!({"args":["51",0]}),
    ] {
        let request =
            json!({"jsonrpc":"1.0","id":"script-arity","method":"decodescript","params":params});
        let reference = core.rpc_raw(&request).expect("Core usage");
        let candidate = node.rpc_raw(&request).expect("candidate usage");
        assert_eq!(
            reference["error"]["code"], candidate["error"]["code"],
            "{params}"
        );
        assert_eq!(
            reference["error"]["message"]
                .as_str()
                .expect("Core text")
                .lines()
                .next(),
            candidate["error"]["message"].as_str(),
            "{params}"
        );
    }
}

#[test]
fn block_rest_and_utxo_consumers_share_core_output_scripts() {
    let mut core = bitcoin_rs_e2e::ProcessNode::spawn_with(
        Kind::Core,
        &bitcoin_rs_e2e::SpawnOptions {
            extra_args: &["-rest=1"],
            ..Default::default()
        },
    )
    .expect("Core REST");
    let mut node = bitcoin_rs_e2e::ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &bitcoin_rs_e2e::SpawnOptions {
            binary: Some(super::self_binary()),
            extra_args: &["--rest=true"],
            ..Default::default()
        },
    )
    .expect("candidate REST");
    let funds = bitcoin_rs_e2e::differential::mine_common_chain(&mut core, &mut node, 1)
        .expect("same block");
    let hash = core.rpc("getbestblockhash", &json!([])).expect("tip");
    let core_block = core.rpc("getblock", &json!([hash, 2])).expect("Core block");
    let node_block = node
        .rpc("getblock", &json!([hash, 2]))
        .expect("candidate block");
    let output = &core_block["tx"][0]["vout"][0]["scriptPubKey"];
    assert_eq!(output, &node_block["tx"][0]["vout"][0]["scriptPubKey"]);
    let route = format!("/rest/block/{}.json", hash.as_str().expect("hash"));
    let core_rest = core
        .http("GET", &route, &[], false)
        .expect("Core REST block")
        .json()
        .expect("JSON");
    let node_rest = node
        .http("GET", &route, &[], false)
        .expect("candidate REST block")
        .json()
        .expect("JSON");
    assert_eq!(output, &core_rest["tx"][0]["vout"][0]["scriptPubKey"]);
    assert_eq!(output, &node_rest["tx"][0]["vout"][0]["scriptPubKey"]);
    let prevout = funds.common_outpoints[0];
    compare_rpc(
        &mut core,
        &mut node,
        "gettxout",
        &json!([prevout.txid.to_string(), prevout.vout]),
    )
    .expect("shared typed gettxout projection");
}

#[test]
fn invalid_curve_key_in_complex_miniscript_has_a_declared_address_fallback() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    let script = "21020000000000000000000000000000000000000000000000000000000000000000ad5ab2";
    let reference = core
        .rpc("decodescript", &json!([script]))
        .expect("Core inference");
    let mut candidate = node
        .rpc("decodescript", &json!([script]))
        .expect("address fallback");
    // Observed against the pinned Core process: Core permits a syntactically
    // encoded public key here; rust-miniscript refuses its invalid curve point.
    assert_eq!(
        reference["segwit"]["desc"],
        "wsh(and_v(v:pk(020000000000000000000000000000000000000000000000000000000000000000),older(10)))#v8fq6k7d"
    );
    assert_eq!(
        candidate["segwit"]["desc"],
        "addr(bcrt1q3fjqvgur5xvpw3cjg8wdgyv740f9qrkv2pdm90rh7ksk4m4kzqmqqnml0m)#h8p3gsak"
    );
    candidate["segwit"]["desc"] = reference["segwit"]["desc"].clone();
    assert_eq!(
        reference, candidate,
        "only the explicitly declared inference field differs"
    );
}
