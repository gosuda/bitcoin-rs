//! Key-free creation/conversion cases driven through two public processes.

use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_e2e::ProcessNode;
use bitcoin_rs_e2e::differential::compare_reply;
use serde_json::{Value, json};

const ADDRESS: &str = "bcrt1pfeesnyr2tx";

fn creator_cases() -> Vec<(&'static str, Value)> {
    let input = json!({"txid": "11".repeat(32), "vout": 0});
    let output = json!({(ADDRESS): "0.00000001"});
    let mut cases = vec![
        ("minimal", json!([[input], [output]])),
        (
            "transaction id byte order",
            json!([[{"txid": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "vout": 3}], [output]]),
        ),
        ("empty", json!([[], []])),
        ("null inputs", json!([null, []])),
        ("null outputs", json!([[], null])),
        ("named", json!({"inputs": [input], "outputs": [output]})),
        (
            "named version and sequence",
            json!({"inputs": [input], "outputs": [output], "version": 3, "replaceable": false, "locktime": 7}),
        ),
        (
            "args prefix",
            json!({"args": [[input]], "outputs": [output]}),
        ),
        ("missing", json!([])),
        ("extra", json!([[], [], 0, true, 2, 0])),
        ("wrong types", json!([1, [], true, "x"])),
        ("empty input object", json!([[{}], []])),
        ("wrong input element", json!([[true], []])),
        (
            "wrong vout type",
            json!([[{"txid": "11".repeat(32), "vout": true}], []]),
        ),
        (
            "vout overflow",
            json!([[{"txid": "11".repeat(32), "vout": 2_147_483_648_u64}], []]),
        ),
        (
            "negative vout",
            json!([[{"txid": "11".repeat(32), "vout": -1}], []]),
        ),
        (
            "ignored sequence string",
            json!([[{"txid": "11".repeat(32), "vout": 0, "sequence": "x"}], []]),
        ),
        ("duplicate inputs", json!([[input, input], []])),
        ("false locktime", json!([[input], [], 1, false])),
        ("false final", json!([[input], [], 0, false])),
        (
            "true final sequence",
            json!([[{"txid": "11".repeat(32), "vout": 0, "sequence": 4_294_967_295_u64}], [], 0, true]),
        ),
        (
            "false low sequence",
            json!([[{"txid": "11".repeat(32), "vout": 0, "sequence": 1}], [], 0, false]),
        ),
        ("version three", json!([[input], [], 0, true, 3])),
        ("version one", json!([[input], [], 0, null, 1])),
        ("version zero", json!([[input], [], 0, true, 0])),
        ("negative version", json!([[input], [], 0, true, -1])),
        (
            "version decode before locktime",
            json!([[], [], -1, true, -1]),
        ),
        (
            "locktime before version range",
            json!([[], [], -1, true, 0]),
        ),
        ("locktime negative", json!([[], [], -1])),
        ("locktime overflow", json!([[], [], 4_294_967_296_u64])),
    ];
    cases.extend(creator_output_cases(&input, &output));
    cases
}

fn creator_output_cases(input: &Value, output: &Value) -> Vec<(&'static str, Value)> {
    vec![
        ("duplicate output", json!([[], [output, output]])),
        (
            "duplicate output ignores later bad amount",
            json!([[], [output, {(ADDRESS): false}]]),
        ),
        (
            "duplicate data",
            json!([[], [{"data": "12"}, {"data": "zz"}]]),
        ),
        ("wrong output element", json!([[], [1]])),
        (
            "multiple output keys",
            json!([[], [{"data": "12", (ADDRESS): 1}]]),
        ),
        ("wrong amount type", json!([[], {(ADDRESS): true}])),
        ("exponent amount", json!([[], {(ADDRESS): "1e-8"}])),
        ("zero extreme exponent", json!([[], {(ADDRESS): "0e100"}])),
        (
            "fractional satoshi",
            json!([[], {(ADDRESS): "0.000000001"}]),
        ),
        (
            "precise invalid amount",
            json!([[], {(ADDRESS): "1.00000000000000001"}]),
        ),
        ("leading zero", json!([[], {(ADDRESS): "01"}])),
        ("negative amount", json!([[], {(ADDRESS): "-1"}])),
        ("maximum money", json!([[], {(ADDRESS): "21000000"}])),
        (
            "above maximum money",
            json!([[], {(ADDRESS): "21000000.00000001"}]),
        ),
        (
            "amount before invalid address",
            json!([[], {"invalid": "bad amount"}]),
        ),
        ("invalid address", json!([[], {"invalid": 1}])),
        ("data number", json!([[], {"data": 12}])),
        ("data true", json!([[], {"data": true}])),
        ("data empty", json!([[], {"data": ""}])),
        ("data invalid", json!([[], {"data": "zz"}])),
        (
            "output ordering",
            json!([[input], [{"data": "1234"}, output]]),
        ),
    ]
}

pub(super) fn creation(core: &mut ProcessNode, node: &mut ProcessNode) {
    for method in ["createpsbt", "createrawtransaction"] {
        for (name, params) in creator_cases() {
            let request = json!({"jsonrpc": "2.0", "id": name, "method": method, "params": params});
            let reference = core.rpc_raw(&request).expect("Core creator request");
            let candidate = node.rpc_raw(&request).expect("candidate creator request");
            if ["missing", "extra"].contains(&name) {
                // Declared deviation: Core returns full help; this node
                // returns concise usage text with the same -1 code.
                assert_eq!(reference.pointer("/error/code"), Some(&json!(-1)));
                assert_eq!(candidate.pointer("/error/code"), Some(&json!(-1)));
            } else {
                compare_reply(&request.to_string(), &reference, &candidate)
                    .expect("creator result/error matches Core");
            }
        }
    }
    for amount in [
        "1.00000000000000001",
        "1e-8",
        "21000000.000000001",
        "1e-9",
        "-0",
        "0e100",
        "1.0",
        "1e999",
    ] {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":"decimal","method":"createpsbt","params":[[],{{"{ADDRESS}":{amount}}}]}}"#
        );
        let reference = core
            .http("POST", "/", body.as_bytes(), true)
            .expect("Core numeric spelling")
            .json()
            .expect("Core JSON");
        let candidate = node
            .http("POST", "/", body.as_bytes(), true)
            .expect("candidate numeric spelling")
            .json()
            .expect("candidate JSON");
        compare_reply(&body, &reference, &candidate).expect("exact numeric amount matches Core");
    }
    for integer in ["1.0", "1e0", "2147483648", "-0"] {
        let txid = "11".repeat(32);
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":"integer","method":"createpsbt","params":[[{{"txid":"{txid}","vout":{integer}}}],{{}}]}}"#
        );
        let reference = core
            .http("POST", "/", body.as_bytes(), true)
            .expect("Core integer spelling")
            .json()
            .expect("Core JSON");
        let candidate = node
            .http("POST", "/", body.as_bytes(), true)
            .expect("candidate integer spelling")
            .json()
            .expect("candidate JSON");
        compare_reply(&body, &reference, &candidate)
            .expect("integer lexical contract matches Core");
    }
    // Keeping raw decimal text must not turn the request decoder into a
    // streaming parser that accepts trailing JSON after the first value.
    let trailing = br#"{"jsonrpc":"2.0","id":1,"method":"createpsbt","params":[[],{}]} null"#;
    for process in [core, node] {
        let reply = process
            .http("POST", "/", trailing, true)
            .expect("trailing JSON request")
            .json()
            .expect("error JSON");
        assert_eq!(reply.pointer("/error/code"), Some(&json!(-32700)));
    }
}

fn exact(core: &mut ProcessNode, node: &mut ProcessNode, method: &str, params: Value) {
    let mut request = json!({"jsonrpc": "2.0", "id": "conversion", "method": method});
    request["params"] = params;
    let reference = core.rpc_raw(&request).expect("Core conversion request");
    let candidate = node
        .rpc_raw(&request)
        .expect("candidate conversion request");
    compare_reply(&request.to_string(), &reference, &candidate)
        .expect("conversion result/error matches Core");
}

pub(super) fn conversion(core: &mut ProcessNode, node: &mut ProcessNode) {
    let raw = core
        .rpc(
            "createrawtransaction",
            &json!([
                [{"txid": "11".repeat(32), "vout": 0}], {(ADDRESS): "0.00000001"}
            ]),
        )
        .expect("Core unsigned transaction");
    let unsigned: bitcoin::Transaction =
        bitcoin::consensus::encode::deserialize_hex(raw.as_str().expect("raw hex"))
            .expect("independent transaction fixture");
    let mut variants = vec![unsigned.clone()];
    for (script_sig, witness) in [(true, false), (false, true), (true, true)] {
        let mut tx = unsigned.clone();
        // Nonempty data is enough to exercise permitsigdata; no signing or
        // private key material is needed or generated by this scenario.
        if script_sig {
            tx.input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        }
        if witness {
            tx.input[0].witness.push([0x01]);
        }
        variants.push(tx);
    }
    for tx in variants {
        let raw = bitcoin::consensus::serialize(&tx).to_lower_hex_string();
        for iswitness in [Value::Null, json!(false), json!(true)] {
            for permitsigdata in [Value::Null, json!(false), json!(true)] {
                exact(
                    core,
                    node,
                    "converttopsbt",
                    json!([raw, permitsigdata, iswitness]),
                );
            }
            exact(core, node, "decoderawtransaction", json!([raw, iswitness]));
        }
    }
    let zero_input = core
        .rpc(
            "createrawtransaction",
            &json!([[], {(ADDRESS): "0.00000001"}]),
        )
        .expect("Core legacy zero-input transaction");
    for iswitness in [Value::Null, json!(false), json!(true)] {
        exact(
            core,
            node,
            "converttopsbt",
            json!([zero_input, false, iswitness]),
        );
        exact(
            core,
            node,
            "decoderawtransaction",
            json!([zero_input, iswitness]),
        );
    }
    exact(
        core,
        node,
        "decoderawtransaction",
        json!({"hexstring": zero_input, "iswitness": false}),
    );
    for params in [
        json!([""]),
        json!(["zz"]),
        json!([1, "a", 1]),
        json!({"hexstring": zero_input, "permitsigdata": null, "iswitness": false}),
    ] {
        exact(core, node, "converttopsbt", params);
    }
    for (method, params) in [
        ("converttopsbt", json!([])),
        ("converttopsbt", json!(["00", false, false, false])),
        ("decoderawtransaction", json!([])),
        ("decoderawtransaction", json!(["00", false, false])),
    ] {
        let request = json!({"jsonrpc": "2.0", "id": "arity", "method": method, "params": params});
        for process in [&mut *core, &mut *node] {
            let reply = process.rpc_raw(&request).expect("arity failure");
            assert_eq!(reply.pointer("/error/code"), Some(&json!(-1)));
        }
    }
    let trailing = format!("{}00", raw.as_str().expect("raw hex"));
    exact(core, node, "converttopsbt", json!([trailing, true]));
    conversion_preserves_wire_integers(core, node, &unsigned);
    ambiguous_serializations(core, node, unsigned);
}

/// Conversion preserves arbitrary transaction version/amount wire bits; it
/// does not apply creator `MoneyRange` or mempool/consensus admission rules.
fn conversion_preserves_wire_integers(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    template: &bitcoin::Transaction,
) {
    for version in [i32::MIN, -1, 0, 1, 2, 3, i32::MAX] {
        for amount in [0, 1, 2_100_000_000_000_000, 1_u64 << 63, u64::MAX] {
            let mut tx = template.clone();
            tx.version = bitcoin::transaction::Version(version);
            tx.output[0].value = bitcoin::Amount::from_sat(amount);
            let hex = bitcoin::consensus::serialize(&tx).to_lower_hex_string();
            exact(core, node, "converttopsbt", json!([hex]));
        }
    }
}

/// One byte image can represent either a witness transaction or a legacy
/// zero-input transaction. The sole native parser selects each wire mode;
/// Core independently decides which script-sanity interpretation wins.
fn ambiguous_serializations(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    mut tx: bitcoin::Transaction,
) {
    tx.output.clear();
    tx.input[0].sequence = bitcoin::Sequence::ZERO;
    tx.input[0].witness.push([0x00]);
    for (input_opcode, legacy_opcode) in [(0xff, 0x00), (0x00, 0x00), (0xff, 0xff)] {
        let mut txid = [0_u8; 32];
        txid[7] = 38; // Legacy script length in this 57-byte witness image.
        txid[8] = legacy_opcode;
        tx.input[0].previous_output.txid = bitcoin::Txid::from_byte_array(txid);
        tx.input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![input_opcode]);
        let bytes = bitcoin::consensus::serialize(&tx);
        assert_eq!(bytes.len(), 57);
        let hex = bytes.to_lower_hex_string();
        for iswitness in [Value::Null, json!(false), json!(true)] {
            exact(core, node, "converttopsbt", json!([hex, true, iswitness]));
            exact(core, node, "decoderawtransaction", json!([hex, iswitness]));
        }
    }
}
