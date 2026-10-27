//! Independent Core oracle for the context-free body rules used by verifychain.
//! RPC wiring and read-only daemon behavior remain in their existing owners.
#![expect(
    clippy::expect_used,
    reason = "reference failures must identify the failed fixture step"
)]

use bitcoin_rs_consensus::verify_block::verify_block_non_contextual;
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions};
use serde_json::json;

#[test]
fn coinbase_input_sigop_growth_agrees_with_core() -> Result<(), Box<dyn std::error::Error>> {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let address = bitcoin_rs_e2e::helpers::funding_address()?;
    let hashes = core.rpc("generatetoaddress", &json!([1, address.to_string()]))?;
    let raw = core.rpc("getblock", &json!([hashes[0], 0]))?;
    let original: bitcoin::Block =
        bitcoin::consensus::encode::deserialize_hex(raw.as_str().ok_or("block hex")?)?;
    for opcode in [0xac, 0xae] {
        let mut block = original.clone();
        block.header.prev_blockhash = original.block_hash();
        block.header.time += 1;
        block.txdata[0].output[0].script_pubkey =
            bitcoin::ScriptBuf::from_bytes(vec![0xac; 19_999]);
        let mut script = bitcoin::script::Builder::new()
            .push_int(2)
            .push_int(0)
            .into_bytes();
        script.push(opcode);
        block.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(script);
        block.header.merkle_root = block.compute_merkle_root().ok_or("merkle")?;
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce += 1;
        }
        let bytes = bitcoin::consensus::serialize(&block);
        let native = bitcoin_rs_primitives::deserialize(&bytes)?;
        let result = core.rpc(
            "submitblock",
            &json!([bitcoin::consensus::encode::serialize_hex(&block)]),
        )?;
        let native_verdict = verify_block_non_contextual(&native);
        println!(
            "A Core31.1 opcode={opcode:x} script_len={} weight={} native={:?} core={result}",
            block.txdata[0].input[0].script_sig.len(),
            block.weight().to_wu(),
            native_verdict
        );
        assert_eq!(
            result,
            if opcode == 0xac {
                json!(null)
            } else {
                json!("bad-blk-sigops")
            }
        );
        if opcode == 0xac {
            assert!(
                native_verdict.is_ok(),
                "native validation should accept 0xac: {native_verdict:?}"
            );
        } else {
            assert!(
                matches!(
                    native_verdict,
                    Err(bitcoin_rs_consensus::ConsensusError::SigopsLimit { .. })
                ),
                "native validation should reject 0xae with sigops limit: {native_verdict:?}"
            );
        }
    }
    core.stop()?;
    Ok(())
}

#[test]
fn level_one_body_rules_agree_with_pinned_core_block_rejections() {
    let mut core =
        ProcessNode::spawn_with(Kind::Core, &SpawnOptions::default()).expect("pinned Core process");
    let address = bitcoin_rs_e2e::helpers::funding_address().expect("funding address");
    let hashes = core
        .rpc("generatetoaddress", &json!([1, address.to_string()]))
        .expect("mine fixture");
    let raw = core
        .rpc("getblock", &json!([hashes[0], 0]))
        .expect("reference block bytes");
    let original: bitcoin::Block =
        bitcoin::consensus::encode::deserialize_hex(raw.as_str().expect("hex block"))
            .expect("decode reference block");
    let original_bytes = bitcoin::consensus::serialize(&original);
    let native = bitcoin_rs_primitives::deserialize(&original_bytes).expect("native block decode");
    assert!(verify_block_non_contextual(&native).is_ok());

    for (fault, reason) in [
        ("coinbase length", "bad-cb-length"),
        ("output value", "bad-txns-vout-toolarge"),
        ("duplicate input", "bad-txns-inputs-duplicate"),
        ("legacy sigops", "bad-blk-sigops"),
        ("stripped size", "bad-blk-length"),
    ] {
        let mut block = original.clone();
        match fault {
            "coinbase length" => {
                block.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0]);
            }
            "output value" => {
                block.txdata[0].output[0].value = bitcoin::Amount::from_sat(2_100_000_000_000_001);
            }
            "duplicate input" => {
                let mut spend = block.txdata[0].clone();
                // Distinct from the coinbase, but internally repeats one input.
                spend.input[0].previous_output.vout = 0;
                spend.input.push(spend.input[0].clone());
                block.txdata.push(spend);
            }
            "legacy sigops" => {
                block.txdata[0].output[0].script_pubkey =
                    bitcoin::ScriptBuf::from_bytes(vec![0xac; 20_001]);
            }
            "stripped size" => {
                block.txdata[0].output[0].script_pubkey =
                    bitcoin::ScriptBuf::from_bytes(vec![0; 1_000_000]);
            }
            _ => unreachable!(),
        }
        block.header.merkle_root = block.compute_merkle_root().expect("nonempty fixture");
        block.header.nonce = 0;
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce = block.header.nonce.checked_add(1).expect("regtest PoW");
        }
        let bytes = bitcoin::consensus::serialize(&block);
        let native =
            bitcoin_rs_primitives::deserialize(&bytes).expect("native damaged block decode");
        assert!(verify_block_non_contextual(&native).is_err(), "{fault}");
        assert_eq!(
            core.rpc(
                "submitblock",
                &json!([bitcoin::consensus::encode::serialize_hex(&block)])
            )
            .expect("Core CheckBlock verdict"),
            json!(reason),
            "{fault}: Core must reject the intended rule, not a stale root or invalid PoW"
        );
    }
    core.stop().expect("stop reference process");
}
