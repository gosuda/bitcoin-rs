#![expect(
    clippy::expect_used,
    reason = "reference failures must identify the failed fixture step"
)]

use bitcoin::hashes::Hash;
use bitcoin_rs_consensus::verify_block::verify_block_non_contextual;
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions};
use sonic_rs::{JsonValueTrait as _, json};

use crate::support::TestError;

type Result<T = ()> = std::result::Result<T, TestError>;

#[test]
fn coinbase_input_sigop_growth_agrees_with_core() -> Result<()> {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let address = bitcoin_rs_e2e::helpers::funding_address()?;
    let hashes = core.rpc("generatetoaddress", &json!([1, address.to_string()]))?;
    let raw = core.rpc("getblock", &json!([hashes[0], 0]))?;
    let original: bitcoin::Block = bitcoin::consensus::encode::deserialize_hex(
        raw.as_str().ok_or(TestError::Missing("block hex"))?,
    )?;
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
        block.header.merkle_root = block
            .compute_merkle_root()
            .ok_or(TestError::Missing("merkle"))?;
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
        ("coinbase empty outputs", "bad-txns-vout-empty"),
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
            "coinbase empty outputs" => {
                block.txdata[0].output.clear();
            }
            "output value" => {
                block.txdata[0].output[0].value = bitcoin::Amount::from_sat(2_100_000_000_000_001);
            }
            "duplicate input" => {
                let mut spend = block.txdata[0].clone();
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

fn spawn_consensus_pair() -> Result<(ProcessNode, ProcessNode)> {
    let core = ProcessNode::spawn_with(Kind::Core, &SpawnOptions::default())?;
    let node = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(std::path::Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
            ..SpawnOptions::default()
        },
    )?;
    Ok((core, node))
}

fn regtest_genesis() -> bitcoin::Block {
    bitcoin::constants::genesis_block(bitcoin::Network::Regtest)
}

fn mine(mut header: bitcoin::block::Header) -> bitcoin::block::Header {
    header.nonce = 0;
    while header.validate_pow(header.target()).is_err() {
        header.nonce = header.nonce.checked_add(1).expect("regtest PoW");
    }
    header
}

fn genesis_child_block(txdata: Vec<bitcoin::Transaction>) -> bitcoin::Block {
    let genesis = regtest_genesis();
    let mut block = bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: genesis.block_hash(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: genesis.header.time.checked_add(600).expect("regtest time"),
            bits: genesis.header.bits,
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block.compute_merkle_root().expect("nonempty fixture");
    block.header = mine(block.header);
    block
}

fn coinbase_tx(
    script_sig: Vec<u8>,
    witness: bitcoin::Witness,
    outputs: Vec<bitcoin::TxOut>,
) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::from_bytes(script_sig),
            sequence: bitcoin::Sequence::MAX,
            witness,
        }],
        output: outputs,
    }
}

fn submit(node: &mut ProcessNode, block: &bitcoin::Block) -> Result<sonic_rs::Value> {
    Ok(node.rpc(
        "submitblock",
        &json!([bitcoin::consensus::encode::serialize_hex(block)]),
    )?)
}

#[test]
fn wrong_merkle_two_coinbase_body_is_a_merkle_failure_and_keeps_the_header() -> Result<()> {
    let (mut core, mut node) = spawn_consensus_pair()?;
    let coinbase = coinbase_tx(
        vec![0x02, 0x00],
        bitcoin::Witness::new(),
        vec![bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    );
    let real = genesis_child_block(vec![coinbase.clone()]);
    let mut damaged = real.clone();
    let mut second = coinbase;
    second.input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0x02, 0x01]);
    damaged.txdata.push(second);

    let core_reason = submit(&mut core, &damaged)?;
    assert_eq!(
        core_reason,
        json!("bad-txnmrklroot"),
        "Core CheckBlock judges the merkle root before the coinbase count"
    );
    let node_reason = submit(&mut node, &damaged)?;
    assert_eq!(
        node_reason, core_reason,
        "the node must report Core's first failing body check, not the later coinbase count"
    );

    let real_verdict = submit(&mut node, &real)?;
    assert!(
        real_verdict.is_null(),
        "the real body for the same header must stay admissible: {real_verdict}"
    );
    core.stop()?;
    node.stop()?;
    Ok(())
}

#[test]
fn over_weight_body_with_duplicate_inputs_names_the_transaction_failure() -> Result<()> {
    let (mut core, mut node) = spawn_consensus_pair()?;
    let reserved = [0_u8; 32];
    let placeholder = {
        let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        script.extend_from_slice(&[0_u8; 32]);
        bitcoin::ScriptBuf::from_bytes(script)
    };
    let coinbase = coinbase_tx(
        vec![0x02, 0x00],
        bitcoin::Witness::from_slice(&[reserved]),
        vec![
            bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0_u8; 900_000]),
            },
            bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: placeholder,
            },
        ],
    );
    let duplicated = bitcoin::TxIn {
        previous_output: bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([9_u8; 32]),
            vout: 0,
        },
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::from_slice(&[vec![7_u8; 400_000]]),
    };
    let spend = bitcoin::Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![duplicated.clone(), duplicated],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };
    let mut txs = vec![coinbase, spend];
    let witness_root = bitcoin::Block {
        header: regtest_genesis().header,
        txdata: txs.clone(),
    }
    .witness_root()
    .ok_or(TestError::Missing("witness root"))?;
    let commitment = bitcoin::block::Block::compute_witness_commitment(&witness_root, &reserved);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(commitment.as_byte_array());
    txs[0].output[1].script_pubkey = bitcoin::ScriptBuf::from_bytes(script);
    let block = genesis_child_block(txs);

    assert!(
        block.weight().to_wu() > 4_000_000,
        "the fixture must exceed the block weight limit"
    );
    let stripped = 80
        + 1
        + block
            .txdata
            .iter()
            .map(bitcoin::Transaction::base_size)
            .sum::<usize>();
    assert!(
        stripped * 4 <= 4_000_000,
        "the fixture must stay under the stripped size limit so the weight is the only size fault"
    );

    let core_reason = submit(&mut core, &block)?;
    assert_eq!(
        core_reason,
        json!("bad-txns-inputs-duplicate"),
        "Core CheckTransaction reports duplicated inputs before its weight limit"
    );
    let node_reason = submit(&mut node, &block)?;
    assert_eq!(
        node_reason, core_reason,
        "the node must report Core's transaction failure, not the later weight limit"
    );
    core.stop()?;
    node.stop()?;
    Ok(())
}

#[test]
fn stripped_size_body_names_the_size_limit() -> Result<()> {
    let (mut core, mut node) = spawn_consensus_pair()?;
    let coinbase = coinbase_tx(
        vec![0x02, 0x00],
        bitcoin::Witness::new(),
        vec![bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0_u8; 1_000_000]),
        }],
    );
    let block = genesis_child_block(vec![coinbase]);
    assert!(
        block.weight().to_wu() > 4_000_000,
        "the fixture must also exceed the block weight limit"
    );

    let core_reason = submit(&mut core, &block)?;
    assert_eq!(
        core_reason,
        json!("bad-blk-length"),
        "Core CheckBlock reports the stripped size limit before the weight limit"
    );
    let node_reason = submit(&mut node, &block)?;
    assert_eq!(
        node_reason, core_reason,
        "the node must report Core's stripped size limit, not the later weight limit"
    );
    core.stop()?;
    node.stop()?;
    Ok(())
}
