#![expect(
    clippy::expect_used,
    reason = "a failed fixture expectation must stop this test module"
)]

use std::{
    io::Cursor,
    path::{Path, PathBuf},
    process::Command,
};

use bitcoin::{
    Amount, Block, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
    absolute::LockTime,
    block::{Header, Version as BlockVersion},
    consensus::encode::serialize_hex,
    hashes::Hash as _,
    transaction::Version,
};
use bitcoin_rs_p2pk_scan::{KeyShape, P2pkCoin, ScanError, p2pk_pubkey, scan_blocks};
use sonic_rs::JsonValueTrait as _;

const KEY_A: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const KEY_B: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const KEY_UNCOMPRESSED: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
const KEY_NOT_ON_CURVE: &str = "02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const KEY_WRONG_PREFIX: &str = "091111111111111111111111111111111111111111111111111111111111111111";

const SUBSIDY_SAT: u64 = 50 * 100_000_000;
const UNSPENT_COMPRESSED_SAT: u64 = 5_000;
const UNSPENT_UNCOMPRESSED_SAT: u64 = 6_000;
const SPENT_SAT: u64 = 7_000;
const P2PKH_SAT: u64 = 4_000;
const P2SH_SAT: u64 = 3_000;
const MULTISIG_SAT: u64 = 2_000;
const WRONG_PREFIX_SAT: u64 = 1_500;
const NOT_ON_CURVE_SAT: u64 = 9_000;
const SAME_BLOCK_SAT: u64 = 4_000;

const FUNDING_HEIGHT: u32 = 101;
const TIP_HEIGHT: u32 = 102;

fn bytes(hex: &str) -> Vec<u8> {
    bitcoin_rs_primitives::hex::hex_decode(hex).expect("fixture hex is valid")
}

fn p2pk(pubkey: &str) -> ScriptBuf {
    let key = bytes(pubkey);
    let mut script = Vec::with_capacity(key.len() + 2);
    script.push(u8::try_from(key.len()).expect("fixture key is at most 65 bytes"));
    script.extend_from_slice(&key);
    script.push(0xac);
    ScriptBuf::from_bytes(script)
}

fn p2pkh() -> ScriptBuf {
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&[0x11; 20]);
    script.extend_from_slice(&[0x88, 0xac]);
    ScriptBuf::from_bytes(script)
}

fn p2sh() -> ScriptBuf {
    let mut script = vec![0xa9, 0x14];
    script.extend_from_slice(&[0x22; 20]);
    script.push(0x87);
    ScriptBuf::from_bytes(script)
}

fn bare_multisig() -> ScriptBuf {
    let mut script = vec![0x51, 0x21];
    script.extend_from_slice(&bytes(KEY_A));
    script.extend_from_slice(&[0x51, 0xae]);
    ScriptBuf::from_bytes(script)
}

fn output(value_sat: u64, script: ScriptBuf) -> TxOut {
    TxOut {
        value: Amount::from_sat(value_sat),
        script_pubkey: script,
    }
}

fn coinbase(height: u32, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(height.to_le_bytes().to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: outputs,
    }
}

fn spend(previous_output: OutPoint, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: outputs,
    }
}

fn next_block(previous: &Block, height: u32, txdata: Vec<Transaction>) -> Block {
    let mut block = Block {
        header: Header {
            version: BlockVersion::ONE,
            prev_blockhash: previous.block_hash(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_600_000_000 + 600 * height,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .expect("fixture blocks are non-empty");
    block
}

struct Chain {
    lines: Vec<String>,
    funding: Txid,
}

fn fixture_chain() -> Chain {
    build_fixture(None)
}

fn fixture_chain_with_non_curve_key() -> Chain {
    build_fixture(Some(output(NOT_ON_CURVE_SAT, p2pk(KEY_NOT_ON_CURVE))))
}

fn build_fixture(extra_output: Option<TxOut>) -> Chain {
    let genesis = bitcoin::constants::genesis_block(Network::Regtest);
    let mut blocks = vec![genesis.clone()];
    let mut previous = genesis;

    for height in 1..=100 {
        let block = next_block(
            &previous,
            height,
            vec![coinbase(height, vec![output(SUBSIDY_SAT, p2pkh())])],
        );
        previous = block.clone();
        blocks.push(block);
    }

    let mut funding_outputs = vec![
        output(UNSPENT_COMPRESSED_SAT, p2pk(KEY_A)),
        output(UNSPENT_UNCOMPRESSED_SAT, p2pk(KEY_UNCOMPRESSED)),
        output(SPENT_SAT, p2pk(KEY_B)),
        output(P2PKH_SAT, p2pkh()),
        output(P2SH_SAT, p2sh()),
        output(MULTISIG_SAT, bare_multisig()),
        output(WRONG_PREFIX_SAT, p2pk(KEY_WRONG_PREFIX)),
    ];
    if let Some(extra) = extra_output {
        funding_outputs.push(extra);
    }
    let funding = spend(
        OutPoint::new(blocks[1].txdata[0].compute_txid(), 0),
        funding_outputs,
    );
    let funding_txid = funding.compute_txid();
    let funding_block = next_block(
        &previous,
        FUNDING_HEIGHT,
        vec![
            coinbase(FUNDING_HEIGHT, vec![output(SUBSIDY_SAT, p2pkh())]),
            funding,
        ],
    );
    blocks.push(funding_block.clone());

    let spend_of_spent = spend(
        OutPoint::new(funding_txid, 2),
        vec![output(SAME_BLOCK_SAT, p2pk(KEY_B)), output(1_000, p2pkh())],
    );
    let same_block_spend = spend(
        OutPoint::new(spend_of_spent.compute_txid(), 0),
        vec![output(3_000, p2pkh())],
    );
    blocks.push(next_block(
        &funding_block,
        TIP_HEIGHT,
        vec![
            coinbase(TIP_HEIGHT, vec![output(SUBSIDY_SAT, p2pkh())]),
            spend_of_spent,
            same_block_spend,
        ],
    ));

    Chain {
        lines: blocks.iter().map(serialize_hex).collect(),
        funding: funding_txid,
    }
}

fn scan_lines(lines: &[String]) -> Result<bitcoin_rs_p2pk_scan::ScanReport, ScanError> {
    let mut text = lines.join("\n");
    text.push('\n');
    scan_blocks(Cursor::new(text))
}

fn example_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/regtest-p2pk.blocks.hex")
}

fn example_text() -> String {
    let mut text = fixture_chain_with_non_curve_key().lines.join("\n");
    text.push('\n');
    if std::env::var_os("P2PK_SCAN_WRITE_EXAMPLE").is_some() {
        std::fs::write(example_path(), &text).expect("example dataset is writable");
    }
    text
}

fn coin(txid: Txid, vout: u32, value_sat: u64, key: KeyShape, pubkey: &str) -> P2pkCoin {
    P2pkCoin {
        txid: txid.to_string(),
        vout,
        height: FUNDING_HEIGHT,
        value_sat,
        key,
        pubkey: pubkey.to_owned(),
    }
}

#[test]
fn lists_only_unspent_pay_to_pubkey_outputs() {
    let chain = fixture_chain();
    let report = scan_lines(&chain.lines).expect("fixture chain replays");

    let expected = vec![
        coin(
            chain.funding,
            0,
            UNSPENT_COMPRESSED_SAT,
            KeyShape::Compressed,
            KEY_A,
        ),
        coin(
            chain.funding,
            1,
            UNSPENT_UNCOMPRESSED_SAT,
            KeyShape::Uncompressed,
            KEY_UNCOMPRESSED,
        ),
    ];
    assert_eq!(
        report.p2pk, expected,
        "oracle is the fixture construction: the two unspent P2PK outputs at height \
         {FUNDING_HEIGHT}; the spent output, the same-block spend, P2PKH, P2SH, bare \
         multisig and the 0x09-prefixed key must not appear"
    );
    assert_eq!(
        report.p2pk_value_sat,
        UNSPENT_COMPRESSED_SAT + UNSPENT_UNCOMPRESSED_SAT
    );
    assert_eq!(report.blocks, TIP_HEIGHT + 1);
    assert_eq!(report.tip_height, TIP_HEIGHT);
}

#[test]
fn reports_key_shaped_non_curve_pubkeys_like_core() {
    let text = example_text();
    let committed =
        std::fs::read_to_string(example_path()).expect("committed example dataset exists");
    assert_eq!(
        committed, text,
        "the committed example dataset must equal the fixture construction; \
         regenerate with P2PK_SCAN_WRITE_EXAMPLE=1"
    );

    let report = scan_blocks(Cursor::new(committed)).expect("example dataset replays");
    let chain = fixture_chain_with_non_curve_key();
    let expected = vec![
        coin(
            chain.funding,
            0,
            UNSPENT_COMPRESSED_SAT,
            KeyShape::Compressed,
            KEY_A,
        ),
        coin(
            chain.funding,
            1,
            UNSPENT_UNCOMPRESSED_SAT,
            KeyShape::Uncompressed,
            KEY_UNCOMPRESSED,
        ),
        coin(
            chain.funding,
            7,
            NOT_ON_CURVE_SAT,
            KeyShape::Compressed,
            KEY_NOT_ON_CURVE,
        ),
    ];
    assert_eq!(
        report.p2pk, expected,
        "oracle is the fixture construction: a 0x02-prefixed key that is not a curve \
         point passes the shape rule and is reported, so it must be listed as a limit"
    );
}

#[test]
fn refuses_malformed_lines_naming_the_line() {
    let error = scan_blocks(Cursor::new("zz\n")).expect_err("invalid hex must be refused");
    assert!(
        matches!(error, ScanError::Hex { line: 1, .. }),
        "oracle is the block file grammar: one hexadecimal block per line; got {error}"
    );

    let error = scan_blocks(Cursor::new("\n")).expect_err("an empty line must be refused");
    assert!(
        matches!(error, ScanError::EmptyLine { line: 1 }),
        "an empty line would shift every later height; got {error}"
    );

    let error = scan_blocks(Cursor::new("00\n")).expect_err("a truncated block must be refused");
    assert!(
        matches!(error, ScanError::Decode { line: 1, .. }),
        "oracle is consensus block decoding; got {error}"
    );
}

#[test]
fn refuses_a_reordered_block_file_naming_the_line() {
    let Chain { mut lines, .. } = fixture_chain();
    lines.swap(1, 2);
    let error = scan_lines(&lines).expect_err("a reordered file must be refused");
    assert!(
        matches!(error, ScanError::BrokenChain { line: 2, .. }),
        "oracle is header linkage: file line 2 holds block 101, which does not extend \
         the genesis block; got {error}"
    );
}

#[test]
fn p2pk_shape_requires_key_prefix_and_checksig() {
    assert!(
        p2pk_pubkey(&p2pk(KEY_WRONG_PREFIX).to_bytes()).is_none(),
        "oracle is the workspace P2PK rule in bitcoin_rs_script::is_p2pk: a 33-byte push \
         must start with 0x02 or 0x03"
    );
    assert!(
        p2pk_pubkey(&p2pkh().to_bytes()).is_none(),
        "P2PKH ends with OP_CHECKSIG but is not a bare key push"
    );
    assert!(
        p2pk_pubkey(&bytes(KEY_A)).is_none(),
        "a bare key without OP_CHECKSIG is not a P2PK script"
    );
    let mut truncated = p2pk(KEY_A).to_bytes();
    truncated.pop();
    assert!(
        p2pk_pubkey(&truncated).is_none(),
        "removing OP_CHECKSIG must stop the match"
    );
}

#[test]
fn cli_reports_the_example_dataset_as_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_p2pk-scan"))
        .arg("--json")
        .arg(example_path())
        .output()
        .expect("binary runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: sonic_rs::Value = sonic_rs::from_slice(&output.stdout).expect("stdout is JSON");
    assert_eq!(
        report["p2pk_outputs"].as_u64(),
        Some(3),
        "oracle is the fixture construction: two spendable P2PK outputs plus the non-curve shape"
    );
    assert_eq!(
        report["p2pk_value_sat"].as_u64(),
        Some(UNSPENT_COMPRESSED_SAT + UNSPENT_UNCOMPRESSED_SAT + NOT_ON_CURVE_SAT)
    );
    assert_eq!(report["blocks"].as_u64(), Some(u64::from(TIP_HEIGHT) + 1));
    assert_eq!(report["tip_height"].as_u64(), Some(u64::from(TIP_HEIGHT)));
}
