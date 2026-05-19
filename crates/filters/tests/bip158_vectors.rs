//! Bitcoin Core BIP158 compact-filter vector tests.

use std::{collections::BTreeSet, fs, path::Path, process::Command};

use bitcoin::{Block, consensus::deserialize};
use bitcoin_rs_filters::{cfheaders, gcs};
use bitcoin_rs_primitives::Hash256;
use serde_json::Value;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn bip158_vectors_match_bitcoin_core() -> TestResult<()> {
    let vectors = load_vectors()?;
    let rows = vectors
        .as_array()
        .ok_or("blockfilters.json top level must be an array")?;

    for row in rows.iter().skip(1) {
        let fields = row.as_array().ok_or("vector row must be an array")?;
        let block_hash = parse_hash(str_field(fields, 1)?)?;
        let block = deserialize::<Block>(&hex_to_bytes(str_field(fields, 2)?)?)?;
        let prev_output_scripts = fields
            .get(3)
            .and_then(Value::as_array)
            .ok_or("prev output scripts field must be an array")?;
        let prev_header = parse_hash(str_field(fields, 4)?)?;
        let expected_filter = hex_to_bytes(str_field(fields, 5)?)?;
        let expected_header = parse_hash(str_field(fields, 6)?)?;

        let mut elements = BTreeSet::new();
        for tx in &block.txdata {
            for output in &tx.output {
                let script = output.script_pubkey.as_bytes();
                if !script.is_empty() && script[0] != 0x6a {
                    elements.insert(script.to_vec());
                }
            }
        }
        for script in prev_output_scripts {
            let bytes = hex_to_bytes(script.as_str().ok_or("script must be hex string")?)?;
            if !bytes.is_empty() {
                elements.insert(bytes);
            }
        }

        let key = gcs::key_from_block_hash(block_hash);
        let values = gcs::hash_elements(&elements.into_iter().collect::<Vec<_>>(), key);
        let filter = gcs::encode(&values, key);
        assert_eq!(
            filter, expected_filter,
            "filter mismatch at block {block_hash}"
        );

        let header = cfheaders::next_header(prev_header, &filter);
        assert_eq!(
            header, expected_header,
            "header mismatch at block {block_hash}"
        );
    }

    Ok(())
}

fn load_vectors() -> TestResult<Value> {
    let local = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../bitcoin/src/test/data/blockfilters.json");
    let bytes = if local.exists() {
        fs::read(local)?
    } else {
        let output = Command::new("python3")
            .args([
                "-c",
                "import urllib.request; print(urllib.request.urlopen('https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/test/data/blockfilters.json', timeout=30).read().decode(), end='')",
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "failed to fetch blockfilters.json: status {}",
                output.status
            )
            .into());
        }
        output.stdout
    };
    Ok(serde_json::from_slice(&bytes)?)
}

fn str_field(fields: &[Value], index: usize) -> TestResult<&str> {
    fields
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("field {index} must be a string").into())
}

fn parse_hash(hex: &str) -> TestResult<Hash256> {
    Ok(hex.parse()?)
}

fn hex_to_bytes(hex: &str) -> TestResult<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex string has odd length".into());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let hi = decode_nibble(pair[0])?;
        let lo = decode_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn decode_nibble(byte: u8) -> TestResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex byte {byte:#04x}").into()),
    }
}
