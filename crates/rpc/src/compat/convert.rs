//! Native <-> rust-bitcoin conversions and typed wire serialization.
//!
//! Every conversion between this node's native primitives and the
//! `bitcoin`/`corepc-types` vocabulary crosses the RPC boundary here, by
//! consensus-byte round trip or explicit field mapping. Handlers build
//! `corepc_types::v31` values and emit them through [`typed_to_sonic`]; they
//! never hand-assemble response JSON.
//!
//! Address strings, `asm`, and `desc` are wire-format strings that must match
//! Bitcoin Core byte-for-byte; they ride the sanctioned rust-bitcoin seam
//! (`Script` formatting, `Address` rendering) at this boundary only.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bitcoin::Address;
use bitcoin_rs_primitives::{CompactTarget, Network, Tx, TxIn, TxOut, consensus_bytes};
use bitcoin_rs_script::{
    is_multisig, is_op_return, is_p2a, is_p2pk, is_p2pkh, is_p2sh, witness_program,
};
use sonic_rs::{JsonValueMutTrait as _, JsonValueTrait as _, Value};

use crate::error::RpcError;
use crate::tx_render;

/// Maps a native network onto the rust-bitcoin network for the sanctioned
/// address seams (`Address` parsing requires it).
#[must_use]
pub(crate) const fn bitcoin_network(network: Network) -> bitcoin::Network {
    match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet3 => bitcoin::Network::Testnet,
        Network::Testnet4 => bitcoin::Network::Testnet4,
        Network::Signet => bitcoin::Network::Signet,
        Network::Regtest => bitcoin::Network::Regtest,
    }
}

/// Saturating `u64 -> i64` for Core wire counters typed as `i64`.
#[must_use]
pub(crate) fn i64_saturated(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Saturating `usize -> i64` for Core wire counters typed as `i64`.
#[must_use]
pub(crate) fn i64_saturated_len(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Saturating `i64 -> i32` for Core wire counters typed as `i32`.
#[must_use]
pub(crate) fn i32_saturated(value: i64) -> i32 {
    i32::try_from(value).unwrap_or_else(|_| {
        if value.is_negative() {
            i32::MIN
        } else {
            i32::MAX
        }
    })
}

/// Converts satoshis to the BTC float carried by the versioned Core types.
///
/// Consensus bounds money at 2.1e15 sat, well inside the 2^53 range where
/// `f64` is exact, so the division is value-exact.
#[must_use]
pub(crate) fn sat_to_btc(sats: u64) -> f64 {
    signed_sat_to_btc(i128::from(sats))
}

/// Saturates a signed satoshi value to the range of Core's `CAmount`.
#[must_use]
pub(crate) fn signed_sat_to_i64(sats: i128) -> i64 {
    i64::try_from(sats).unwrap_or_else(|_| {
        if sats.is_negative() {
            i64::MIN
        } else {
            i64::MAX
        }
    })
}

/// Signed counterpart for fee fields that carry deltas.
#[must_use]
pub(crate) fn signed_sat_to_btc(sats: i128) -> f64 {
    let clamped = signed_sat_to_i64(sats);
    let magnitude = clamped.unsigned_abs();
    let high = u32::try_from(magnitude >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(magnitude & 0xffff_ffff).unwrap_or(u32::MAX);
    let value = f64::from(high).mul_add(4_294_967_296.0, f64::from(low));
    (if clamped.is_negative() { -value } else { value }) / 100_000_000.0
}

/// Expands a compact `nBits` into its 64-character lowercase target hex, the
/// spelling Core uses for `target` fields: the `SetCompact` magnitude rendered
/// MSB-first by `arith_uint256::GetHex`.
///
/// The 23-bit masked mantissa is right-shifted into the low bytes for
/// exponents up to three, and left-shifted to byte `exponent - 3` above that,
/// with bytes pushed past 256 bits dropped — Core's shift semantics, including
/// the degenerate exponents that collapse to an all-zero target. The sign bit
/// only negates in Core's arithmetic; the rendered magnitude is unaffected.
#[must_use]
pub(crate) fn compact_target_hex(bits: CompactTarget) -> String {
    let bits = bits.to_consensus();
    let exponent = bits >> 24;
    let word = u64::from(bits & 0x007f_ffff);
    // Least-significant byte first; reversed for the wire's big-endian hex.
    let mut target = [0_u8; 32];
    if exponent <= 3 {
        let shifted = word >> (8 * (3 - exponent));
        target[..8].copy_from_slice(&shifted.to_le_bytes());
    } else {
        let shift = usize::try_from(exponent - 3).unwrap_or(32);
        let raw = word.to_le_bytes();
        for (offset, byte) in raw.iter().enumerate() {
            if let Some(slot) = target.get_mut(shift + offset) {
                *slot = *byte;
            }
        }
    }
    target.reverse();
    hex_encode(&target)
}

/// Script disassembly (`asm`) via the sanctioned rust-bitcoin seam.
#[must_use]
pub(crate) fn script_asm(script: &[u8]) -> String {
    bitcoin::Script::from_bytes(script).to_asm_string()
}

/// The internal script-shape classification shared by the Core RPC/REST
/// renderer and the Esplora renderer.
///
/// Each protocol names a shape in its own spelling table: [`core_type_name`]
/// for Core `scriptPubKey.type`, and `esplora_type_name` in
/// `esplora/projection.rs` for Esplora `scriptpubkey_type`.
///
/// INVARIANT: a shape is a pure function of raw output-script bytes; no
/// transaction, witness, network, or chain state takes part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScriptShape {
    Empty,
    Nonstandard,
    Pubkey,
    PubkeyHash,
    ScriptHash,
    Multisig,
    NullData,
    WitnessV0KeyHash,
    WitnessV0ScriptHash,
    WitnessV1Taproot,
    Anchor,
    WitnessUnknown,
}

/// Classifies one raw `scriptPubKey` into its shape.
///
/// PRE: `script` is the raw `scriptPubKey` byte slice.
/// POST: returns exactly one shape. Empty bytes return `ScriptShape::Empty`;
///   a recognized template returns its shape; all other bytes return
///   `ScriptShape::Nonstandard`.
/// INVARIANT: classification is a pure function of script bytes.
///
/// The order follows pinned Bitcoin Core 31.1
/// `bitcoin-core/src/script/solver.cpp::Solver`: P2SH first, then recognized
/// witness program forms, with pay-to-anchor ahead of the generic unknown
/// witness arm, then null data, pubkey, pubkey hash, and bare multisig.
#[must_use]
pub(crate) fn classify(script: &[u8]) -> ScriptShape {
    if script.is_empty() {
        return ScriptShape::Empty;
    }
    if is_p2sh(script) {
        return ScriptShape::ScriptHash;
    }
    if let Some((version, program)) = witness_program(script) {
        return match (version, program.len()) {
            (0, 20) => ScriptShape::WitnessV0KeyHash,
            (0, 32) => ScriptShape::WitnessV0ScriptHash,
            (1, 32) => ScriptShape::WitnessV1Taproot,
            _ if is_p2a(script) => ScriptShape::Anchor,
            _ if version != 0 => ScriptShape::WitnessUnknown,
            _ => ScriptShape::Nonstandard,
        };
    }
    if is_op_return(script) {
        return ScriptShape::NullData;
    }
    if is_p2pk(script) {
        return ScriptShape::Pubkey;
    }
    if is_p2pkh(script) {
        return ScriptShape::PubkeyHash;
    }
    if is_multisig(script) {
        return ScriptShape::Multisig;
    }
    ScriptShape::Nonstandard
}

/// Names one script shape in the Core `scriptPubKey.type` vocabulary.
///
/// PRE: `shape` is a value returned by [`classify`].
/// POST: returns the exact name from the Core spelling table. An empty script
///   is spelled `nonstandard`, matching Core.
/// INVARIANT: the match is exhaustive. A new `ScriptShape` variant does not
///   compile until both this table and the Esplora table name it.
#[must_use]
pub(crate) const fn core_type_name(shape: ScriptShape) -> &'static str {
    match shape {
        // Core spells an empty script `nonstandard`, like any unrecognized one.
        ScriptShape::Empty | ScriptShape::Nonstandard => "nonstandard",
        ScriptShape::Pubkey => "pubkey",
        ScriptShape::PubkeyHash => "pubkeyhash",
        ScriptShape::ScriptHash => "scripthash",
        ScriptShape::Multisig => "multisig",
        ScriptShape::NullData => "nulldata",
        ScriptShape::WitnessV0KeyHash => "witness_v0_keyhash",
        ScriptShape::WitnessV0ScriptHash => "witness_v0_scripthash",
        ScriptShape::WitnessV1Taproot => "witness_v1_taproot",
        ScriptShape::Anchor => "anchor",
        ScriptShape::WitnessUnknown => "witness_unknown",
    }
}

/// Renders the Core address string for a script, or `None` when the script
/// has no standard address form (via the sanctioned rust-bitcoin seam).
///
/// PRE: `script` is raw script bytes and `network` is the selected Bitcoin
///   network.
/// POST: returns the existing rust-bitcoin address string, or `None` when
///   conversion fails.
/// INVARIANT: non-address scripts are omitted by the caller; no fallback
///   string is produced here.
#[must_use]
pub(crate) fn script_address(script: &[u8], network: Network) -> Option<String> {
    Address::from_script(
        bitcoin::Script::from_bytes(script),
        bitcoin_network(network),
    )
    .ok()
    .map(|address| address.to_string())
}

/// Re-serializes one typed Core wire value through the serde boundary into
/// the transport value.
pub(crate) fn typed_to_sonic<T: serde::Serialize>(typed: &T) -> Result<Value, RpcError> {
    sonic_rs::to_value(typed).map_err(RpcError::from)
}

/// Serializes one typed Core wire value, omitting keys whose value is `null`.
///
/// Core renders unset optional response fields by leaving them out of the
/// object — every `/*optional=*/true` result is pushed only when set — while
/// several upstream types carry `Option` fields without
/// `skip_serializing_if`, which would emit an explicit JSON `null`. Methods
/// whose optional fields are all omitted-when-unset in Core use this
/// projection so the typed construction still drives an omission-faithful
/// wire shape.
pub(crate) fn typed_to_sonic_omitting_nulls<T: serde::Serialize>(
    typed: &T,
) -> Result<Value, RpcError> {
    let mut value = sonic_rs::to_value(typed)?;
    omit_json_nulls(&mut value);
    Ok(value)
}

/// Recurses through objects and arrays, dropping object entries whose value
/// is `null`. Array slots are kept: Core omits optional fields, never array
/// items.
fn omit_json_nulls(value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        object.retain(|_, field| {
            omit_json_nulls(field);
            !field.is_null()
        });
    } else if let Some(items) = value.as_array_mut() {
        for item in items {
            omit_json_nulls(item);
        }
    }
}

/// Converts a transport value into a typed Core wire value, enforcing the
/// pinned strict field set (`deny_unknown_fields` where the upstream type
/// opts in).
pub(crate) fn sonic_to_typed<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, RpcError> {
    sonic_rs::from_value(value).map_err(RpcError::from)
}

/// Projects one output script into the versioned `scriptPubKey` object,
/// reusing the transport renderer and validating against the pinned type.
pub(crate) fn script_pub_key_typed(
    script: &[u8],
    network: Network,
) -> Result<corepc_types::ScriptPubKey, RpcError> {
    sonic_to_typed(&tx_render::script_pub_key_json(script, network))
}

/// Input script object (`asm` + `hex`).
#[must_use]
pub(crate) fn script_sig_typed(script: &[u8]) -> corepc_types::ScriptSig {
    corepc_types::ScriptSig {
        asm: script_asm(script),
        hex: hex_encode(script),
    }
}

/// The coinbase transaction object carried by verbose block responses.
///
/// Takes the block's `txs.first()` directly. Returns `None` when the block
/// carries no coinbase, which no valid block has; the caller renders that
/// absence as a typed RPC error.
pub(crate) fn coinbase_transaction_typed(
    tx: Option<&Tx>,
) -> Option<corepc_types::v31::CoinbaseTransaction> {
    let tx = tx?;
    let input = tx.inputs.first()?;
    Some(corepc_types::v31::CoinbaseTransaction {
        version: tx.version,
        locktime: tx.lock_time.to_consensus(),
        sequence: input.sequence.to_consensus(),
        coinbase: hex_encode(&input.script_sig),
        witness: input.witness.first().map(|item| hex_encode(item)),
    })
}

/// Confirmed-chain context attached to a verbose transaction projection.
#[derive(Clone, Debug)]
pub(crate) struct VerboseTxChain {
    /// Confirming block hash.
    pub block_hash: String,
    /// Confirmations on the applied chain.
    pub confirmations: u64,
    /// Confirming block time (reported as both `time` and `blocktime`).
    pub time: u64,
    /// Whether the confirming block is on the applied chain.
    pub in_active_chain: Option<bool>,
}

/// Projects one native transaction into Core's verbose wire shape
/// (`getrawtransaction` verbosity >= 1 and verbose block entries).
pub(crate) fn raw_transaction_verbose(
    tx: &Tx,
    network: Network,
    chain: Option<VerboseTxChain>,
) -> Result<corepc_types::v31::GetRawTransactionVerbose, RpcError> {
    let coinbase = tx_render::is_coinbase(tx);
    let inputs = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| raw_input_typed(input, index == 0 && coinbase))
        .collect::<Vec<_>>();
    let outputs = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(index, output)| raw_output_typed(output, index, network))
        .collect::<Result<Vec<_>, _>>()?;
    let (block_hash, confirmations, transaction_time, block_time, in_active_chain) =
        chain.map_or((None, None, None, None, None), |chain| {
            (
                Some(chain.block_hash),
                Some(chain.confirmations),
                Some(chain.time),
                Some(chain.time),
                chain.in_active_chain,
            )
        });
    Ok(corepc_types::v31::GetRawTransactionVerbose {
        in_active_chain,
        hex: hex_encode(&consensus_bytes(tx)),
        txid: tx.txid().to_string(),
        hash: tx.wtxid().to_string(),
        size: u64::try_from(tx.total_size()).unwrap_or(u64::MAX),
        vsize: tx.vsize(),
        weight: tx.weight(),
        version: tx.version,
        lock_time: tx.lock_time.to_consensus(),
        inputs,
        outputs,
        block_hash,
        confirmations,
        transaction_time,
        block_time,
    })
}

/// Projects one native transaction into Core's `decoderawtransaction` shape.
///
/// The response body is the `psbt`-level `RawTransaction` that `corepc_types`
/// re-exports from `v17`; `v31` re-exports the `DecodeRawTransaction` wrapper
/// and the input/output component types but not the bare body name, so the
/// body is named at its only public path. Same struct, same wire shape.
pub(crate) fn raw_transaction(
    tx: &Tx,
    network: Network,
) -> Result<corepc_types::v17::RawTransaction, RpcError> {
    let coinbase = tx_render::is_coinbase(tx);
    let inputs = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| raw_input_typed(input, index == 0 && coinbase))
        .collect::<Vec<_>>();
    let outputs = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(index, output)| raw_output_typed(output, index, network))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(corepc_types::v17::RawTransaction {
        txid: tx.txid().to_string(),
        hash: tx.wtxid().to_string(),
        size: u64::try_from(tx.total_size()).unwrap_or(u64::MAX),
        vsize: tx.vsize(),
        weight: tx.weight(),
        version: tx.version,
        lock_time: tx.lock_time.to_consensus(),
        inputs,
        outputs,
    })
}

/// Projects one transaction input, coinbase-shaped when flagged.
fn raw_input_typed(input: &TxIn, coinbase: bool) -> corepc_types::v31::RawTransactionInput {
    let txin_witness = (!input.witness.is_empty()).then(|| {
        input
            .witness
            .iter()
            .map(|item| hex_encode(item))
            .collect::<Vec<_>>()
    });
    if coinbase {
        return corepc_types::v31::RawTransactionInput {
            coinbase: Some(hex_encode(&input.script_sig)),
            txid: None,
            vout: None,
            script_sig: None,
            txin_witness,
            sequence: input.sequence.to_consensus(),
        };
    }
    // Field copies come before any `&self` method: `OutPoint` is
    // `#[repr(packed)]` (consensus wire layout), so field references would be
    // unaligned.
    let (prev_txid, prev_vout) = (input.previous_output.txid, input.previous_output.vout);
    corepc_types::v31::RawTransactionInput {
        coinbase: None,
        txid: Some(prev_txid.to_string()),
        vout: Some(prev_vout),
        script_sig: Some(script_sig_typed(&input.script_sig)),
        txin_witness,
        sequence: input.sequence.to_consensus(),
    }
}

/// Projects one transaction output at its zero-based index.
fn raw_output_typed(
    output: &TxOut,
    index: usize,
    network: Network,
) -> Result<corepc_types::v31::RawTransactionOutput, RpcError> {
    Ok(corepc_types::v31::RawTransactionOutput {
        value: sat_to_btc(output.value.to_sat()),
        index: u64::try_from(index).unwrap_or(u64::MAX),
        script_pubkey: script_pub_key_typed(&output.script_pubkey, network)?,
    })
}

/// Lowercase hex encoding for wire strings.
#[must_use]
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Representative raw `scriptPubKey` bytes for every [`ScriptShape`].
///
/// Both spelling-table tests classify these scripts, so one list states what
/// a script of each shape looks like; each protocol's names stay in its own
/// test.
#[cfg(test)]
pub(crate) mod fixtures {
    use alloc::vec::Vec;

    use super::ScriptShape;

    /// No bytes at all.
    pub(crate) fn empty() -> Vec<u8> {
        Vec::new()
    }

    /// Bytes no template recognizes.
    pub(crate) fn nonstandard() -> Vec<u8> {
        vec![0x51, 0x52]
    }

    /// `<33-byte key> OP_CHECKSIG`.
    pub(crate) fn p2pk() -> Vec<u8> {
        let mut script = vec![0x21, 0x02];
        script.extend([0x11; 32]);
        script.push(0xac);
        script
    }

    /// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`.
    pub(crate) fn p2pkh() -> Vec<u8> {
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend([0x11; 20]);
        script.extend([0x88, 0xac]);
        script
    }

    /// `OP_HASH160 <20> OP_EQUAL`.
    pub(crate) fn p2sh() -> Vec<u8> {
        let mut script = vec![0xa9, 0x14];
        script.extend([0x11; 20]);
        script.push(0x87);
        script
    }

    /// `OP_1 <key> OP_1 OP_CHECKMULTISIG`: bare multisig with one key.
    pub(crate) fn multisig() -> Vec<u8> {
        let mut script = vec![0x51, 0x21, 0x03];
        script.extend([0x22; 32]);
        script.extend([0x51, 0xae]);
        script
    }

    /// `OP_RETURN <4>`.
    pub(crate) fn op_return() -> Vec<u8> {
        vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]
    }

    /// `OP_0 <20>`.
    pub(crate) fn p2wpkh() -> Vec<u8> {
        let mut script = vec![0x00, 0x14];
        script.extend([0x11; 20]);
        script
    }

    /// `OP_0 <32>`.
    pub(crate) fn p2wsh() -> Vec<u8> {
        let mut script = vec![0x00, 0x20];
        script.extend([0x11; 32]);
        script
    }

    /// `OP_1 <32>`.
    pub(crate) fn p2tr() -> Vec<u8> {
        let mut script = vec![0x51, 0x20];
        script.extend([0x11; 32]);
        script
    }

    /// `OP_1 OP_PUSHBYTES_2 0x4e73`: pay-to-anchor.
    pub(crate) fn anchor() -> Vec<u8> {
        vec![0x51, 0x02, 0x4e, 0x73]
    }

    /// `OP_2 <20>`: a valid witness program no recognized version carries.
    pub(crate) fn future_witness() -> Vec<u8> {
        let mut script = vec![0x52, 0x14];
        script.extend([0x11; 20]);
        script
    }

    /// Every shape with one representative script, in declaration order.
    pub(crate) fn by_shape() -> Vec<(ScriptShape, Vec<u8>)> {
        vec![
            (ScriptShape::Empty, empty()),
            (ScriptShape::Nonstandard, nonstandard()),
            (ScriptShape::Pubkey, p2pk()),
            (ScriptShape::PubkeyHash, p2pkh()),
            (ScriptShape::ScriptHash, p2sh()),
            (ScriptShape::Multisig, multisig()),
            (ScriptShape::NullData, op_return()),
            (ScriptShape::WitnessV0KeyHash, p2wpkh()),
            (ScriptShape::WitnessV0ScriptHash, p2wsh()),
            (ScriptShape::WitnessV1Taproot, p2tr()),
            (ScriptShape::Anchor, anchor()),
            (ScriptShape::WitnessUnknown, future_witness()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encoding_matches_standard_formatting_for_every_byte() -> core::fmt::Result {
        use core::fmt::Write as _;

        let bytes: Vec<u8> = (u8::MIN..=u8::MAX).collect();
        let mut expected = String::new();
        for byte in &bytes {
            write!(&mut expected, "{byte:02x}")?;
        }
        assert_eq!(hex_encode(&bytes), expected);
        assert_eq!(hex_encode(&[]), "");
        Ok(())
    }

    #[test]
    fn compact_target_places_mantissa_bytes_core_style() {
        // Historical pow limit 0x1d00ffff: ffff lands at bytes 4-5.
        let mut expected = String::from("00000000ffff");
        expected.push_str(&"0".repeat(52));
        assert_eq!(
            compact_target_hex(CompactTarget::from_consensus(0x1d00_ffff)),
            expected
        );

        // Regtest difficulty-one 0x207fffff: 7fffff at the very top.
        let mut expected = String::from("7fffff");
        expected.push_str(&"0".repeat(58));
        assert_eq!(
            compact_target_hex(CompactTarget::from_consensus(0x207f_ffff)),
            expected
        );
    }

    #[test]
    fn compact_target_right_shifts_sub_three_exponents() {
        // 0x0200ff00: word 0x00ff00 >> 8 = 0xff in the lowest byte.
        let mut expected = String::new();
        expected.push_str(&"0".repeat(62));
        expected.push_str("ff");
        assert_eq!(
            compact_target_hex(CompactTarget::from_consensus(0x0200_ff00)),
            expected
        );

        // Exponent three keeps all three mantissa bytes in place.
        let mut expected = "0".repeat(58);
        expected.push_str("7fff80");
        assert_eq!(
            compact_target_hex(CompactTarget::from_consensus(0x03ff_ff80)),
            expected
        );
    }

    #[test]
    fn compact_target_ignores_sign_and_drops_overflow_shifts() {
        // The sign bit negates; the rendered magnitude is unchanged.
        assert_eq!(
            compact_target_hex(CompactTarget::from_consensus(0x1d80_ffff)),
            compact_target_hex(CompactTarget::from_consensus(0x1d00_ffff))
        );

        // Exponent 35 shifts every mantissa byte past 256 bits: zero target.
        assert_eq!(
            compact_target_hex(CompactTarget::from_consensus(0x2300_ffff)),
            "0".repeat(64)
        );
    }

    #[test]
    fn classify_matches_core_type_name_for_every_shape() {
        let expected: &[(ScriptShape, &str)] = &[
            (ScriptShape::Empty, "nonstandard"),
            (ScriptShape::Nonstandard, "nonstandard"),
            (ScriptShape::Pubkey, "pubkey"),
            (ScriptShape::PubkeyHash, "pubkeyhash"),
            (ScriptShape::ScriptHash, "scripthash"),
            (ScriptShape::Multisig, "multisig"),
            (ScriptShape::NullData, "nulldata"),
            (ScriptShape::WitnessV0KeyHash, "witness_v0_keyhash"),
            (ScriptShape::WitnessV0ScriptHash, "witness_v0_scripthash"),
            (ScriptShape::WitnessV1Taproot, "witness_v1_taproot"),
            (ScriptShape::Anchor, "anchor"),
            (ScriptShape::WitnessUnknown, "witness_unknown"),
        ];
        let cases = fixtures::by_shape();
        assert_eq!(cases.len(), expected.len());
        for ((shape, script), (want_shape, name)) in cases.iter().zip(expected) {
            assert_eq!(classify(script), *want_shape, "classify {script:?}");
            assert_eq!(core_type_name(*shape), *name);
        }
    }

    #[test]
    fn core_json_types_anchor_and_future_witness_programs() {
        let anchor = tx_render::script_pub_key_json(&fixtures::anchor(), Network::Mainnet);
        assert_eq!(
            anchor
                .get("type")
                .and_then(sonic_rs::JsonValueTrait::as_str),
            Some("anchor")
        );
        assert_eq!(
            anchor.get("hex").and_then(sonic_rs::JsonValueTrait::as_str),
            Some("51024e73")
        );
        assert_eq!(
            anchor
                .get("desc")
                .and_then(sonic_rs::JsonValueTrait::as_str),
            Some("addr(bc1pfeessrawgf)")
        );
        assert_eq!(
            anchor
                .get("address")
                .and_then(sonic_rs::JsonValueTrait::as_str),
            Some("bc1pfeessrawgf")
        );

        let future = tx_render::script_pub_key_json(&fixtures::future_witness(), Network::Mainnet);
        assert_eq!(
            future
                .get("type")
                .and_then(sonic_rs::JsonValueTrait::as_str),
            Some("witness_unknown")
        );
        assert_eq!(
            future
                .get("address")
                .and_then(sonic_rs::JsonValueTrait::as_str),
            Some("bc1zzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg35w7nfk")
        );
    }
}
