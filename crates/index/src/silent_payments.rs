//! Keyless BIP352 v0 scan material for already validated transactions.

use bitcoin_hashes::{Hash as _, hash160};
use bitcoin_rs_primitives::{BlockHash, Script, Tx, TxIn, Txid, consensus_bytes};
use bitcoin_rs_utxo::contract::{BlockSpends, BlockSpendsError};
use secp256k1::{PublicKey, Scalar, Secp256k1};
use sha2::{Digest as _, Sha256};

pub const MAX_BODY_BYTES: usize = 4_000_000;
pub const MAX_PREVOUT_BYTES: usize = 64 * 1024 * 1024;

const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionTweak {
    pub txid: Txid,
    pub input_public_key_sum: [u8; 33],
    pub input_hash: [u8; 32],
    pub tweak: [u8; 33],
    pub outputs: Vec<TaprootCandidate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaprootCandidate {
    pub vout: u32,
    pub output_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockTweaks {
    pub hash: BlockHash,
    pub transactions: Vec<TransactionTweak>,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum TweakError {
    #[error("prevout scripts must be in complete input order")]
    PrevoutCount,
    #[error("silent payment input {input} prevout unavailable")]
    Unavailable { input: usize },
    #[error("invalid validated input material at input {input}")]
    InvalidInput { input: usize },
    #[error("BIP352 input hash is not a nonzero secp256k1 scalar")]
    InvalidInputHash,
    #[error("silent payment projection exceeds its work budget")]
    ResourceLimit,
}

/// prevout scripts. `None` means BIP352 v0 ineligibility, never incomplete history.
/// programs rather than BIP341 Taproot outputs; the transaction produces no tweaks
pub fn transaction_tweak(
    tx: &Tx,
    prevouts: &[Option<&Script>],
    taproot_active: bool,
) -> Result<Option<TransactionTweak>, TweakError> {
    let secp = Secp256k1::verification_only();
    transaction_tweak_with_ctx(tx, prevouts, taproot_active, &secp)
}

fn transaction_tweak_with_ctx<C: secp256k1::Verification>(
    tx: &Tx,
    prevouts: &[Option<&Script>],
    taproot_active: bool,
    secp: &Secp256k1<C>,
) -> Result<Option<TransactionTweak>, TweakError> {
    if tx.total_size() > MAX_BODY_BYTES {
        return Err(TweakError::ResourceLimit);
    }
    if tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null() {
        return Ok(None);
    }
    if prevouts.len() != tx.inputs.len() {
        return Err(TweakError::PrevoutCount);
    }
    let mut bytes = 0_usize;
    for (input, script) in prevouts.iter().enumerate() {
        let script = script.ok_or(TweakError::Unavailable { input })?;
        bytes = bytes.saturating_add(script.len());
        if bytes > MAX_PREVOUT_BYTES {
            return Err(TweakError::ResourceLimit);
        }
    }
    if !taproot_active {
        return Ok(None);
    }
    let outputs = tx
        .outputs
        .iter()
        .enumerate()
        .filter_map(|(vout, output)| {
            taproot_key(&output.script_pubkey).map(|output_key| {
                u32::try_from(vout)
                    .map(|vout| TaprootCandidate { vout, output_key })
                    .map_err(|_| TweakError::ResourceLimit)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if outputs.is_empty() {
        return Ok(None);
    }
    let mut keys = Vec::new();
    for (index, (input, script)) in tx.inputs.iter().zip(prevouts).enumerate() {
        let script = script.ok_or(TweakError::Unavailable { input: index })?;
        if future_witness(script) {
            return Ok(None);
        }
        if let Some(key) = input_key(input, script, index)? {
            keys.push(key);
        }
    }
    let refs: Vec<_> = keys.iter().collect();
    let Ok(sum) = PublicKey::combine_keys(&refs) else {
        return Ok(None);
    };
    let Some(lowest) = tx
        .inputs
        .iter()
        .map(|input| consensus_bytes(&input.previous_output))
        .min()
    else {
        return Ok(None);
    };
    let tag = Sha256::digest(b"BIP0352/Inputs");
    let mut hash = Sha256::new();
    hash.update(tag);
    hash.update(tag);
    hash.update(lowest);
    hash.update(sum.serialize());
    let input_hash: [u8; 32] = hash.finalize().into();
    let scalar = Scalar::from_be_bytes(input_hash).map_err(|_| TweakError::InvalidInputHash)?;
    if scalar == Scalar::ZERO {
        return Err(TweakError::InvalidInputHash);
    }
    let tweak = sum
        .mul_tweak(secp, &scalar)
        .map_err(|_| TweakError::InvalidInputHash)?
        .serialize();
    Ok(Some(TransactionTweak {
        txid: tx.txid(),
        input_public_key_sum: sum.serialize(),
        input_hash,
        tweak,
        outputs,
    }))
}

pub fn block_tweaks(
    view: &BlockSpends,
    taproot_active: bool,
) -> Result<BlockTweaks, BlockSpendsError> {
    let spent = view
        .spent
        .as_ref()
        .map_err(|reason| BlockSpendsError::History(*reason))?;
    if view.block.total_size() > MAX_BODY_BYTES {
        return Err(BlockSpendsError::ResourceLimit);
    }
    if spent.len() != view.block.txs.len() {
        return Err(BlockSpendsError::Corrupt(
            "silent payment spent transaction count differs",
        ));
    }
    let bytes = spent.iter().flatten().fold(0_usize, |bytes, coin| {
        bytes.saturating_add(coin.txout.script_pubkey.len())
    });
    if bytes > MAX_PREVOUT_BYTES {
        return Err(BlockSpendsError::ResourceLimit);
    }
    if !taproot_active {
        return Ok(BlockTweaks {
            hash: view.block.block_hash(),
            transactions: Vec::new(),
        });
    }
    let secp = Secp256k1::verification_only();
    let mut transactions = Vec::new();
    for (tx, coins) in view.block.txs.iter().zip(spent) {
        if tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null() {
            if !coins.is_empty() {
                return Err(BlockSpendsError::Corrupt("coinbase has spent inputs"));
            }
            continue;
        }
        if tx.inputs.len() != coins.len()
            || tx
                .inputs
                .iter()
                .zip(coins)
                .any(|(input, coin)| input.previous_output != coin.outpoint)
        {
            return Err(BlockSpendsError::Corrupt(
                "silent payment prevout order differs",
            ));
        }
        let scripts: Vec<_> = coins
            .iter()
            .map(|coin| Some(&coin.txout.script_pubkey))
            .collect();
        match transaction_tweak_with_ctx(tx, &scripts, true, &secp) {
            Ok(Some(tweak)) => transactions.push(tweak),
            Ok(None) => {}
            Err(TweakError::ResourceLimit) => return Err(BlockSpendsError::ResourceLimit),
            Err(_) => {
                return Err(BlockSpendsError::Corrupt(
                    "invalid silent payment input material",
                ));
            }
        }
    }
    Ok(BlockTweaks {
        hash: view.block.block_hash(),
        transactions,
    })
}

fn taproot_key(script: &[u8]) -> Option<[u8; 32]> {
    (script.len() == 34 && script[..2] == [0x51, 0x20]).then(|| {
        let mut key = [0; 32];
        key.copy_from_slice(&script[2..]);
        key
    })
}

fn future_witness(script: &[u8]) -> bool {
    (4..=42).contains(&script.len())
        && (0x52..=0x60).contains(&script[0])
        && usize::from(script[1]) == script.len() - 2
}

fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23 && script[..2] == [0xa9, 0x14] && script[22] == 0x87
}

fn is_p2wpkh(script: &[u8]) -> bool {
    script.len() == 22 && script[..2] == [0x00, 0x14]
}

fn redeem_script(input: &TxIn) -> Option<&[u8]> {
    let bytes = input.script_sig.as_bytes();
    let (&len, program) = bytes.split_first()?;
    (usize::from(len) == program.len() && len <= 75).then_some(program)
}

fn compressed_key(bytes: &[u8]) -> Option<PublicKey> {
    (bytes.len() == 33)
        .then(|| PublicKey::from_slice(bytes).ok())
        .flatten()
}

fn input_key(input: &TxIn, script: &[u8], index: usize) -> Result<Option<PublicKey>, TweakError> {
    if let Some(xonly) = taproot_key(script) {
        let witness = &input.witness;
        let mut len = witness.len();
        if len > 1 && witness[len - 1].first() == Some(&0x50) {
            len -= 1;
        }
        if len == 0 {
            return Err(TweakError::InvalidInput { input: index });
        }
        if len > 1 {
            let control = &witness[len - 1];
            if control.len() < 33
                || control.len() > 33 + 32 * 128
                || !(control.len() - 33).is_multiple_of(32)
            {
                return Err(TweakError::InvalidInput { input: index });
            }
            if control[1..33] == NUMS_H {
                return Ok(None);
            }
        }
        let mut encoded = [0x02; 33];
        encoded[1..].copy_from_slice(&xonly);
        return PublicKey::from_slice(&encoded)
            .map(Some)
            .map_err(|_| TweakError::InvalidInput { input: index });
    }
    if is_p2wpkh(script) || (is_p2sh(script) && redeem_script(input).is_some_and(is_p2wpkh)) {
        return Ok(input.witness.last().and_then(|bytes| compressed_key(bytes)));
    }
    if script.len() == 25 && script[..3] == [0x76, 0xa9, 0x14] && script[23..] == [0x88, 0xac] {
        return Ok(input.script_sig.windows(33).rev().find_map(|bytes| {
            (hash160::Hash::hash(bytes).as_byte_array()[..] == script[3..23])
                .then(|| compressed_key(bytes))
                .flatten()
        }));
    }
    Ok(None)
}
