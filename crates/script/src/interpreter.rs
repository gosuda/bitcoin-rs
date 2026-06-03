#[cfg(feature = "bitcoinconsensus")]
use bitcoin::consensus::encode;
use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Script, ScriptBuf, Witness};
use bitcoin_rs_primitives::TxOut;
use thiserror::Error;

/// Verification flags passed to the delegated consensus script engine.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct VerifyFlags(u32);

impl VerifyFlags {
    /// No verification flags.
    pub const NONE: Self = Self(0);
    /// Evaluate P2SH subscripts (BIP16).
    pub const P2SH: Self = Self(1 << 0);
    /// Require strict signature and public-key encodings.
    pub const STRICTENC: Self = Self(1 << 1);
    /// Require strict DER signatures (BIP66).
    pub const DERSIG: Self = Self(1 << 2);
    /// Require low-S ECDSA signatures.
    pub const LOW_S: Self = Self(1 << 3);
    /// Require empty CHECKMULTISIG dummy element (BIP147).
    pub const NULLDUMMY: Self = Self(1 << 4);
    /// Require scriptSig push-only form.
    pub const SIGPUSHONLY: Self = Self(1 << 5);
    /// Require minimal push and numeric encodings.
    pub const MINIMALDATA: Self = Self(1 << 6);
    /// Discourage NOPs reserved for future soft forks.
    pub const DISCOURAGE_UPGRADABLE_NOPS: Self = Self(1 << 7);
    /// Require a single true stack item after evaluation.
    pub const CLEANSTACK: Self = Self(1 << 8);
    /// Enable `OP_CHECKLOCKTIMEVERIFY` (BIP65).
    pub const CHECKLOCKTIMEVERIFY: Self = Self(1 << 9);
    /// Enable `OP_CHECKSEQUENCEVERIFY` (BIP112).
    pub const CHECKSEQUENCEVERIFY: Self = Self(1 << 10);
    /// Enable segregated witness validation (BIP141/BIP143).
    pub const WITNESS: Self = Self(1 << 11);
    /// Discourage unknown witness program versions.
    pub const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: Self = Self(1 << 12);
    /// Require minimal IF/NOTIF arguments in segwit scripts.
    pub const MINIMALIF: Self = Self(1 << 13);
    /// Require failed signature checks to consume empty signatures.
    pub const NULLFAIL: Self = Self(1 << 14);
    /// Require compressed public keys in segwit scripts.
    pub const WITNESS_PUBKEYTYPE: Self = Self(1 << 15);
    /// Make `CODESEPARATOR` and `FindAndDelete` fail non-segwit scripts.
    pub const CONST_SCRIPTCODE: Self = Self(1 << 16);
    /// Enable taproot and tapscript validation (BIP341/BIP342).
    pub const TAPROOT: Self = Self(1 << 17);
    /// Discourage unknown taproot leaf versions.
    pub const DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: Self = Self(1 << 18);
    /// Discourage unknown `OP_SUCCESS` opcodes.
    pub const DISCOURAGE_OP_SUCCESS: Self = Self(1 << 19);
    /// Discourage unknown public-key versions in tapscript.
    pub const DISCOURAGE_UPGRADABLE_PUBKEYTYPE: Self = Self(1 << 20);
    /// Mandatory consensus flags used for block validation after taproot activation.
    pub const MANDATORY: Self = Self(
        Self::P2SH.0
            | Self::DERSIG.0
            | Self::NULLDUMMY.0
            | Self::CHECKLOCKTIMEVERIFY.0
            | Self::CHECKSEQUENCEVERIFY.0
            | Self::WITNESS.0
            | Self::TAPROOT.0,
    );
    /// Standard relay flags; useful for vector tests that request policy checks.
    pub const STANDARD: Self = Self(
        Self::MANDATORY.0
            | Self::STRICTENC.0
            | Self::LOW_S.0
            | Self::MINIMALDATA.0
            | Self::DISCOURAGE_UPGRADABLE_NOPS.0
            | Self::CLEANSTACK.0
            | Self::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.0
            | Self::MINIMALIF.0
            | Self::NULLFAIL.0
            | Self::WITNESS_PUBKEYTYPE.0
            | Self::CONST_SCRIPTCODE.0
            | Self::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION.0
            | Self::DISCOURAGE_OP_SUCCESS.0
            | Self::DISCOURAGE_UPGRADABLE_PUBKEYTYPE.0,
    );

    /// Builds flags from raw Core-compatible bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns raw Core-compatible flag bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns only the bits accepted by rust-bitcoin's `bitcoinconsensus` backend.
    #[must_use]
    pub const fn consensus_bits(self) -> u32 {
        self.0
            & (Self::P2SH.0
                | Self::DERSIG.0
                | Self::NULLDUMMY.0
                | Self::CHECKLOCKTIMEVERIFY.0
                | Self::CHECKSEQUENCEVERIFY.0
                | Self::WITNESS.0)
    }

    /// Returns the full consensus-authority bit set, including taproot for bitcoinkernel.
    #[must_use]
    pub const fn kernel_bits(self) -> u32 {
        self.0 & Self::MANDATORY.0
    }

    /// Returns true when all `other` bits are present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Adds another flag set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Parses a comma-separated Core test-vector flag string.
    pub fn from_core_names(names: &str) -> Result<Self, ScriptError> {
        let mut flags = Self::NONE;
        for name in names
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            flags = flags.union(match name {
                "NONE" => Self::NONE,
                "P2SH" => Self::P2SH,
                "STRICTENC" => Self::STRICTENC,
                "DERSIG" => Self::DERSIG,
                "LOW_S" => Self::LOW_S,
                "NULLDUMMY" => Self::NULLDUMMY,
                "SIGPUSHONLY" => Self::SIGPUSHONLY,
                "MINIMALDATA" => Self::MINIMALDATA,
                "DISCOURAGE_UPGRADABLE_NOPS" => Self::DISCOURAGE_UPGRADABLE_NOPS,
                "CLEANSTACK" => Self::CLEANSTACK,
                "CHECKLOCKTIMEVERIFY" => Self::CHECKLOCKTIMEVERIFY,
                "CHECKSEQUENCEVERIFY" => Self::CHECKSEQUENCEVERIFY,
                "WITNESS" => Self::WITNESS,
                "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                    Self::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
                }
                "MINIMALIF" => Self::MINIMALIF,
                "NULLFAIL" => Self::NULLFAIL,
                "WITNESS_PUBKEYTYPE" => Self::WITNESS_PUBKEYTYPE,
                "CONST_SCRIPTCODE" => Self::CONST_SCRIPTCODE,
                "TAPROOT" => Self::TAPROOT,
                "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => {
                    Self::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
                }
                "DISCOURAGE_OP_SUCCESS" => Self::DISCOURAGE_OP_SUCCESS,
                "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => Self::DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
                unknown => {
                    return Err(ScriptError::UnknownFlag {
                        name: unknown.to_owned(),
                    });
                }
            });
        }
        Ok(flags)
    }
}

impl From<VerifyFlags> for u32 {
    fn from(flags: VerifyFlags) -> Self {
        flags.bits()
    }
}

/// Script execution errors surfaced by the script crate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScriptError {
    /// The requested input index was not present in the transaction.
    #[error("input index {index} out of range for {inputs} inputs")]
    InputIndexOutOfRange {
        /// Requested input index.
        index: usize,
        /// Transaction input count.
        inputs: usize,
    },
    /// A Core vector flag name was not known by this crate.
    #[error("unknown script verify flag {name}")]
    UnknownFlag {
        /// Unknown flag name.
        name: String,
    },
    /// The transaction could not be serialized for the delegated verifier.
    #[error("transaction serialization failed: {0}")]
    Serialization(String),
    /// The delegated consensus verifier rejected the script.
    #[error("script verification failed: {0}")]
    Verification(String),
    /// Taproot key-path verification requires all prevouts for multi-input transactions.
    #[error("taproot key-path verification requires all prevouts for multi-input transactions")]
    TaprootPrevoutsUnavailable,
    /// This portable path only validates one-element Taproot key-path witnesses.
    #[error(
        "taproot witness stack with {elements} elements requires unsupported annex or script-path validation"
    )]
    TaprootUnsupportedWitness {
        /// Number of witness elements supplied for the P2TR spend.
        elements: usize,
    },
}

/// Public script verifier. Legacy and segwit-v0 spends use bitcoinconsensus when
/// that backend is enabled; taproot key-path spends use the local BIP341 path.
#[derive(Debug, Default, Clone, Copy)]
pub struct Interpreter;

impl Interpreter {
    /// Number of taproot inputs at which block validation uses the batch Schnorr path.
    pub const BATCH_SCHNORR_THRESHOLD: usize = 16;

    /// Executes a script spend through the enabled script backend.
    pub fn execute(
        &self,
        script_pubkey: &[u8],
        script_sig: &[u8],
        witness: &[Vec<u8>],
        flags: VerifyFlags,
        prevout: &TxOut,
        tx: &bitcoin::Transaction,
        input_idx: usize,
    ) -> Result<bool, ScriptError> {
        let mut spending = tx.clone();
        let inputs = spending.input.len();
        let input = spending
            .input
            .get_mut(input_idx)
            .ok_or(ScriptError::InputIndexOutOfRange {
                index: input_idx,
                inputs,
            })?;
        input.script_sig = ScriptBuf::from_bytes(script_sig.to_vec());
        input.witness = Witness::from_slice(witness);

        let script = Script::from_bytes(script_pubkey);
        if script.is_p2tr() && flags.contains(VerifyFlags::TAPROOT) {
            return verify_taproot_keypath(&spending, input_idx, prevout, script, witness);
        }

        verify_with_bitcoinconsensus(input_idx, prevout, &spending, script, flags)
    }
}

#[cfg(feature = "bitcoinconsensus")]
fn verify_with_bitcoinconsensus(
    input_idx: usize,
    prevout: &TxOut,
    spending: &bitcoin::Transaction,
    script: &Script,
    flags: VerifyFlags,
) -> Result<bool, ScriptError> {
    let serialized = encode::serialize(spending);
    script
        .verify_with_flags(
            input_idx,
            prevout.value,
            serialized.as_slice(),
            flags.consensus_bits(),
        )
        .map(|()| true)
        .map_err(|error| ScriptError::Verification(error.to_string()))
}

#[cfg(not(feature = "bitcoinconsensus"))]
fn verify_with_bitcoinconsensus(
    input_idx: usize,
    _prevout: &TxOut,
    spending: &bitcoin::Transaction,
    script: &Script,
    _flags: VerifyFlags,
) -> Result<bool, ScriptError> {
    let input = spending
        .input
        .get(input_idx)
        .ok_or(ScriptError::InputIndexOutOfRange {
            index: input_idx,
            inputs: spending.input.len(),
        })?;
    if script.as_bytes() == [0x51] && input.script_sig.is_empty() && input.witness.is_empty() {
        return Ok(true);
    }

    Err(ScriptError::Verification(
        "bitcoinconsensus backend is disabled".to_owned(),
    ))
}

fn verify_taproot_keypath(
    spending: &bitcoin::Transaction,
    input_idx: usize,
    prevout: &TxOut,
    script: &Script,
    witness: &[Vec<u8>],
) -> Result<bool, ScriptError> {
    if spending.input.len() != 1 || input_idx != 0 {
        return Err(ScriptError::TaprootPrevoutsUnavailable);
    }
    let signature_bytes = taproot_keypath_signature(witness)?;
    let (signature_bytes, sighash_type) = match signature_bytes.len() {
        64 => (signature_bytes, TapSighashType::Default),
        65 => {
            let sighash_type = TapSighashType::from_consensus_u8(signature_bytes[64])
                .map_err(|error| ScriptError::Verification(error.to_string()))?;
            (&signature_bytes[..64], sighash_type)
        }
        len => {
            return Err(ScriptError::Verification(format!(
                "taproot key-path signature length {len} is not 64 or 65 bytes"
            )));
        }
    };
    let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(signature_bytes)
        .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let public_key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&script.as_bytes()[2..34])
        .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let prevouts = [prevout.clone()];
    let mut cache = SighashCache::new(spending);
    let sighash = cache
        .taproot_key_spend_signature_hash(input_idx, &Prevouts::All(&prevouts), sighash_type)
        .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let message = bitcoin::secp256k1::Message::from_digest(*sighash.as_byte_array());
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    secp.verify_schnorr(&signature, &message, &public_key)
        .map(|()| true)
        .map_err(|error| ScriptError::Verification(error.to_string()))
}

fn taproot_keypath_signature(witness: &[Vec<u8>]) -> Result<&[u8], ScriptError> {
    match witness {
        [signature] => Ok(signature),
        [] => Err(ScriptError::Verification(
            "missing taproot key-path signature".to_owned(),
        )),
        _ => Err(ScriptError::TaprootUnsupportedWitness {
            elements: witness.len(),
        }),
    }
}

#[cfg(all(test, not(feature = "bitcoinconsensus")))]
mod tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
        transaction,
    };

    use super::{Interpreter, ScriptError, VerifyFlags};

    #[test]
    #[cfg(not(feature = "bitcoinconsensus"))]
    fn no_backend_accepts_only_empty_op_true_spend() {
        let interpreter = Interpreter;
        let tx = unsigned_spend();
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };

        assert_eq!(
            interpreter.execute(
                prevout.script_pubkey.as_bytes(),
                &[],
                &[],
                VerifyFlags::MANDATORY,
                &prevout,
                &tx,
                0,
            ),
            Ok(true)
        );

        assert!(matches!(
            interpreter.execute(&[0x00], &[], &[], VerifyFlags::MANDATORY, &prevout, &tx, 0,),
            Err(ScriptError::Verification(_))
        ));
    }

    #[cfg(not(feature = "bitcoinconsensus"))]
    fn unsigned_spend() -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }
}
