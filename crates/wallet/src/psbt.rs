use bitcoin::psbt::{Input, Psbt};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute};

use crate::{Descriptor, WalletError};

/// Previous output selected for spending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrevUtxo {
    /// Outpoint being spent.
    pub outpoint: OutPoint,
    /// Output data required by PSBT signers and finalizers.
    pub txout: TxOut,
}

impl PrevUtxo {
    /// Creates previous-output metadata.
    #[must_use]
    pub const fn new(outpoint: OutPoint, txout: TxOut) -> Self {
        Self { outpoint, txout }
    }
}

/// Watch-only unsigned PSBT builder.
#[derive(Debug)]
pub struct PsbtBuilder<'a> {
    descriptors: &'a [Descriptor],
    inputs: Vec<(PrevUtxo, usize)>,
    outputs: Vec<TxOut>,
}

impl<'a> PsbtBuilder<'a> {
    /// Creates a builder backed by public descriptors.
    #[must_use]
    pub const fn new(descriptors: &'a [Descriptor]) -> Self {
        Self {
            descriptors,
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    /// Adds an input and records which descriptor controls it.
    pub fn add_input(
        &mut self,
        prev_utxo: PrevUtxo,
        descriptor_index: usize,
    ) -> Result<&mut Self, WalletError> {
        if self.descriptors.get(descriptor_index).is_none() {
            return Err(WalletError::Psbt(
                "descriptor index out of range".to_owned(),
            ));
        }
        self.inputs.push((prev_utxo, descriptor_index));
        Ok(self)
    }

    /// Adds a payment output.
    // SPEC: Task 14 requires `add_output(addr, amount)` to take address ownership.
    #[allow(clippy::needless_pass_by_value)]
    pub fn add_output(
        &mut self,
        addr: bitcoin::Address,
        amount: Amount,
    ) -> Result<&mut Self, WalletError> {
        self.outputs.push(TxOut {
            value: amount,
            script_pubkey: addr.script_pubkey(),
        });
        Ok(self)
    }

    /// Adds a raw output.
    pub fn add_txout(&mut self, output: TxOut) -> &mut Self {
        self.outputs.push(output);
        self
    }

    /// Finalizes an unsigned PSBT v2 container.
    pub fn finalize(self) -> Result<Psbt, WalletError> {
        if self.inputs.is_empty() {
            return Err(WalletError::Psbt(
                "PSBT needs at least one input".to_owned(),
            ));
        }
        if self.outputs.is_empty() {
            return Err(WalletError::Psbt(
                "PSBT needs at least one output".to_owned(),
            ));
        }

        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: self
                .inputs
                .iter()
                .map(|(prev, _descriptor_index)| TxIn {
                    previous_output: prev.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: self.outputs,
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)
            .map_err(|error| WalletError::Psbt(error.to_string()))?;
        psbt.version = 2;

        for (input, (prev, descriptor_index)) in psbt.inputs.iter_mut().zip(self.inputs) {
            let descriptor = &self.descriptors[descriptor_index];
            input.witness_utxo = Some(prev.txout);
            attach_descriptor_scripts(input, descriptor);
        }

        Ok(psbt)
    }
}

fn attach_descriptor_scripts(input: &mut Input, descriptor: &Descriptor) {
    let script = descriptor.script_pubkey();
    if script.is_p2sh() {
        if let Ok(redeem_script) = descriptor.inner.explicit_script() {
            input.redeem_script = Some(redeem_script);
        }
    } else if script.is_p2wsh()
        && let Ok(witness_script) = descriptor.inner.explicit_script()
    {
        input.witness_script = Some(witness_script);
    }
}
