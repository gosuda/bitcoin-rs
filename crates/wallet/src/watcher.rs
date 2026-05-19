use hashbrown::HashMap;

use bitcoin::{Address, Network, OutPoint};
use bitcoin_rs_index::{ScriptHash, ScriptHashRow};

use crate::{Descriptor, WalletError};

/// Watch-only descriptor index.
#[derive(Clone, Debug, Default)]
pub struct Watcher {
    /// Watched public descriptors.
    pub descriptors: Vec<Descriptor>,
    /// Address-to-outpoint cache populated from index scans.
    pub addr_to_utxos: HashMap<Address, Vec<OutPoint>>,
}

impl Watcher {
    /// Builds a watcher for `descriptors`.
    #[must_use]
    pub fn new(descriptors: Vec<Descriptor>) -> Self {
        Self {
            descriptors,
            addr_to_utxos: HashMap::new(),
        }
    }

    /// Derives an address for a descriptor and index.
    pub fn derive_address(
        &self,
        descriptor_index: usize,
        network: Network,
        child_index: u32,
    ) -> Result<Address, WalletError> {
        let descriptor = self
            .descriptors
            .get(descriptor_index)
            .ok_or_else(|| WalletError::Descriptor("descriptor index out of range".to_owned()))?;
        descriptor.derive_address(network, child_index)
    }

    /// Returns the electrum script-hash scan prefix for a descriptor index.
    pub fn script_hash_scan_prefix(
        &self,
        descriptor_index: usize,
    ) -> Result<bitcoin_rs_index::HashPrefix, WalletError> {
        let descriptor = self
            .descriptors
            .get(descriptor_index)
            .ok_or_else(|| WalletError::Descriptor("descriptor index out of range".to_owned()))?;
        let script_hash = ScriptHash::new(descriptor.script_pubkey().as_script());
        Ok(ScriptHashRow::scan_prefix(script_hash))
    }

    /// Records an outpoint observed for an address.
    pub fn record_utxo(&mut self, address: Address, outpoint: OutPoint) {
        self.addr_to_utxos
            .entry(address)
            .or_default()
            .push(outpoint);
    }

    /// Returns cached UTXOs for an address.
    #[must_use]
    pub fn utxos_for(&self, address: &Address) -> &[OutPoint] {
        self.addr_to_utxos.get(address).map_or(&[], Vec::as_slice)
    }
}
