use core::ops::RangeInclusive;

use hashbrown::HashMap;

use bitcoin::{Address, Network, OutPoint};
use bitcoin_rs_index::{HashPrefix, ScriptHash, ScriptHashRow};

use crate::{Descriptor, WalletError, descriptor::validate_range};
/// Timestamp attached to a watch-only descriptor import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorTimestamp {
    /// Scan from the current chain tip.
    Now,
    /// Scan from the first block at or after this Unix timestamp.
    Time(u64),
}

/// Persisted metadata for one public descriptor branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorImport {
    /// Canonical public descriptor, including its checksum.
    pub descriptor: String,
    /// Earliest relevant block time.
    pub timestamp: DescriptorTimestamp,
    /// Inclusive derivation range.
    pub range: RangeInclusive<u32>,
    /// Whether the descriptor participates in automatic address generation.
    pub active: bool,
    /// Whether the descriptor describes change outputs.
    pub internal: bool,
    /// Optional caller label.
    pub label: Option<String>,
}

/// Watch-only descriptor index.
#[derive(Clone, Debug, Default)]
pub struct Watcher {
    /// Watched public descriptors.
    pub descriptors: Vec<Descriptor>,
    /// Metadata for descriptors imported through the watch-only RPC surface.
    ///
    /// One record is stored per expanded multipath branch.
    pub imports: Vec<DescriptorImport>,
    /// Address-to-outpoint cache populated from index scans.
    pub addr_to_utxos: HashMap<Address, Vec<OutPoint>>,
}

impl Watcher {
    /// Builds a watcher for `descriptors`.
    #[must_use]
    pub fn new(descriptors: Vec<Descriptor>) -> Self {
        Self {
            descriptors,
            imports: Vec::new(),
            addr_to_utxos: HashMap::new(),
        }
    }

    /// Imports one public descriptor for watching and returns the indices of
    /// the appended branches.
    ///
    /// Private descriptor material is rejected before any state changes, and
    /// multipath descriptors import one branch per index.
    pub fn import_descriptor(&mut self, descriptor: &str) -> Result<Vec<usize>, WalletError> {
        self.import(&DescriptorImport {
            descriptor: descriptor.to_owned(),
            timestamp: DescriptorTimestamp::Time(0),
            range: 0..=0,
            active: false,
            internal: false,
            label: None,
        })
    }

    /// Imports a public descriptor and atomically retains its watch metadata.
    ///
    /// The supplied identity is replaced with each branch's canonical public
    /// descriptor before storage, so private material can never enter state.
    pub fn import(&mut self, import: &DescriptorImport) -> Result<Vec<usize>, WalletError> {
        let parsed = Descriptor::parse_all(&import.descriptor)?;
        for descriptor in &parsed {
            validate_range(descriptor.is_ranged(), &import.range)?;
        }

        let first = self.descriptors.len();
        let records = parsed.iter().map(|descriptor| {
            let mut record = import.clone();
            record.descriptor = descriptor.to_descriptor_string();
            record
        });
        self.imports.extend(records);
        self.descriptors.extend(parsed);
        Ok((first..self.descriptors.len()).collect())
    }

    /// Returns the watched descriptor at `descriptor_index`.
    fn descriptor(&self, descriptor_index: usize) -> Result<&Descriptor, WalletError> {
        self.descriptors
            .get(descriptor_index)
            .ok_or_else(|| WalletError::Descriptor("descriptor index out of range".to_owned()))
    }

    /// Derives an address for a descriptor and index.
    pub fn derive_address(
        &self,
        descriptor_index: usize,
        network: Network,
        child_index: u32,
    ) -> Result<Address, WalletError> {
        self.descriptor(descriptor_index)?
            .derive_address(network, child_index)
    }

    /// Returns the generic script-index scan prefix for a descriptor index.
    pub fn script_hash_scan_prefix(
        &self,
        descriptor_index: usize,
    ) -> Result<HashPrefix, WalletError> {
        let script_hash = ScriptHash::new(
            self.descriptor(descriptor_index)?
                .script_pubkey()?
                .as_script(),
        );
        Ok(ScriptHashRow::scan_prefix(script_hash))
    }

    /// Returns the script-index scan prefixes for every derivation index in
    /// `range`.
    ///
    /// Ranged descriptors yield one prefix per index; unranged descriptors
    /// accept only the zero range, mirroring address derivation.
    pub fn script_hash_scan_prefixes(
        &self,
        descriptor_index: usize,
        range: RangeInclusive<u32>,
    ) -> Result<Vec<HashPrefix>, WalletError> {
        let descriptor = self.descriptor(descriptor_index)?;
        validate_range(descriptor.is_ranged(), &range)?;
        range
            .map(|index| {
                let script_hash = ScriptHash::new(descriptor.script_pubkey_at(index)?.as_script());
                Ok(ScriptHashRow::scan_prefix(script_hash))
            })
            .collect()
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
