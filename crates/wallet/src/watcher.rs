use core::ops::RangeInclusive;

use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use bitcoin::{Address, Amount, Network, OutPoint};
use bitcoin_rs_index::{HashPrefix, ScriptHash, ScriptHashRow};

use crate::{Descriptor, WalletError, descriptor::validate_range};

const WALLET_STATE_VERSION: u32 = 1;
/// Timestamp attached to a watch-only descriptor import.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Known output values for recorded outpoints.
    pub utxo_values: HashMap<OutPoint, Amount>,
}

impl Watcher {
    /// Builds a watcher for `descriptors`.
    #[must_use]
    pub fn new(descriptors: Vec<Descriptor>) -> Self {
        Self {
            descriptors,
            imports: Vec::new(),
            addr_to_utxos: HashMap::new(),
            utxo_values: HashMap::new(),
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

    /// Records an outpoint observed for an address without a known amount.
    ///
    /// Unknown amounts stay absent rather than being stored as zero.
    pub fn record_outpoint(&mut self, address: Address, outpoint: OutPoint) {
        let outs = self.addr_to_utxos.entry(address).or_default();
        if !outs.contains(&outpoint) {
            outs.push(outpoint);
        }
    }

    /// Records an outpoint and its authoritative amount.
    pub fn record_utxo(&mut self, address: Address, outpoint: OutPoint, value: Amount) {
        self.record_outpoint(address, outpoint);
        self.utxo_values.insert(outpoint, value);
    }

    /// Drops runtime UTXO cache facts. Descriptor imports stay intact.
    pub fn clear_utxos(&mut self) {
        self.addr_to_utxos.clear();
        self.utxo_values.clear();
    }

    /// Encodes canonical descriptor imports. UTXO cache facts are omitted.
    pub fn encode_state(&self) -> Result<Vec<u8>, WalletError> {
        let state = DurableWatcherState {
            version: WALLET_STATE_VERSION,
            imports: self
                .imports
                .iter()
                .map(DurableImport::from_import)
                .collect(),
        };
        serde_json::to_vec(&state).map_err(|error| WalletError::State(error.to_string()))
    }

    /// Rebuilds a watcher by routing stored imports through [`Watcher::import`].
    pub fn decode_state(bytes: &[u8]) -> Result<Self, WalletError> {
        let state: DurableWatcherState =
            serde_json::from_slice(bytes).map_err(|error| WalletError::State(error.to_string()))?;
        if state.version != WALLET_STATE_VERSION {
            return Err(WalletError::State(format!(
                "unsupported watch-only state version {}",
                state.version
            )));
        }
        let mut watcher = Self::new(Vec::new());
        for import in state.imports {
            watcher.import(&import.into_import())?;
        }
        Ok(watcher)
    }

    /// Returns cached UTXOs for an address.
    #[must_use]
    pub fn utxos_for(&self, address: &Address) -> &[OutPoint] {
        self.addr_to_utxos.get(address).map_or(&[], Vec::as_slice)
    }

    /// Returns the known value for `outpoint`, if one was recorded.
    #[must_use]
    pub fn utxo_value(&self, outpoint: &OutPoint) -> Option<Amount> {
        self.utxo_values.get(outpoint).copied()
    }
}

#[derive(Serialize, Deserialize)]
struct DurableWatcherState {
    version: u32,
    imports: Vec<DurableImport>,
}

#[derive(Serialize, Deserialize)]
struct DurableImport {
    descriptor: String,
    timestamp: DescriptorTimestamp,
    range_start: u32,
    range_end: u32,
    active: bool,
    internal: bool,
    label: Option<String>,
}

impl DurableImport {
    fn from_import(import: &DescriptorImport) -> Self {
        Self {
            descriptor: import.descriptor.clone(),
            timestamp: import.timestamp,
            range_start: *import.range.start(),
            range_end: *import.range.end(),
            active: import.active,
            internal: import.internal,
            label: import.label.clone(),
        }
    }

    fn into_import(self) -> DescriptorImport {
        DescriptorImport {
            descriptor: self.descriptor,
            timestamp: self.timestamp,
            range: self.range_start..=self.range_end,
            active: self.active,
            internal: self.internal,
            label: self.label,
        }
    }
}
