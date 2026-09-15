//! BIP431 / Core 31.1 TRUC topology checks over the admitted graph.

use bitcoin_rs_primitives::{Tx, Txid};
use hashbrown::HashSet;
use thiserror::Error;

use crate::{EntryId, Mempool, RbfError};

/// A typed TRUC rejection. The public policy reason is `TRUC-violation`.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("TRUC-violation")]
pub enum TrucError {
    /// Confirmed transactions may cross versions; unconfirmed parents may not.
    Version,
    /// A version-3 transaction exceeds 10,000 sigop-adjusted virtual bytes.
    Size,
    /// A version-3 child exceeds 1,000 sigop-adjusted virtual bytes.
    ChildSize,
    /// A version-3 transaction would have more than one unconfirmed ancestor.
    Ancestors,
    /// A version-3 parent would have more than one descendant.
    Descendants,
}

impl Mempool {
    /// Direct conflicts, with the sole eligible TRUC sibling added when
    /// allowed. Descendant collection and all fee decisions remain in RBF.
    pub(crate) fn truc_conflicts(
        &self,
        tx: &Tx,
        vsize: u32,
        allow_sibling: bool,
    ) -> Result<(Vec<EntryId>, bool), RbfError> {
        let mut conflicts = self.conflicts_for(tx);
        let mut sibling_eviction = false;
        let parent_txids: HashSet<_> = tx.inputs.iter().map(|i| i.previous_output.txid).collect();
        let parents: Vec<_> = parent_txids
            .iter()
            .filter_map(|id| {
                self.entry_id_by_txid(id)
                    .and_then(|id| self.entry(id).map(|entry| (id, entry)))
            })
            .collect();
        if parents
            .iter()
            .any(|(_, parent)| (parent.tx.version == 3) != (tx.version == 3))
        {
            return Err(TrucError::Version.into());
        }
        if tx.version != 3 {
            return Ok((conflicts, false));
        }
        if vsize > 10_000 {
            return Err(TrucError::Size.into());
        }
        if parents.len() > 1 {
            return Err(TrucError::Ancestors.into());
        }
        if let Some((parent_id, _parent)) = parents.first() {
            if !self.ancestor_ids_for_entry(*parent_id).is_empty() {
                return Err(TrucError::Ancestors.into());
            }
            if vsize > 1_000 {
                return Err(TrucError::ChildSize.into());
            }
            let descendants = self.descendant_ids_for_entry(*parent_id);
            let replacing_child = descendants.iter().any(|id| conflicts.contains(id));
            if !descendants.is_empty() && !replacing_child {
                let sibling = descendants.first().copied().filter(|id| {
                    allow_sibling
                        && descendants.len() == 1
                        && self.ancestor_ids_for_entry(*id).len() == 1
                });
                let sibling = sibling.ok_or(TrucError::Descendants)?;
                conflicts.push(sibling);
                sibling_eviction = true;
            }
        }
        Ok((conflicts, sibling_eviction))
    }

    /// `PackageTestAccept` forbids sibling eviction. Package-only ancestry,
    /// siblings and children are checked after every row's prechecks.
    pub(crate) fn check_package_truc(&self, txs: &[Tx], vsizes: &[u32]) -> Result<(), TrucError> {
        for (index, tx) in txs.iter().enumerate() {
            let parent_ids: HashSet<Txid> =
                tx.inputs.iter().map(|i| i.previous_output.txid).collect();
            let parents: Vec<_> = parent_ids
                .iter()
                .filter_map(|id| {
                    txs[..index]
                        .iter()
                        .find(|parent| parent.txid() == *id)
                        .or_else(|| self.entry_by_txid(id).map(|entry| entry.tx.as_ref()))
                })
                .collect();
            if parents
                .iter()
                .any(|parent| (parent.version == 3) != (tx.version == 3))
            {
                return Err(TrucError::Version);
            }
            if tx.version != 3 {
                continue;
            }
            if parents.len() > 1 {
                return Err(TrucError::Ancestors);
            }
            if let Some(parent) = parents.first() {
                if vsizes[index] > 1_000 {
                    return Err(TrucError::ChildSize);
                }
                let parent_id = parent.txid();
                let txid = tx.txid();
                for (other_index, other) in txs.iter().enumerate() {
                    if other_index == index {
                        continue;
                    }
                    for input in &other.inputs {
                        if input.previous_output.txid == parent_id {
                            return Err(TrucError::Descendants);
                        }
                        if input.previous_output.txid == txid {
                            return Err(TrucError::Ancestors);
                        }
                    }
                }
                if self
                    .entry_id_by_txid(&parent_id)
                    .is_some_and(|id| !self.descendant_ids_for_entry(id).is_empty())
                {
                    return Err(TrucError::Descendants);
                }
            }
        }
        Ok(())
    }
}
