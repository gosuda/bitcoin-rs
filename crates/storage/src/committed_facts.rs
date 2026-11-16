use core::{alloc::Layout, mem::size_of, ops::Deref, sync::atomic::AtomicUsize};
use std::sync::Arc;

use hashbrown::HashSet;

/// An immutable, complete script allocation, shared only by cloning its owner.
///
/// Empty scripts retain no allocation. Borrowed subslices cannot become owners.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FactsScript(Option<Arc<[u8]>>);

impl FactsScript {
    #[must_use]
    pub fn copy_from_slice(script: &[u8]) -> Self {
        if script.is_empty() {
            Self::default()
        } else {
            Self(Some(Arc::from(script)))
        }
    }
}

impl AsRef<[u8]> for FactsScript {
    fn as_ref(&self) -> &[u8] {
        self.0.as_deref().unwrap_or_default()
    }
}

impl Deref for FactsScript {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedFacts {
    pub commit_id: u64,
    pub blocks: Vec<CommittedBlock>,
}

impl CommittedFacts {
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        let mut scripts = HashSet::new();
        let mut total = bytes(size_of::<Self>())
            .saturating_add(capacity_bytes::<CommittedBlock>(self.blocks.capacity()));
        for block in &self.blocks {
            total = total.saturating_add(block.heap_bytes(&mut scripts));
        }
        total
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedBlock {
    pub height: u32,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub header: [u8; 80],
    pub txs: Vec<TxFacts>,
}

impl CommittedBlock {
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        bytes(size_of::<Self>()).saturating_add(self.heap_bytes(&mut HashSet::new()))
    }

    fn heap_bytes(&self, scripts: &mut HashSet<*const u8>) -> u64 {
        let mut total = capacity_bytes::<TxFacts>(self.txs.capacity());
        for tx in &self.txs {
            total = total.saturating_add(tx.heap_bytes(scripts));
        }
        total
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxFacts {
    pub txid: [u8; 32],
    pub offset: u32,
    pub len: u32,
    pub inputs: Vec<SpentPrevout>,
    pub outputs: Vec<CreatedOutput>,
}

impl TxFacts {
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        bytes(size_of::<Self>()).saturating_add(self.heap_bytes(&mut HashSet::new()))
    }

    fn heap_bytes(&self, scripts: &mut HashSet<*const u8>) -> u64 {
        let mut total = capacity_bytes::<SpentPrevout>(self.inputs.capacity())
            .saturating_add(capacity_bytes::<CreatedOutput>(self.outputs.capacity()));
        for script in self
            .inputs
            .iter()
            .map(|input| &input.script)
            .chain(self.outputs.iter().map(|output| &output.script))
        {
            let Some(owner) = &script.0 else {
                continue;
            };
            if scripts.insert(owner.as_ptr()) {
                total = total.saturating_add(script_allocation_bytes(owner));
            }
        }
        total
    }
}

fn bytes(size: usize) -> u64 {
    u64::try_from(size).unwrap_or(u64::MAX)
}

fn capacity_bytes<T>(capacity: usize) -> u64 {
    bytes(capacity).saturating_mul(bytes(size_of::<T>()))
}

/// Includes the two atomic reference counts and trailing alignment padding of
/// the standard library's `ArcInner<[u8]>` allocation, not allocator bookkeeping.
fn script_allocation_bytes(script: &[u8]) -> u64 {
    Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::for_value(script))
        .map_or(u64::MAX, |(layout, _)| bytes(layout.pad_to_align().size()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedOutput {
    pub vout: u32,
    pub value: u64,
    pub script: FactsScript,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentPrevout {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value: u64,
    pub script: FactsScript,
    pub height: u32,
    pub coinbase: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction(script: FactsScript) -> TxFacts {
        TxFacts {
            txid: [1; 32],
            offset: 0,
            len: 0,
            inputs: Vec::new(),
            outputs: vec![CreatedOutput {
                vout: 0,
                value: 1,
                script,
            }],
        }
    }

    fn block(txs: Vec<TxFacts>) -> CommittedBlock {
        CommittedBlock {
            height: 1,
            hash: [1; 32],
            parent_hash: [0; 32],
            header: [0; 80],
            txs,
        }
    }

    // BUD-06
    #[test]
    fn retained_size_covers_spare_capacity_at_every_vec_level() {
        let mut tx = transaction(FactsScript::default());
        tx.inputs.reserve(7);
        tx.outputs.reserve(9);
        let input_capacity = tx.inputs.capacity();
        let output_capacity = tx.outputs.capacity();
        let mut txs = vec![tx];
        txs.reserve(5);
        let tx_capacity = txs.capacity();
        let mut blocks = vec![block(txs)];
        blocks.reserve(3);
        let block_capacity = blocks.capacity();
        let facts = CommittedFacts {
            commit_id: 1,
            blocks,
        };
        let expected = size_of::<CommittedFacts>()
            + block_capacity * size_of::<CommittedBlock>()
            + tx_capacity * size_of::<TxFacts>()
            + input_capacity * size_of::<SpentPrevout>()
            + output_capacity * size_of::<CreatedOutput>();
        assert_eq!(u64::try_from(expected), Ok(facts.size_bytes()));
    }

    // BUD-06
    #[test]
    fn shared_scripts_are_charged_once_across_blocks_and_transactions() {
        let script = FactsScript::copy_from_slice(&[0x51; size_of::<usize>()]);
        let facts = CommittedFacts {
            commit_id: 1,
            blocks: vec![
                block(vec![
                    transaction(script.clone()),
                    transaction(script.clone()),
                ]),
                block(vec![transaction(script)]),
            ],
        };
        let container_bytes = size_of::<CommittedFacts>()
            + facts.blocks.capacity() * size_of::<CommittedBlock>()
            + facts
                .blocks
                .iter()
                .map(|block| {
                    block.txs.capacity() * size_of::<TxFacts>()
                        + block
                            .txs
                            .iter()
                            .map(|tx| tx.outputs.capacity() * size_of::<CreatedOutput>())
                            .sum::<usize>()
                })
                .sum::<usize>();
        assert_eq!(
            u64::try_from(container_bytes + 3 * size_of::<usize>()),
            Ok(facts.size_bytes())
        );
    }

    // BUD-06
    #[test]
    fn standalone_block_deduplicates_output_and_spent_input_owner() {
        let script = FactsScript::copy_from_slice(&[0x51; size_of::<usize>()]);
        let mut tx = transaction(script.clone());
        tx.inputs.push(SpentPrevout {
            txid: [2; 32],
            vout: 0,
            value: 1,
            script,
            height: 0,
            coinbase: false,
        });
        let expected_heap = tx.inputs.capacity() * size_of::<SpentPrevout>()
            + tx.outputs.capacity() * size_of::<CreatedOutput>()
            + 3 * size_of::<usize>();
        assert_eq!(
            u64::try_from(size_of::<TxFacts>() + expected_heap),
            Ok(tx.size_bytes())
        );
        let block = block(vec![tx]);
        assert_eq!(
            u64::try_from(
                size_of::<CommittedBlock>()
                    + block.txs.capacity() * size_of::<TxFacts>()
                    + expected_heap
            ),
            Ok(block.size_bytes())
        );
    }

    // BUD-06
    #[test]
    fn equal_content_in_distinct_allocations_is_charged_twice() {
        let first = FactsScript::copy_from_slice(&[0x51; size_of::<usize>()]);
        let second = FactsScript::copy_from_slice(&[0x51; size_of::<usize>()]);
        assert_eq!(first, second);
        let block = block(vec![transaction(first), transaction(second)]);
        let expected = size_of::<CommittedBlock>()
            + block.txs.capacity() * size_of::<TxFacts>()
            + block
                .txs
                .iter()
                .map(|tx| tx.outputs.capacity() * size_of::<CreatedOutput>())
                .sum::<usize>()
            + 6 * size_of::<usize>();
        assert_eq!(u64::try_from(expected), Ok(block.size_bytes()));
    }

    // BUD-06
    #[test]
    fn empty_scripts_retain_no_buffer_allocation() {
        let tx = transaction(FactsScript::copy_from_slice(&[]));
        assert_eq!(tx.outputs[0].script, FactsScript::default());
        assert_eq!(
            u64::try_from(
                size_of::<TxFacts>() + tx.outputs.capacity() * size_of::<CreatedOutput>()
            ),
            Ok(tx.size_bytes())
        );
    }

    // BUD-06
    #[test]
    fn cloned_script_keeps_owner_alive_until_last_handle_drops() {
        let script = FactsScript::copy_from_slice(&[0x51]);
        let weak = script.0.as_ref().map(Arc::downgrade);
        let clone = script.clone();
        drop(script);
        assert!(weak.as_ref().and_then(std::sync::Weak::upgrade).is_some());
        drop(clone);
        assert!(weak.as_ref().and_then(std::sync::Weak::upgrade).is_none());
    }
}
