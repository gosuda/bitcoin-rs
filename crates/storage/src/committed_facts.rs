use bytes::Bytes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedFacts {
    pub commit_id: u64,
    pub blocks: Vec<CommittedBlock>,
}

impl CommittedFacts {
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        let mut total = u64::try_from(core::mem::size_of::<Self>()).unwrap_or(u64::MAX);
        for block in &self.blocks {
            total = total.saturating_add(block.size_bytes());
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
        let mut total = u64::try_from(core::mem::size_of::<Self>()).unwrap_or(u64::MAX);
        for tx in &self.txs {
            total = total.saturating_add(tx.size_bytes());
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
        let mut total = u64::try_from(core::mem::size_of::<Self>()).unwrap_or(u64::MAX);
        for input in &self.inputs {
            let prevout_size =
                u64::try_from(core::mem::size_of::<SpentPrevout>()).unwrap_or(u64::MAX);
            let script_len = u64::try_from(input.script.len()).unwrap_or(u64::MAX);
            total = total
                .saturating_add(prevout_size)
                .saturating_add(script_len);
        }
        for output in &self.outputs {
            let output_size =
                u64::try_from(core::mem::size_of::<CreatedOutput>()).unwrap_or(u64::MAX);
            let script_len = u64::try_from(output.script.len()).unwrap_or(u64::MAX);
            total = total.saturating_add(output_size).saturating_add(script_len);
        }
        total
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedOutput {
    pub vout: u32,
    pub value: u64,
    pub script: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentPrevout {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value: u64,
    pub script: Bytes,
    pub height: u32,
    pub coinbase: bool,
}
