//! Node-owned composition adapter: wires the storage-owned recovery evidence
//! publisher into the index worker (`IndexAheadSink`) and RPC
//! (`RollbackWarningSource`).

use bitcoin_rs_storage::recovery_evidence::RecoveryEvidencePublisher;

pub(crate) struct RecoveryReporter(pub(crate) RecoveryEvidencePublisher);

impl bitcoin_rs_index::runtime::IndexAheadSink for RecoveryReporter {
    fn report_index_ahead(
        &self,
        capability: &str,
        index_height: u32,
        tip_height: u32,
        tip_hash_be: &str,
        index_hash_be: &str,
        depth: u32,
        unix_secs: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.0
            .publish_index_ahead(
                capability,
                index_height,
                tip_height,
                tip_hash_be,
                index_hash_be,
                depth,
                unix_secs,
            )
            .map_err(Into::into)
    }
}

impl bitcoin_rs_index::RollbackWarningSource for RecoveryReporter {
    fn rollback_warnings(&self) -> Vec<String> {
        self.0.warnings()
    }
}
