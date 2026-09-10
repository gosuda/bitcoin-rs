from pathlib import Path
import re, subprocess, os
root=Path.cwd(); cand=Path(os.environ['CANDIDATE_SOURCE'])
def replace(path, old, new, count=1):
 p=root/path;s=p.read_text();assert s.count(old)==count,(path,s.count(old),old[:120]);p.write_text(s.replace(old,new))
p='crates/utxo/src/set.rs';s=(root/p).read_text();c=(cand/p).read_text();a=s.index('/// Durability mode for one persisted connect or disconnect.');b=c.index('/// Durability requested for one persisted connect or disconnect.');(root/p).write_text(s[:a]+c[b:])
p='crates/utxo/tests/overhaul_persistent_coins.rs';(root/p).write_text((cand/p).read_text())
patch=subprocess.check_output(['git','diff','--binary','f8bb0f8d0f49ade933eb558d6722041d37a9c02c','db1504be00f994a7d3d214a8ecb3c0ea6e25181a'],text=True)
paths=['crates/utxo/src/shard.rs','crates/node/src/metrics.rs','crates/rpc/src/compat_manifest.rs','bin/bitcoin-rs/tests/overhaul_evidence.rs','bin/bitcoin-rs/tests/overhaul_reference_set.rs']
parts=re.split(r'(?=^diff --git )',patch,flags=re.M)
selected=''.join(part for part in parts if any(part.startswith(f'diff --git a/{p} b/{p}\n') for p in paths))
subprocess.run(['git','apply','--check','-'],cwd=root,input=selected,text=True,check=True)
subprocess.run(['git','apply','-'],cwd=root,input=selected,text=True,check=True)
replace('crates/utxo/src/set.rs','self.retained_before_images.insert(*txid, image.clone());','self.retained_before_images.entry(*txid).or_insert_with(|| image.clone());')
replace('crates/utxo/src/set.rs','/// mismatch is a failed precondition, not proof of a concurrent writer.','''/// mismatch is a failed precondition, not proof of a concurrent writer.
/// Independent instances sharing a store still require an external writer owner;
/// exclusive access serializes this cache, not other handles to the database.''')
for name in ['fjall_impl.rs','redb_impl.rs','rocksdb_impl.rs','mdbx_impl.rs']:
 p=root/'crates/storage/src'/name;s=p.read_text();offset=0
 while (start:=s.find('return match fault {',offset))>=0:
  opening=s.index('{',start);depth=1;end=opening+1
  while depth:
   depth+=(s[end]=='{')-(s[end]=='}');end+=1
  if s[end:end+1]==';':end+=1
  body=s[opening+1:end-2];indent=' '*(start-s.rfind('\n',0,start)-1)
  if 'only releases Sync-boundary faults' in body or 'only releases Flush-boundary faults' in body:
   replacement='return Err(fault.injected_error());'
  elif 'only releases Apply-boundary faults' in body:
   m=re.search(r'crate::PersistFault::PartialApply => \{(.*)\n\s+\}\n\s+_ =>',body,re.S)
   if m:
    partial=m[1];tail=partial.rfind('Err(fault.injected_error())');assert tail>=0,(name,body)
    lines=[line for line in partial[:tail].rstrip().splitlines() if line.strip()];minimum=min(len(l)-len(l.lstrip()) for l in lines)
    partial='\n'.join(indent+'    '+l[minimum:] for l in lines)
    replacement='if fault == crate::PersistFault::PartialApply {\n'+partial+'\n'+indent+'}\n'+indent+'return Err(fault.injected_error());'
   else:
    assert 'crate::PersistFault::PartialApply => Err(fault.injected_error())' in body,(name,body)
    replacement='return Err(fault.injected_error());'
  else:offset=end;continue
  s=s[:start]+replacement+s[end:];offset=start+len(replacement)
 p.write_text(s)
replace('crates/storage/src/trait_.rs','    /// Drop the apply step.','    /// Drop the apply step and return an error; no visible write was accepted.')
replace('crates/storage/src/trait_.rs','    /// Return from flush without syncing deferred writes.','    /// Drop the flush sync and return an error; durability is not acknowledged.')
replace('crates/storage/src/trait_.rs','    /// Drop durability completion after apply.','    /// Drop durability completion after apply and return an error, not a receipt.')
p=root/'crates/storage/tests/overhaul_atomic_durability.rs';s=p.read_text();a=s.index('    fn completion_fault(');b=s.index('\n}\n\nconst FAULTS',a)
s=s[:a]+'''    fn crosses(&self, boundary: bitcoin_rs_storage::PersistBoundary) -> bool {
        use bitcoin_rs_storage::PersistBoundary;
        match boundary {
            PersistBoundary::Apply => true,
            PersistBoundary::Sync => matches!(self, Self::WriteDurable | Self::WriteDurableIf),
            PersistBoundary::Flush => matches!(self, Self::FlushDeferred),
        }
    }
'''+s[b:]
s=s.replace('''            assert_atomic_recovery(&snapshot_all(&store, rows), &old, &proposed, &label);
            if route.completion_fault(fault) {''','''            let recovered = snapshot_all(&store, rows);
            assert_atomic_recovery(&recovered, &old, &proposed, &label);
            if outcome.is_ok() && !matches!(route, Route::Write) {
                assert_eq!(recovered, proposed, "{label}: success acknowledged an absent durable batch");
            }
            if route.crosses(fault.boundary()) {''')
s=s.replace('"{label}: durable route reported success on a faulted completion"','"{label}: route reported success on an injected fault at its boundary"');p.write_text(s)
replace('crates/storage/tests/backend_metrics.rs','#[test]\nfn fjall_counts_each_durability_path_once','#[test]\n#[cfg(feature = "fjall")]\nfn fjall_counts_each_durability_path_once')
replace('crates/storage/tests/storage_footprint.rs','''use bitcoin_rs_storage::{
    ColumnFamily, DataDirAnchor, FootprintError, KvStore, PhysicalObservationKind, WriteBatch,
    logical_column_family, logical_store_owners, measure_physical_tree,
};''','''use bitcoin_rs_storage::{DataDirAnchor, FootprintError, PhysicalObservationKind, measure_physical_tree};
#[cfg(feature = "fjall")]
use bitcoin_rs_storage::{ColumnFamily, KvStore, WriteBatch, logical_column_family, logical_store_owners};''')
replace('crates/utxo/tests/overhaul_persistent_coins.rs','    fail_writes: std::sync::Arc<std::sync::atomic::AtomicBool>,','    fail_writes: std::sync::Arc<std::sync::atomic::AtomicBool>,\n    fail_flush: std::sync::Arc<std::sync::atomic::AtomicBool>,')
replace('crates/utxo/tests/overhaul_persistent_coins.rs','''    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }''','''    fn flush(&self) -> Result<(), StorageError> {
        if self.fail_flush.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(StorageError::InvalidOperation("injected flush failure"));
        }
        Ok(())
    }''')
p=root/'crates/utxo/tests/overhaul_persistent_coins.rs'
p.write_text(p.read_text()+'''

/// RCV-04: a failed flush cannot release pins and reopen an uncertain cache.
#[test]
fn flush_failure_requires_recovery_even_after_the_fault_is_cleared() {
    let store = MemoryStore::default();
    let a = txid(27);
    let mut coins = PersistentUtxoSet::new(store.clone());
    coins.connect_block(&block(two_output_add(a, &[0x51], &[0x52]), vec![]), &a, CoinDurability::Deferred).expect("deferred add");
    store.fail_flush.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(coins.flush(), Err(PersistentUtxoError::Storage(_))));
    store.fail_flush.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(coins.get(&outpoint(a, 0)), Err(PersistentUtxoError::RecoveryRequired)));
    assert!(matches!(coins.ledger(), Err(PersistentUtxoError::RecoveryRequired)));
    assert!(matches!(coins.flush(), Err(PersistentUtxoError::RecoveryRequired)));
}

/// RCV-04 / FP-05: repeated deferred writes retain the start of the durability window.
#[test]
fn repeated_deferred_spends_keep_the_original_before_image() {
    let store = MemoryStore::default();
    let a = txid(28);
    let mut coins = PersistentUtxoSet::new(store.clone());
    coins.connect_block(&block(two_output_add(a, &[0x51], &[0x52]), vec![]), &a, CoinDurability::Durable).expect("seed");
    let original_bytes = store.get(ColumnFamily::CoinRecords, a.as_byte_array()).expect("read").expect("row").len();
    for vout in [0, 1] {
        coins.connect_block(&block(vec![], vec![outpoint(a, vout)]), &a, CoinDurability::Deferred).expect("deferred spend");
        assert_eq!(coins.ledger().expect("ledger").retained_before_image_bytes, original_bytes);
    }
    coins.flush().expect("flush");
    assert_eq!(coins.ledger().expect("ledger").retained_before_image_bytes, 0);
}
''')
replace('docs/contracts/recovery.md','''How the node recovers an authoritative chainstate after a crash, a lost
write, a reorganization, or an incompatible datadir. `chainstate` is the
single durable authority. Every other persisted component is derived and
reconciles to it.

Owners:''','''## Implementation status

This page specifies the **target durable-root protocol**, not the current
startup implementation. The proposed `crates/chainstate` owner and `DurableHead`
below do not exist in the runtime. Current startup/shutdown still restores and
publishes node checkpoints; see [embedding](embedding.md). `PersistentUtxoSet`
is an isolated persisted-cache API, not an integrated node recovery protocol.

Existing `crates/storage/tests/overhaul_atomic_durability.rs` checks injected
backend faults and clean reopen: each recovered batch is wholly old or new,
and a successful durable receipt requires the proposed bytes. It does not
simulate power loss or prove whole-node recovery. The owner paths and crash,
reorg, and checkpoint-independence tests below are planned unless they actually
exist; naming a test here is not evidence that it ran.

Target owners:''')
replace('docs/contracts/recovery.md','The authoritative durable root is:','The proposed authoritative durable root is:')
replace('docs/contracts/recovery.md','`DurableHead` is the persisted form:','The proposed persisted form (not an implemented Rust type) is:')
replace('docs/contracts/recovery.md','The crash and error points in `docs/contracts/chainstate-recovery.md` and','The target crash and error points in `docs/chainstate-recovery.md` and')
replace('docs/contracts/recovery.md','| Sync before durable batch | The atomic batch contains only data that reached the OS; any missing body or undo prevents commit. |','| Append/sync fails before the atomic batch is attempted | Keep the prior root. Even synced orphan frames do not authorize a new head. |')
replace('docs/contracts/recovery.md','| Durable batch ambiguous | Recovery resolves the ambiguity by `CommitId` and full identity; no mixed head/coins. |','| Durable batch ambiguous | Keep the fence closed. Recover the prior or whole proposed root by `CommitId` and full identity, then reconcile before publication or retry. Do not assume rollback. |')
