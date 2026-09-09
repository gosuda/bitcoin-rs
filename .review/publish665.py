from pathlib import Path
import hashlib, subprocess
BASE = "df8717e86a25de3d94e51d93cb2787d9021cb2fa"
CANDIDATE = "a066da4621264bd478e843be984e6b0eaae8c2b9"
EXPECTED = {'bin/bitcoin-rs/tests/overhaul_evidence.rs': 'a4a3e4aea94d272bd550b27ee156a646d3c7e8ada47dd6b4eb7ea5347f8bb41f', 'bin/bitcoin-rs/tests/overhaul_reference_set.rs': 'c8d96d7c5703d79277355e247cb6336aa44b0122a335864852422b3d22e024b1', 'crates/consensus/tests/overhaul_parse_parity.rs': 'd79c84a60b73cd6518ec69dbda6a58a6f805d30acc65b4ae26a3ada059dab872', 'crates/consensus/tests/overhaul_prepared_inputs.rs': '905176ca75e4d5d0421298a7d763bfbde01103ffcf7bd0f731a032f5345349af', 'crates/mempool/src/gateway.rs': '12c93ffbd6ca367bc424d99f5d0611a889ab0f7660cef56259c735ad385b1b8d', 'crates/node/src/metrics.rs': 'ea302c920ad0295c6a9f02c5877daed5618064ad834dc959260b33f2e7e67a3a', 'crates/primitives/tests/overhaul_layout.rs': 'a6d4794cbdf60b69eb8018bdc7bc7f483679e5355f5bf996acc3df0d8b4d1a5b', 'crates/rpc/src/compat_manifest.rs': '66b130b0ca532c92889dfcb89d086e82f5a0fe626b93e4bd5acb416a3eebb8d8', 'crates/rpc/src/esplora.rs': 'a4b8d3a78ddcd85b7779530f77f92fe2405b19fd778b82f641ae233383446378', 'crates/rpc/src/handlers/chain.rs': 'dd9ad2fe894fa647f4100ac7d635af9501bb54d142cf7eac0acf63a354e9bc93', 'crates/rpc/src/server.rs': '2d56b5d95cf129223ec36cf91e5e1d7d0419f8d11145492f6417ea6e37bf4999', 'crates/rpc/tests/auth.rs': '88506ef1dc047be64123189f740b3f1c551563497447a07ddf5b472a3e2baea4', 'crates/script/src/taproot.rs': '11cdb0e8476e030d1aa5c3e93ad7cc1366e4267ef07e0a30e2662d357909b7a1', 'crates/storage/examples/storage_footprint.rs': '138df9ac6ce3f2cf5b2ffcd9936562ac26ca7d6f3e3ea65b2b81eb101032fd2b', 'crates/storage/src/fjall_impl.rs': '4caf0a13f359af389ac46f62cf1fc5dd02cbe14286486213890339113abea801', 'crates/storage/src/mdbx_impl.rs': '36d776f9ff8d8b172fd1b986f5fd03a93f1e8f7b23d2303691edc220853369a6', 'crates/storage/src/redb_impl.rs': '814f56e5def16db90daedcd100a9fe537cb07a065869d616c18a109dba7f91e0', 'crates/storage/src/rocksdb_impl.rs': 'cb5c978006e874147a5a5c4387b41df3ae5c7abef0b5ce1409fd1b0577f52f54', 'crates/storage/src/trait_.rs': '14083f893fab8a5956f9b1b603e5bdbeab18688a7b6000902a688b8d4a13dfb7', 'crates/storage/tests/backend_metrics.rs': '9614670558930ee3d7d9c4726e855794febe063e5ceaee2b511e29b158a85378', 'crates/storage/tests/overhaul_atomic_durability.rs': '68716ad6307e00b8b21423401c2ed67c901268332ed0fcb2b526725fc242aeba', 'crates/storage/tests/storage_footprint.rs': '7904ff8c88e82f059d8c78af97e42034d8ec296f17594c71f0f65f1ed4a206be', 'crates/utxo/src/set.rs': '5d1d7a429d8175692ce3e66e1365149961e162c65318e5857d3bd7f87dc3b4a9', 'crates/utxo/src/shard.rs': '4f6be8e19c670ad7d2b5912bff9c3e64fcf2e3a5ff6a0e89ef3c79d156953e42', 'crates/utxo/tests/overhaul_persistent_coins.rs': '1aa0304ce9f49a4c118cbee3ce5361113ca48e315cbb2039e6eba758180be9a3', 'docs/benchmarks/muhash-rpc.md': '08a0de5e68fc287139fc176dacb73e2497518e6fa95a4e97a1f749133db9b8f9', 'docs/benchmarks/native-validation-default.md': '6f67072764beae7037720b59e38b4a3095d7a1dc2e236f17291d894903c02a4c', 'docs/benchmarks/offline-full-validation.md': '150912d3a195193a2da78ff2b460b6d02ae66062e76fc27e3223431a8b186647', 'docs/benchmarks/p2p-loopback.md': 'c8249b0f5fd49d07e1ba98ad8d175abf8f47887a68da6d4e66c8b8d1e8720881', 'docs/contracts/chain-events.md': 'b89bd4075e94dd4bf8a3b8c4f29758ad5230b5a386420f245b08e88dea7f54f2', 'docs/contracts/hot-path-attribution.md': 'f3554439e4e31f990d8f469d6b145c6962d759d6f5a147a9fabc9b115af21ff7', 'docs/contracts/mempool-mutations.md': '6e568c9d5ecdcfc03b6fbdf706c2ad0210c05b67ba373329bbd2d1480383606a', 'docs/contracts/mempool-policy.md': '21e68a524a209a287cc8af60f88b2f94f145ae0cfd20a28b56057f8918aaedfa', 'docs/contracts/muhash-rpc.md': 'df0f77e7faff168316217a8fc18a78682b8c30c27dbaa792b996ebc0f1068fc0', 'docs/contracts/recovery.md': 'e9565bdd38e0045d4766dd8333b58d6c8d90e331dcce497a179477f47e18efa9', 'docs/contracts/reference-set.md': '9f1b813aecbe894058b4174008cf852c635edfa7cd04095eb42d6ffe6099eaed', 'docs/contracts/wallet-facing.md': 'e88596f82faa708e84fb5376eb1d8ff1148aa7d942bcba8054509bfe3949a3c1'}
r = Path.cwd()
assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == BASE
subprocess.run(["git", "restore", "--source=" + CANDIDATE, "--", *[p for p in EXPECTED if p != "crates/storage/src/trait_.rs"]], check=True)
def replace(path, old, new):
    p = r / path
    s = p.read_text()
    assert s.count(old) == 1, (path, old)
    p.write_text(s.replace(old, new))
replace("bin/bitcoin-rs/tests/overhaul_evidence.rs", "//! CONTRACT: docs/contracts/hot-path-attribution.md#HPA-12.\n//!\n//! T02 — a measurement without its identity is not evidence.", "//! HPA-12 — a measurement without its identity is not evidence.")
replace("crates/storage/src/trait_.rs", "    /// Drop the apply step.", "    /// The engine write is dropped before apply. The call returns `Err`:\n    /// even a deferred write must not acknowledge bytes that are not visible.")
replace("crates/storage/src/trait_.rs", "    /// Drop durability completion after apply.", "    /// Durability completion is lost after apply. The call returns `Err`;\n    /// recovery may observe the whole batch or none, never a cross-family mix.")
replace("crates/storage/src/trait_.rs", "    /// Return from flush without syncing deferred writes.", "    /// The flush sync is dropped. The call returns `Err` rather than\n    /// acknowledging deferred durability that has not completed.")
replace('crates/storage/tests/backend_metrics.rs','fn put_one_row(', '#[cfg(any(feature = "fjall", feature = "rocksdb", feature = "mdbx"))]\nfn put_one_row(')
replace('crates/storage/examples/storage_footprint.rs','fn fjall_cf_sizes(', '#[cfg(feature = "fjall")]\nfn fjall_cf_sizes(')
replace('crates/storage/examples/storage_footprint.rs','        other => {\n', '''        #[cfg(feature = "mdbx")]
        "mdbx" => {
            let store = bitcoin_rs_storage::MdbxStore::open(path).expect("open mdbx");
            write_corpus(&store);
            drop(store);
            print_results(&backend, dir_size(path), logical, &HashMap::new(), 0);
        }
        other => {
''')
p=r/'crates/storage/examples/storage_footprint.rs';s=p.read_text().replace('`redb`, `rocksdb`. The corpus is\n//! designed to complete in under a minute on a laptop.', '`redb`, `rocksdb`, or `mdbx`. Enable the corresponding Cargo feature.').replace('[fjall|redb|rocksdb]', '[fjall|redb|rocksdb|mdbx]');p.write_text(s)
replace('crates/script/src/taproot.rs', '''    for node in path.chunks_exact(TAPROOT_CONTROL_NODE_SIZE) {
        let mut sibling = [0_u8; TAPROOT_CONTROL_NODE_SIZE];
        sibling.copy_from_slice(node);
        k = compute_tapbranch_hash(&k, &sibling);
    }''','''    for sibling in path.as_chunks::<TAPROOT_CONTROL_NODE_SIZE>().0 {
        k = compute_tapbranch_hash(&k, sibling);
    }''')
replace('crates/utxo/tests/overhaul_persistent_coins.rs','''        apply_ops(&mut rows, batch.ops.into_iter());
        Ok(true)''','''        if self.fail_writes.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(StorageError::InvalidOperation("injected write failure"));
        }
        apply_ops(&mut rows, batch.ops.into_iter());
        Ok(true)''')
replace('crates/utxo/tests/overhaul_persistent_coins.rs','''    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }''','''    fn flush(&self) -> Result<(), StorageError> {
        if self.fail_writes.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(StorageError::InvalidOperation("injected flush failure"));
        }
        Ok(())
    }''')
p=r/'crates/utxo/tests/overhaul_persistent_coins.rs'; s=p.read_text()
a=s.index('    let store = MemoryStore::default();',s.index('fn write_failure_requires_recovery_before_serving_or_retrying()'))
b=s.index('\n}\n',a)
body=s[a:b].replace('CoinDurability::Durable','mode')
s=s[:a]+'''    for mode in [CoinDurability::Deferred, CoinDurability::Durable, CoinDurability::CasGuarded] {
'''+''.join('    '+line+'\n' for line in body.splitlines())+'    }'+s[b:]
s+='''

/// RCV-04: failed flush completion fences the deferred cache, even if bytes are visible.
#[test]
fn failed_flush_requires_recovery_even_after_the_store_recovers() {
    let store = MemoryStore::default();
    let a = txid(27);
    let mut coins = PersistentUtxoSet::new(store.clone());
    coins.connect_block(
        &block(two_output_add(a, &[0x51], &[0x52]), vec![]),
        &a,
        CoinDurability::Deferred,
    ).expect("deferred apply");
    store.fail_writes.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(coins.flush(), Err(PersistentUtxoError::Storage(_))));
    store.fail_writes.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(coins.get(&outpoint(a, 0)), Err(PersistentUtxoError::RecoveryRequired)));
    assert!(matches!(coins.flush(), Err(PersistentUtxoError::RecoveryRequired)));
    assert!(matches!(coins.ledger(), Err(PersistentUtxoError::RecoveryRequired)));
    // Visibility is not a durability receipt and does not repair the old cache.
    assert!(store.get(ColumnFamily::CoinRecords, a.as_byte_array()).expect("visible row").is_some());
}
''';p.write_text(s)
p=r/'crates/mempool/src/gateway.rs';s=p.read_text();a=s.index('        // Script verification runs OUTSIDE');b=s.index('        let generation = ',a)
s=s[:a]+'''        // Verification runs outside the pool writer. Retain every provisional
        // verdict until the generation and sequence are rechecked under that
        // writer; callers retry stale requests with freshly resolved inputs.
'''+s[b:]
s=s.replace('''        for policy_rejection in [false, true] {''','''        for rejection in ["policy", "script", "height"] {''')
s=s.replace('''                if policy_rejection {
                    request.context.missing_inputs = true;
                } else {
                    request.prevouts[0].1.script_pubkey = vec![0x00];
                }''','''                match rejection {
                    "policy" => request.context.missing_inputs = true,
                    "script" => request.prevouts[0].1.script_pubkey = vec![0x00],
                    _ => request.height = u32::MAX,
                }''')
p.write_text(s)
for name, digest in EXPECTED.items():
    assert hashlib.sha256((r / name).read_bytes()).hexdigest() == digest, name
subprocess.run(["git", "diff", "--check"], check=True)
