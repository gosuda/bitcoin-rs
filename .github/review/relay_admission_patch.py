"""Apply the local-relay admission-identity candidate to a verified source tree."""
from pathlib import Path
import subprocess
import sys

BASE = "6838258a3dbca18e78e1995cd5c274d52460167b"
EXPECTED = {
    "crates/mempool/src/pool.rs": "f45739921f96aa2e392f056ec08cf3012e401da8",
    "crates/p2p/src/tx_relay.rs": "cf4de6cec7fbca404460d55fae5410e498456a75",
    "docs/policies/p2p-compatibility.md": "bdf95fd02b249748434ac49a2911cb50d59f3ac3",
}


def replace(path, old, new, count=1):
    p = Path(path)
    text = p.read_text()
    if text.count(old) != count:
        raise RuntimeError(f"unexpected preimage count in {path}: {old!r}: {text.count(old)}")
    p.write_text(text.replace(old, new))


TESTS = r'''
    fn relay_identity_tx() -> Arc<bitcoin_rs_primitives::Tx> {
        use bitcoin_rs_primitives::{OutPoint, Tx, TxIn, TxOut};
        Arc::new(Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(dummy_txid(90), 0),
                script_sig: Vec::new(),
                sequence: 0xffff_fffd,
                witness: vec![vec![1]],
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x6a, 4, 1, 2, 3, 4],
            }],
            lock_time: 0,
        })
    }

    fn relay_identity_peer() -> AdmissionOrigin {
        AdmissionOrigin::Peer(bitcoin_rs_mempool::PeerToken {
            addr: SocketAddr::from(([127, 0, 0, 1], 8333)),
            connection_id: 7,
        })
    }

    fn relay_identity_gateway() -> Arc<MempoolGateway> {
        use bitcoin_rs_mempool::{CompositeObserver, Mempool, MempoolLimits};
        Arc::new(MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(Mempool::new(MempoolLimits::default()))),
            Some(Arc::new(CompositeObserver::new())),
        ))
    }

    struct MutateBeforeLocalRelay {
        gateway: Weak<MempoolGateway>,
        next: Mutex<Option<bitcoin_rs_mempool::MempoolEntry>>,
        clear_first: bool,
    }

    impl MempoolObserver for MutateBeforeLocalRelay {
        fn on_mutation(&self, envelope: &MutationEnvelope) {
            let Some(entry) = self.next.lock().take() else {
                return;
            };
            let gateway = self.gateway.upgrade().expect("fixture gateway lives");
            if self.clear_first {
                gateway.clear(AdmissionOrigin::Block);
            }
            gateway.insert_entry(relay_identity_peer(), entry).expect("nested admission");
            let original = Txid(envelope.result.changes[0].txid);
            gateway.prioritise(original, 1).expect("fee overlay does not change admission identity");
        }
    }

    fn delayed_relay_fixture(
        origin: AdmissionOrigin,
        original: Arc<bitcoin_rs_primitives::Tx>,
        next: Arc<bitcoin_rs_primitives::Tx>,
        clear_first: bool,
    ) -> (Arc<MempoolGateway>, Receiver<RelayRequest>) {
        use bitcoin_rs_mempool::MempoolEntry;
        let gateway = relay_identity_gateway();
        let (relay, rx) = TxRelayQueue::new(8);
        gateway.attach_observer_leg("mutate-first", Arc::new(MutateBeforeLocalRelay {
            gateway: Arc::downgrade(&gateway),
            next: Mutex::new(Some(MempoolEntry::new(next, 100, 10_000, 2, 0))),
            clear_first,
        })).expect("fixture observer slot");
        gateway.attach_observer_leg("relay", Arc::new(LocalTxRelayObserver::new(
            relay, Arc::downgrade(&gateway),
        ))).expect("relay observer slot");
        gateway.insert_entry(origin, MempoolEntry::new(original, 100, 10_000, 1, 0))
            .expect("local admission");
        (gateway, rx)
    }

    // P2P-01 / MPL-01: callbacks may re-enter the gateway before a later leg.
    // An old local event must not borrow a new peer admission's identity.
    #[test]
    fn delayed_local_relay_does_not_adopt_a_reinserted_body() {
        for origin in [AdmissionOrigin::Rpc, AdmissionOrigin::Reorg] {
            for alternate_witness in [false, true] {
                let original = relay_identity_tx();
                let next = if alternate_witness {
                    let mut variant = (*original).clone();
                    variant.inputs[0].witness = vec![vec![2]];
                    Arc::new(variant)
                } else {
                    // Same allocation, not merely equal bytes: Arc identity is
                    // not an admission identity either.
                    Arc::clone(&original)
                };
                assert_eq!(original.txid(), next.txid());
                assert_eq!(original.wtxid() != next.wtxid(), alternate_witness);
                let txid = original.txid();
                let (gateway, rx) = delayed_relay_fixture(origin, original, Arc::clone(&next), true);
                assert_eq!(gateway.read().entry_by_txid(&txid).map(|entry| entry.wtxid), Some(next.wtxid()));
                assert!(rx.try_recv().is_err(), "old local event cannot advertise the peer re-admission");
            }
        }
    }

    #[test]
    fn delayed_local_relay_survives_unrelated_mutations() {
        let original = relay_identity_tx();
        let mut unrelated = (*original).clone();
        unrelated.inputs[0].previous_output = bitcoin_rs_primitives::OutPoint::new(dummy_txid(91), 0);
        let (gateway, rx) = delayed_relay_fixture(AdmissionOrigin::Rpc, Arc::clone(&original), Arc::new(unrelated), false);
        assert_eq!(gateway.read().sequence_number(), 2);
        let request = rx.try_recv().expect("unrelated mutation does not invalidate the local admission");
        assert_eq!((request.txid, request.wtxid, request.source), (original.txid(), original.wtxid(), None));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn local_replacement_relay_uses_the_accepted_change_sequence() {
        use bitcoin_rs_mempool::{MempoolEntry, ReplacementCandidate};
        let gateway = relay_identity_gateway();
        let (relay, rx) = TxRelayQueue::new(8);
        gateway.attach_observer_leg("relay", Arc::new(LocalTxRelayObserver::new(relay, Arc::downgrade(&gateway))))
            .expect("observer slot");
        let original = relay_identity_tx();
        gateway.insert_entry(relay_identity_peer(), MempoolEntry::new(Arc::clone(&original), 100, 10_000, 1, 0))
            .expect("original peer admission");
        assert!(rx.try_recv().is_err());
        let mut replacement = (*original).clone();
        replacement.outputs[0].value = 900;
        let replacement = Arc::new(replacement);
        let outcome = gateway.replace_transaction(
            AdmissionOrigin::Rpc,
            ReplacementCandidate::new(Arc::clone(&replacement), 100, 11_000, 1_000),
            2, 0, 4,
        ).expect("local replacement");
        assert_eq!(outcome.mutation().len(), 2);
        assert!(matches!(outcome.mutation().changes[0].outcome, MutationOutcome::Removed(_)));
        assert_eq!(outcome.mutation().changes[1].outcome, MutationOutcome::Accepted);
        let request = rx.try_recv().expect("accepted change after removal is announced");
        assert_eq!((request.txid, request.wtxid, request.source), (replacement.txid(), replacement.wtxid(), None));
        assert!(rx.try_recv().is_err());
    }
'''


def tests():
    for path, expected in EXPECTED.items():
        actual = subprocess.check_output(["git", "hash-object", path], text=True).strip()
        if actual != expected:
            raise RuntimeError(f"changed base file {path}: {actual}")
    p = Path("crates/p2p/src/tx_relay.rs")
    text = p.read_text()
    if not text.endswith("}\n"):
        raise RuntimeError("unexpected test module end")
    p.write_text(text[:-2] + TESTS + "}\n")


def fix():
    pool = "crates/mempool/src/pool.rs"
    replace(pool, "by_txid: HashMap<Txid, EntryId>,", "by_txid: HashMap<Txid, IndexedEntry>,")
    replace(pool, "pub(crate) struct PreparedInsert {", '''/// Current pool membership, retired together with the existing txid index row.
#[derive(Clone, Copy, Debug)]
struct IndexedEntry {
    id: EntryId,
    admitted_sequence: u64,
}

pub(crate) struct PreparedInsert {''')
    replace(pool, "    /// Tx id to entry id lookup. Owned by this module; reach it\n", "    /// Tx id to entry id and acceptance sequence. Owned by this module; reach it\n")
    replace(pool, "        let mut changes = Vec::new();\n        self.push_change(&mut changes, txid, MutationOutcome::Accepted);\n", "")
    replace(pool, "        self.by_txid.insert(txid, id);", '''        let mut changes = Vec::new();
        self.push_change(&mut changes, txid, MutationOutcome::Accepted);
        self.by_txid.insert(txid, IndexedEntry {
            id,
            admitted_sequence: self.mempool_sequence,
        });''')
    replace(pool, ".is_some_and(|id| excluded.contains(id))", ".is_some_and(|indexed| excluded.contains(&indexed.id))")
    replace(pool, "        let id = *self.by_txid.get(txid)?;\n        self.entry(id)", "        self.entry(self.entry_id_by_txid(txid)?)")
    replace(pool, "    /// Composite of `self.by_txid.get(txid)` and `self.entry(*id)`. Saves the\n", "    /// Composite of `self.entry_id_by_txid(txid)` and `self.entry(id)`. Saves the\n")
    replace(pool, '''    pub fn entry_id_by_txid(&self, txid: &Txid) -> Option<EntryId> {
        self.by_txid.get(txid).copied()
    }''', '''    pub fn entry_id_by_txid(&self, txid: &Txid) -> Option<EntryId> {
        self.by_txid.get(txid).map(|indexed| indexed.id)
    }

    /// Returns the resident entry only when its acceptance has `sequence`.
    ///
    /// Compare with the sequence of an `Accepted` mutation change from this
    /// pool. Removal and re-admission invalidate the old receipt, even when
    /// the same transaction allocation is reused. Unrelated mutations and fee
    /// prioritisation do not invalidate it. The returned reference shares the
    /// pool borrow, so identity and body are observed together.
    #[must_use]
    pub fn entry_by_txid_at_sequence(&self, txid: &Txid, sequence: u64) -> Option<&MempoolEntry> {
        let indexed = self.by_txid.get(txid)?;
        if indexed.admitted_sequence != sequence {
            return None;
        }
        self.entry(indexed.id)
    }''')
    replace(pool, "self.by_txid.get(txid).copied()", "self.entry_id_by_txid(txid)", count=2)
    replace(pool, "let Some(&id) = self.by_txid.get(&txid) else", "let Some(id) = self.entry_id_by_txid(&txid) else")
    replace(pool, '''                modified_fee: self
                    .by_txid
                    .get(&txid)
                    .and_then(|&id| self.entry(id).map(MempoolEntry::modified_fee)),''', '''                modified_fee: self.entry_by_txid(&txid).map(MempoolEntry::modified_fee),''')
    replace(pool, "self.by_txid.get(&input.previous_output.txid).copied()", "self.entry_id_by_txid(&input.previous_output.txid)", count=3)
    replace(pool, '''                    if let Some(parent) = self.by_txid.get(&input.previous_output.txid) {
                        stack.push(*parent);''', '''                    if let Some(parent) = self.entry_id_by_txid(&input.previous_output.txid) {
                        stack.push(parent);''')
    replace(pool, "size_of::<(Txid, EntryId)>()", "size_of::<(Txid, IndexedEntry)>()")

    relay = "crates/p2p/src/tx_relay.rs"
    replace(relay, "        for change in &envelope.result.changes {", "        for (index, change) in envelope.result.changes.iter().enumerate() {")
    replace(relay, '''            let wtxid = gateway.read().entry_by_txid(&txid).map(|entry| entry.wtxid);''', '''            let Some(sequence) = envelope.result.sequence_of(index) else {
                continue;
            };
            let wtxid = gateway
                .read()
                .entry_by_txid_at_sequence(&txid, sequence)
                .map(|entry| entry.wtxid);''')
    replace(relay, "//! entry's real wtxid and skip entries removed before observer delivery. The\n", "//! entry's real wtxid only while that acceptance remains resident. The\n")

    policy = "docs/policies/p2p-compatibility.md"
    replace(policy, '''RPC/reorg mutation observers resolve the retained entry's wtxid and skip
entries removed before observer delivery. Missing-parent requests use txids,''', '''RPC/reorg mutation observers resolve the retained entry's wtxid only when
its acceptance sequence matches the committed event. Removal and re-admission
invalidate older callbacks, including reinsertion of an identical body;
unrelated mutations and fee prioritisation do not. Identity and body are read
under one pool guard, released before relay enqueue. A later removal can still
overtake an already queued best-effort announcement. Missing-parent requests use txids,''')
    replace(policy, "  cover negotiated announcements and actual retained witness identity.\n", '''  cover negotiated announcements and actual retained witness identity.
  `delayed_local_relay_does_not_adopt_a_reinserted_body`,
  `delayed_local_relay_survives_unrelated_mutations`, and
  `local_replacement_relay_uses_the_accepted_change_sequence` cover delayed
  callback identity and per-change sequence selection.
''')


if __name__ == "__main__":
    if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != BASE:
        raise SystemExit("expected the pinned source checkout")
    if sys.argv[1:] == ["tests"]:
        tests()
    elif sys.argv[1:] == ["fix"]:
        fix()
    else:
        raise SystemExit("usage: relay_admission_patch.py tests|fix")
