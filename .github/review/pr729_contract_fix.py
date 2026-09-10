from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"unexpected preimage count for {path}: {text.count(old)}")
    p.write_text(text.replace(old, new, 1))


relay = "crates/p2p/src/tx_relay.rs"
old_module = (
    "//! Peer-origin accepts are announced by the ingress caller after the gateway\n"
    "//! returns a committed admission. RPC and reorg accepts announce through\n"
    "//! [`LocalTxRelayObserver`] on the same queue. These triggers intentionally\n"
    "//! retain their separate timing. Local notifications look up the accepted\n"
    "//! entry's real wtxid only while that acceptance remains resident. The\n"
    "//! gateway reference is weak so its observer cannot retain the gateway.\n"
)
new_module = (
    "//! Peer-origin versus RPC/reorg relay trigger and admission-identity semantics\n"
    "//! are owned by `docs/policies/p2p-compatibility.md` §5. This module owns the\n"
    "//! bounded queue/worker mechanics; the observer keeps only a weak gateway\n"
    "//! reference so relay cannot retain mempool ownership.\n"
)
replace_once(relay, old_module, new_module)
replace_once(
    relay,
    "    #[test]\n    fn delayed_local_relay_survives_unrelated_mutations() {",
    "    // MPL-01: unrelated commits do not retire a resident local admission.\n"
    "    #[test]\n    fn delayed_local_relay_survives_unrelated_mutations() {",
)
replace_once(
    relay,
    "    #[test]\n    fn local_replacement_relay_uses_the_accepted_change_sequence() {",
    "    // MPL-01: relay keys the Accepted change, not the batch base or removal.\n"
    "    #[test]\n    fn local_replacement_relay_uses_the_accepted_change_sequence() {",
)

policy = "docs/policies/p2p-compatibility.md"
old_policy = (
    "RPC/reorg mutation observers resolve the retained entry's wtxid and skip\n"
    "entries removed before observer delivery. Missing-parent requests use txids,\n"
)
new_policy = (
    "RPC/reorg mutation observers relay only while the exact accepted admission\n"
    "remains resident: the accepted change's mempool sequence qualifies the txid/wtxid\n"
    "lookup. Removal and re-admission retire the older callback even when the body is\n"
    "identical; unrelated mempool mutations and fee prioritisation do not. Identity and\n"
    "wtxid are read under one pool guard, released before relay enqueue; an already\n"
    "queued best-effort announcement may still be overtaken by a later removal.\n"
    "Missing-parent requests use txids,\n"
)
replace_once(policy, old_policy, new_policy)

contract = "docs/contracts/mempool-mutations.md"
marker = (
    "  mining observer at gateway construction and the ZMQ sequence observer as\n"
    "  an extra named leg on the gateway's `CompositeObserver`.\n"
)
addition = marker + (
    "- Local RPC/reorg transaction relay is qualified by the accepted mempool\n"
    "  admission identified by that change's sequence. A delayed callback may\n"
    "  relay only while that admission remains resident. Removal and\n"
    "  re-admission retire the older callback even when the txid, wtxid, or\n"
    "  transaction allocation is identical. Unrelated mempool mutations and fee\n"
    "  prioritisation do not retire the admission. The observer resolves\n"
    "  admission identity and wtxid under one pool read guard, releases it before\n"
    "  relay enqueue, and remains a best-effort mirror: removal may still\n"
    "  overtake an announcement already queued. Sequence rollover follows\n"
    "  `MPL-02`; this clause does not create a second identity counter.\n"
)
replace_once(contract, marker, addition)
proof_marker = "## Proven by\n\n"
proof = proof_marker + (
    "- `crates/p2p/src/tx_relay.rs` (inline tests):\n"
    "  `delayed_local_relay_does_not_adopt_a_reinserted_body`,\n"
    "  `delayed_local_relay_survives_unrelated_mutations`,\n"
    "  `local_replacement_relay_uses_the_accepted_change_sequence`.\n"
)
replace_once(contract, proof_marker, proof)
