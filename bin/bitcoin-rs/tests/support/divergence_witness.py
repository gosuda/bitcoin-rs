"""Fault injection at the diagnostic RPC boundary of the real regtest pair."""
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "scripts"))
import consensus_monitor as monitor


def witness_config(port, auth):
    return {"url": f"http://127.0.0.1:{port}", "credentials": str(auth),
            "settings": {"consensus": {"network": "regtest", "profile": "regtest-500-1251-1351-432"},
                         "full_validation": True}}


class InjectedWitness(monitor.Witness):
    def __init__(self, port, auth, local, reject):
        super().__init__(witness_config(port, auth))
        self.local = local
        self.reject = reject
        self.stale = False
        self.flagged_tip = None

    def call(self, method, *params):
        reply = super().call(method, *params)
        if self.flagged_tip and method == "getchaintips":
            return [self.flagged_tip, *reply]
        if self.stale and method == "getblockheader":
            return dict(reply, time=0)
        if self.reject == "timeout" and method in ("getblockverdict", "getblocktemplate"):
            raise monitor.RpcFailure("injected timeout")
        if self.reject and method == "getblockverdict" and self.local:
            assert reply["verdict"] == "pending" and reply["reason"].startswith("proposal passed"), reply
            return dict(reply, verdict="consensus-invalid" if self.reject == "bad-cb-amount" else "pending",
                        reason=self.reject)
        if self.reject and method == "getblocktemplate" and not self.local:
            assert reply is None, reply
            return self.reject
        return reply


def wait_for_quarantine(node):
    for _ in range(50):
        if node.call("getrpcinfo").get("consensus_quarantine"):
            return
        time.sleep(0.1)
    raise AssertionError("node did not observe confirmed incident")


def exercise(local_port, ref_port, rejected):
    with tempfile.TemporaryDirectory() as tmp:
        auth = Path(tmp) / "credentials"
        auth.write_text("parity:parity")
        node = InjectedWitness(local_port, auth, True, False)
        core = InjectedWitness(ref_port, auth, False, False)
        witnesses = [node, core]
        datadir = Path(node.call("getrpcinfo")["logpath"]).parent
        baseline = monitor.sample(witnesses, datadir, arm=True)
        assert baseline["state"] in ("consistent", "inconclusive"), baseline
        if "block" not in baseline:
            parent = node.call("getblockhash", 2)
            raise AssertionError((baseline, [monitor.deployments(w, parent, 2) for w in witnesses]))
        assert not (datadir / monitor.MARKER).exists()
        if rejected == "fork":
            assert baseline["state"] == "inconclusive", baseline
            assert node.call("getbestblockhash") != core.call("getbestblockhash")
            return
        winner = core if rejected == "local" else node
        changed = bytearray.fromhex(winner.call("getblock", baseline["block"]["hash"], 0))
        changed[-1] ^= 1
        variant = monitor.sample(witnesses, datadir, arm=True, supplied=bytes(changed))
        assert variant["block"]["hash"] == baseline["block"]["hash"]
        assert variant["block"]["sha256"] != baseline["block"]["sha256"]
        assert variant["state"] == "inconclusive" and not (datadir / monitor.MARKER).exists()
        target = node if rejected == "local" else core
        for reason in ("duplicate-invalid", "duplicate-inconclusive", "inconclusive-not-best-prevblk", "timeout"):
            target.reject = reason
            negative = monitor.sample(witnesses, datadir, arm=True)
            assert negative["state"] == "inconclusive", negative
            assert not (datadir / monitor.MARKER).exists()
        target.reject = "duplicate-invalid"
        target.flagged_tip = {"status": "invalid", "height": baseline["height"], "hash": baseline["block"]["hash"]}
        historical = monitor.sample(witnesses, datadir, arm=True)
        assert historical["state"] == "suspected", historical
        assert not (datadir / monitor.MARKER).exists()
        target.flagged_tip = None
        core.stale = True
        assert monitor.sample(witnesses, datadir, arm=True)["state"] == "inconclusive"
        core.stale = False
        core.settings["consensus"]["profile"] = "other-parameters"
        assert monitor.sample(witnesses, datadir, arm=True)["state"] == "inconclusive"
        core.settings["consensus"]["profile"] = "regtest-500-1251-1351-432"
        assert not (datadir / monitor.MARKER).exists()
        target.reject = "bad-cb-amount"
        record = monitor.sample(witnesses, datadir, arm=True)
        assert record["state"] == "confirmed", record
        assert record["verdicts"][rejected]["category"] == "consensus-invalid"
        assert record["verdicts"]["reference" if rejected == "local" else "local"]["category"] == "valid"
        evidence = monitor.json.loads((datadir / monitor.MARKER).read_bytes())
        assert monitor.exact_block(bytes.fromhex(evidence["block_hex"])) == record["block"]
        try:
            monitor.clear(datadir, record["incident_id"], Path(tmp) / "archive", "fixture")
        except BlockingIOError:
            pass
        else:
            raise AssertionError("cleared incident while node holds its datadir lock")
        wait_for_quarantine(node)
        later = monitor.sample(witnesses, datadir, arm=True)
        assert later["incident_id"] == record["incident_id"] and later["incident_latched"]
        assert set(later["current_tips"]) == {"local", "reference"}


class InjectedActiveTip:
    def __init__(self, node, core, raw):
        self.node, self.core, self.raw = node, core, raw
        self.settings, self.log = node.settings, node.log
        self.block_hash = monitor.exact_block(bytes.fromhex(raw))["hash"]

    def call(self, method, *params):
        if method == "getbestblockhash" or (method == "getblockhash" and params == (3,)):
            return self.block_hash
        if method == "getblock" and params == (self.block_hash, 0):
            return self.raw
        if method == "getblockheader" and params == (self.block_hash,):
            return self.core.call(method, *params)
        reply = self.node.call(method, *params)
        if method == "getblockchaininfo":
            reply["bestblockhash"] = self.block_hash
        if method == "getchainstates":
            reply["chainstates"][0]["bestblockhash"] = self.block_hash
        return reply


def cached_rejection(local_port, ref_port, replay_port, invalid_hex, address):
    with tempfile.TemporaryDirectory() as tmp:
        auth = Path(tmp) / "credentials"
        auth.write_text("parity:parity")
        node, core = monitor.configured_witnesses({name: witness_config(port, auth) for name, port in
                                                   (("local", local_port), ("reference", ref_port),
                                                    ("reference_replay", replay_port))})
        replay = core.replay
        datadir = Path(node.call("getrpcinfo")["logpath"]).parent
        parent = replay.call("getbestblockhash")
        assert core.call("getbestblockhash") == node.call("getblockhash", 2) == parent

        def proposal(w, raw):
            return w.call("getblocktemplate", {"mode": "proposal", "rules": ["segwit"], "data": raw})

        valid_hash = node.call("getbestblockhash")
        valid_hex = node.call("getblock", valid_hash, 0)
        assert core.call("submitblock", valid_hex) is None
        core.call("invalidateblock", valid_hash)
        assert proposal(core, valid_hex) == "duplicate-invalid"
        assert proposal(replay, valid_hex) is None
        admin = monitor.sample([node, core], datadir, arm=True)
        assert admin["state"] == "suspected" and not (datadir / monitor.MARKER).exists(), admin
        assert admin["verdicts"]["reference"]["category"] == "pending"
        assert admin["verdicts"]["reference"]["replay"]["tip"] == parent

        assert core.call("submitblock", invalid_hex) == "bad-cb-amount"
        assert proposal(core, invalid_hex) == "duplicate-invalid"
        assert proposal(replay, invalid_hex) == "bad-cb-amount"
        local = InjectedActiveTip(node, core, invalid_hex)
        witnesses = [local, core]
        core.replay = None
        cached = monitor.sample(witnesses, datadir, arm=True)
        assert cached["state"] != "confirmed" and not (datadir / monitor.MARKER).exists(), cached
        core.replay = replay
        replay.settings["consensus"]["profile"] = "different"
        mismatch = monitor.sample(witnesses, datadir, arm=True, supplied=bytes.fromhex(invalid_hex))
        assert mismatch["verdicts"]["reference"]["category"] == "pending"
        assert not (datadir / monitor.MARKER).exists()
        replay.settings["consensus"]["profile"] = "regtest-500-1251-1351-432"
        other_tip, = replay.call("generatetoaddress", 1, address)
        wrong_parent = monitor.sample(witnesses, datadir, arm=True, supplied=bytes.fromhex(invalid_hex))
        assert wrong_parent["verdicts"]["reference"]["category"] == "pending"
        assert not (datadir / monitor.MARKER).exists()
        replay.call("invalidateblock", other_tip)
        at_parent = monitor.observe(witnesses, bytes.fromhex(invalid_hex))[0]
        assert at_parent["verdicts"]["reference"]["reason"] == "bad-cb-amount", at_parent
        alternate_tip, = core.call("generatetoaddress", 1, address)
        assert alternate_tip != parent
        record = monitor.sample(witnesses, datadir, arm=True)
        assert record["state"] == "confirmed", record
        rejecting = record["verdicts"]["reference"]
        assert rejecting["reason"] == "bad-cb-amount" and rejecting["cached_reason"] == "duplicate-invalid"
        assert rejecting["replay"]["tip"] == parent
        assert core.call("getbestblockhash") == alternate_tip
        assert core.call("getblockhash", 2) == replay.call("getbestblockhash") == parent
        assert proposal(replay, invalid_hex) == "bad-cb-amount"
        incident = monitor.json.loads((datadir / monitor.MARKER).read_bytes())
        assert incident["block_hex"] == invalid_hex and incident["incident_id"] == record["incident_id"]
        wait_for_quarantine(node)

        assert replay.call("submitblock", invalid_hex) == "bad-cb-amount"
        raw = bytes.fromhex(invalid_hex)
        both_cached = monitor.verdict(core, monitor.snapshot(core), monitor.exact_block(raw), raw, 3, False)
        assert both_cached["category"] == "pending" and both_cached["reason"] == "duplicate-invalid"


if __name__ == "__main__":
    if sys.argv[1] == "cached":
        cached_rejection(*sys.argv[2:])
    else:
        exercise(*sys.argv[1:])
