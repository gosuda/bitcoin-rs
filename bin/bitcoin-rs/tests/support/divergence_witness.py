"""Fault injection at the diagnostic RPC boundary of the real regtest pair."""
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "scripts"))
import consensus_monitor as monitor


class InjectedWitness(monitor.Witness):
    def __init__(self, port, auth, local, reject):
        super().__init__({"url": f"http://127.0.0.1:{port}", "credentials": str(auth),
                          "settings": {"consensus": {"network": "regtest", "profile": "regtest-500-1251-1351-432"},
                                       "full_validation": True}})
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
        for _ in range(50):
            if node.call("getrpcinfo").get("consensus_quarantine"):
                break
            time.sleep(0.1)
        else:
            raise AssertionError("node did not observe confirmed incident")
        later = monitor.sample(witnesses, datadir, arm=True)
        assert later["incident_id"] == record["incident_id"] and later["incident_latched"]
        assert set(later["current_tips"]) == {"local", "reference"}


if __name__ == "__main__":
    exercise(*sys.argv[1:])
