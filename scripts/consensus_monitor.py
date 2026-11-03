#!/usr/bin/env python3
"""Compare exact blocks on two independently configured Bitcoin RPC witnesses."""
import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import sys
import stat
import time
from pathlib import Path
from urllib.parse import urlsplit

MAX_BLOCK = 4_000_000
MARKER = "consensus-divergence.json"
LATEST = "consensus-divergence-latest.json"
PERMANENT = frozenset({
    "bad-cb-amount", "bad-cb-height", "bad-cb-length", "bad-cb-missing",
    "bad-cb-multiple", "bad-blk-weight", "bad-blk-length", "bad-blk-sigops",
    "bad-txnmrklroot", "bad-txns-duplicate", "bad-txns-BIP30",
    "bad-txns-inputs-missingorspent", "bad-txns-premature-spend-of-coinbase",
    "bad-txns-in-belowout", "bad-txns-vin-empty", "bad-txns-vout-empty",
    "bad-txns-inputs-duplicate", "bad-txns-prevout-null", "bad-txns-nonfinal",
    "bad-witness-merkle-match", "bad-witness-nonce-size", "unexpected-witness",
    "high-hash", "bad-diffbits", "bad-signet-blksig",
})


class Unknown(Exception):
    """An observation lacks a prerequisite for comparison."""


class RpcFailure(Exception):
    """Transport, protocol, or operational failure."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class Witness:
    def __init__(self, config):
        url = urlsplit(config["url"])
        if (url.scheme != "http" or url.username or url.password or url.path not in ("", "/")
                or url.query or url.fragment or not ipaddress.ip_address(url.hostname).is_loopback):
            raise ValueError("use a numeric loopback HTTP RPC endpoint")
        self.host, self.port = url.hostname, url.port
        self.cookie = Path(config["credentials"])
        self.settings = config["settings"]
        if len(encoded(self.settings)) > 4096:
            raise ValueError("settings exceed 4096 bytes")
        self.log = config.get("log")

    def call(self, method, *params):
        with self.cookie.open("rb") as f:
            auth = f.read(1025).strip()
        if len(auth) > 1024 or b":" not in auth:
            raise RpcFailure("invalid RPC credentials file")
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        try:
            conn.request("POST", "/", encoded(dict(jsonrpc="2.0", id=1, method=method, params=params)),
                         {"Authorization": "Basic " + base64.b64encode(auth).decode(),
                          "Content-Type": "application/json"})
            response = conn.getresponse()
            raw = response.read(MAX_BLOCK * 2 + 65537)
            if len(raw) > MAX_BLOCK * 2 + 65536:
                raise RpcFailure("oversized RPC response")
            reply = json.loads(raw)
            if reply.get("error") or response.status != 200 or reply.get("id") != 1:
                raise RpcFailure(f"{method}: {str(reply.get('error') or response.status)[:256]}")
            return reply["result"]
        finally:
            conn.close()


def exact_block(raw):
    if not 80 <= len(raw) <= MAX_BLOCK:
        raise Unknown("invalid block size")
    header = raw[:80]
    block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()
    return dict(hash=block_hash, parent=header[4:36][::-1].hex(), sha256=digest(raw), size=len(raw))


def snapshot(w):
    chain = w.call("getblockchaininfo")
    states = w.call("getchainstates")["chainstates"]
    tip = w.call("getblockheader", chain["bestblockhash"])
    if chain.get("is_closed_for_recovery") or chain.get("is_apply_halted"):
        raise RpcFailure("chainstate is closed for recovery")
    if chain.get("consensus_quarantine"):
        raise Unknown("an incident is already latched")
    if (len(states) != 1 or states[0].get("validated") is not True
            or states[0].get("bestblockhash") != chain["bestblockhash"]
            or states[0].get("blocks") != chain["blocks"]
            or chain["initialblockdownload"] or time.time() - tip["time"] > 86400):
        raise Unknown("incomplete validation, changing state, IBD or stale tip")
    version = w.call("getnetworkinfo")
    genesis = w.call("getblockhash", 0)
    params = w.settings.get("consensus", {})
    if (params.get("network") != chain["chain"] or not params.get("profile")
            or w.settings.get("full_validation") is not True):
        raise Unknown("no operator attestation for effective parameters and full validation")
    return dict(network=chain["chain"], genesis=genesis, tip=chain["bestblockhash"],
                height=chain["blocks"], work=tip["chainwork"], version=version["version"],
                software=version["subversion"][:128], settings=w.settings)


def common_height(witnesses, height):
    low, high = 0, height
    while low < high:
        mid = (low + high + 1) // 2
        if witnesses[0].call("getblockhash", mid) == witnesses[1].call("getblockhash", mid):
            low = mid
        else:
            high = mid - 1
    return low


def deployments(w, parent, height):
    info = w.call("getdeploymentinfo", parent)
    if info["hash"] != parent or info["height"] != height:
        raise Unknown("deployment query did not identify the parent")
    rules = {}
    for name, dep in info["deployments"].items():
        if name == "testdummy":
            continue
        if dep["active"] and isinstance(dep.get("height"), int):
            rules[name] = {"active": True, "height": dep["height"]}
        else:
            rules[name] = {k: v for k, v in dep.items() if k in ("type", "height", "active", "bip9")}
    return rules


def verdict(w, tip, block, raw, height, local):
    block_hash, parent = block["hash"], block["parent"]
    if height <= tip["height"] and w.call("getblockhash", height) == block_hash:
        if w.call("getblock", block_hash, 0) != raw.hex():
            return dict(category="pending", reason="same header, different block bytes")
        return dict(category="valid", reason="exact body on fully validated active chain",
                    chainwork=w.call("getblockheader", block_hash)["chainwork"])
    if tip["tip"] != parent:
        return dict(category="pending", reason="parent is not the applied tip")
    if local:
        reply = w.call("getblockverdict", raw.hex())
        if (reply["hash"], reply["parent"], reply["sha256"]) != (block_hash, parent, block["sha256"]):
            return dict(category="pending", reason="verdict identity mismatch")
        category = reply["verdict"]
        if category not in ("pending", "consensus-invalid", "operational-failure"):
            raise Unknown("unknown local verdict")
        return dict(category=category, reason=str(reply["reason"] or category)[:256])
    reason = w.call("getblocktemplate", {"mode": "proposal", "rules": ["segwit", "signet"],
                                          "data": raw.hex()})
    if isinstance(reason, str) and (reason in PERMANENT or
            (reason.startswith("block-script-verify-flag-failed (") and reason.endswith(")"))):
        return dict(category="consensus-invalid", reason=reason[:256])
    return dict(category="pending", reason=str(reason or "proposal only; no active-chain proof")[:256])


def compare(witnesses, snapshots, raw):
    block = exact_block(raw)
    parents = [w.call("getblockheader", block["parent"]) for w in witnesses]
    height = parents[0]["height"] + 1
    if any(p["hash"] != block["parent"] or p["height"] != height - 1 or
           w.call("getblockhash", height - 1) != block["parent"] for w, p in zip(witnesses, parents)):
        raise Unknown("no shared active parent")
    if parents[0]["chainwork"] != parents[1]["chainwork"]:
        raise Unknown("parent chainwork differs")
    contexts = [deployments(w, block["parent"], height - 1) for w in witnesses]
    if contexts[0] != contexts[1]:
        raise Unknown("parent deployment parameters differ")
    sides = {}
    for index, name in enumerate(("local", "reference")):
        try:
            sides[name] = verdict(witnesses[index], snapshots[index], block, raw, height, index == 0)
        except (RpcFailure, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, http.client.HTTPException) as e:
            sides[name] = dict(category="operational-failure", reason=str(e)[:256])
    categories = {v["category"] for v in sides.values()}
    if any(w.call("getbestblockhash") != snap["tip"] for w, snap in zip(witnesses, snapshots)):
        raise Unknown("tip changed during comparison")
    state = "suspected" if categories == {"valid", "consensus-invalid"} else (
        "consistent" if categories == {"valid"} else "inconclusive")
    return dict(state=state, block=block, height=height, matching_ancestor=block["parent"],
                parent_work=parents[0]["chainwork"], deployments_sha256=digest(encoded(contexts[0])),
                witnesses=dict(zip(("local", "reference"), snapshots)), verdicts=sides)


def invalid_tip(witnesses, snapshots, common):
    for lo in (0, 1):
        hi = 1 - lo
        if int(snapshots[hi]["work"], 16) <= int(snapshots[lo]["work"], 16):
            continue
        invalid = (t for t in witnesses[lo].call("getchaintips") if t["status"] == "invalid"
                   and common < t["height"] <= snapshots[hi]["height"])
        for tip in sorted(invalid, key=lambda t: t["height"])[:16]:
            block_hash, height = tip["hash"], tip["height"]
            active = witnesses[hi]
            if active.call("getblockhash", height) != block_hash:
                continue
            raw = bytes.fromhex(active.call("getblock", block_hash, 0))
            block = exact_block(raw)
            if block["hash"] != block_hash:
                raise Unknown("block identity changed")
            ancestor = active.call("getblockhash", common)
            if any(w.call("getbestblockhash") != s["tip"] for w, s in zip(witnesses, snapshots)):
                raise Unknown("tip changed during invalid-ancestor comparison")
            names = ("local", "reference")
            return dict(state="suspected", block=block, height=height, matching_ancestor=ancestor,
                        witnesses=dict(zip(names, snapshots)), verdicts={
                            names[lo]: dict(category="pending", reason="tree marks header invalid"),
                            names[hi]: dict(category="valid", reason="exact body on validated higher-work chain")
                        }, reason="replay the original bytes; an invalid flag can be administrative")
    return None


def observe(witnesses, supplied=None):
    snapshots = []
    failures = {}
    for name, w in zip(("local", "reference"), witnesses):
        try:
            snapshots.append(snapshot(w))
        except Unknown as e:
            failures[name] = dict(category="pending", reason=str(e)[:256])
        except (RpcFailure, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, http.client.HTTPException) as e:
            failures[name] = dict(category="operational-failure", reason=str(e)[:256])
    if failures:
        return dict(state="inconclusive", verdicts=failures), None
    a, b = snapshots
    if (a["network"], a["genesis"], a["settings"]["consensus"]) != (
            b["network"], b["genesis"], b["settings"]["consensus"]):
        raise Unknown("network, genesis or consensus settings differ")
    if supplied is not None:
        return compare(witnesses, snapshots, supplied), supplied
    if a["tip"] == b["tip"]:
        return dict(state="consistent", reason="same observed tip", witnesses=dict(zip(
            ("local", "reference"), snapshots))), None
    common = common_height(witnesses, min(a["height"], b["height"]))
    last = None
    for w, snap in zip(witnesses, snapshots):
        if snap["height"] <= common:
            continue
        block_hash = w.call("getblockhash", common + 1)
        raw = bytes.fromhex(w.call("getblock", block_hash, 0))
        if exact_block(raw)["hash"] != block_hash:
            raise Unknown("RPC returned a different block")
        last = compare(witnesses, snapshots, raw)
        if last["state"] == "suspected":
            return last, raw
    flagged = invalid_tip(witnesses, snapshots, common)
    return flagged or last or dict(state="inconclusive", reason="changing tips"), None


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(path, record, exclusive=False):
    data = encoded(record) + b"\n"
    if len(data) > (2 * MAX_BLOCK + 32768 if exclusive else 32768):
        raise ValueError("evidence exceeds retention limit")
    import fcntl
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    staging = path.with_name("." + path.name + ".tmp")
    try:
        fcntl.flock(directory, fcntl.LOCK_EX)
        staging.unlink(missing_ok=True)
        with os.fdopen(os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        if exclusive:
            os.link(staging, path)
            staging.unlink()
        else:
            os.replace(staging, path)
        os.fsync(directory)
    finally:
        os.close(directory)


def tail(w):
    if not w.log:
        return None
    try:
        with open(w.log, "rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - 1024))
            return stream.read(1024).decode(errors="replace")
    except OSError:
        return None


def sample(witnesses, datadir, *, arm, supplied=None):
    try:
        local_info = witnesses[0].call("getrpcinfo")
        if Path(local_info["logpath"]).resolve().parent != datadir:
            return dict(state="inconclusive", reason="local RPC datadir does not match destination",
                        timestamp=int(time.time()), schema=1)
        if local_info.get("consensus_quarantine"):
            incident = load_incident(datadir)
            record = {k: v for k, v in incident.items() if k not in ("block_hex", "logs")}
            record.update(incident_latched=True, checked_at=int(time.time()), current_tips={})
            for name, w in zip(("local", "reference"), witnesses):
                try:
                    record["current_tips"][name] = w.call("getblockchaininfo")["bestblockhash"]
                except (RpcFailure, OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as e:
                    record["current_tips"][name] = dict(category="operational-failure", reason=str(e)[:256])
            publish(datadir / LATEST, record)
            return record
        record, raw = observe(witnesses, supplied)
        if raw is not None and record["state"] == "suspected":
            first_seen = int(time.time())
            time.sleep(1)
            again, _ = observe(witnesses, raw)
            if encoded(again) == encoded(record):
                record.update(state="confirmed", first_seen=first_seen)
            else:
                record.update(state="suspected", reason="second observation did not agree")
    except Unknown as error:
        record = dict(state="inconclusive", reason=str(error)[:256])
    except (OSError, RpcFailure, ValueError, KeyError, TypeError, AttributeError, IndexError, http.client.HTTPException) as error:
        record = dict(state="inconclusive", category="operational-failure", reason=str(error)[:256])
    record.update(timestamp=int(time.time()), schema=1)
    if record["state"] == "confirmed" and arm:
        incident = dict(record, block_hex=raw.hex(), logs=dict(zip(("local", "reference"), map(tail, witnesses))))
        incident["incident_id"] = digest(encoded(incident))
        try:
            publish(datadir / MARKER, incident, exclusive=True)
            record["incident_id"] = incident["incident_id"]
        except FileExistsError:
            record["retained_prior_incident"] = True
    record["incident_latched"] = (datadir / MARKER).is_file()
    publish(datadir / LATEST, record)
    return record


def load_incident(datadir):
    with os.fdopen(os.open(datadir / MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("incident marker is not a regular file")
        data = stream.read(2 * MAX_BLOCK + 32769)
    if len(data) > 2 * MAX_BLOCK + 32768:
        raise ValueError("oversized incident record")
    record = json.loads(data)
    stored_id = record.pop("incident_id")
    if record["state"] != "confirmed" or digest(encoded(record)) != stored_id:
        raise ValueError("damaged incident evidence")
    record["incident_id"] = stored_id
    return record


def clear(datadir, incident_id, archive, verification):
    import fcntl
    if not verification.strip() or len(verification) > 1024:
        raise ValueError("supply the verification and regression-vector reference")
    with os.fdopen(os.open(datadir / ".lock", os.O_RDWR | os.O_NOFOLLOW), "r+b") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise ValueError("datadir lock is not a regular file")
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = datadir / MARKER
        record = load_incident(datadir)
        if record["incident_id"] != incident_id:
            raise ValueError("incident does not match the acknowledged evidence")
        with archive.open("xb") as output:
            output.write(encoded(dict(incident=record, verification=verification, cleared=int(time.time()))))
            output.flush()
            os.fsync(output.fileno())
        fsync_dir(archive.parent)
        marker.unlink()
        fsync_dir(datadir)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--datadir", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    watch = commands.add_parser("watch")
    watch.add_argument("--config", required=True, type=Path)
    watch.add_argument("--block", type=Path, help="binary block; otherwise discover the first differing height")
    watch.add_argument("--arm", action="store_true", help="persist a confirmed incident for node containment")
    watch.add_argument("--once", action="store_true")
    watch.add_argument("--interval", type=int, default=15)
    ack = commands.add_parser("clear")
    ack.add_argument("--incident-id", required=True)
    ack.add_argument("--archive", type=Path, required=True)
    ack.add_argument("--verification", required=True)
    args = parser.parse_args()
    datadir = args.datadir.resolve(strict=True)
    if args.command == "clear":
        clear(datadir, args.incident_id, args.archive, args.verification)
        return 0
    if not 1 <= args.interval <= 3600:
        parser.error("interval must be 1..3600 seconds")
    config = json.loads(args.config.read_bytes())
    witnesses = [Witness(config[name]) for name in ("local", "reference")]
    if (witnesses[0].host, witnesses[0].port) == (witnesses[1].host, witnesses[1].port):
        parser.error("use separate endpoints")
    raw = None
    if args.block:
        with args.block.open("rb") as f:
            raw = f.read(MAX_BLOCK + 1)
        exact_block(raw)
    while True:
        record = sample(witnesses, datadir, arm=args.arm, supplied=raw)
        print(encoded(record).decode(), flush=True)
        if args.once:
            return {"confirmed": 2, "inconclusive": 3, "suspected": 4, "consistent": 0}[record["state"]]
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, Unknown) as exc:
        sys.exit(str(exc))
