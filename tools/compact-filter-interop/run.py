#!/usr/bin/env python3
"""Opt-in, loopback-only Core/Kyoto evidence. No node internals are imported."""
import argparse
import base64
import hashlib
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def wait_for(predicate, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise TimeoutError("condition did not become ready")


class RpcError(Exception):
    def __init__(self, error):
        self.code = error["code"]
        super().__init__(str(error))


class Node:
    def __init__(self, binary, directory, core=False, filters=False, prune=False):
        self.directory = pathlib.Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.reservations = [socket.socket(), socket.socket()]
        for sock in self.reservations:
            sock.bind(("127.0.0.1", 0))
        self.p2p, self.rpcport = [sock.getsockname()[1] for sock in self.reservations]
        self.core = core
        self.process = None
        self.log_path = self.directory.with_suffix(".log")
        self.log = open(self.log_path, "ab", buffering=0)
        self.args = [str(binary)]
        if core:
            self.args += ["-regtest", "-datadir=" + str(directory), "-server=1", "-listen=1", "-bind=127.0.0.1", "-port=" + str(self.p2p), "-rpcbind=127.0.0.1", "-rpcport=" + str(self.rpcport), "-rpcuser=probe", "-rpcpassword=local-regtest-only", "-connect=0", "-dnsseed=0", "-discover=0", "-blockfilterindex=1", "-peerblockfilters=1", "-v2transport=0"]
        else:
            self.args += ["--network=regtest", "--data-dir=" + str(directory), "--storage-backend=fjall", "--dbcache-mb=64", "--p2p-listen=127.0.0.1:" + str(self.p2p), "--rpc-bind=127.0.0.1:" + str(self.rpcport), "--rpc-user=probe", "--rpc-password=local-regtest-only", "--dns-seeds-enabled=false", "--v2transport=false"]
            if filters:
                self.args += ["--blockfilterindex"]
            if prune:
                self.args += ["--prune-target-mb=550"]

    def start(self):
        # Reserve distinct ports until the process is ready to bind them.
        for sock in self.reservations:
            sock.close()
        self.reservations.clear()
        self.process = subprocess.Popen(self.args, stdout=self.log, stderr=self.log)
        def ready():
            if self.process.poll() is not None:
                raise RuntimeError(self.log_path.read_text())
            try:
                return self.rpc("getblockchaininfo")
            except (OSError, urllib.error.URLError, RpcError):
                return False
        wait_for(ready)
        return self

    def rpc(self, method, *params):
        data = self.post({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        if data.get("error"):
            raise RpcError(data["error"])
        return data["result"]

    def batch(self, method, params):
        results = []
        for start in range(0, len(params), 256):
            calls = [{"jsonrpc": "2.0", "id": index, "method": method, "params": row} for index, row in enumerate(params[start:start + 256])]
            replies = sorted(self.post(calls), key=lambda reply: reply["id"])
            assert len(replies) == len(calls)
            for reply in replies:
                if reply.get("error"):
                    raise RpcError(reply["error"])
                results.append(reply["result"])
        return results

    def post(self, body):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.rpcport}",
            data=json.dumps(body).encode(),
            headers={"Authorization": "Basic " + base64.b64encode(b"probe:local-regtest-only").decode(), "Content-Type": "application/json"},
        )
        try:
            response = urllib.request.urlopen(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = json.load(response)
        return data

    def wait_index(self):
        def ready():
            try:
                info = self.rpc("getindexinfo").get("basic block filter index", {})
                return info.get("synced") and info["best_block_height"] == self.rpc("getblockcount")
            except RpcError:
                return False
        wait_for(ready)

    def stop(self, crash=False):
        for sock in self.reservations:
            sock.close()
        self.reservations.clear()
        if self.process is not None and self.process.poll() is None:
            if crash:
                self.process.kill()
            else:
                try:
                    self.rpc("stop")
                except (OSError, RpcError):
                    self.process.terminate()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class Peer:
    """Bounded BIP157 wire probe; Kyoto itself still supplies consumer evidence."""
    def __init__(self, node):
        self.socket = socket.create_connection(("127.0.0.1", node.p2p), timeout=5)
        self.socket.settimeout(5)
        address = struct.pack("<Q", 0) + b"\x00" * 10 + b"\xff\xff\x7f\x00\x00\x01" + struct.pack(">H", node.p2p)
        version = struct.pack("<iQq", 70016, 8, int(time.time())) + address * 2
        version += struct.pack("<Q", 0x1502) + b"\x00" + struct.pack("<i?", 0, False)
        self.send("version", version)
        self.services = None
        self.disconnected = False
        for _ in range(32):
            command, payload = self.receive()
            if command == "version":
                self.services = struct.unpack_from("<Q", payload, 4)[0]
                self.send("verack")
            if command == "verack":
                assert self.services is not None
                break
        else:
            raise AssertionError("handshake did not finish")

    def send(self, command, payload=b""):
        header = b"\xfa\xbf\xb5\xda" + command.encode().ljust(12, b"\x00")
        self.socket.sendall(header + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload)

    def read(self, size):
        result = bytearray()
        while len(result) < size:
            part = self.socket.recv(size - len(result))
            if not part:
                raise EOFError("peer closed")
            result.extend(part)
        return bytes(result)

    def receive(self):
        header = self.read(24)
        assert header[:4] == b"\xfa\xbf\xb5\xda"
        size = struct.unpack_from("<I", header, 16)[0]
        assert size <= 4 * 1024 * 1024
        payload = self.read(size)
        assert sha256d(payload)[:4] == header[20:]
        return header[4:16].rstrip(b"\x00").decode(), payload

    def query(self, command, payload):
        self.send(command, payload)
        self.send("ping", struct.pack("<Q", 0x1502))
        result = []
        for _ in range(2200):
            try:
                name, response = self.receive()
            except EOFError:
                self.disconnected = True
                return result
            if name == "pong" and response == struct.pack("<Q", 0x1502):
                return result
            if name == "ping":
                self.send("pong", response)
            if name in ("cfilter", "cfheaders", "cfcheckpt"):
                result.append((name, response))
        raise AssertionError("response exceeded message bound")

    def close(self):
        self.socket.close()


def wire_query(node, command, payload):
    peer = Peer(node)
    try:
        responses = peer.query(command, payload)
        return responses, peer.disconnected
    finally:
        peer.close()


def wire_checks(core, node, tip, evidence):
    cases = []
    def request(command, start, stop, valid=True, kind=0):
        hash_ = bytes.fromhex(core.rpc("getblockhash", stop))[::-1] if stop is not None else bytes(32)
        payload = bytes([kind]) + (struct.pack("<I", start) if start is not None else b"") + hash_
        actual, node_disconnected = wire_query(node, command, payload)
        expected, core_disconnected = wire_query(core, command, payload)
        assert actual == expected, (command, start, stop, kind, len(actual), len(expected))
        # Core disconnects invalid requests without discouragement. bitcoin-rs
        # deliberately ignores them and remains responsive to the following ping.
        assert not node_disconnected, (command, start, stop, kind)
        assert core_disconnected == (not valid), (command, start, stop, kind)
        if valid:
            assert actual, (command, start, stop)
        else:
            assert not actual, (command, start, stop)
        cases.append({"command": command, "start": start, "stop": stop, "type": kind, "responses": len(actual), "bitcoin_rs_disconnected": node_disconnected, "core_disconnected": core_disconnected, "response_sha256": hashlib.sha256(b"".join(payload for _, payload in actual)).hexdigest()})
    request("getcfilters", 0, min(999, tip))
    request("getcfheaders", 0, min(1999, tip))
    request("getcfheaders", tip, tip)
    request("getcfcheckpt", None, tip)
    for command in ("getcfilters", "getcfheaders"):
        request(command, 0, None, valid=False)
        request(command, tip + 1, tip, valid=False)
        request(command, 0, tip, valid=False, kind=1)
    request("getcfcheckpt", None, tip, valid=False, kind=1)
    request("getcfcheckpt", None, None, valid=False)
    if tip >= 2000:
        request("getcfilters", 0, 1000, valid=False)
        request("getcfheaders", 0, 2000, valid=False)
    (evidence / "wire-cases.json").write_text(json.dumps(cases, indent=2) + "\n")
    return len(cases)


def transaction(prev_txid, vout, outputs):
    # Fixture spends raw(OP_TRUE) outputs; no signature/wallet is necessary.
    raw = struct.pack("<I", 2) + b"\x01" + bytes.fromhex(prev_txid)[::-1] + struct.pack("<I", vout)
    raw += b"\x00\xff\xff\xff\xff" + bytes([len(outputs)])
    for value, script in outputs:
        raw += struct.pack("<Q", value) + bytes([len(script)]) + script
    raw += b"\x00" * 4
    return raw


def consumer(client, node, target, evidence, label):
    result = subprocess.run([str(client), str(node.p2p), str(target)], capture_output=True, text=True, timeout=100)
    (evidence / (label + ".jsonl")).write_text(result.stdout)
    (evidence / (label + ".log")).write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    events = [json.loads(line) for line in result.stdout.splitlines()]
    filters = [event for event in events if event["event"] == "filter"]
    assert len(filters) == target, len(filters)
    expected = node.batch("getblockfilter", [[event["hash"]] for event in filters])
    for event, result in zip(filters, expected, strict=True):
        assert bytes(event["bytes"]).hex() == result["filter"], event
    assert any(event["matched"] for event in filters), "watched same-block output was not found"
    assert events[-1] == {"event": "block", "height": target, "hash": node.rpc("getblockhash", target)}
    return len(filters)


def compare(core, node, heights):
    hashes = core.batch("getblockhash", [[height] for height in heights])
    assert node.batch("getblockhash", [[height] for height in heights]) == hashes
    assert node.batch("getblockfilter", [[hash_] for hash_ in hashes]) == core.batch("getblockfilter", [[hash_] for hash_ in hashes])


def main():
    if sys.version_info < (3, 10):
        raise SystemExit("compact-filter-interop requires Python 3.10 or newer")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", required=True, type=pathlib.Path)
    parser.add_argument("--bitcoin-rs", required=True, type=pathlib.Path)
    parser.add_argument("--client", required=True, type=pathlib.Path)
    parser.add_argument("--evidence", required=True, type=pathlib.Path)
    parser.add_argument("--blocks", type=int, default=2105)
    args = parser.parse_args()
    assert args.blocks >= 101
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    # This must be the repository's pinned release, installed by its installer.
    version = subprocess.check_output([str(args.bitcoind), "-version"], text=True).splitlines()[0]
    assert "v31.1.0" in version, version
    report = {"core": version, "kyoto_commit": "0169dc3514c8238147302535a1123d5c37468de6", "blocks": args.blocks}
    report["binary_sha256"] = hashlib.sha256(args.bitcoin_rs.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="bitcoin-rs-filter-interop-") as directory:
        directory = pathlib.Path(directory)
        core = Node(args.bitcoind, directory / "core", core=True)
        node = Node(args.bitcoin_rs, directory / "node")
        enabled = Node(args.bitcoin_rs, directory / "enabled", filters=True)
        pruned = Node(args.bitcoin_rs, directory / "pruned", prune=True)
        try:
            core.start()
            descriptor = core.rpc("getdescriptorinfo", "raw(51)")["descriptor"]
            blocks = core.rpc("generatetodescriptor", args.blocks, descriptor)
            first = core.rpc("getblock", blocks[0], 2)["tx"][0]["txid"]
            parent = transaction(first, 0, [(4_900_000_000, b"\x51"), (99_900_000, b"\x51"), (0, b"\x6a\x02\xab\xab"), (0, b"")])
            child = transaction(sha256d(parent)[::-1].hex(), 0, [(4_899_900_000, b"\x52")])
            last = core.rpc("generateblock", descriptor, [parent.hex(), child.hex()])["hash"]
            blocks.append(last)
            core.wait_index()
            print("Core fixture ready", flush=True)
            node.start()
            genesis = core.rpc("getblockhash", 0)
            try:
                node.rpc("getblockfilter", genesis)
                raise AssertionError("disabled filter index answered")
            except RpcError as error:
                assert error.code == -1, error
            assert not (int(node.rpc("getnetworkinfo")["localservices"], 16) & 64)
            peer = Peer(node)
            assert not (peer.services & 64)
            assert not peer.query("getcfheaders", b"\x00" + struct.pack("<I", 0) + bytes.fromhex(genesis)[::-1])
            assert not peer.disconnected
            peer.close()
            bodies = core.batch("getblock", [[hash_, 0] for hash_ in blocks])
            started = time.monotonic()
            assert node.batch("submitblock", [[body] for body in bodies]) == [None] * len(bodies)
            report["disabled_import_seconds"] = time.monotonic() - started
            assert not (node.directory / "txindex").exists(), "default-off mode opened an index"
            node.stop()
            enabled.start()
            started = time.monotonic()
            assert enabled.batch("submitblock", [[body] for body in bodies]) == [None] * len(bodies)
            report["enabled_import_seconds"] = time.monotonic() - started
            enabled.wait_index()
            report["enabled_import_and_index_seconds"] = time.monotonic() - started
            compare(core, enabled, range(len(blocks) + 1))
            enabled.stop()
            pruned.start()
            peer = Peer(pruned)
            assert peer.services & 1024 and not (peer.services & (1 | 64))
            peer.close()
            pruned.stop()
            pruned.args += ["--blockfilterindex"]
            try:
                pruned.start()
                raise AssertionError("pruning and compact filters were accepted")
            except RuntimeError as error:
                assert "not compatible" in str(error).lower() and "prun" in str(error).lower(), error
            report["pruned_service_and_config_rejection"] = True
            node.args += ["--blockfilterindex"]
            started = time.monotonic()
            node.start()
            node.wait_index()
            report["backfill_startup_seconds"] = time.monotonic() - started
            compare(core, node, range(len(blocks) + 1))
            assert set(node.rpc("getindexinfo")) == {"basic block filter index"}
            named = node.post({"jsonrpc": "2.0", "id": 1, "method": "getblockfilter", "params": {"blockhash": genesis, "filtertype": "basic"}})
            assert named["result"] == core.rpc("getblockfilter", genesis)
            assert int(node.rpc("getnetworkinfo")["localservices"], 16) & 64
            peer = Peer(node)
            assert peer.services & 64
            peer.close()
            report["wire_cases"] = wire_checks(core, node, len(blocks), evidence)
            print("Backfill bytes and headers match Core", flush=True)
            report["core_consumer_filters"] = consumer(args.client, core, len(blocks), evidence, "kyoto-core")
            report["node_consumer_filters"] = consumer(args.client, node, len(blocks), evidence, "kyoto-node")
            print("Unmodified Kyoto synced both nodes and fetched matching blocks", flush=True)
            node.stop(crash=True)
            started = time.monotonic()
            node.start()
            node.wait_index()
            report["crash_restart_seconds"] = time.monotonic() - started
            compare(core, node, range(len(blocks) + 1))
            # Keep the unchanged client connected across the actual reorg.
            live_path = evidence / "kyoto-live-reorg.jsonl"
            live_log = evidence / "kyoto-live-reorg.log"
            with open(live_path, "w") as output, open(live_log, "w") as errors:
                live = subprocess.Popen([str(args.client), str(node.p2p), str(len(blocks) + 1)], stdout=output, stderr=errors)
                try:
                    def synced():
                        assert live.poll() is None, live_log.read_text()
                        # The producer may still be writing its last JSON record.
                        return any(json.loads(line).get("event") == "synced"
                                   for line in live_path.read_text().splitlines(keepends=True)
                                   if line.endswith("\n"))
                    wait_for(synced)
                    perform_reorg(core, node, last, evidence, report, blocks, args.client)
                    assert live.wait(timeout=100) == 0, live_log.read_text()
                    events = [json.loads(line) for line in live_path.read_text().splitlines()]
                    assert events[-1] == {"event": "block", "height": len(blocks) + 1, "hash": node.rpc("getbestblockhash")}
                    report["connected_consumer_reorg"] = True
                finally:
                    if live.poll() is None:
                        live.kill()
                        live.wait(timeout=5)
            node.stop()
            report["index_storage_bytes"] = sum(path.stat().st_size for path in (node.directory / "txindex").rglob("*") if path.is_file())
            print("Crash restart and reorg passed", flush=True)
        finally:
            for label, process in [("core", core), ("node", node), ("enabled", enabled), ("pruned", pruned)]:
                process.stop()
                process.log.close()
                (evidence / (label + "-process.log")).write_bytes(process.log_path.read_bytes())
    (evidence / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def perform_reorg(core, node, last, evidence, report, blocks, client):
    # Public invalidateblock disconnects the block with both kinds of spend,
    # then a replacement branch reconnects through the same owner.
    core.rpc("invalidateblock", last)
    node.rpc("invalidateblock", last)
    alternate = core.rpc("getdescriptorinfo", "raw(52)")["descriptor"]
    replacements = core.rpc("generatetodescriptor", 2, alternate)
    started = time.monotonic()
    for hash_ in replacements:
        result = node.rpc("submitblock", core.rpc("getblock", hash_, 0))
        assert result in (None, "inconclusive"), result
    node.wait_index()
    core.wait_index()
    report["reorg_seconds"] = time.monotonic() - started
    compare(core, node, range(len(blocks) + 2))
    try:
        node.rpc("getblockfilter", last)
        raise AssertionError("orphan filter was served")
    except RpcError as error:
        assert error.code == -1
    report["reorg_consumer_filters"] = consumer(client, node, len(blocks) + 1, evidence, "kyoto-reorg")


if __name__ == "__main__":
    main()
