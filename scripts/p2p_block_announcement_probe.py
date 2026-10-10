#!/usr/bin/env python3
"""Compare proactive block announcements from Core and bitcoin-rs on the wire."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import socket
import struct
import time
import urllib.error
import urllib.request


MAGIC = b"\xfa\xbf\xb5\xda"


def _env_seconds(name: str, default: str) -> float:
    value = float(os.environ.get(name, default))
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite, got {value!r}")
    return value


TIMEOUT = _env_seconds("ANNOUNCEMENT_TIMEOUT_SECONDS", "60")
OBSERVATION_WINDOW = _env_seconds("ANNOUNCEMENT_OBSERVATION_SECONDS", "1")


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def varint(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def read_varint(payload: bytes, offset: int = 0) -> tuple[int, int]:
    marker = payload[offset]
    if marker < 0xFD:
        return marker, offset + 1
    sizes = {0xFD: (2, "<H"), 0xFE: (4, "<I"), 0xFF: (8, "<Q")}
    size, encoding = sizes[marker]
    start = offset + 1
    return struct.unpack(encoding, payload[start : start + size])[0], start + size


def frame(command: str, payload: bytes) -> bytes:
    header = (
        MAGIC
        + command.encode().ljust(12, b"\x00")
        + struct.pack("<I", len(payload))
        + sha256d(payload)[:4]
    )
    return header + payload


def rpc(port: int, authentication: str, method: str, params: list[object] | None = None):
    body = json.dumps(
        {"jsonrpc": "1.0", "id": "announcement-probe", "method": method, "params": params or []}
    ).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        data=body,
        headers={
            "Authorization": "Basic " + base64.b64encode(authentication.encode()).decode(),
            "Content-Type": "text/plain",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            decoded = json.load(response)
    except urllib.error.HTTPError as error:
        try:
            decoded = json.load(error)
        except Exception:
            raise RuntimeError(f"{method} failed with HTTP {error.code}: {error.reason}") from error
    if decoded.get("error") is not None:
        raise RuntimeError(f"{method} failed: {decoded['error']}")
    return decoded["result"]


class Peer:
    def __init__(self, port: int, name: str, start_height: int):
        self.name = name
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
        self.sock.settimeout(TIMEOUT)
        self.receive_buffer = bytearray()
        self._handshake(start_height)

    def _fill_receive_buffer(self, count: int) -> None:
        while len(self.receive_buffer) < count:
            chunk = self.sock.recv(count - len(self.receive_buffer))
            if not chunk:
                raise ConnectionError(f"{self.name}: unexpected EOF")
            self.receive_buffer.extend(chunk)

    def read_message(self) -> tuple[str, bytes]:
        # Keep partial headers and payloads across socket timeouts. `drain()`
        # deliberately uses a short timeout, so discarding a partial read there
        # would desynchronize every later frame on this connection.
        self._fill_receive_buffer(24)
        header = self.receive_buffer[:24]
        if header[:4] != MAGIC:
            raise ConnectionError(f"{self.name}: bad network magic")
        command = header[4:16].rstrip(b"\x00").decode()
        length = struct.unpack("<I", header[16:20])[0]
        frame_length = 24 + length
        self._fill_receive_buffer(frame_length)
        payload = bytes(self.receive_buffer[24:frame_length])
        if sha256d(payload)[:4] != header[20:24]:
            raise ConnectionError(f"{self.name}: bad payload checksum")
        del self.receive_buffer[:frame_length]
        return command, payload

    def send(self, command: str, payload: bytes = b"") -> None:
        self.sock.sendall(frame(command, payload))

    def _handshake(self, start_height: int) -> None:
        address = struct.pack("<Q", 9) + bytes(16) + struct.pack(">H", 0)
        agent = f"/announcement-probe:{self.name}/".encode()
        payload = (
            struct.pack("<i", 70016)
            + struct.pack("<Q", 9)
            + struct.pack("<q", int(time.time()))
            + address
            + address
            + struct.pack("<Q", hash(self.name) & 0xFFFFFFFFFFFFFFFF)
            + varint(len(agent))
            + agent
            + struct.pack("<i", start_height)
            + b"\x01"
        )
        self.send("version", payload)
        sent_verack = False
        while True:
            command, _ = self.read_message()
            if command == "version" and not sent_verack:
                self.send("verack")
                sent_verack = True
            elif command == "verack":
                if not sent_verack:
                    self.send("verack")
                break

    def configure(self, mode: str, known_header: bytes) -> None:
        if mode in {"headers", "compact"}:
            self.send("sendheaders")
        if mode == "compact":
            self.send("sendcmpct", b"\x01" + struct.pack("<Q", 2))
        # Demonstrate the exact parent hash to both implementations. A height
        # alone from `version` is intentionally insufficient for compact relay.
        self.send("headers", varint(1) + known_header + b"\x00")

    def drain(self) -> None:
        self.sock.settimeout(0.2)
        try:
            while True:
                command, payload = self.read_message()
                if command == "ping":
                    self.send("pong", payload)
        except socket.timeout:
            pass
        finally:
            self.sock.settimeout(TIMEOUT)

    def wait_for_tip(self, target: str, abandoned: str | None = None) -> tuple[str, bool]:
        deadline = time.monotonic() + TIMEOUT
        observation_deadline = None
        target_command = None
        saw_abandoned = False
        while True:
            now = time.monotonic()
            active_deadline = observation_deadline or deadline
            if now >= active_deadline:
                if target_command is not None:
                    return target_command, saw_abandoned
                raise TimeoutError(f"{self.name}: did not receive announcement for {target}")
            self.sock.settimeout(max(0.01, active_deadline - now))
            try:
                command, payload = self.read_message()
            except socket.timeout:
                continue
            if command == "ping":
                self.send("pong", payload)
                continue
            hashes = announcement_hashes(command, payload)
            if abandoned in hashes:
                saw_abandoned = True
            if target_command is None and target in hashes:
                target_command = command
                observation_deadline = time.monotonic() + OBSERVATION_WINDOW


def announcement_hashes(command: str, payload: bytes) -> list[str]:
    if command == "cmpctblock" and len(payload) >= 80:
        return [sha256d(payload[:80])[::-1].hex()]
    if command == "headers":
        count, offset = read_varint(payload)
        hashes = []
        for _ in range(count):
            header = payload[offset : offset + 80]
            if len(header) != 80:
                raise ValueError("truncated headers announcement")
            hashes.append(sha256d(header)[::-1].hex())
            offset += 80
            transactions, offset = read_varint(payload, offset)
            if transactions != 0:
                raise ValueError("headers announcement carried transactions")
        return hashes
    if command == "inv":
        count, offset = read_varint(payload)
        hashes = []
        for _ in range(count):
            inventory_type = struct.unpack("<I", payload[offset : offset + 4])[0]
            item_hash = payload[offset + 4 : offset + 36]
            offset += 36
            if inventory_type in {2, 0x40000002}:
                hashes.append(item_hash[::-1].hex())
        return hashes
    return []


def wait_for_rs_tip(port: int, authentication: str, target: str) -> None:
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        if rpc(port, authentication, "getbestblockhash") == target:
            return
        time.sleep(0.2)
    raise TimeoutError(f"bitcoin-rs did not reach {target}")


def observe_round(
    peers: dict[str, dict[str, Peer]], target: str, abandoned: str | None = None
) -> tuple[dict[str, dict[str, str]], dict[str, bool]]:
    observed: dict[str, dict[str, str]] = {"core": {}, "bitcoin_rs": {}}
    stale = {"core": False, "bitcoin_rs": False}
    for implementation in ("core", "bitcoin_rs"):
        for mode in ("inv", "headers", "compact"):
            command, saw_abandoned = peers[implementation][mode].wait_for_tip(target, abandoned)
            observed[implementation][mode] = command
            stale[implementation] |= saw_abandoned
    return observed, stale


def main() -> None:
    core_p2p_port = int(os.environ["CORE_P2P_PORT"])
    core_rpc_port = int(os.environ["CORE_RPC_PORT"])
    core_auth = os.environ["CORE_COOKIE"]
    rs_p2p_port = int(os.environ["RS_P2P_PORT"])
    rs_rpc_port = int(os.environ["RS_RPC_PORT"])
    rs_auth = os.environ["RS_RPC_AUTH"]
    mining_address = os.environ["MINING_ADDRESS"]

    parent = rpc(core_rpc_port, core_auth, "getbestblockhash")
    height = rpc(core_rpc_port, core_auth, "getblockcount")
    parent_header = bytes.fromhex(rpc(core_rpc_port, core_auth, "getblockheader", [parent, False]))

    peers = {
        implementation: {
            mode: Peer(port, f"{implementation}-{mode}", height)
            for mode in ("inv", "headers", "compact")
        }
        for implementation, port in (("core", core_p2p_port), ("bitcoin_rs", rs_p2p_port))
    }
    for modes in peers.values():
        for mode, peer in modes.items():
            peer.configure(mode, parent_header)
    time.sleep(1)
    for modes in peers.values():
        for peer in modes.values():
            peer.drain()

    first_tip = rpc(core_rpc_port, core_auth, "generateblock", [mining_address, []])["hash"]
    wait_for_rs_tip(rs_rpc_port, rs_auth, first_tip)
    first, _ = observe_round(peers, first_tip)

    for modes in peers.values():
        for peer in modes.values():
            peer.drain()

    rpc(core_rpc_port, core_auth, "invalidateblock", [first_tip])
    reorg_address = rpc(core_rpc_port, core_auth, "getnewaddress")
    rpc(core_rpc_port, core_auth, "generateblock", [reorg_address, []])
    reorg_tip = rpc(core_rpc_port, core_auth, "generateblock", [reorg_address, []])["hash"]
    wait_for_rs_tip(rs_rpc_port, rs_auth, reorg_tip)
    reorg, stale = observe_round(peers, reorg_tip, first_tip)

    expected = {"inv": "inv", "headers": "headers", "compact": "cmpctblock"}
    for implementation in ("core", "bitcoin_rs"):
        if first[implementation] != expected:
            raise RuntimeError(
                f"{implementation} announcement mismatch: {first[implementation]} != {expected}"
            )
        if reorg[implementation] != expected:
            raise RuntimeError(
                f"{implementation} reorg announcement mismatch: {reorg[implementation]} != {expected}"
            )
        if stale[implementation]:
            raise RuntimeError(f"{implementation} re-announced abandoned tip {first_tip}")

    print(
        json.dumps(
            {
                "parent_tip": parent,
                "first_tip": first_tip,
                "reorg_tip": reorg_tip,
                "first": first,
                "reorg": reorg,
                "abandoned_reannounced": stale,
            }
        )
    )


if __name__ == "__main__":
    main()
