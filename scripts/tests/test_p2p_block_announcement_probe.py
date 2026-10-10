"""Offline regressions for the live block-announcement wire probe."""

import importlib.util
import socket
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/p2p_block_announcement_probe.py"
SPEC = importlib.util.spec_from_file_location("p2p_block_announcement_probe", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {SCRIPT}")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class FakeSocket:
    def __init__(self, actions):
        self.actions = list(actions)
        self.sent = []
        self.timeout = None

    def recv(self, count):
        if not self.actions:
            raise socket.timeout()
        action = self.actions.pop(0)
        if isinstance(action, BaseException):
            raise action
        chunk = action[:count]
        if len(action) > count:
            self.actions.insert(0, action[count:])
        return chunk

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, timeout):
        self.timeout = timeout


def peer_with(actions):
    peer = probe.Peer.__new__(probe.Peer)
    peer.name = "test-peer"
    peer.sock = FakeSocket(actions)
    peer.receive_buffer = bytearray()
    return peer


class P2pBlockAnnouncementProbeTest(unittest.TestCase):
    def test_partial_frame_survives_drain_timeout(self):
        wire = probe.frame("inv", b"\x00")
        peer = peer_with([wire[:10], socket.timeout(), wire[10:]])

        with self.assertRaises(socket.timeout):
            peer.read_message()
        self.assertEqual(peer.receive_buffer, wire[:10])

        command, payload = peer.read_message()
        self.assertEqual(command, "inv")
        self.assertEqual(payload, b"\x00")
        self.assertEqual(peer.receive_buffer, b"")

    def test_stale_announcement_after_target_is_observed(self):
        target_header = bytes(range(80))
        abandoned_header = bytes(reversed(range(80)))
        target = probe.sha256d(target_header)[::-1].hex()
        abandoned = probe.sha256d(abandoned_header)[::-1].hex()
        target_message = probe.frame("headers", b"\x01" + target_header + b"\x00")
        stale_message = probe.frame("headers", b"\x01" + abandoned_header + b"\x00")
        peer = peer_with([target_message, stale_message])

        with mock.patch.object(probe, "OBSERVATION_WINDOW", 0.001):
            command, saw_abandoned = peer.wait_for_tip(target, abandoned)

        self.assertEqual(command, "headers")
        self.assertTrue(saw_abandoned)


if __name__ == "__main__":
    unittest.main()
