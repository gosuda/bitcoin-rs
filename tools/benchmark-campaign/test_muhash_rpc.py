#!/usr/bin/env python3.14
# pyright: strict
"""Protocol-level tests for the external MuHash comparator."""

import base64
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("muhash_rpc.py")
MODULE_NAME = "muhash_rpc_under_test"
SPEC = importlib.util.spec_from_file_location(MODULE_NAME, MODULE_PATH)
assert SPEC is not None
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

BESTBLOCK = "ab" * 32
MUHASH = "cd" * 32
OTHER_MUHASH = "ef" * 32
HEIGHT = 840_000
CREDENTIAL_SECRET = "bench-pass-7f3a"
REQUEST_BODY = module._request_body()


def _raw_response(state: dict[str, object]) -> bytes:
    return module.canonical_json_bytes(
        {"jsonrpc": "2.0", "id": 1, "error": None, "result": state}
    )


def _state_literal(
    height: int = HEIGHT,
    bestblock: str = BESTBLOCK,
    muhash: str = MUHASH,
    amount: str = "12.50000000",
) -> str:
    return (
        f'{{"height": {height}, "bestblock": "{bestblock}", "transactions": 1, '
        f'"txouts": 2, "bogosize": 300, "disk_size": 400, '
        f'"total_amount": {amount}, "muhash": "{muhash}"}}'
    )


def _state_map(**overrides: object) -> dict[str, object]:
    raw = json.loads(_state_literal(), parse_float=Decimal, parse_int=int)
    assert isinstance(raw, dict)
    return {**raw, **overrides}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_object(value: object) -> bool:
    return isinstance(value, dict)


class _FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, format_string: str, *args: object) -> None:
        del format_string, args

    def do_POST(self) -> None:
        server = self.server
        if not isinstance(server, _FixtureServer):
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            request: object = json.loads(raw.decode("utf-8")) if raw else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            request = {}
        if isinstance(request, dict):
            server.requests.append(request)
        if server.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", server.endpoint)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if server.mode == "http_error":
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if server.mode == "oversized":
            body = (
                b'{"jsonrpc":"2.0","id":1,"error":null,"result":{"pad":"' + b"x" * 8192
            )
        elif server.mode == "malformed":
            body = b"{definitely not json"
        elif server.mode == "deep":
            body = (
                '{"jsonrpc":"2.0","id":1,"error":null,"result":'
                + "[" * 40
                + "]" * 40
                + "}"
            ).encode("utf-8")
        elif server.mode == "decoder_deep":
            body = (
                '{"jsonrpc":"2.0","id":1,"error":null,"result":'
                + "[" * 1_100
                + "]" * 1_100
                + "}"
            ).encode("utf-8")
        elif server.mode == "overlong_int":
            shaped = (
                '{"jsonrpc":"2.0","id":1,"error":null,"result":'
                + server.state_literal
                + "}"
            )
            body = shaped.replace(
                '"bogosize": 300', '"bogosize": ' + "9" * 5_000
            ).encode("utf-8")
        elif server.mode == "duplicate_key":
            body = (
                '{"jsonrpc":"2.0","id":1,"error":null,"result":'
                + '{"height": 1, "height": 2}'
                + "}"
            ).encode("utf-8")
        elif server.mode == "wrong_id":
            body = b'{"jsonrpc":"2.0","id":9,"error":null,"result":{}}'
        elif server.mode == "wrong_version":
            body = b'{"jsonrpc":"1.9","id":1,"error":null,"result":{}}'
        elif server.mode == "rpc_error":
            body = (
                b'{"jsonrpc":"2.0","id":1,'
                b'"error":{"code":-8,"message":"no such block"},"result":null}'
            )
        elif (
            server.mode == "duplicate_length"
            or server.mode == "folded_header"
            or server.mode == "chunked"
            or server.mode == "long_length"
            or server.mode == "coalesced_whitespace"
            or server.mode == "coalesced_extra"
            or server.mode == "delayed_extra"
        ):
            body = (
                '{"jsonrpc":"2.0","id":1,"error":null,"result":'
                + server.state_literal
                + "}"
            ).encode("utf-8")
        else:
            body = (
                '{"jsonrpc":"2.0","id":1,"error":null,"result":'
                + server.state_literal
                + "}"
            ).encode("utf-8")
        if server.mode in (
            "duplicate_length",
            "folded_header",
            "chunked",
            "long_length",
            "coalesced_whitespace",
            "coalesced_extra",
            "delayed_extra",
            "silent",
        ):
            # Raw frames exercise framing defects the stock handler cannot
            # express; each closes the connection itself.
            head = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
            if server.mode == "duplicate_length":
                frame = (
                    head + f"Content-Length: {len(body)}\r\nContent-Length: 0\r\n\r\n"
                ).encode("ascii") + body
            elif server.mode == "folded_header":
                frame = (
                    head
                    + "X-Folded: part\r\n continued\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n"
                ).encode("ascii") + body
            elif server.mode == "chunked":
                frame = (head + "Transfer-Encoding: chunked\r\n\r\n").encode(
                    "ascii"
                ) + body
            elif server.mode == "long_length":
                frame = (head + "Content-Length: " + "9" * 5_000 + "\r\n\r\n").encode(
                    "ascii"
                ) + body
            elif server.mode == "coalesced_whitespace":
                frame = (
                    (head + f"Content-Length: {len(body)}\r\n\r\n").encode("ascii")
                    + body
                    + b"   "
                )
            elif server.mode == "coalesced_extra":
                frame = (
                    (head + f"Content-Length: {len(body)}\r\n\r\n").encode("ascii")
                    + body
                    + b"X"
                )
            elif server.mode == "delayed_extra":
                frame = (head + f"Content-Length: {len(body)}\r\n\r\n").encode(
                    "ascii"
                ) + body
            else:
                frame = (head + "Content-Length: 0\r\n\r\n").encode("ascii")
            self.wfile.write(frame)
            self.wfile.flush()
            if server.mode == "delayed_extra":
                time.sleep(0.05)
                self.wfile.write(b"X")
                self.wfile.flush()
            self.close_connection = True
            return
        if server.mode == "slow_header":
            # Drip the status and header bytes themselves so only a client
            # whose absolute deadline covers header parsing passes.
            frame = (
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n"
            ).encode("ascii")
            server.drips_finished = False
            for index in range(0, len(frame), 4):
                try:
                    self.wfile.write(frame[index : index + 4])
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                time.sleep(0.05)
            server.drips_finished = True
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if server.mode == "slow_drip":
            # Mark the drip in-flight before the first byte so a client that
            # refuses at its deadline cannot race this handler's state.
            server.drips_finished = False
            for index in range(0, len(body), 4):
                try:
                    self.wfile.write(body[index : index + 4])
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    # The client cut the connection at its deadline; the
                    # incomplete drip is the expected outcome, stay False.
                    return
                time.sleep(0.05)
            server.drips_finished = True
            return
        self.wfile.write(body)


class _FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode: str, state_literal: str) -> None:
        self.mode = mode
        self.state_literal = state_literal
        self.requests: list[dict[str, object]] = []
        self.drips_finished = True
        super().__init__(("127.0.0.1", 0), _FixtureHandler)

    @property
    def endpoint(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}/"

    def start(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        return thread


def _trusted_base() -> Path:
    # The strict namespace rule refuses group-writable ancestors, and this
    # repository's own directories are group-writable. XDG_RUNTIME_DIR is
    # the per-user private directory: root-owned 0755 ancestors and a 0700
    # euid-owned leaf, accepted with no exception. /tmp is the fallback and
    # is accepted only through the sticky-root exception.
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        return Path(runtime) / ".muhash-test-tmp"
    return Path(tempfile.gettempdir()) / ".muhash-test-tmp"


def _make_root(prefix: str) -> Path:
    base = _trusted_base()
    base.mkdir(mode=0o700, exist_ok=True)
    os.chmod(base, 0o700)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base))


def _sweep_base() -> None:
    base = _trusted_base()
    with contextlib.suppress(OSError):
        base.rmdir()


def _write_file(
    directory: Path, name: str, data: bytes, *, private: bool = False
) -> dict[str, object]:
    path = directory / name
    path.write_bytes(data)
    if private:
        path.chmod(0o600)
    return {"path": str(path), "sha256": _sha256(data), "bytes": len(data)}


class _TrialEnv:
    def __init__(
        self,
        mode: str = "ok",
        *,
        policy: str = "warm",
        timeout: str = "5",
        max_response_bytes: int = 65_536,
        expected_height: int = HEIGHT,
        expected_bestblock: str = BESTBLOCK,
        state: str | None = None,
        endpoint: str | None = None,
        credential_mode: int = 0o600,
        corrupt: str | None = None,
    ) -> None:
        self.root = _make_root("muhash-trial-")
        self.server = _FixtureServer(mode, state or _state_literal())
        self.thread = self.server.start()
        self.endpoint = endpoint or self.server.endpoint
        self.owner_pid = os.getpid()
        self.owner_starttime = module._read_starttime(self.owner_pid)
        corpus = _write_file(self.root, "corpus.bin", b"frozen-corpus")
        executable = _write_file(self.root, "bitcoind", b"core-binary")
        config = _write_file(self.root, "bitcoin.conf", b"conf-bytes")
        cookie = self.root / "rpc.cookie"
        cookie.write_bytes(f"bench-user:{CREDENTIAL_SECRET}".encode())
        cookie.chmod(credential_mode)
        self.credential_ref = {
            "path": str(cookie),
            "sha256": _sha256(f"bench-user:{CREDENTIAL_SECRET}".encode()),
            "bytes": len(f"bench-user:{CREDENTIAL_SECRET}".encode()),
        }
        self.coordinates = {
            "campaign_id": "camp-41",
            "policy": policy,
            "pair_index": 0,
            "position": 0,
            "arm_id": "core-arm",
            "arm_kind": "core",
        }
        pre: dict[str, object] = {
            **self.coordinates,
            "schema": module.PRE_RECEIPT_SCHEMA,
            "executable": executable,
            "config": config,
            "corpus": {
                "identity": "frozen-tip",
                "file": corpus,
                "height": HEIGHT,
                "bestblock": BESTBLOCK,
            },
            "backend": "coinsdb",
            "datadir": str(self.root / "datadir"),
            "endpoint": self.endpoint,
            "attested_pid": self.owner_pid,
            "attested_starttime": self.owner_starttime,
            "affinity": "0-3",
            "cache_policy_action": {
                "warm": "warm-untimed-query-done",
                "process-cold/page-cache-unspecified": "fresh-process-before-observation",
                "process-cold/page-cache-evicted": "page-cache-evicted",
            }[policy],
            "eviction_procedure": None,
            "frozen_height": HEIGHT,
            "frozen_bestblock": BESTBLOCK,
            "proc_stat_before": {"minflt": 1, "majflt": 0},
            "proc_io_before": {
                "rchar": 10,
                "read_bytes": 20,
                "wchar": 30,
                "write_bytes": 40,
                "syscr": 2,
                "syscw": 1,
            },
            "operator_trust_boundary": module.OPERATOR_TRUST_BOUNDARY,
        }
        pre_bytes = module.canonical_json_bytes(pre)
        self.pre_ref = _write_file(self.root, "pre.json", pre_bytes)
        self.expected = {"height": expected_height, "bestblock": expected_bestblock}
        self.trial_input: dict[str, object] = {
            **self.coordinates,
            "schema": module.TRIAL_INPUT_SCHEMA,
            "endpoint": self.endpoint,
            "credential_file": self.credential_ref,
            "timeout_seconds": timeout,
            "max_response_bytes": max_response_bytes,
            "corpus": {
                "identity": "frozen-tip",
                "file": corpus,
                "height": HEIGHT,
                "bestblock": BESTBLOCK,
            },
            "expected": self.expected,
            "controller_pre_receipt": self.pre_ref,
        }
        input_bytes = module.canonical_json_bytes(self.trial_input)
        self.input_path = self.root / "trial-input.json"
        self.input_path.write_bytes(input_bytes)
        if corrupt == "input_oversize":
            self.input_path.write_bytes(b"[" * 70_000)
        elif corrupt == "input_deep":
            self.input_path.write_bytes(("[" * 40 + "]" * 40).encode())
        elif corrupt == "input_decoder_deep":
            self.input_path.write_bytes(("[" * 1_100 + "]" * 1_100).encode())

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def run(self, output_name: str = "observation.json") -> tuple[int, str]:
        code, output_path, _ = self.run_capture(output_name)
        return code, output_path

    def run_capture(
        self, output_name: str = "observation.json"
    ) -> tuple[int, str, str]:
        output_path = self.root / output_name
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = module.main(
                ["trial", "--input", str(self.input_path), "--output", str(output_path)]
            )
        return code, str(output_path), stderr.getvalue()


class TrialTests(unittest.TestCase):
    def setUp(self) -> None:
        self._environments: list[_TrialEnv] = []

    def tearDown(self) -> None:
        for environment in self._environments:
            environment.stop()
            environment.cleanup()
        _sweep_base()

    def _environment(self, **kwargs: object) -> _TrialEnv:
        environment = _TrialEnv(**kwargs)  # type: ignore[arg-type]
        self._environments.append(environment)
        return environment

    def test_trial_sends_only_the_fixed_production_rpc(self) -> None:
        environment = self._environment()
        code, output_path = environment.run()
        self.assertEqual(code, 0)
        self.assertTrue(Path(output_path).exists())
        self.assertEqual(len(environment.server.requests), 1)
        request = environment.server.requests[0]
        self.assertEqual(request.get("method"), "gettxoutsetinfo")
        self.assertEqual(request.get("params"), ["muhash", None, False])
        self.assertEqual(request.get("jsonrpc"), "2.0")
        for recorded in environment.server.requests:
            serialized = json.dumps(recorded)
            self.assertNotIn("benchmarkreceipt", serialized)
            self.assertNotIn("flushstate", serialized)

    def test_observation_timing_and_self_hash_recompute(self) -> None:
        environment = self._environment()
        code, output_path = environment.run()
        self.assertEqual(code, 0)
        observation = json.loads(
            Path(output_path).read_text(), parse_float=Decimal, parse_int=int
        )
        self.assertIsInstance(observation, dict)
        self.assertGreater(observation["duration_ns"], 0)
        self.assertEqual(
            observation["duration_ns"],
            observation["monotonic_end_ns"] - observation["monotonic_start_ns"],
        )
        recorded = observation.pop("self_sha256")
        self.assertEqual(module.canonical_sha256(observation), recorded)
        self.assertEqual(observation["query"]["method"], "gettxoutsetinfo")
        self.assertEqual(observation["query"]["params"], ["muhash", None, False])
        self.assertEqual(observation["request_sha256"], _sha256(REQUEST_BODY))
        raw = base64.b64decode(observation["raw_response_b64"])
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(), observation["raw_response_sha256"]
        )
        self.assertIn(_state_literal(), raw.decode("utf-8"))

    def test_wrong_frozen_tip_is_refused_without_output(self) -> None:
        environment = self._environment(state=_state_literal(height=839_999))
        code, output_path = environment.run()
        self.assertEqual(code, 2)
        self.assertFalse(Path(output_path).exists())

    def test_wrong_bestblock_is_refused(self) -> None:
        environment = self._environment(state=_state_literal(bestblock=OTHER_MUHASH))
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_malformed_json_is_refused(self) -> None:
        environment = self._environment(mode="malformed")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_oversized_response_is_refused(self) -> None:
        environment = self._environment(mode="oversized", max_response_bytes=4096)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_deep_response_is_refused(self) -> None:
        environment = self._environment(mode="deep")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_slow_drip_hits_end_to_end_deadline(self) -> None:
        environment = self._environment(mode="slow_drip", timeout="0.3")
        started = time.monotonic()
        code, _ = environment.run()
        elapsed = time.monotonic() - started
        self.assertEqual(code, 2)
        # The refusal must land near the 0.3 s deadline, strictly below the
        # ~2.5 s the fixture needs to drip its whole body.
        self.assertLess(elapsed, 1.5)
        self.assertFalse(environment.server.drips_finished)

    def test_slow_header_hits_end_to_end_deadline(self) -> None:
        environment = self._environment(mode="slow_header", timeout="0.3")
        started = time.monotonic()
        code, _ = environment.run()
        elapsed = time.monotonic() - started
        self.assertEqual(code, 2)
        # Header bytes must be covered by the same absolute deadline; the
        # fixture needs several seconds to finish its header drip.
        self.assertLess(elapsed, 1.5)
        self.assertFalse(environment.server.drips_finished)

    def test_decoder_depth_overflow_is_refused(self) -> None:
        environment = self._environment(mode="decoder_deep")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_decoder_deep_trial_input_is_refused(self) -> None:
        environment = self._environment(corrupt="input_decoder_deep")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_overlong_integer_token_is_refused(self) -> None:
        environment = self._environment(mode="overlong_int")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_overlong_integer_in_trial_input_is_refused(self) -> None:
        environment = self._environment()
        environment.server.shutdown()
        poisoned = environment.input_path.read_bytes().replace(
            b'"max_response_bytes":65536', b'"max_response_bytes":' + b"9" * 5_000
        )
        self.assertNotEqual(poisoned, environment.input_path.read_bytes())
        environment.input_path.write_bytes(poisoned)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_duplicate_member_key_is_not_echoed_to_stderr(self) -> None:
        environment = self._environment()
        environment.server.shutdown()
        secret_key = b'"secret-9af3-bearer-token-duplicate"'
        raw = environment.input_path.read_bytes()
        poisoned = raw.replace(
            b'"controller_pre_receipt"',
            secret_key + b":1," + secret_key + b':2,"controller_pre_receipt"',
        )
        environment.input_path.write_bytes(poisoned)
        code, _, stderr = environment.run_capture()
        self.assertEqual(code, 2)
        self.assertNotIn(b"secret-9af3-bearer-token-duplicate".decode(), stderr)

    def test_non_loopback_endpoint_is_refused(self) -> None:
        environment = self._environment(endpoint="http://10.0.0.1:8332/")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_endpoint_with_userinfo_is_refused(self) -> None:
        environment = self._environment(endpoint="http://user:pass@127.0.0.1:8332/")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_endpoint_without_port_or_path_is_refused(self) -> None:
        environment = self._environment(endpoint="http://127.0.0.1")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_endpoint_with_fragment_is_refused(self) -> None:
        environment = self._environment(endpoint="http://127.0.0.1:8332/#frag")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_redirect_is_refused(self) -> None:
        environment = self._environment(mode="redirect")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_http_error_status_is_refused(self) -> None:
        environment = self._environment(mode="http_error")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_mismatched_json_rpc_id_is_refused(self) -> None:
        environment = self._environment(mode="wrong_id")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_mismatched_json_rpc_version_is_refused(self) -> None:
        environment = self._environment(mode="wrong_version")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_rpc_error_envelope_is_refused(self) -> None:
        environment = self._environment(mode="rpc_error")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_response_byte_cap_is_enforced(self) -> None:
        environment = self._environment(max_response_bytes=8)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_credentials_never_appear_in_observation_or_stderr(self) -> None:
        environment = self._environment()
        code, output_path = environment.run()
        self.assertEqual(code, 0)
        self.assertNotIn(CREDENTIAL_SECRET, Path(output_path).read_text())
        failing = self._environment(state=_state_literal(height=1))
        failing.server.shutdown()
        _, _, stderr = failing.run_capture("refused.json")
        self.assertNotIn(CREDENTIAL_SECRET, stderr)
        self.assertNotIn("bench-user", stderr)

    def test_world_readable_credential_file_is_refused(self) -> None:
        environment = self._environment(credential_mode=0o644)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def _fifo_case(self, kind: str) -> None:
        environment = self._environment()
        environment.server.shutdown()
        fifo = environment.root / f"hostile-{kind}.fifo"
        os.mkfifo(fifo)
        if kind == "input":
            environment.input_path.unlink()
            os.rename(fifo, environment.input_path)
        elif kind == "corpus":
            poisoned = dict(environment.trial_input)
            corpus = dict(poisoned["corpus"])
            assert isinstance(corpus, dict)
            corpus_file = dict(corpus["file"])
            assert isinstance(corpus_file, dict)
            corpus_file["path"] = str(fifo)
            corpus["file"] = corpus_file
            poisoned["corpus"] = corpus
            environment.input_path.write_bytes(module.canonical_json_bytes(poisoned))
        else:
            poisoned = dict(environment.trial_input)
            credential = dict(poisoned["credential_file"])
            assert isinstance(credential, dict)
            credential["path"] = str(fifo)
            poisoned["credential_file"] = credential
            environment.input_path.write_bytes(module.canonical_json_bytes(poisoned))
        result: dict[str, object] = {"done": False}

        def runner() -> None:
            result["code"] = environment.run()[0]
            result["done"] = True

        worker = threading.Thread(target=runner, daemon=True)
        worker.start()
        worker.join(timeout=10)
        self.assertTrue(result["done"], f"{kind} FIFO open blocked the comparator")
        self.assertEqual(result["code"], 2)
        environment.cleanup()

    def test_fifo_input_is_refused_promptly(self) -> None:
        self._fifo_case("input")

    def test_fifo_corpus_ref_is_refused_promptly(self) -> None:
        self._fifo_case("corpus")

    def test_fifo_credential_file_is_refused_promptly(self) -> None:
        self._fifo_case("credential")

    def test_silent_peer_waits_without_spinning(self) -> None:
        environment = self._environment(mode="silent", timeout="0.3")
        original_default = module.selectors.DefaultSelector
        calls = {"select": 0}

        class CountingSelector(original_default):
            def select(self, timeout: object = None) -> object:
                calls["select"] += 1
                return super().select(timeout)

        module.selectors.DefaultSelector = CountingSelector  # type: ignore[assignment]
        try:
            code, _ = environment.run()
        finally:
            module.selectors.DefaultSelector = original_default  # type: ignore[assignment]
        self.assertEqual(code, 2)
        # A write-ready spin would call select thousands of times inside
        # the 0.3 s deadline; read-only interest blocks instead.
        self.assertLess(calls["select"], 50)

    def test_coalesced_and_delayed_overruns_are_refused(self) -> None:
        for mode in (
            "coalesced_whitespace",
            "coalesced_extra",
            "delayed_extra",
            "duplicate_length",
            "folded_header",
            "chunked",
            "long_length",
        ):
            environment = self._environment(mode=mode)
            code, output_path = environment.run()
            self.assertEqual(code, 2, mode)
            self.assertFalse(Path(output_path).exists(), mode)
            environment.stop()
            environment.cleanup()

    def test_numeric_raw_response_b64_is_refused(self) -> None:
        environment = _AggregateEnv()

        # Coherent tamper: the numeric scalar is kept as-is while the
        # observation self-hash and post edge are recomputed around it, so
        # the refusal must come from the scalar type check itself.
        observation = environment._read_evidence(6, "observation")
        observation["raw_response_b64"] = 12345
        observation.pop("self_sha256")
        observation["self_sha256"] = module.canonical_sha256(observation)
        post = environment._read_evidence(6, "post_receipt")
        post["observation_sha256"] = observation["self_sha256"]
        environment.rewrite_triple(6, "observation", observation)
        environment.rewrite_triple(6, "post_receipt", post)
        code, _ = environment.run()
        self.assertEqual(code, 2)
        environment.cleanup()

    def test_unknown_member_names_are_not_echoed(self) -> None:
        environment = self._environment()
        environment.server.shutdown()
        poisoned = dict(environment.trial_input)
        poisoned["secret-7f-token-unknown"] = 1
        poisoned["x-control"] = "\x1b[31mred"
        environment.input_path.write_bytes(module.canonical_json_bytes(poisoned))
        code, _, stderr = environment.run_capture()
        self.assertEqual(code, 2)
        self.assertNotIn("secret-7f-token-unknown", stderr)
        self.assertNotIn("\x1b[31m", stderr)

    def test_custody_hash_mismatch_is_refused(self) -> None:
        environment = self._environment()
        environment.server.shutdown()
        corpus_path = environment.root / "corpus.bin"
        corpus_path.write_bytes(b"tampered-corpus")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_file_changed_during_read_is_refused(self) -> None:
        environment = self._environment()
        environment.server.shutdown()
        original_read = module.os.read
        opened: list[int] = []

        def mutating_read(descriptor: int, count: int) -> bytes:
            data = original_read(descriptor, count)
            # Fire on the corpus read (identified by its pinned 13-byte
            # size; os.read is called once for data and once for EOF per
            # file) and keep the size stable so the mid-read identity
            # check — not a size mismatch — is the gate under test.
            if not opened and os.fstat(descriptor).st_size == 13 and data:
                writable = os.open(environment.root / "corpus.bin", os.O_WRONLY)
                opened.append(writable)
                os.pwrite(writable, b"T" * min(len(data), 13), 0)
            return data

        module.os.read = mutating_read  # type: ignore[assignment]
        try:
            code, _, stderr = environment.run_capture()
        finally:
            module.os.read = original_read  # type: ignore[assignment]
            for descriptor in opened:
                os.close(descriptor)
        self.assertEqual(code, 2)
        self.assertIn("changed while being read", stderr)

    def test_duplicate_key_in_trial_input_is_refused(self) -> None:
        environment = self._environment()
        environment.server.shutdown()
        raw = environment.input_path.read_bytes()
        poisoned = raw.replace(
            b'"controller_pre_receipt"',
            b'"campaign_id":"x","campaign_id":"y","controller_pre_receipt"',
        )
        self.assertNotEqual(raw, poisoned)
        environment.input_path.write_bytes(poisoned)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_duplicate_key_in_rpc_result_is_refused(self) -> None:
        environment = self._environment(mode="duplicate_key")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_extreme_amount_exponents_are_refused(self) -> None:
        for amount in ("1e999999999", "1e-999999999", "0.000000001", "-1"):
            environment = self._environment(state=_state_literal(amount=amount))
            code, _ = environment.run()
            self.assertEqual(code, 2, amount)

    def test_credential_size_mismatch_is_refused(self) -> None:
        environment = self._environment()
        environment.server.shutdown()
        poisoned = dict(environment.trial_input)
        credential = dict(poisoned["credential_file"])
        assert isinstance(credential, dict)
        credential["bytes"] = int(credential["bytes"]) + 1
        poisoned["credential_file"] = credential
        environment.input_path.write_bytes(module.canonical_json_bytes(poisoned))
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_proxy_environment_never_receives_the_request(self) -> None:
        trap = _FixtureServer("ok", _state_literal())
        trap_thread = trap.start()
        environment = self._environment()
        proxies = (
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
        )
        saved = {name: os.environ.get(name) for name in proxies}
        code = 2
        output_exists = False
        target_requests: list[dict[str, object]] = []
        trap_requests: list[dict[str, object]] = []
        try:
            for name in proxies:
                os.environ[name] = trap.endpoint
            code, output_path = environment.run()
            output_exists = Path(output_path).exists()
            target_requests = list(environment.server.requests)
            trap_requests = list(trap.requests)
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
            environment.stop()
            environment.cleanup()
            trap.shutdown()
            trap.server_close()
            trap_thread.join(timeout=5)
        self.assertEqual(code, 0)
        self.assertTrue(output_exists)
        self.assertEqual(len(target_requests), 1)
        self.assertEqual(trap_requests, [])

    def test_oversized_trial_input_is_refused_before_parse(self) -> None:
        environment = self._environment(corrupt="input_oversize")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_deeply_nested_trial_input_is_refused(self) -> None:
        environment = self._environment(corrupt="input_deep")
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_unknown_trial_input_key_is_refused(self) -> None:
        environment = self._environment()
        environment.server.shutdown()
        poisoned = dict(environment.trial_input)
        poisoned["rpc_method"] = "getbestblockhash"
        environment.input_path.write_bytes(module.canonical_json_bytes(poisoned))
        code, _ = environment.run()
        self.assertEqual(code, 2)


class _AggregateEnv:
    def __init__(
        self,
        policy: str = "warm",
        core_arm_id: str = "core-arm",
        rs_identity: tuple[int, int] | None = None,
        cold_reuse_core: bool = False,
    ) -> None:
        self.root = _make_root("muhash-aggregate-")
        self.policy = policy
        corpus = _write_file(self.root, "corpus.bin", b"frozen-corpus")
        self.corpus_ref = corpus
        self.core_files = {
            "executable": _write_file(self.root, "core-bin", b"core-binary"),
            "config": _write_file(self.root, "core.conf", b"core-conf"),
        }
        self.rs_files = {
            "executable": _write_file(self.root, "rs-bin", b"rs-binary"),
            "config": _write_file(self.root, "rs.conf", b"rs-conf"),
        }
        cookie = self.root / "rpc.cookie"
        cookie.write_bytes(f"bench-user:{CREDENTIAL_SECRET}".encode())
        cookie.chmod(0o600)
        self.cookie_ref = {
            "path": str(cookie),
            "sha256": _sha256(f"bench-user:{CREDENTIAL_SECRET}".encode()),
            "bytes": len(f"bench-user:{CREDENTIAL_SECRET}".encode()),
        }
        self.endpoints = {
            "core": "http://127.0.0.1:18332/",
            "bitcoin-rs": "http://127.0.0.1:28332/",
        }
        self.backends = {"core": "coinsdb", "bitcoin-rs": "fjall"}
        self.arm_ids = {"core": core_arm_id, "bitcoin-rs": "rs-arm"}
        self.procedure: dict[str, object] | None = None
        if policy == "process-cold/page-cache-evicted":
            self.procedure = _write_file(self.root, "evict.sh", b"evict-procedure")
        # Physically possible schedule: each observation starts strictly
        # after the previous one ends, so manifest order is execution
        # order.
        self.next_start = 1_000
        self.rs_identity = rs_identity
        self.cold_reuse_core = cold_reuse_core
        self.campaign = "camp-41"
        self.triples: list[dict[str, object]] = []
        for pair in range(module.PAIR_COUNT):
            for position, kind in enumerate(module.trial_order(pair)):
                self.triples.append(self._triple(pair, position, kind, corpus))

    def _pid(self, kind: str, index: int) -> tuple[int, int]:
        if self.policy == "warm":
            if kind != "core" and self.rs_identity is not None:
                return self.rs_identity
            return (4242 if kind == "core" else 5151, 100)
        if self.cold_reuse_core and kind != "core":
            index -= 1
        return (5000 + index, 1000 + index)

    def _triple(
        self, pair: int, position: int, kind: str, corpus: dict[str, object]
    ) -> dict[str, object]:
        index = len(self.triples)
        arm_id = self.arm_ids[kind]
        files = self.core_files if kind == "core" else self.rs_files
        coordinates = {
            "campaign_id": self.campaign,
            "policy": self.policy,
            "pair_index": pair,
            "position": position,
            "arm_id": arm_id,
            "arm_kind": kind,
        }
        pid, starttime = self._pid(kind, index)
        pre: dict[str, object] = {
            **coordinates,
            "schema": module.PRE_RECEIPT_SCHEMA,
            "executable": files["executable"],
            "config": files["config"],
            "corpus": {
                "identity": "frozen-tip",
                "file": corpus,
                "height": HEIGHT,
                "bestblock": BESTBLOCK,
            },
            "backend": self.backends[kind],
            "datadir": str(self.root / f"datadir-{kind}"),
            "endpoint": self.endpoints[kind],
            "attested_pid": pid,
            "attested_starttime": starttime,
            "affinity": "0-3",
            "cache_policy_action": {
                "warm": "warm-untimed-query-done",
                "process-cold/page-cache-unspecified": "fresh-process-before-observation",
                "process-cold/page-cache-evicted": "page-cache-evicted",
            }[self.policy],
            "eviction_procedure": self.procedure,
            "frozen_height": HEIGHT,
            "frozen_bestblock": BESTBLOCK,
            "proc_stat_before": {"minflt": 1, "majflt": 0},
            "proc_io_before": {
                "rchar": 10,
                "read_bytes": 20,
                "wchar": 30,
                "write_bytes": 40,
                "syscr": 2,
                "syscw": 1,
            },
            "operator_trust_boundary": module.OPERATOR_TRUST_BOUNDARY,
        }
        pre_bytes = module.canonical_json_bytes(pre)
        pre_ref = _write_file(self.root, f"pre-{index}.json", pre_bytes)
        trial_manifest: dict[str, object] = {
            **coordinates,
            "schema": module.TRIAL_INPUT_SCHEMA,
            "endpoint": self.endpoints[kind],
            "credential_file": self.cookie_ref,
            "timeout_seconds": "5",
            "max_response_bytes": 65_536,
            "corpus": {
                "identity": "frozen-tip",
                "file": corpus,
                "height": HEIGHT,
                "bestblock": BESTBLOCK,
            },
            "expected": {"height": HEIGHT, "bestblock": BESTBLOCK},
            "controller_pre_receipt": pre_ref,
        }
        trial_bytes = module.canonical_json_bytes(trial_manifest)
        trial_ref = _write_file(self.root, f"trial-{index}.json", trial_bytes)
        raw = _raw_response(_state_map())
        duration = (index + 1) * 100 if kind == "core" else (index + 1) * 100 + 1
        observation: dict[str, object] = {
            **coordinates,
            "schema": module.OBSERVATION_SCHEMA,
            "input_sha256": module.canonical_sha256(trial_manifest),
            "controller_declaration_sha256": _sha256(pre_bytes),
            "query": {
                "method": "gettxoutsetinfo",
                "params": ["muhash", None, False],
                "use_index": False,
            },
            "request_sha256": _sha256(REQUEST_BODY),
            "http_status": 200,
            "raw_response_sha256": _sha256(raw),
            "raw_response_b64": base64.b64encode(raw).decode("ascii"),
            "duration_ns": duration,
            "monotonic_start_ns": self.next_start,
            "monotonic_end_ns": self.next_start + duration,
            "state": _state_map(),
        }
        observation["self_sha256"] = module.canonical_sha256(observation)
        self.next_start += duration + 1
        obs_ref = _write_file(
            self.root, f"obs-{index}.json", module.canonical_json_bytes(observation)
        )
        execution: dict[str, object] | None = None
        if (
            self.policy == "process-cold/page-cache-evicted"
            and self.procedure is not None
        ):
            execution = {
                "procedure_sha256": self.procedure["sha256"],
                "exit_status": 0,
                "monotonic_ns": 500,
            }
        post: dict[str, object] = {
            **coordinates,
            "schema": module.POST_RECEIPT_SCHEMA,
            "pre_receipt_sha256": pre_ref["sha256"],
            "observation_sha256": observation["self_sha256"],
            "attested_pid": pid,
            "attested_starttime": starttime,
            "proc_stat_after": {"minflt": 4, "majflt": 1},
            "proc_io_after": {
                "rchar": 15,
                "read_bytes": 25,
                "wchar": 33,
                "write_bytes": 41,
                "syscr": 3,
                "syscw": 2,
            },
            "faults_delta": {"minflt": 3, "majflt": 1},
            "io_delta": {"rchar": 5, "read_bytes": 5, "wchar": 3, "write_bytes": 1},
            "eviction_execution": execution,
        }
        post_ref = _write_file(
            self.root, f"post-{index}.json", module.canonical_json_bytes(post)
        )
        return {
            "trial_input": trial_ref,
            "pre_receipt": pre_ref,
            "observation": obs_ref,
            "post_receipt": post_ref,
        }

    @property
    def corpus(self) -> dict[str, object]:
        return {
            "identity": "frozen-tip",
            "file": {
                "path": str(self.root / "corpus.bin"),
                "sha256": _sha256(b"frozen-corpus"),
                "bytes": len(b"frozen-corpus"),
            },
            "height": HEIGHT,
            "bestblock": BESTBLOCK,
        }

    def manifest(self) -> dict[str, object]:
        return {
            "schema": module.AGGREGATE_INPUT_SCHEMA,
            "campaign_id": self.campaign,
            "policy": self.policy,
            "corpus": self.corpus,
            "triples": self.triples,
        }

    def write_manifest(self, manifest: dict[str, object] | None = None) -> Path:
        path = self.root / "aggregate-input.json"
        path.write_bytes(module.canonical_json_bytes(manifest or self.manifest()))
        return path

    def run(
        self,
        manifest: dict[str, object] | None = None,
        output_name: str = "result.json",
    ) -> tuple[int, str]:
        path = self.write_manifest(manifest)
        output_path = self.root / output_name
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = module.main(
                ["aggregate", "--input", str(path), "--output", str(output_path)]
            )
        return code, str(output_path)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def rewrite_triple(self, index: int, slot: str, value: dict[str, object]) -> None:
        reference = self.triples[index]
        assert _is_object(reference)
        old_path = Path(str(reference[slot]["path"]))
        old_path.unlink()
        new_ref = _write_file(
            self.root,
            f"{slot}-rewritten-{index}.json",
            module.canonical_json_bytes(value),
        )
        reference[slot] = new_ref

    def _read_evidence(self, index: int, slot: str) -> dict[str, object]:
        value = json.loads(
            Path(str(self.triples[index][slot]["path"])).read_text(),
            parse_float=Decimal,
            parse_int=int,
        )
        assert isinstance(value, dict)
        return value

    def rewrite_pre(self, index: int, mutation: object) -> None:
        pre = self._read_evidence(index, "pre_receipt")
        post = self._read_evidence(index, "post_receipt")
        trial = self._read_evidence(index, "trial_input")
        assert callable(mutation)
        mutation(pre, post)
        pre_ref = _write_file(
            self.root, f"pre-rewritten-{index}.json", module.canonical_json_bytes(pre)
        )
        trial["controller_pre_receipt"] = pre_ref
        trial_ref = _write_file(
            self.root,
            f"trial-rewritten-{index}.json",
            module.canonical_json_bytes(trial),
        )
        observation = self._read_evidence(index, "observation")
        observation["input_sha256"] = module.canonical_sha256(trial)
        observation["controller_declaration_sha256"] = pre_ref["sha256"]
        observation.pop("self_sha256")
        observation["self_sha256"] = module.canonical_sha256(observation)
        obs_ref = _write_file(
            self.root,
            f"obs-rewritten-{index}.json",
            module.canonical_json_bytes(observation),
        )
        post["pre_receipt_sha256"] = pre_ref["sha256"]
        post["observation_sha256"] = observation["self_sha256"]
        post_ref = _write_file(
            self.root, f"post-rewritten-{index}.json", module.canonical_json_bytes(post)
        )
        self.triples[index] = {
            "trial_input": trial_ref,
            "pre_receipt": pre_ref,
            "observation": obs_ref,
            "post_receipt": post_ref,
        }

    def rewrite_observation(self, index: int, mutation: object) -> None:
        observation = self._read_evidence(index, "observation")
        post = self._read_evidence(index, "post_receipt")
        assert callable(mutation)
        mutation(observation)
        raw = _raw_response(observation["state"])
        observation["raw_response_sha256"] = _sha256(raw)
        observation["raw_response_b64"] = base64.b64encode(raw).decode("ascii")
        observation.pop("self_sha256")
        observation["self_sha256"] = module.canonical_sha256(observation)
        obs_ref = _write_file(
            self.root,
            f"obs-rewritten-{index}.json",
            module.canonical_json_bytes(observation),
        )
        post["observation_sha256"] = observation["self_sha256"]
        post_ref = _write_file(
            self.root, f"post-rewritten-{index}.json", module.canonical_json_bytes(post)
        )
        self.triples[index]["observation"] = obs_ref
        self.triples[index]["post_receipt"] = post_ref

    def rewrite_trial_input(self, index: int, mutation: object) -> None:
        trial = self._read_evidence(index, "trial_input")
        assert callable(mutation)
        mutation(trial)
        trial_ref = _write_file(
            self.root,
            f"trial-tampered-{index}.json",
            module.canonical_json_bytes(trial),
        )
        self.triples[index]["trial_input"] = trial_ref


class AggregateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._environments: list[_AggregateEnv] = []

    def tearDown(self) -> None:
        for environment in self._environments:
            environment.cleanup()
        _sweep_base()

    def _environment(self, policy: str = "warm", **kwargs: object) -> _AggregateEnv:
        environment = _AggregateEnv(policy, **kwargs)  # type: ignore[arg-type]
        self._environments.append(environment)
        return environment

    def _load_result(self, path: str) -> dict[str, object]:
        value = json.loads(Path(path).read_text(), parse_float=Decimal, parse_int=int)
        assert isinstance(value, dict)
        return value

    def test_seven_alternating_pairs_produce_verdict(self) -> None:
        environment = self._environment()
        code, output_path = environment.run()
        self.assertEqual(code, 0)
        result = self._load_result(output_path)
        recorded = result.pop("result_sha256")
        self.assertEqual(module.canonical_sha256(result), recorded)
        self.assertEqual(len(result["triples"]), module.TRIPLE_COUNT)
        self.assertEqual(result["schema"], module.RESULT_SCHEMA)
        verdict = result["verdict"]
        assert _is_object(verdict)
        self.assertEqual(verdict["metric"], "nearest_rank_p50_ns")
        self.assertIn(verdict["outcome"], {"faster_arm", "tie"})
        frozen = result["frozen_state"]
        assert _is_object(frozen)
        self.assertEqual(frozen["height"], HEIGHT)
        self.assertEqual(frozen["muhash"], MUHASH)

    def test_missing_triple_is_refused(self) -> None:
        environment = self._environment()
        manifest = environment.manifest()
        manifest["triples"] = list(environment.triples)[:-1]
        code, _ = environment.run(manifest)
        self.assertEqual(code, 2)

    def test_reordered_triples_are_refused(self) -> None:
        environment = self._environment()
        manifest = environment.manifest()
        triples = list(manifest["triples"])
        triples[0], triples[1] = triples[1], triples[0]
        manifest["triples"] = triples
        code, _ = environment.run(manifest)
        self.assertEqual(code, 2)

    def test_duplicated_triple_is_refused(self) -> None:
        environment = self._environment()
        manifest = environment.manifest()
        triples = list(manifest["triples"])
        triples[1] = triples[0]
        manifest["triples"] = triples
        code, _ = environment.run(manifest)
        self.assertEqual(code, 2)

    def test_observation_self_hash_mismatch_is_refused(self) -> None:
        environment = self._environment()
        observation = json.loads(
            Path(str(environment.triples[3]["observation"]["path"])).read_text(),
            parse_float=Decimal,
            parse_int=int,
        )
        assert isinstance(observation, dict)
        observation["duration_ns"] += 1
        environment.rewrite_triple(3, "observation", observation)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_broken_pre_receipt_hash_edge_is_refused(self) -> None:
        environment = self._environment()
        post = json.loads(
            Path(str(environment.triples[5]["post_receipt"]["path"])).read_text(),
            parse_float=Decimal,
            parse_int=int,
        )
        assert isinstance(post, dict)
        post["pre_receipt_sha256"] = "9" * 64
        environment.rewrite_triple(5, "post_receipt", post)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_broken_observation_hash_edge_is_refused(self) -> None:
        environment = self._environment()
        post = json.loads(
            Path(str(environment.triples[5]["post_receipt"]["path"])).read_text(),
            parse_float=Decimal,
            parse_int=int,
        )
        assert isinstance(post, dict)
        post["observation_sha256"] = "8" * 64
        environment.rewrite_triple(5, "post_receipt", post)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_broken_trial_input_hash_edge_is_refused(self) -> None:
        environment = self._environment()

        def drift(trial: dict[str, object]) -> None:
            trial["timeout_seconds"] = "9"

        environment.rewrite_trial_input(1, drift)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_broken_request_hash_edge_is_refused(self) -> None:
        environment = self._environment()

        def wrong_request(observation: dict[str, object]) -> None:
            observation["request_sha256"] = "7" * 64

        environment.rewrite_observation(1, wrong_request)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_eviction_equal_to_observation_start_is_refused(self) -> None:
        environment = self._environment("process-cold/page-cache-evicted")
        post = environment._read_evidence(2, "post_receipt")
        observation = environment._read_evidence(2, "observation")
        start = observation["monotonic_start_ns"]
        assert isinstance(start, int)
        execution = post["eviction_execution"]
        assert isinstance(execution, dict)
        execution["monotonic_ns"] = start
        post["eviction_execution"] = execution
        environment.rewrite_triple(2, "post_receipt", post)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_eviction_after_observation_start_is_refused(self) -> None:
        environment = self._environment("process-cold/page-cache-evicted")
        post = environment._read_evidence(2, "post_receipt")
        execution = post["eviction_execution"]
        assert isinstance(execution, dict)
        execution["monotonic_ns"] = 500_000
        post["eviction_execution"] = execution
        environment.rewrite_triple(2, "post_receipt", post)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_embedded_raw_response_must_reproduce_state(self) -> None:
        environment = self._environment()
        observation = environment._read_evidence(4, "observation")
        state = observation["state"]
        assert isinstance(state, dict)
        state["transactions"] = 99
        observation["raw_response_sha256"] = _sha256(_raw_response(state))
        observation["raw_response_b64"] = base64.b64encode(_raw_response(state)).decode(
            "ascii"
        )
        observation.pop("self_sha256")
        observation["self_sha256"] = module.canonical_sha256(observation)
        post = environment._read_evidence(4, "post_receipt")
        post["observation_sha256"] = observation["self_sha256"]
        environment.rewrite_triple(4, "observation", observation)
        environment.rewrite_triple(4, "post_receipt", post)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_divergent_state_between_arms_is_refused(self) -> None:
        environment = self._environment()

        def diverge(observation: dict[str, object]) -> None:
            state = observation["state"]
            assert isinstance(state, dict)
            state["muhash"] = OTHER_MUHASH

        environment.rewrite_observation(1, diverge)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_decimal_value_parity_across_notation(self) -> None:
        environment = self._environment()

        def same_value(observation: dict[str, object]) -> None:
            state = observation["state"]
            assert isinstance(state, dict)
            state["total_amount"] = Decimal("12.50000000")

        environment.rewrite_observation(1, same_value)
        code, _ = environment.run()
        self.assertEqual(code, 0)

    def test_warm_policy_requires_stable_lifecycle(self) -> None:
        environment = self._environment()

        def restart(pre: dict[str, object], post: dict[str, object]) -> None:
            pre["attested_pid"] = 7777
            post["attested_pid"] = 7777

        environment.rewrite_pre(4, restart)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_process_cold_policy_requires_fresh_lifecycle(self) -> None:
        environment = self._environment("process-cold/page-cache-unspecified")

        def reuse(pre: dict[str, object], post: dict[str, object]) -> None:
            pre["attested_pid"] = 5001
            pre["attested_starttime"] = 1001
            post["attested_pid"] = 5001
            post["attested_starttime"] = 1001

        environment.rewrite_pre(6, reuse)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_process_cold_policy_accepts_fresh_lifecycles(self) -> None:
        environment = self._environment("process-cold/page-cache-unspecified")
        code, output_path = environment.run()
        self.assertEqual(code, 0)
        result = self._load_result(output_path)
        self.assertEqual(result["policy"], "process-cold/page-cache-unspecified")

    def test_overlapping_observation_interval_is_refused(self) -> None:
        environment = self._environment()

        def overlap(observation: dict[str, object]) -> None:
            observation["monotonic_start_ns"] = 500

        environment.rewrite_observation(1, overlap)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_reordered_observation_interval_is_refused(self) -> None:
        environment = self._environment()

        def move_before_prior(observation: dict[str, object]) -> None:
            observation["monotonic_start_ns"] = 300

        environment.rewrite_observation(7, move_before_prior)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_warm_policy_requires_distinct_arm_lifecycles(self) -> None:
        environment = self._environment("warm", rs_identity=(4242, 100))
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_process_cold_requires_campaign_wide_fresh_lifecycles(self) -> None:
        environment = self._environment(
            "process-cold/page-cache-unspecified", cold_reuse_core=True
        )
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_evicted_policy_requires_procedure_and_execution(self) -> None:
        environment = self._environment("process-cold/page-cache-evicted")

        def drop_procedure(pre: dict[str, object], post: dict[str, object]) -> None:
            del post
            pre["eviction_procedure"] = None

        environment.rewrite_pre(2, drop_procedure)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_evicted_policy_requires_execution_record(self) -> None:
        environment = self._environment("process-cold/page-cache-evicted")
        post = json.loads(
            Path(str(environment.triples[2]["post_receipt"]["path"])).read_text(),
            parse_float=Decimal,
            parse_int=int,
        )
        assert isinstance(post, dict)
        post["eviction_execution"] = None
        environment.rewrite_triple(2, "post_receipt", post)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_evicted_policy_accepts_complete_evidence(self) -> None:
        environment = self._environment("process-cold/page-cache-evicted")
        code, output_path = environment.run()
        self.assertEqual(code, 0)
        self.assertTrue(Path(output_path).exists())

    def test_shared_endpoint_between_arms_is_refused(self) -> None:
        environment = self._environment()

        def share(pre: dict[str, object], post: dict[str, object]) -> None:
            del post
            pre["endpoint"] = "http://127.0.0.1:28332/"

        for index in range(0, module.TRIPLE_COUNT, 2):
            environment.rewrite_pre(index, share)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_corpus_identity_drift_is_refused(self) -> None:
        environment = self._environment()

        def drift(pre: dict[str, object], post: dict[str, object]) -> None:
            del post
            corpus = pre["corpus"]
            assert isinstance(corpus, dict)
            corpus["identity"] = "other-tip"

        environment.rewrite_pre(7, drift)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_frozen_coordinate_disagreement_is_refused(self) -> None:
        environment = self._environment()

        def move_tip(pre: dict[str, object], post: dict[str, object]) -> None:
            del post
            pre["frozen_height"] = 839_999

        environment.rewrite_pre(9, move_tip)
        code, _ = environment.run()
        self.assertEqual(code, 2)

    def test_statistics_are_exact_nearest_rank(self) -> None:
        environment = self._environment()
        code, output_path = environment.run()
        self.assertEqual(code, 0)
        result = self._load_result(output_path)
        statistics = result["statistics"]
        assert _is_object(statistics)
        core = statistics["core-arm"]
        assert _is_object(core)
        self.assertEqual(core["p50_ns"], 800)
        self.assertEqual(core["p95_ns"], 1300)
        self.assertEqual(core["p99_ns"], 1300)
        self.assertEqual(core["max_ns"], 1300)
        rs = statistics["rs-arm"]
        assert _is_object(rs)
        self.assertEqual(rs["p50_ns"], 701)
        self.assertEqual(rs["max_ns"], 1401)
        verdict = result["verdict"]
        assert _is_object(verdict)
        self.assertEqual(verdict["outcome"], "faster_arm")
        self.assertEqual(verdict["faster_arm"], "rs-arm")
        self.assertNotIn("mean_ns", core)
        self.assertNotIn("mean_ns", rs)

    def test_tie_produces_null_faster_arm(self) -> None:
        environment = self._environment()

        def flatten_at(index: int) -> object:
            def flatten(observation: dict[str, object]) -> None:
                # Equal durations with a rebuilt sequential schedule: the
                # p50 tie survives while intervals stay non-overlapping.
                observation["duration_ns"] = 500
                observation["monotonic_start_ns"] = 1_000 + index * 501
                observation["monotonic_end_ns"] = 1_000 + index * 501 + 500

            return flatten

        for index in range(module.TRIPLE_COUNT):
            environment.rewrite_observation(index, flatten_at(index))
        code, output_path = environment.run()
        self.assertEqual(code, 0)
        verdict = self._load_result(output_path)["verdict"]
        assert _is_object(verdict)
        self.assertEqual(verdict["outcome"], "tie")
        self.assertIsNone(verdict["faster_arm"])

    def test_pre_existing_output_is_never_clobbered(self) -> None:
        environment = self._environment()
        output_path = environment.root / "result.json"
        output_path.write_bytes(b"existing\n")
        code, _ = environment.run()
        self.assertEqual(code, 2)
        self.assertEqual(output_path.read_bytes(), b"existing\n")
        leftovers = [p.name for p in environment.root.glob(".*result.json*")]
        self.assertEqual(leftovers, [])

    def test_untrusted_writable_ancestor_is_refused(self) -> None:
        environment = self._environment()
        environment.write_manifest()
        # Other-writable: any user may rename the next component.
        shared = environment.root / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        victim = shared / "victim"
        victim.mkdir()
        victim.chmod(0o700)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = module.main(
                [
                    "aggregate",
                    "--input",
                    str(environment.root / "aggregate-input.json"),
                    "--output",
                    str(victim / "result.json"),
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("untrusted renames", stderr.getvalue())

    def test_shared_group_ancestor_is_refused(self) -> None:
        environment = self._environment()
        environment.write_manifest()
        # Group-writable: even the owner's own primary group is not a
        # trust boundary; any member may rename the next component.
        shared = environment.root / "shared-group"
        shared.mkdir()
        shared.chmod(0o770)
        victim = shared / "victim"
        victim.mkdir()
        victim.chmod(0o700)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = module.main(
                [
                    "aggregate",
                    "--input",
                    str(environment.root / "aggregate-input.json"),
                    "--output",
                    str(victim / "result.json"),
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("untrusted renames", stderr.getvalue())
        self.assertFalse((victim / "result.json").exists())

    def test_shared_group_final_parent_is_refused(self) -> None:
        environment = self._environment()
        environment.write_manifest()
        output = environment.root / "shared-parent"
        output.mkdir()
        output.chmod(0o770)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = module.main(
                [
                    "aggregate",
                    "--input",
                    str(environment.root / "aggregate-input.json"),
                    "--output",
                    str(output / "result.json"),
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("not writable by untrusted users", stderr.getvalue())
        self.assertFalse((output / "result.json").exists())

    def test_hostile_arm_id_never_reaches_stderr(self) -> None:
        hostile = "secret-7f3a9c-\x1b[31m\n" + "A" * 300
        environment = self._environment("warm", core_arm_id=hostile)

        def restart(pre: dict[str, object], post: dict[str, object]) -> None:
            pre["attested_pid"] = 7777
            post["attested_pid"] = 7777

        environment.rewrite_pre(4, restart)
        output = environment.root / "hostile.json"
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = module.main(
                [
                    "aggregate",
                    "--input",
                    str(environment.write_manifest()),
                    "--output",
                    str(output),
                ]
            )
        message = stderr.getvalue()
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())
        self.assertLess(len(message), 200)
        self.assertNotIn("secret-7f3a9c-", message)
        self.assertNotIn("\x1b[31m", message)
        self.assertNotIn("A" * 20, message)
        self.assertNotIn("\n", message.rstrip("\n"))

    def test_parent_rebind_during_publication_is_refused(self) -> None:
        environment = self._environment()
        environment.write_manifest()
        output = environment.root / "rebound.json"
        original_open_trusted = module._open_trusted_dir
        calls = {"count": 0}

        def rebinding_open_trusted(candidate: Path) -> int:
            calls["count"] += 1
            if calls["count"] == 2:
                # An attacker renames the approved parent away between the
                # first traversal and the pre-link identity re-check; the
                # requested pathname now resolves elsewhere (here: nowhere).
                moved = environment.root.parent / "rebind-moved"
                if not moved.exists():
                    os.rename(environment.root, moved)
                    environment.root = moved
            return original_open_trusted(candidate)

        module._open_trusted_dir = rebinding_open_trusted  # type: ignore[assignment]
        try:
            code = module.main(
                [
                    "aggregate",
                    "--input",
                    str(environment.root / "aggregate-input.json"),
                    "--output",
                    str(output),
                ]
            )
        finally:
            module._open_trusted_dir = original_open_trusted  # type: ignore[assignment]
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())

    def test_symlink_parent_is_refused(self) -> None:
        environment = self._environment()
        environment.write_manifest()
        link = environment.root / "linked"
        link.symlink_to(environment.root, target_is_directory=True)
        code = module.main(
            [
                "aggregate",
                "--input",
                str(environment.root / "aggregate-input.json"),
                "--output",
                str(link / "result.json"),
            ]
        )
        self.assertEqual(code, 2)

    def test_foreign_temp_file_cannot_substitute_result(self) -> None:
        environment = self._environment()
        attacker_file = environment.root / ".result.json.attacker.tmp"
        attacker_file.write_bytes(b'{"forged": true}')
        code, output_path = environment.run()
        self.assertEqual(code, 0)
        published = json.loads(Path(output_path).read_text())
        self.assertIsInstance(published, dict)
        self.assertEqual(published.get("schema"), module.RESULT_SCHEMA)
        self.assertEqual(attacker_file.read_bytes(), b'{"forged": true}')

    def test_successful_publication_leaves_no_temporary_file(self) -> None:
        environment = self._environment()
        code, _ = environment.run()
        self.assertEqual(code, 0)
        leftovers = [p.name for p in environment.root.glob(".*.tmp")]
        self.assertEqual(leftovers, [])

    def _run_with_post_link_fault(
        self, environment: _AggregateEnv, fault: object
    ) -> tuple[int, Path]:
        # The fault arms only after linkat succeeds, so the test exercises
        # post-link rollback, not pre-link refusal.
        output = environment.root / "rollback.json"
        original_link = module._link_tmpfile
        original_function = getattr(module.os, fault["name"])

        def linking(fd: int, dir_fd: int, name: str) -> None:
            original_link(fd, dir_fd, name)
            setattr(module.os, fault["name"], fault["poison"])  # type: ignore[arg-type]

        module._link_tmpfile = linking  # type: ignore[arg-type]
        try:
            code = module.main(
                [
                    "aggregate",
                    "--input",
                    str(environment.write_manifest()),
                    "--output",
                    str(output),
                ]
            )
        finally:
            module._link_tmpfile = original_link  # type: ignore[arg-type]
            setattr(module.os, fault["name"], original_function)  # type: ignore[arg-type]
        return code, output

    def test_post_link_stat_failure_rolls_back_output(self) -> None:
        environment = self._environment()
        original_stat = module.os.stat

        def poisoned_stat(path: object, **kwargs: object) -> os.stat_result:
            # Fail the final-path verification stat; the rollback's own
            # no-follow stat (follow_symlinks=False) must stay functional
            # so cleanup can confirm and remove the linked inode.
            if kwargs.get("follow_symlinks") is False:
                return original_stat(path, **kwargs)  # type: ignore[arg-type]
            raise OSError(errno.EIO, "injected final stat failure")

        code, output = self._run_with_post_link_fault(
            environment, {"name": "stat", "poison": poisoned_stat}
        )
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())

    def test_post_link_fsync_failure_rolls_back_output(self) -> None:
        environment = self._environment()

        def poisoned_fsync(fd: int) -> None:
            raise OSError(errno.EIO, "injected directory fsync failure")

        # The poison arms only after linkat, so the pre-link inode fsync
        # runs clean and the post-link directory fsync is the failure.
        code, output = self._run_with_post_link_fault(
            environment, {"name": "fsync", "poison": poisoned_fsync}
        )
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())

    def test_substituted_output_is_never_removed(self) -> None:
        environment = self._environment()
        output = environment.root / "substituted.json"
        original_link = module._link_tmpfile

        def linking(fd: int, dir_fd: int, name: str) -> None:
            original_link(fd, dir_fd, name)
            # An attacker replaces the comparator-owned name before the
            # final verification stat runs.
            output.unlink()
            output.write_bytes(b'{"forged": true}')

        module._link_tmpfile = linking  # type: ignore[arg-type]
        try:
            code = module.main(
                [
                    "aggregate",
                    "--input",
                    str(environment.write_manifest()),
                    "--output",
                    str(output),
                ]
            )
        finally:
            module._link_tmpfile = original_link  # type: ignore[arg-type]
        self.assertEqual(code, 2)
        self.assertEqual(output.read_bytes(), b'{"forged": true}')

    def test_alternation_parity(self) -> None:
        self.assertEqual(module.trial_order(0), ("core", "bitcoin-rs"))
        self.assertEqual(module.trial_order(1), ("bitcoin-rs", "core"))
        self.assertEqual(module.trial_order(6), ("core", "bitcoin-rs"))


class PureHelperTests(unittest.TestCase):
    def test_canonical_hash_preserves_decimal_values(self) -> None:
        left = {"a": Decimal("12.50000000"), "list": [1, Decimal("0.0100")]}
        right = {"a": Decimal("12.5"), "list": [1, Decimal("0.01")]}
        self.assertEqual(module.canonical_sha256(left), module.canonical_sha256(right))

    def test_canonical_hash_preserves_key_order_independence(self) -> None:
        self.assertEqual(
            module.canonical_sha256({"a": 1, "z": 2}),
            module.canonical_sha256({"z": 2, "a": 1}),
        )

    def test_nearest_rank_is_exact_not_interpolated(self) -> None:
        samples = [70, 10, 60, 20, 50, 30, 40]
        self.assertEqual(module.nearest_rank(samples, 50), 40)
        self.assertEqual(module.nearest_rank(samples, 95), 70)
        self.assertEqual(module.nearest_rank(samples, 99), 70)

    def test_nearest_rank_rejects_empty_and_bad_percentiles(self) -> None:
        with self.assertRaises(module.ContractError):
            module.nearest_rank([], 50)
        with self.assertRaises(module.ContractError):
            module.nearest_rank([1], 0)
        with self.assertRaises(module.ContractError):
            module.nearest_rank([1], 101)

    def test_stats_require_exactly_seven_samples(self) -> None:
        with self.assertRaises(module.ContractError):
            module._stats([1, 2, 3])
        stats = module._stats([1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(stats["p50_ns"], 4)
        self.assertEqual(stats["max_ns"], 7)

    def test_endpoint_validation_rejects_dns_names(self) -> None:
        with self.assertRaises(module.ContractError):
            module._validate_endpoint("http://localhost:8332/", "endpoint")

    def test_endpoint_validation_requires_http(self) -> None:
        with self.assertRaises(module.ContractError):
            module._validate_endpoint("https://127.0.0.1:8332/", "endpoint")

    def test_amount_bounds_reject_out_of_domain_values(self) -> None:
        self.assertEqual(module._amount(Decimal("12.50000000"), "x"), Decimal("12.5"))
        self.assertEqual(module._amount(0, "x"), Decimal(0))
        self.assertEqual(module._amount(Decimal(21_000_000), "x"), Decimal(21_000_000))
        for bad in (
            Decimal("1e999999999"),
            Decimal("1e-999999999"),
            Decimal("0.000000001"),
            Decimal("21000000.00000001"),
            Decimal(-1),
        ):
            with self.assertRaises(module.ContractError):
                module._amount(bad, "x")

    def test_duplicate_keys_are_rejected_at_every_level(self) -> None:
        with self.assertRaises(module.ContractError):
            module._parse_json(b'{"a": 1, "a": 2}', "x")
        with self.assertRaises(module.ContractError):
            module._parse_json(b'{"a": {"b": 1, "b": 2}}', "x")

    def test_trial_help_and_aggregate_help_exit_zero(self) -> None:
        for command in ("trial", "aggregate", "campaign"):
            with self.assertRaises(SystemExit) as raised:
                module.main([command, "--help"])
            self.assertEqual(raised.exception.code, 0)


FIXTURE_DAEMON = r"""#!/usr/bin/env python3
import argparse
import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn


class ReuseHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--cookie", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--data-dir", required=True)
    args = parser.parse_args()
    Path(args.data_dir).mkdir(parents=True, exist_ok=True)
    cookie = Path(args.cookie).read_bytes().rstrip(b"\r\n")
    expected_auth = "Basic " + base64.b64encode(cookie).decode("ascii")
    state = json.loads(Path(args.config).read_text())
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "error": None, "result": state},
        separators=(",", ":"),
    ).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            if self.headers.get("Authorization") != expected_auth:
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            try:
                request = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                request = {}
            params = request.get("params") if isinstance(request, dict) else None
            ok = (
                isinstance(request, dict)
                and request.get("method") == "gettxoutsetinfo"
                and params == ["muhash", None, False]
            )
            body = payload if ok else b'{"jsonrpc":"2.0","id":1,"error":{"code":-8,"message":"wrong query"},"result":null}'
            self.close_connection = True
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    server = ReuseHTTPServer((args.bind, args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
"""


class CampaignControllerTests(unittest.TestCase):
    def tearDown(self) -> None:
        _sweep_base()

    def _state_bytes(self, muhash: str = MUHASH) -> bytes:
        return module.canonical_json_bytes(
            {
                "height": HEIGHT,
                "bestblock": BESTBLOCK,
                "transactions": 1,
                "txouts": 2,
                "bogosize": 300,
                "disk_size": 400,
                "total_amount": Decimal("12.5"),
                "muhash": muhash,
            }
        )

    def _write_daemon(self, root: Path) -> dict[str, object]:
        path = root / "fixture-daemon.py"
        path.write_bytes(FIXTURE_DAEMON.encode())
        path.chmod(0o700)
        return {
            "path": str(path),
            "sha256": _sha256(FIXTURE_DAEMON.encode()),
            "bytes": len(FIXTURE_DAEMON.encode()),
        }

    def _campaign_files(
        self,
        *,
        backend: str = "fjall",
        policy: str = "warm",
        candidate_muhash: str = MUHASH,
        evict: bool = False,
    ) -> tuple[Path, Path, Path]:
        root = _make_root("muhash-campaign-")
        daemon = self._write_daemon(root)
        corpus = _write_file(root, "corpus.bin", b"frozen-corpus")
        cookie = _write_file(
            root,
            "rpc.cookie",
            f"bench-user:{CREDENTIAL_SECRET}".encode(),
            private=True,
        )
        core_config = _write_file(root, "core-state.json", self._state_bytes())
        rs_config = _write_file(
            root, "rs-state.json", self._state_bytes(candidate_muhash)
        )
        command = [
            "{binary}",
            "--bind",
            "{rpc_bind}",
            "--port",
            "{rpc_port}",
            "--cookie",
            "{cookie}",
            "--config",
            "{config}",
            "--data-dir",
            "{data_dir}",
        ]
        eviction = None
        if evict:
            script = root / "evict.sh"
            script.write_bytes(b"#!/bin/sh\nexit 0\n")
            script.chmod(0o700)
            eviction = {
                "path": str(script),
                "sha256": _sha256(b"#!/bin/sh\nexit 0\n"),
                "bytes": len(b"#!/bin/sh\nexit 0\n"),
            }

        def arm(
            arm_id: str,
            kind_backend: str,
            config: dict[str, object],
            datadir: Path,
        ) -> dict[str, object]:
            return {
                "arm_id": arm_id,
                "binary": daemon["path"],
                "binary_sha256": daemon["sha256"],
                "command": command,
                "backend": kind_backend,
                "config": config,
                "datadir": str(datadir),
            }

        config = {
            "schema": module.CAMPAIGN_CONFIG_SCHEMA,
            "campaign_id": f"camp-{backend}",
            "policy": policy,
            "corpus": {
                "identity": "frozen-tip",
                "file": corpus,
                "height": HEIGHT,
                "bestblock": BESTBLOCK,
            },
            "expected": {"height": HEIGHT, "bestblock": BESTBLOCK},
            "timeout_seconds": Decimal("5"),
            "max_response_bytes": 65_536,
            "credential_file": cookie,
            "affinity": "0-3",
            "core": arm("core-arm", "coinsdb", core_config, root / "core-data"),
            "candidate": arm(
                "rs-arm", backend, rs_config, root / "rs-data"
            ),
            "eviction_procedure": eviction,
        }
        config_path = root / "campaign.json"
        config_path.write_bytes(module.canonical_json_bytes(config))
        return root, config_path, root / "result.json"

    def _run(
        self,
        backend: str = "fjall",
        policy: str = "warm",
        candidate_muhash: str = MUHASH,
        evict: bool = False,
    ) -> tuple[int, Path, Path]:
        root, config_path, output = self._campaign_files(
            backend=backend,
            policy=policy,
            candidate_muhash=candidate_muhash,
            evict=evict,
        )
        workspace = root / "work"
        workspace.mkdir()
        code = module.main(
            [
                "campaign",
                "--input",
                str(config_path),
                "--output",
                str(output),
                "--workspace",
                str(workspace),
            ]
        )
        return code, output, workspace

    def test_warm_campaign_agrees_across_all_backends(self) -> None:
        # Contract clause: docs/contracts/muhash-rpc.md MRPC-03.
        frozen: object | None = None
        for backend in sorted(module.BITCOIN_RS_BACKENDS):
            code, output, workspace = self._run(backend=backend, policy="warm")
            self.assertEqual(code, 0, backend)
            self.assertEqual(
                _sha256((workspace / "core-config").read_bytes()),
                _sha256(self._state_bytes()),
            )
            self.assertEqual(
                _sha256((workspace / "candidate-config").read_bytes()),
                _sha256(self._state_bytes()),
            )
            result = json.loads(output.read_bytes(), parse_float=Decimal, parse_int=int)
            self.assertEqual(result["schema"], module.RESULT_SCHEMA)
            self.assertEqual(result["policy"], "warm")
            self.assertEqual(
                result["query"],
                {
                    "method": "gettxoutsetinfo",
                    "params": ["muhash", None, False],
                    "use_index": False,
                },
            )
            backends = {arm["backend"] for arm in result["arms"]}
            self.assertEqual(backends, {"coinsdb", backend})
            self.assertEqual(result["frozen_state"]["muhash"], MUHASH)
            self.assertEqual(result["frozen_state"]["height"], HEIGHT)
            self.assertEqual(len(result["triples"]), 14)
            if frozen is None:
                frozen = result["frozen_state"]
            else:
                self.assertEqual(result["frozen_state"], frozen)

    def test_process_cold_campaign_uses_fresh_identities(self) -> None:
        code, output, workspace = self._run(
            backend="fjall", policy="process-cold/page-cache-unspecified"
        )
        self.assertEqual(code, 0)
        result = json.loads(output.read_bytes())
        self.assertEqual(result["policy"], "process-cold/page-cache-unspecified")
        identities: set[tuple[int, int]] = set()
        for path in sorted(workspace.glob("*-pre.json")):
            receipt = json.loads(path.read_bytes())
            identities.add((receipt["attested_pid"], receipt["attested_starttime"]))
        self.assertEqual(len(identities), 14)

    def test_evicted_campaign_binds_procedure_execution(self) -> None:
        code, output, workspace = self._run(
            backend="redb",
            policy="process-cold/page-cache-evicted",
            evict=True,
        )
        self.assertEqual(code, 0)
        result = json.loads(output.read_bytes())
        self.assertEqual(result["policy"], "process-cold/page-cache-evicted")
        for path in sorted(workspace.glob("*-post.json")):
            receipt = json.loads(path.read_bytes())
            execution = receipt["eviction_execution"]
            self.assertEqual(execution["exit_status"], 0)
            self.assertGreater(execution["monotonic_ns"], 0)

    def test_diverged_backend_state_is_refused(self) -> None:
        code, output, _workspace = self._run(
            backend="rocksdb", candidate_muhash=OTHER_MUHASH
        )
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())

    def test_candidate_backend_must_be_a_storage_engine(self) -> None:
        root, config_path, _output = self._campaign_files()
        parsed, _ = module._load_json_path(
            config_path, module.MAX_INPUT_BYTES, "campaign config"
        )
        assert isinstance(parsed, dict)
        candidate = parsed["candidate"]
        assert isinstance(candidate, dict)
        candidate["backend"] = "coinsdb"
        with self.assertRaises(module.ContractError):
            module._parse_campaign_config(parsed)
        del root

    def test_core_backend_must_be_coinsdb(self) -> None:
        _root, config_path, _output = self._campaign_files()
        parsed, _ = module._load_json_path(
            config_path, module.MAX_INPUT_BYTES, "campaign config"
        )
        assert isinstance(parsed, dict)
        core = parsed["core"]
        assert isinstance(core, dict)
        core["backend"] = "fjall"
        with self.assertRaises(module.ContractError):
            module._parse_campaign_config(parsed)

    def test_command_must_include_config_placeholder(self) -> None:
        # Contract clause: docs/contracts/muhash-rpc.md MRPC-03.
        _root, config_path, _output = self._campaign_files()
        parsed, _ = module._load_json_path(
            config_path, module.MAX_INPUT_BYTES, "campaign config"
        )
        assert isinstance(parsed, dict)
        candidate = parsed["candidate"]
        assert isinstance(candidate, dict)
        command = list(candidate["command"])  # type: ignore[arg-type]
        command[command.index("{config}")] = str(_root / "other.json")
        candidate["command"] = command
        with self.assertRaises(module.ContractError):
            module._parse_campaign_config(parsed)

    def test_readiness_rejects_a_listener_the_child_does_not_own(self) -> None:
        # Contract clause: docs/contracts/muhash-rpc.md MRPC-02.
        decoy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        decoy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        decoy.bind(("127.0.0.1", 0))
        decoy.listen()
        port = int(decoy.getsockname()[1])
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            with self.assertRaises(module.ContractError) as raised:
                module._wait_owned_endpoint(
                    child, port, time.perf_counter_ns() + 2_000_000_000
                )
            self.assertIn("not owned", str(raised.exception))
        finally:
            child.kill()
            child.wait(timeout=2)
            decoy.close()

    def test_rpc_does_not_send_credentials_to_a_foreign_peer(self) -> None:
        # Contract clause: docs/contracts/muhash-rpc.md MRPC-02.
        spy = _FixtureServer("ok", _state_literal())
        thread = spy.start()
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            with self.assertRaises(module.ContractError) as raised:
                module._rpc_once(
                    spy.endpoint,
                    ("bench-user", CREDENTIAL_SECRET),
                    Decimal("2"),
                    65_536,
                    HEIGHT,
                    BESTBLOCK,
                    child.pid,
                    module._read_starttime(child.pid),
                )
            self.assertRegex(str(raised.exception), r"not owned|never owned")
            self.assertEqual(spy.requests, [])
        finally:
            child.kill()
            child.wait(timeout=2)
            spy.shutdown()
            spy.server_close()
            thread.join(timeout=5)

    def test_pinned_config_copy_ignores_later_operator_path_writes(self) -> None:
        # Contract clause: docs/contracts/muhash-rpc.md MRPC-03.
        root = _make_root("muhash-config-copy-")
        source = root / "operator.json"
        source.write_bytes(b"pinned-config")
        digest = _sha256(b"pinned-config")
        destination = root / "workspace-config"
        module._copy_pinned_file(
            source,
            digest,
            destination,
            cap=module.MAX_RECEIPT_BYTES,
            mode=0o400,
            field="arm config",
        )
        source.write_bytes(b"replaced-config")
        module._rehash_copy(
            destination, digest, module.MAX_RECEIPT_BYTES, "arm config copy"
        )
        with self.assertRaises(module.ContractError):
            module._rehash_copy(
                source, digest, module.MAX_RECEIPT_BYTES, "operator config"
            )
        shutil.rmtree(root, ignore_errors=True)

    def test_verified_config_inode_survives_workspace_path_replace(self) -> None:
        # Contract clause: docs/contracts/muhash-rpc.md MRPC-03.
        root = _make_root("muhash-config-inode-")
        path = root / "workspace-config"
        path.write_bytes(b"pinned-config")
        digest = _sha256(b"pinned-config")
        descriptor = module._open_verified_inode(
            path, digest, module.MAX_RECEIPT_BYTES, "arm config copy"
        )
        try:
            replacement = root / "attacker-config"
            replacement.write_bytes(b"replaced-config")
            os.replace(replacement, path)
            self.assertEqual(path.read_bytes(), b"replaced-config")
            self.assertEqual(
                Path(f"/proc/self/fd/{descriptor}").read_bytes(), b"pinned-config"
            )
        finally:
            os.close(descriptor)
        shutil.rmtree(root, ignore_errors=True)

    def test_spawn_reads_verified_config_after_workspace_replace(self) -> None:
        # Contract clause: docs/contracts/muhash-rpc.md MRPC-03.
        root = _make_root("muhash-spawn-inode-")
        datadir = root / "data"
        datadir.mkdir()
        cookie = root / "rpc.cookie"
        cookie.write_bytes(b"bench-user:secret")
        cookie.chmod(0o600)
        pinned = b'{"ok": true}'
        config = root / "workspace-config"
        config.write_bytes(pinned)
        script = b"""#!/usr/bin/env python3
import argparse, hashlib, time
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument("--bind")
parser.add_argument("--port", type=int)
parser.add_argument("--cookie")
parser.add_argument("--config", required=True)
parser.add_argument("--data-dir", required=True)
args = parser.parse_args()
Path(args.data_dir).mkdir(parents=True, exist_ok=True)
digest = hashlib.sha256(Path(args.config).read_bytes()).hexdigest()
(Path(args.data_dir) / "seen").write_text(digest)
time.sleep(30)
"""
        daemon = root / "node.py"
        daemon.write_bytes(script)
        daemon.chmod(0o700)
        spec = module.ArmSpec(
            "core",
            "core-arm",
            daemon,
            _sha256(script),
            (
                "{binary}",
                "--bind",
                "{rpc_bind}",
                "--port",
                "{rpc_port}",
                "--cookie",
                "{cookie}",
                "--config",
                "{config}",
                "--data-dir",
                "{data_dir}",
            ),
            "coinsdb",
            module.FileRef(config, _sha256(pinned), len(pinned)),
            datadir,
        )
        arm = module._ArmProcess(
            spec,
            daemon,
            config,
            cookie,
            1,
            ("bench-user", "secret"),
            Decimal("1"),
            1024,
            1,
            "aa" * 32,
        )
        replacement = root / "attacker-config"
        replacement.write_bytes(b'{"ok": false}')
        real_popen = module.subprocess.Popen

        def hijack(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            os.replace(replacement, config)
            return real_popen(*args, **kwargs)

        previous_timeout = module.ARM_READY_TIMEOUT_NS
        module.ARM_READY_TIMEOUT_NS = 200_000_000
        module.subprocess.Popen = hijack  # type: ignore[method-assign]
        try:
            with self.assertRaises(module.ContractError):
                arm.spawn()
        finally:
            module.subprocess.Popen = real_popen  # type: ignore[method-assign]
            module.ARM_READY_TIMEOUT_NS = previous_timeout
            arm.terminate()
        self.assertEqual((datadir / "seen").read_text(), _sha256(pinned))
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
