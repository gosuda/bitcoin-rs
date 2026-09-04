#!/usr/bin/env python3.14
# pyright: strict
"""Behavioral tests for the offline full-validation comparator."""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import TypeIs

sys.path.insert(0, str(Path(__file__).parent))

import offline_full_validation as offline
from offline_full_validation import (
    CONFIG_SCHEMA,
    MANIFEST_SCHEMA,
    PAIR_COUNT,
    RESULT_SCHEMA,
    CertifiedState,
    ContractError,
    canonical_bytes,
    canonical_sha256,
    header_hash,
    load_config,
    main,
    parse_config,
    run_campaign,
    state_json,
    summarize,
)

JsonObject = dict[str, object]
MAGIC = "f9beb4d9"
HASH64 = "ab" * 32
OUTPUT_NAME = Path("out") / "result.json"


def _is_object(value: object) -> TypeIs[JsonObject]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _object(value: object) -> JsonObject:
    if not _is_object(value):
        raise TypeError("expected JSON object")
    return value


def _write_executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record(payload: bytes, magic: bytes = bytes.fromhex(MAGIC)) -> bytes:
    return magic + len(payload).to_bytes(4, "little") + payload


def _payload(marker: int) -> bytes:
    return bytes([marker]) * 80 + bytes([marker])


def _state(
    *,
    height: int = 1,
    bestblock: str | None = None,
    txouts: int = 2,
) -> CertifiedState:
    return CertifiedState(
        height,
        bestblock or HASH64,
        txouts,
        5_000_000_000,
        "cd" * 32,
        "ef" * 32,
        True,
        True,
    )


def _node_source(expected: CertifiedState, *, reopen: bool = False) -> str:
    payload = json.dumps(state_json(expected), sort_keys=True)
    reopen_flag = "True" if reopen else "False"
    return f"""#!{sys.executable}
import argparse, json, sys
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--data-dir', required=True)
parser.add_argument('--corpus', required=True)
parser.add_argument('--manifest', required=True)
parser.add_argument('--state', required=True)
parser.add_argument('--assume-valid-height', default='0')
parser.add_argument('--reopen', action='store_true')
args = parser.parse_args()
corpus = Path(args.corpus).read_bytes()
if not corpus:
    raise SystemExit(3)
data = Path(args.data_dir)
if {reopen_flag} and args.reopen:
    marker = data / 'imported'
    if not marker.is_file():
        raise SystemExit(4)
else:
    (data / 'imported').write_bytes(corpus)
Path(args.state).write_text({payload!r} + '\\n', encoding='utf-8')
raise SystemExit(0)
"""


def _command(*, reopen: bool = False) -> list[str]:
    command = [
        "{binary}",
        "--data-dir",
        "{data_dir}",
        "--corpus",
        "{corpus_path}",
        "--manifest",
        "{manifest_path}",
        "--state",
        "{state_path}",
        "--assume-valid-height=0",
    ]
    if reopen:
        command.append("--reopen")
    return command


def _build_workspace(root: Path, *, reopen: bool = False) -> tuple[Path, CertifiedState]:
    payloads = (_payload(1), _payload(2))
    records = [_record(payload) for payload in payloads]
    archive_bytes = b"".join(records)
    archive_path = root / "blocks.dat"
    archive_path.write_bytes(archive_bytes)
    hashes = [header_hash(payload) for payload in payloads]
    offset = 0
    entries: list[JsonObject] = []
    for height, (payload, digest, record) in enumerate(
        zip(payloads, hashes, records, strict=True)
    ):
        entries.append(
            {
                "height": height,
                "hash": digest,
                "offset": offset,
                "payload_length": len(payload),
            }
        )
        offset += len(record)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "network": "mainnet",
        "network_magic": MAGIC,
        "start_height": 0,
        "stop_height": 1,
        "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "archive_bytes": len(archive_bytes),
        "blocks": entries,
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_bytes(canonical_bytes(manifest) + b"\n")
    expected = _state(height=1, bestblock=hashes[-1])
    node = _write_executable(root / "node.py", _node_source(expected, reopen=reopen))
    digest = _sha256_file(node)

    def program() -> JsonObject:
        return {
            "binary": str(node),
            "binary_sha256": digest,
            "command": _command(),
            "reopen_command": _command(reopen=True) if reopen else None,
        }

    config = {
        "schema": CONFIG_SCHEMA,
        "network_magic": MAGIC,
        "arm_timeout_ns": 10_000_000_000,
        "posture": {
            "assume_valid": False,
            "txindex": False,
            "blockfilterindex": False,
            "coinstatsindex": False,
            "cache_policy": "process-cold/page-cache-unspecified",
        },
        "corpus": {
            "archive": {
                "path": str(archive_path),
                "sha256": hashlib.sha256(archive_bytes).hexdigest(),
                "bytes": len(archive_bytes),
            },
            "manifest": {
                "path": str(manifest_path),
                "sha256": _sha256_file(manifest_path),
                "bytes": manifest_path.stat().st_size,
            },
        },
        "expected_state": state_json(expected),
        "core": program(),
        "candidate": program(),
        "lifecycle": {
            "mode": "reopen" if reopen else "fresh",
            "expected_reopen_state": state_json(expected) if reopen else None,
        },
    }
    config_path = root / "config.json"
    config_path.write_bytes(canonical_bytes(config) + b"\n")
    return config_path, expected


class ArchiveContractTests(unittest.TestCase):
    def test_header_hash_is_reversed_double_sha256(self) -> None:
        payload = _payload(9)
        digest = hashlib.sha256(hashlib.sha256(payload[:80]).digest()).digest()
        self.assertEqual(header_hash(payload), digest[::-1].hex())

    def test_header_hash_matches_published_mainnet_genesis(self) -> None:
        # 80-byte header from Bitcoin Core CMainParams / bitcoin-rs MAINNET_GENESIS.
        header = bytes.fromhex(
            "01000000"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
            "29ab5f49"
            "ffff001d"
            "1dac2b7c"
        )
        self.assertEqual(len(header), 80)
        self.assertEqual(
            header_hash(header),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )

    def test_trailing_bytes_are_refused(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-trailing-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        archive = root / "blocks.dat"
        archive.write_bytes(archive.read_bytes() + b"\x00")
        with self.assertRaises(ContractError):
            load_config(config_path)

    def test_magic_mismatch_is_refused(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-magic-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        archive = root / "blocks.dat"
        raw = bytearray(archive.read_bytes())
        raw[0:4] = b"\x00\x00\x00\x00"
        archive.write_bytes(raw)
        with self.assertRaises(ContractError):
            load_config(config_path)

    def test_header_hash_mismatch_is_refused(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-hash-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        manifest_path = root / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["blocks"][0]["hash"] = HASH64
        manifest_path.write_bytes(canonical_bytes(manifest) + b"\n")
        config = json.loads(config_path.read_text())
        config["corpus"]["manifest"]["sha256"] = _sha256_file(manifest_path)
        config["corpus"]["manifest"]["bytes"] = manifest_path.stat().st_size
        config_path.write_bytes(canonical_bytes(config) + b"\n")
        with self.assertRaises(ContractError):
            load_config(config_path)


class ConfigContractTests(unittest.TestCase):
    def test_assume_valid_is_refused(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-assume-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        config = json.loads(config_path.read_text())
        config["posture"]["assume_valid"] = True
        with self.assertRaises(ContractError):
            parse_config(config)

    def test_txindex_on_is_refused(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-txindex-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        config = json.loads(config_path.read_text())
        config["posture"]["txindex"] = True
        with self.assertRaises(ContractError):
            parse_config(config)

    def test_evicted_cache_policy_is_refused(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-evict-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        config = json.loads(config_path.read_text())
        config["posture"]["cache_policy"] = "process-cold/page-cache-evicted"
        with self.assertRaises(ContractError):
            parse_config(config)

    def test_timed_command_must_disable_assume_valid(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-assume-token-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        config = json.loads(config_path.read_text())
        config["core"]["command"] = [
            part
            for part in config["core"]["command"]
            if part != "--assume-valid-height=0"
        ]
        with self.assertRaises(ContractError):
            parse_config(config)

    def test_timed_command_index_on_token_is_refused(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-index-token-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        config = json.loads(config_path.read_text())
        config["candidate"]["command"].append("-txindex=1")
        with self.assertRaises(ContractError):
            parse_config(config)

    def test_assume_valid_height_two_token_form_is_accepted(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-assume-two-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        config = json.loads(config_path.read_text())
        command = [
            part
            for part in config["core"]["command"]
            if part != "--assume-valid-height=0"
        ]
        command.extend(["--assume-valid-height", "0"])
        config["core"]["command"] = command
        parse_config(config)

    def test_reopen_command_need_not_repeat_assume_valid(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-reopen-token-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root, reopen=True)
        config = json.loads(config_path.read_text())
        config["core"]["reopen_command"] = [
            part
            for part in config["core"]["reopen_command"]
            if part != "--assume-valid-height=0"
        ]
        parse_config(config)

    def test_expected_height_must_match_manifest_tip(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-height-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        config = json.loads(config_path.read_text())
        config["expected_state"]["height"] = 99
        with self.assertRaises(ContractError):
            parse_config(config)

    def test_command_must_use_binary_placeholder(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-argv0-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        config = json.loads(config_path.read_text())
        config["core"]["command"][0] = "/usr/bin/bitcoind"
        with self.assertRaises(ContractError):
            parse_config(config)

    def test_public_argv_strips_secret_text(self) -> None:
        projected = offline._public_argv(
            (
                "{binary}",
                "-datadir=/secret",
                "{data_dir}",
                "--rpcpassword=hunter2",
                "{corpus_path}",
            )
        )
        self.assertEqual(
            projected,
            [
                "<executable>",
                "<short-option>",
                "<data-dir>",
                "<long-option=value>",
                "<corpus-path>",
            ],
        )


class CampaignTests(unittest.TestCase):
    def test_seven_pairs_publish_a_gated_result(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-campaign-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, expected = _build_workspace(root)
        output = root / OUTPUT_NAME
        self.assertEqual(main(["--config", str(config_path), "--output", str(output)]), 0)
        result = json.loads(output.read_bytes())
        self.assertEqual(result["schema"], RESULT_SCHEMA)
        self.assertEqual(result["pair_count"], PAIR_COUNT)
        self.assertEqual(result["arm_count"], 14)
        correctness = _object(result["correctness"])
        self.assertTrue(all(correctness.values()))
        arms = result["arms"]
        assert isinstance(arms, list)
        self.assertEqual(len(arms), 14)
        roles = [ _object(arm)["role"] for arm in arms ]
        self.assertEqual(
            roles,
            ["core", "candidate", "candidate", "core"] * 3 + ["core", "candidate"],
        )
        for arm in arms:
            record = _object(arm)
            self.assertEqual(record["exit_code"], 0)
            self.assertGreater(record["wall_ns"], 0)
            self.assertEqual(record["final_state"], state_json(expected))
        body = {key: value for key, value in result.items() if key != "result_sha256"}
        self.assertEqual(result["result_sha256"], canonical_sha256(body))
        leftovers = [path.name for path in output.parent.glob(".*result.json*")]
        self.assertEqual(leftovers, [])

    def test_reopen_lifecycle_is_untimed_and_gated(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-reopen-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, expected = _build_workspace(root, reopen=True)
        output = root / OUTPUT_NAME
        self.assertEqual(main(["--config", str(config_path), "--output", str(output)]), 0)
        result = json.loads(output.read_bytes())
        for arm in result["arms"]:
            record = _object(arm)
            self.assertEqual(record["reopen_exit_code"], 0)
            self.assertEqual(record["reopen_state"], state_json(expected))
            self.assertTrue(record["durability_ok"])

    def test_state_mismatch_refuses_publication(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-mismatch-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, expected = _build_workspace(root)
        liar = _write_executable(
            root / "liar.py",
            _node_source(_state(height=expected.height, bestblock=HASH64)),
        )
        config = json.loads(config_path.read_text())
        config["candidate"]["binary"] = str(liar)
        config["candidate"]["binary_sha256"] = _sha256_file(liar)
        config_path.write_bytes(canonical_bytes(config) + b"\n")
        output = root / OUTPUT_NAME
        with self.assertRaises(ContractError):
            main(["--config", str(config_path), "--output", str(output)])
        self.assertFalse(output.exists())

    def test_nonzero_exit_refuses_publication(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-exit-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, expected = _build_workspace(root)
        failing = _write_executable(
            root / "fail.py",
            _node_source(expected).replace("raise SystemExit(0)", "raise SystemExit(9)"),
        )
        config = json.loads(config_path.read_text())
        config["core"]["binary"] = str(failing)
        config["core"]["binary_sha256"] = _sha256_file(failing)
        config_path.write_bytes(canonical_bytes(config) + b"\n")
        output = root / OUTPUT_NAME
        with self.assertRaises(ContractError):
            main(["--config", str(config_path), "--output", str(output)])
        self.assertFalse(output.exists())

    def test_existing_output_is_refused(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-exists-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        output = root / OUTPUT_NAME
        output.parent.mkdir(parents=True)
        output.write_text("keep\n", encoding="utf-8")
        with self.assertRaises(ContractError):
            main(["--config", str(config_path), "--output", str(output)])
        self.assertEqual(output.read_text(encoding="utf-8"), "keep\n")

    def test_archive_mutation_after_load_is_refused(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-mutate-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        config = load_config(config_path)
        raw = bytearray((root / "blocks.dat").read_bytes())
        raw[-1] ^= 0xFF
        (root / "blocks.dat").write_bytes(raw)
        with self.assertRaises(ContractError):
            run_campaign(config, root / "arms")

    def test_leftover_descendant_refuses_publication(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-daemon-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, expected = _build_workspace(root)
        daemon = _write_executable(
            root / "daemon.py",
            _node_source(expected).replace(
                "raise SystemExit(0)\n",
                "child = __import__('os').fork()\n"
                "if child == 0:\n"
                "    __import__('time').sleep(30)\n"
                "    raise SystemExit(0)\n"
                "raise SystemExit(0)\n",
            ),
        )
        config = json.loads(config_path.read_text())
        config["candidate"]["binary"] = str(daemon)
        config["candidate"]["binary_sha256"] = _sha256_file(daemon)
        config_path.write_bytes(canonical_bytes(config) + b"\n")
        output = root / OUTPUT_NAME
        with self.assertRaises(ContractError):
            main(["--config", str(config_path), "--output", str(output)])
        self.assertFalse(output.exists())

    def test_child_manifest_mutation_is_refused(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-manifest-mut-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, expected = _build_workspace(root)
        mutator = _write_executable(
            root / "mutate.py",
            _node_source(expected).replace(
                "raise SystemExit(0)\n",
                "manifest = __import__('pathlib').Path(args.manifest)\n"
                "__import__('os').chmod(manifest, 0o600)\n"
                "manifest.write_bytes(manifest.read_bytes()[::-1])\n"
                "raise SystemExit(0)\n",
            ),
        )
        config = json.loads(config_path.read_text())
        config["candidate"]["binary"] = str(mutator)
        config["candidate"]["binary_sha256"] = _sha256_file(mutator)
        config_path.write_bytes(canonical_bytes(config) + b"\n")
        output = root / OUTPUT_NAME
        with self.assertRaises(ContractError):
            main(["--config", str(config_path), "--output", str(output)])
        self.assertFalse(output.exists())

    def test_summarize_uses_nearest_rank(self) -> None:
        summary = summarize([10, 20, 30, 40, 50, 60, 70])
        self.assertEqual(summary["samples"], 7)
        self.assertEqual(summary["p50_ns"], 40)
        self.assertEqual(summary["max_ns"], 70)


class NonVacuityProofs(unittest.TestCase):
    def test_RED_wrong_schema_is_caught(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-red-schema-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        output = root / OUTPUT_NAME
        main(["--config", str(config_path), "--output", str(output)])
        result = json.loads(output.read_bytes())
        with self.assertRaises(AssertionError):
            self.assertEqual(result["schema"], "offline-full-validation-result-v0")

    def test_RED_wrong_arm_count_is_caught(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="offline-red-arms-"))
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        config_path, _ = _build_workspace(root)
        output = root / OUTPUT_NAME
        main(["--config", str(config_path), "--output", str(output)])
        result = json.loads(output.read_bytes())
        with self.assertRaises(AssertionError):
            self.assertEqual(result["arm_count"], 12)


if __name__ == "__main__":
    unittest.main()
