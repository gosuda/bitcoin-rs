"""Offline regressions for QAC-01 QA corpus import behavior.

Contracts: docs/contracts/qa-corpus.md, fuzz/CORPUS_PROVENANCE.md, and PR #747.
Fixtures are synthetic transport bytes, not Bitcoin validity vectors.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "import-qa-assets.sh"
MAPPER = SCRIPT.with_name("import_qa_assets.py")
match = re.search(r"^readonly MAX_SEED_BYTES=(\d+)", SCRIPT.read_text(), re.M)
if match is None or int(match.group(1)) < 1:
    raise RuntimeError("missing positive MAX_SEED_BYTES owner")
BUDGET = int(match.group(1))
spec = importlib.util.spec_from_file_location("qa_mapper", MAPPER)
mapper = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mapper)


class MapperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.corpora = self.root / "corpora"; self.out = self.root / "out"
        names = ["p2p_deserialize_raw_net_msg", "bitcoin_deserialize_script", "bitcoin_script_bytes_to_asm_fmt",
                 "bitcoin_deserialize_block", "bitcoin_deserialize_transaction"]
        for name in names: (self.corpora / name).mkdir(parents=True)
        self.inv = self.root / "compat.rs"
        self.inv.write_text('pub const COMMANDS: &[Command] = &[Command { name: "ping" }, Command { name: "pong" }];\n')
        self.harness = self.root / "script_eval.rs"; self.harness.write_text("const ELEMENT_LEN_MAX: usize = 1_024;\n")

    def msg(self, command: str, payload: bytes) -> None:
        (self.corpora / "p2p_deserialize_raw_net_msg" / command).write_bytes(
            b"\0" * 4 + command.encode().ljust(12, b"\0") + b"\0" * 8 + payload)

    def test_p2p_uses_owner_order_and_budget(self):
        self.msg("pong", b"P" * BUDGET)
        mapper.map_p2p(self.corpora / "p2p_deserialize_raw_net_msg", self.inv, self.out, BUDGET)
        [seed] = self.out.iterdir()
        data = seed.read_bytes(); self.assertEqual(data[0], 1); self.assertEqual(len(data), BUDGET)

    def test_invalid_inventory_fails_closed(self):
        self.inv.write_text('pub const COMMANDS: &[Command] = &[Command { name: "ping" }, Command { name: "ping" }];')
        with self.assertRaises(ValueError):
            mapper.map_p2p(self.corpora / "p2p_deserialize_raw_net_msg", self.inv, self.out, BUDGET)

    def test_script_frames_follow_owner_limit(self):
        source = self.corpora / "bitcoin_deserialize_script"; (source / "s").write_bytes(b"Q" * BUDGET)
        mapper.map_script([source, self.corpora / "bitcoin_script_bytes_to_asm_fmt"], self.harness, self.out, BUDGET)
        data = [p.read_bytes() for p in self.out.iterdir()]
        self.assertEqual(len(data), 2); self.assertTrue(all(len(seed) <= BUDGET for seed in data))
        self.assertIn(b"\0\0\0\0\x04" + b"Q" * 1024 + b"\0", data)

    def test_direct_mapping_is_bounded_and_atomic(self):
        source = self.corpora / "bitcoin_deserialize_block"
        (source / "small").write_bytes(b"ok"); (source / "large").write_bytes(b"x" * BUDGET)
        outside = self.root / "outside"; outside.write_bytes(b"preserve")
        self.out.mkdir(); (self.out / "small").symlink_to(outside)
        mapper.map_direct(source, self.out, BUDGET, "block")
        self.assertEqual(outside.read_bytes(), b"preserve"); self.assertEqual((self.out / "small").read_bytes(), b"ok")
        self.assertFalse((self.out / "small").is_symlink()); self.assertFalse((self.out / "large").exists())
        self.assertFalse(any(p.name.startswith(".qa-import-") for p in self.out.iterdir()))

    def test_missing_source_fails_before_output(self):
        with self.assertRaises(OSError):
            mapper.map_direct(self.root / "missing", self.out, BUDGET, "block")
        self.assertEqual(list(self.out.iterdir()), [])

    def test_cli_maps_all_targets(self):
        self.msg("ping", b"p")
        (self.corpora / "bitcoin_deserialize_script" / "s").write_bytes(b"Q")
        for name in ("bitcoin_deserialize_block", "bitcoin_deserialize_transaction"):
            (self.corpora / name / "seed").write_bytes(b"D")
        repo = self.root / "repo"; (repo / "crates/p2p/src").mkdir(parents=True); (repo / "fuzz/fuzz_targets").mkdir(parents=True)
        (repo / "crates/p2p/src/compat.rs").write_text(self.inv.read_text()); (repo / "fuzz/fuzz_targets/script_eval.rs").write_text(self.harness.read_text())
        result = subprocess.run([sys.executable, str(MAPPER), "--corpora", str(self.corpora), "--repo-root", str(repo),
                                 "--out-base", str(self.out), "--max-seed-bytes", str(BUDGET)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name for p in self.out.iterdir()}, {"p2p_message", "script_eval", "block_decode", "tx_decode"})


class ShellFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.bin = self.root / "bin"; self.bin.mkdir(); self.stage = self.root / "stage"; self.stage.mkdir()
        scripts = self.root / "scripts"; scripts.mkdir(); (scripts / MAPPER.name).write_bytes(MAPPER.read_bytes())
        (self.root / "crates/p2p/src").mkdir(parents=True); (self.root / "fuzz/fuzz_targets").mkdir(parents=True)
        (self.root / "crates/p2p/src/compat.rs").write_text('pub const COMMANDS: &[Command] = &[Command { name: "ping" }];')
        (self.root / "fuzz/fuzz_targets/script_eval.rs").write_text("const ELEMENT_LEN_MAX: usize = 1_024;\n")
        self.prov = self.root / "fuzz/CORPUS_PROVENANCE.md"; self.prov.parent.mkdir(exist_ok=True); self.prov.write_text("old\n")
        self.pin = re.search(r'^readonly QA_ASSETS_PIN="([0-9a-f]{40})"', SCRIPT.read_text(), re.M).group(1)
        corpus = self.stage / "fuzz_corpora"
        for name in ["p2p_deserialize_raw_net_msg", "bitcoin_deserialize_script", "bitcoin_script_bytes_to_asm_fmt",
                     "bitcoin_deserialize_block", "bitcoin_deserialize_transaction"]: (corpus / name).mkdir(parents=True)
        (corpus / "p2p_deserialize_raw_net_msg/s").write_bytes(b"\0"*4+b"ping"+b"\0"*8+b"\0"*8+b"p")
        (corpus / "bitcoin_deserialize_script/s").write_bytes(b"Q")
        for name in ("bitcoin_deserialize_block", "bitcoin_deserialize_transaction"): (corpus / name / "s").write_bytes(b"D")
        self.install_stubs()

    def stub(self, name, body):
        p = self.bin / name; p.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body + "\n"); p.chmod(0o755)

    def install_stubs(self):
        self.stub("rustc", "printf 'host: x86_64-unknown-linux-gnu\\n'")
        self.stub("df", "printf 'Filesystem B U A C M\\nX 1 0 100000 0%% /\\n'")
        self.stub("du", "[[ ${FAIL:-} != du ]] || exit 31; printf '1\\tclone\\n'")
        self.stub("date", "[[ ${FAIL:-} != date ]] || exit 47; [[ -f ${TEST_ROOT}/cmin.log ]] && [[ $(cat ${TEST_ROOT}/cmin.log) == $'p2p_message\\nblock_decode\\ntx_decode\\nscript_eval' ]] || exit 48; printf '2000-01-01T00:00:00Z\\n'")
        self.stub("cargo", "[[ ${FAIL:-} != cmin ]] || exit 43; [[ $1 == fuzz && $2 == cmin ]] || exit 99; printf '%s\\n' \"$5\" >> \"${TEST_ROOT}/cmin.log\"")
        self.stub("git", r'''
if [[ $1 == rev-parse ]]; then printf '%s\n' "$TEST_ROOT"; exit; fi
if [[ $1 == init ]]; then mkdir -p "${!#}/fuzz_corpora"; exit; fi
[[ $1 == -C ]] || exit 99
case "$3" in
 remote|fetch) exit 0 ;;
 checkout) cp -a "$SOURCE/." "$2/" ;;
 rev-parse) [[ ${FAIL:-} != git_head ]] || exit 29; printf '%s\n' "$PIN" ;;
 *) exit 99 ;;
esac''')

    def run_import(self, fail=""):
        env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}", TEST_ROOT=str(self.root), SOURCE=str(self.stage), PIN=self.pin,
                   TMPDIR=str(self.root / "tmp"), FAIL=fail, RUSTC_WRAPPER="x", CARGO_BUILD_BUILD_DIR="x")
        Path(env["TMPDIR"]).mkdir(exist_ok=True)
        return subprocess.run(["bash", str(SCRIPT)], cwd=self.root, env=env, capture_output=True, text=True, timeout=15)

    def test_success_replaces_provenance_after_cmin(self):
        result = self.run_import(); self.assertEqual(result.returncode, 0, result.stderr)
        text = self.prov.read_text(); self.assertIn(self.pin, text); self.assertIn("2000-01-01T00:00:00Z", text)
        self.assertEqual((self.root / "cmin.log").read_text().splitlines(), ["p2p_message", "block_decode", "tx_decode", "script_eval"])
        self.assertEqual(self.prov.stat().st_mode & 0o777, 0o644)
        self.assertFalse(any(self.prov.parent.glob(".corpus-provenance.*")))

    def test_acquisition_failures_preserve_provenance(self):
        for fail, code in (("git_head", 29), ("du", 31), ("cmin", 43), ("date", 47)):
            with self.subTest(fail=fail):
                self.prov.write_text("old\n"); result = self.run_import(fail)
                self.assertEqual(result.returncode, code, result.stderr); self.assertEqual(self.prov.read_text(), "old\n")
                self.assertFalse(any(self.prov.parent.glob(".corpus-provenance.*")))


if __name__ == "__main__": unittest.main()
