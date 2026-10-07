"""Emit the pinned reference-fixture identity tuple for this host.

usage: scripts/resolve_reference_identity.py {core|formal} <repo-root>

core   -> core_version, archive, archive_sha256, bitcoind_sha256, version_output
formal -> version, archive, archive_sha256, jar_sha256, version

One value per line on stdout; exits nonzero with the reason on stderr when the
manifest pins no artifact for the host platform. The platform-to-archive
mapping is the single owner for every consumer (install/provision scripts and
their offline tests).

Owner: docs/contracts/core-differential.md (CORE-01) and
docs/contracts/formal-verification.md. Requires Python >=3.11 (tomllib).
"""

import platform
import re
import sys
import tomllib
from pathlib import Path

TARGETS = {
    ("linux", "x86_64"): "x86_64-linux-gnu",
    ("linux", "aarch64"): "aarch64-linux-gnu",
    ("darwin", "arm64"): "arm64-apple-darwin",
    ("darwin", "x86_64"): "x86_64-apple-darwin",
}

if len(sys.argv) != 3 or sys.argv[1] not in ("core", "formal"):
    raise SystemExit(f"usage: {Path(sys.argv[0]).name} {{core|formal}} <repo-root>")
mode, root = sys.argv[1], Path(sys.argv[2])

with (root / "crates/rpc/core-compat.toml").open("rb") as stream:
    reference = tomllib.load(stream)["reference"]

if mode == "core":
    release = reference["release"]
    platform_rows = release.get("platforms", [])
    targets = [release["target"], *(row["target"] for row in platform_rows)]
    # Fail closed like load_reference_set's DuplicateArtifactTarget.
    if len(targets) != len(set(targets)):
        raise SystemExit("duplicate Core artifact target")
    artifacts = {row["target"]: row for row in platform_rows}
    artifacts[release["target"]] = release
    pin = artifacts.get(TARGETS.get((sys.platform, platform.machine())))
    if pin is None:
        raise SystemExit(f"no pinned Core artifact for {sys.platform}-{platform.machine()}")
    values = (release["core_version"],) + tuple(
        pin[key] for key in ("archive", "archive_sha256", "bitcoind_sha256")
    ) + (release["version_output"],)
else:
    pin = reference["formal_tool"]
    if pin["name"] != "apalache-mc":
        raise SystemExit("unexpected formal tool")
    contract = (root / "docs/contracts/formal-verification.md").read_text()
    archive = re.search(r"^\| Archive \| `([^`]+)`", contract, re.MULTILINE)
    if archive is None:
        raise SystemExit("formal archive identity missing")
    values = (pin["version"], archive[1], pin["archive_sha256"], pin["jar_sha256"], pin["version"])

if not all(isinstance(value, str) and "\n" not in value for value in values):
    raise SystemExit("invalid fixture identity")
print("\n".join(values))
