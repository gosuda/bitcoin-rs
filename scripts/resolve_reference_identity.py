"""Emit the pinned reference-fixture identity tuple for this host.

usage: scripts/resolve_reference_identity.py {core|formal} <repo-root>

core   -> core_version, archive, archive_sha256, bitcoind_sha256, version_output
formal -> version, archive, archive_sha256, jar_sha256, version

One value per line on stdout; exits nonzero with the reason on stderr when the
manifest pins no artifact for the host platform. The platform-to-archive
mapping is the single owner for every consumer (install/provision scripts and
their offline tests).

Owner: docs/contracts/core-differential.md (CORE-01) and
docs/contracts/formal-verification.md. Runs on Python >=3.6: tomllib is used
when present, otherwise a fixed-shape reader parses the [reference] tree.
"""

import platform
import re
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python <3.11
    tomllib = None

TARGETS = {
    ("linux", "x86_64"): "x86_64-linux-gnu",
    ("linux", "aarch64"): "aarch64-linux-gnu",
    ("darwin", "arm64"): "arm64-apple-darwin",
    ("darwin", "x86_64"): "x86_64-apple-darwin",
}

# Tables whose key/value lines the fixed-shape reader must parse; every other
# table's body is ignored so unrelated syntax can never break the gates.
FIXTURE_TABLES = {
    ("reference",),
    ("reference", "release"),
    ("reference", "release", "platforms"),
    ("reference", "formal_tool"),
}


def _walk(root, path):
    node = root
    for part in path:
        node = node.setdefault(part, {})
    return node


def _strip_comment(value):
    quoted = False
    for index, char in enumerate(value):
        if char == '"':
            quoted = not quoted
        elif char == "#" and not quoted:
            return value[:index].strip()
    return value


def _toml_scalar(value, number):
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        # Escapes would need real decoding; reject them rather than return a
        # value tomllib would have read differently.
        if "\\" in value:
            raise SystemExit(f"unsupported escape in manifest value at line {number}")
        return value[1:-1]
    if value in ("true", "false"):
        return value == "true"
    if re.fullmatch(r"[+-]?\d+", value):
        return int(value)
    raise SystemExit(f"unsupported manifest value at line {number}: {value}")


def _toml_lite(text):
    """tomllib substitute: the manifest's fixed shape only.

    Bare keys assigned basic strings, booleans or integers inside
    [dotted.tables] and [[arrays.of.tables]]; anything else in a fixture
    table fails closed.
    """
    root = {}
    cursor = root
    needed = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        array = re.fullmatch(r"\[\[\s*([\w.]+)\s*\]\]", line)
        table = re.fullmatch(r"\[\s*([\w.]+)\s*\]", line)
        if array:
            path = tuple(part.strip() for part in array[1].split("."))
            rows = _walk(root, path[:-1]).setdefault(path[-1], [])
            rows.append({})
            cursor = rows[-1]
            needed = path in FIXTURE_TABLES
        elif table:
            path = tuple(part.strip() for part in table[1].split("."))
            cursor = _walk(root, path)
            needed = path in FIXTURE_TABLES
        elif line.startswith("["):
            raise SystemExit(f"unreadable manifest header at line {number}")
        elif needed:
            key, sep, value = line.partition("=")
            if not sep:
                raise SystemExit(f"unreadable manifest line {number}")
            key = key.strip()
            # tomllib rejects duplicate keys; the fallback must too.
            if key in cursor:
                raise SystemExit(f"duplicate manifest key at line {number}: {key}")
            cursor[key] = _toml_scalar(_strip_comment(value.strip()), number)
    return root


def load_manifest(path):
    if tomllib is not None:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    return _toml_lite(path.read_text())


if len(sys.argv) != 3 or sys.argv[1] not in ("core", "formal"):
    raise SystemExit(f"usage: {Path(sys.argv[0]).name} {{core|formal}} <repo-root>")
mode, root = sys.argv[1], Path(sys.argv[2])

reference = load_manifest(root / "crates/rpc/core-compat.toml")["reference"]

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
