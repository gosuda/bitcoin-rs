# pyright: strict
"""Operator-retained benchmark identity bundle capture and verification.

The campaign runner and analyzer record the artifact, corpus, and per-case
host CPU identity for every sample. Three required identities stay with the
operator (`docs/benchmarks/measured-campaign.md`, section "How the six
benchmark sample identities map to registration and records"): the resolved
NodeConfig, feature set, allocator, and validation mode; the backend, batch
mode, flush posture, and sync posture; the exact rustc toolchain; and the
hardware tail (CPU model, online and pinned cores, cpufreq governor, total
memory, storage device, OS kernel). This tool captures those identities into
one `operator-identity-v1` JSON bundle that sits beside a campaign run's
`results.json`.

The tool is read-only on the host: it reads `/proc`, `/sys`, the named
binary and NodeConfig, and the run directory. It writes only the bundle at
`--output`, through the durable publication in `evidence.py`, and refuses to
overwrite an existing bundle. Its one subprocess is a single bounded attempt
at `rustc --version --verbose` (60 s timeout, no retry); a rustc that cannot
run is a blocked identity, never a blank field. Storage identity comes from
the `filesystem.py` `identify_scope` owner and is recorded exactly as that
owner reports it, including an `unavailable` ZFS pool scope.

Subcommands:
  capture --run-dir DIR --binary PATH [--node-config PATH] --output PATH
          --commit SHA --features F --allocator A --validation-mode V
          --backend B --batch-mode M --flush-posture FP --sync-posture SP
  verify  --bundle PATH --binary PATH

A required value that is missing or refused makes `capture` exit 2, print
one `BLOCKED: <identity>` line per missing identity on stderr, and write
nothing. `verify` recomputes the canonical bundle digest and the binary
SHA-256 and rejects any mismatch with exit 1.
"""

import argparse
import dataclasses
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import evidence
import filesystem
import hashlib

SCHEMA = "operator-identity-v1"
BATCH_MODES = ("write", "write_deferred", "write_durable")
RUSTC_TIMEOUT_SECONDS = 60

COMMIT_PATTERN = re.compile(r"[0-9a-f]{7,64}")
MEMINFO_TOTAL_PATTERN = re.compile(r"^MemTotal:\s+(\d+)\s*kB", re.MULTILINE)

PROC_CPUINFO = Path("/proc/cpuinfo")
PROC_MEMINFO = Path("/proc/meminfo")
SYS_CPU_BASE = Path("/sys/devices/system/cpu")

type BlockedEntry = tuple[str, str | None]
type FileDigest = tuple[str, int]


@dataclasses.dataclass(frozen=True, slots=True)
class CaptureRequest:
    """Operator-supplied identity values for one capture."""

    run_dir: Path
    binary: Path
    commit: str | None
    features: str | None
    allocator: str | None
    validation_mode: str | None
    backend: str | None
    batch_mode: str | None
    flush_posture: str | None
    sync_posture: str | None
    node_config: Path | None = None

    def required_values(self) -> tuple[tuple[str, str | None], ...]:
        return (
            ("source_commit", self.commit),
            ("features", self.features),
            ("allocator", self.allocator),
            ("validation_mode", self.validation_mode),
            ("backend", self.backend),
            ("batch_mode", self.batch_mode),
            ("flush_posture", self.flush_posture),
            ("sync_posture", self.sync_posture),
        )


class BlockedIdentity(Exception):
    """One or more required identities are missing or refused."""

    def __init__(self, blocked: list[BlockedEntry]) -> None:
        self.blocked = blocked
        super().__init__("; ".join(identity for identity, _ in blocked))


def _file_digest(path: Path, identity: str) -> FileDigest:
    """SHA-256 and byte size of one existing regular file."""
    try:
        descriptor = os.open(
            path.resolve(),
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as error:
        raise BlockedIdentity([(identity, f"cannot stat {path}: {error}")]) from error
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise BlockedIdentity([(identity, f"{path} is not a regular file")])
        digest = hashlib.sha256()
        try:
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        except OSError as error:
            raise BlockedIdentity([(identity, str(error))]) from error
    finally:
        os.close(descriptor)
    return digest.hexdigest(), status.st_size


def _validated_required(identity: str, value: str | None) -> tuple[str | None, str | None]:
    """Acceptable value with no reason, or no value with an optional reason."""
    if not value:
        return None, None
    if identity == "source_commit" and COMMIT_PATTERN.fullmatch(value) is None:
        return None, f"refused {value!r}: not a clean lowercase hex git commit name"
    if identity == "batch_mode" and value not in BATCH_MODES:
        return None, f"refused {value!r}: not one of {', '.join(BATCH_MODES)}"
    return value, None


def _collect_values(
    required: tuple[tuple[str, str | None], ...], blocked: list[BlockedEntry]
) -> dict[str, str]:
    values: dict[str, str] = {}
    for identity, value in required:
        cleaned, reason = _validated_required(identity, value)
        if reason is not None:
            blocked.append((identity, reason))
        elif cleaned is None:
            blocked.append((identity, None))
        else:
            values[identity] = cleaned
    return values


def _collect_file_digests(request: CaptureRequest, blocked: list[BlockedEntry]) -> dict[str, FileDigest]:
    digests: dict[str, FileDigest] = {}
    try:
        digests["binary"] = _file_digest(request.binary, "binary")
    except BlockedIdentity as error:
        blocked.extend(error.blocked)
    if request.node_config is None:
        return digests
    try:
        digests["node_config"] = _file_digest(request.node_config, "node_config")
    except BlockedIdentity as error:
        blocked.extend(error.blocked)
    return digests


def _cpuinfo_fields(raw_line: str) -> tuple[str, str] | None:
    key, separator, value = raw_line.partition(":")
    if not separator:
        return None
    return key.strip(), value.strip()


def _cpuinfo_block(block: str) -> tuple[int | None, str | None]:
    processor: int | None = None
    model: str | None = None
    for raw_line in block.splitlines():
        fields = _cpuinfo_fields(raw_line)
        if fields is None:
            continue
        key, value = fields
        if key == "processor" and processor is None:
            try:
                processor = int(value.split()[0])
            except (ValueError, IndexError):
                processor = None
        elif key == "model name" and model is None and value:
            model = value
    return processor, model


def _read_cpuinfo(cpuinfo_path: Path) -> tuple[str, list[int], list[str]]:
    """First model name, online processor ids, and distinct model names."""
    try:
        text = cpuinfo_path.read_text(encoding="utf-8")
    except OSError as error:
        raise BlockedIdentity(
            [("hardware", f"cannot read {cpuinfo_path}: {error}")]
        ) from error
    cpus_online: list[int] = []
    models: list[str] = []
    for block in re.split(r"\n[ \t]*\n", text):
        processor, model = _cpuinfo_block(block)
        if processor is None:
            continue
        cpus_online.append(processor)
        if model is not None:
            models.append(model)
    if not models:
        raise BlockedIdentity(
            [("hardware", f"{cpuinfo_path} shows no processor model name")]
        ) from None
    return models[0], cpus_online, sorted(set(models))


def _read_memory_total(meminfo_path: Path) -> int:
    try:
        text = meminfo_path.read_text(encoding="utf-8")
    except OSError as error:
        raise BlockedIdentity(
            [("hardware", f"cannot read {meminfo_path}: {error}")]
        ) from error
    match = MEMINFO_TOTAL_PATTERN.search(text)
    if match is None:
        raise BlockedIdentity(
            [("hardware", f"{meminfo_path} has no MemTotal line")]
        ) from None
    return int(match.group(1)) * 1024


def _pinned_cpus() -> list[int]:
    try:
        pinned = sorted(os.sched_getaffinity(0))
    except OSError as error:
        raise BlockedIdentity(
            [("hardware", f"cannot read process affinity: {error}")]
        ) from error
    if not pinned:
        raise BlockedIdentity([("hardware", "process affinity is empty")]) from None
    return pinned


def _cpufreq_governors(sys_base: Path, pinned: list[int]) -> dict[str, str]:
    """Best-effort governor per pinned core; cpufreq can be absent."""
    governors: dict[str, str] = {}
    for cpu in pinned:
        path = sys_base / f"cpu{cpu}" / "cpufreq" / "scaling_governor"
        try:
            governors[f"cpu{cpu}"] = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return governors


def _rustc_verbose(command: str) -> str:
    """One bounded attempt at `rustc --version --verbose` output."""
    try:
        completed = subprocess.run(
            [command, "--version", "--verbose"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=RUSTC_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BlockedIdentity(
            [("toolchain", f"cannot run {command} --version --verbose: {error}")]
        ) from error
    output = completed.stdout.strip()
    if completed.returncode != 0 or not output:
        reason = f"{command} --version --verbose failed with exit {completed.returncode}"
        raise BlockedIdentity([("toolchain", reason)]) from None
    return output


def _hardware_identity(
    cpuinfo_path: Path, meminfo_path: Path, sys_base: Path, blocked: list[BlockedEntry]
) -> evidence.JsonObject:
    """CPU, memory, and kernel identity; failures append to ``blocked``."""
    identity: evidence.JsonObject = {}
    try:
        cpu_model, cpus_online, cpu_models = _read_cpuinfo(cpuinfo_path)
        identity["cpu_model"] = cpu_model
        identity["cpu_models"] = cpu_models
        identity["cpus_online"] = cpus_online
    except BlockedIdentity as error:
        blocked.extend(error.blocked)
    try:
        identity["memory_total_bytes"] = _read_memory_total(meminfo_path)
    except BlockedIdentity as error:
        blocked.extend(error.blocked)
    cpus_pinned: list[int] = []
    try:
        cpus_pinned = _pinned_cpus()
        identity["cpus_pinned"] = cpus_pinned
    except BlockedIdentity as error:
        blocked.extend(error.blocked)
    identity["cpufreq_governors"] = _cpufreq_governors(sys_base, cpus_pinned)
    name = os.uname()
    identity["kernel"] = {
        "sysname": name.sysname,
        "release": name.release,
        "version": name.version,
        "machine": name.machine,
    }
    return identity


def _assemble_bundle(
    request: CaptureRequest,
    values: dict[str, str],
    digests: dict[str, FileDigest],
    hardware: evidence.JsonObject,
    rustc_verbose: str,
    storage_scope: filesystem.ScopeDoc,
) -> evidence.JsonObject:
    configuration: evidence.JsonObject = {
        "features": values["features"],
        "allocator": values["allocator"],
        "validation_mode": values["validation_mode"],
    }
    node_digest = digests.get("node_config")
    if node_digest is not None and request.node_config is not None:
        configuration["node_config_path"] = str(request.node_config.resolve())
        configuration["node_config_sha256"] = node_digest[0]
    binary_digest = digests["binary"]
    bundle: evidence.JsonObject = {
        "schema": SCHEMA,
        "artifact": {
            "binary_path": str(request.binary.resolve()),
            "binary_sha256": binary_digest[0],
            "binary_size_bytes": binary_digest[1],
            "source_commit": values["source_commit"],
        },
        "configuration": configuration,
        "durability": {
            "backend": values["backend"],
            "batch_mode": values["batch_mode"],
            "flush_posture": values["flush_posture"],
            "sync_posture": values["sync_posture"],
        },
        "toolchain": {"rustc_version_verbose": rustc_verbose},
        "hardware": hardware,
        "storage": storage_scope,
    }
    bundle["bundle_sha256"] = evidence.canonical_sha256(bundle)
    return bundle


def capture_bundle(
    request: CaptureRequest,
    *,
    cpuinfo_path: Path | None = None,
    meminfo_path: Path | None = None,
    sys_base: Path | None = None,
    rustc_command: str = "rustc",
) -> evidence.JsonObject:
    """Collect every required identity or raise ``BlockedIdentity``.

    All sources are inspected before the raise, so one capture reports every
    missing identity at once. Nothing is written here; the caller publishes.
    """
    cpuinfo = cpuinfo_path if cpuinfo_path is not None else PROC_CPUINFO
    meminfo = meminfo_path if meminfo_path is not None else PROC_MEMINFO
    sysfs = sys_base if sys_base is not None else SYS_CPU_BASE
    blocked: list[BlockedEntry] = []
    values = _collect_values(request.required_values(), blocked)
    digests = _collect_file_digests(request, blocked)
    hardware = _hardware_identity(cpuinfo, meminfo, sysfs, blocked)
    rustc_verbose = ""
    try:
        rustc_verbose = _rustc_verbose(rustc_command)
    except BlockedIdentity as error:
        blocked.extend(error.blocked)
    _, storage_scope = filesystem.identify_scope(request.run_dir)
    if blocked:
        raise BlockedIdentity(blocked)
    return _assemble_bundle(request, values, digests, hardware, rustc_verbose, storage_scope)


def _bundle_binary_hash(bundle: dict[str, object]) -> str | None:
    artifact = bundle.get("artifact")
    if not isinstance(artifact, dict):
        return None
    candidate = artifact.get("binary_sha256")
    if not isinstance(candidate, str):
        return None
    return candidate


def verify_bundle(bundle_path: Path, binary: Path) -> int:
    """Recompute the bundle digest and the binary hash; 0 or 1."""
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
        print(f"INVALID: cannot read bundle {bundle_path}: {error}", file=sys.stderr)
        return 1
    if not isinstance(bundle, dict):
        print(f"INVALID: {bundle_path} is not a JSON object", file=sys.stderr)
        return 1
    if bundle.get("schema") != SCHEMA:
        print(
            f"INVALID: bundle schema must be {SCHEMA}, got {bundle.get('schema')!r}",
            file=sys.stderr,
        )
        return 1
    recorded_digest = bundle.get("bundle_sha256")
    if not isinstance(recorded_digest, str):
        print("INVALID: bundle carries no bundle_sha256", file=sys.stderr)
        return 1
    payload = dict(bundle)
    payload.pop("bundle_sha256", None)
    try:
        computed_digest = evidence.canonical_sha256(payload)
    except evidence.ContractError as error:
        print(f"INVALID: {error}", file=sys.stderr)
        return 1
    if computed_digest != recorded_digest:
        print(
            f"INVALID: bundle digest mismatch: recorded {recorded_digest}, "
            f"computed {computed_digest}",
            file=sys.stderr,
        )
        return 1
    recorded_hash = _bundle_binary_hash(bundle)
    if recorded_hash is None:
        print("INVALID: bundle carries no artifact.binary_sha256", file=sys.stderr)
        return 1
    try:
        actual_hash = evidence.hash_regular_file(binary.resolve())
    except (OSError, evidence.ContractError) as error:
        print(f"INVALID: cannot hash binary {binary}: {error}", file=sys.stderr)
        return 1
    if actual_hash != recorded_hash:
        print(
            f"INVALID: binary hash mismatch: bundle {recorded_hash}, file {actual_hash}",
            file=sys.stderr,
        )
        return 1
    print(f"VALID bundle_sha256={computed_digest} binary_sha256={actual_hash}")
    return 0


def _parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = top.add_subparsers(dest="command", required=True)
    capture = sub.add_parser(
        "capture", help="capture the operator identity bundle beside results.json"
    )
    capture.add_argument(
        "--run-dir", required=True, type=Path, help="campaign run directory"
    )
    capture.add_argument(
        "--binary", required=True, type=Path, help="benchmark binary to hash"
    )
    capture.add_argument(
        "--node-config",
        type=Path,
        default=None,
        help="resolved NodeConfig file to hash",
    )
    capture.add_argument("--output", required=True, type=Path, help="bundle JSON path")
    capture.add_argument(
        "--commit", default=None, help="clean lowercase hex source commit name"
    )
    capture.add_argument("--features", default=None, help="enabled feature set")
    capture.add_argument("--allocator", default=None, help="allocator in use")
    capture.add_argument("--validation-mode", default=None, help="validation mode in use")
    capture.add_argument("--backend", default=None, help="storage backend in use")
    capture.add_argument(
        "--batch-mode",
        default=None,
        choices=BATCH_MODES,
        help="write batch mode in use",
    )
    capture.add_argument("--flush-posture", default=None, help="flush posture in use")
    capture.add_argument("--sync-posture", default=None, help="sync posture in use")
    verify = sub.add_parser(
        "verify", help="recompute the bundle digest and the binary hash"
    )
    verify.add_argument(
        "--bundle", required=True, type=Path, help="bundle JSON path to check"
    )
    verify.add_argument(
        "--binary", required=True, type=Path, help="benchmark binary to re-hash"
    )
    return top


def _capture_command(args: argparse.Namespace) -> int:
    request = CaptureRequest(
        run_dir=args.run_dir,
        binary=args.binary,
        commit=args.commit,
        features=args.features,
        allocator=args.allocator,
        validation_mode=args.validation_mode,
        backend=args.backend,
        batch_mode=args.batch_mode,
        flush_posture=args.flush_posture,
        sync_posture=args.sync_posture,
        node_config=args.node_config,
    )
    try:
        bundle = capture_bundle(request)
    except BlockedIdentity as error:
        for identity, reason in error.blocked:
            if reason is None:
                print(f"BLOCKED: {identity}", file=sys.stderr)
            else:
                print(f"BLOCKED: {identity}: {reason}", file=sys.stderr)
        return 2
    try:
        evidence.publish_result(bundle, args.output)
    except evidence.ContractError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"captured {args.output} bundle_sha256={bundle['bundle_sha256']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "verify":
        return verify_bundle(args.bundle, args.binary)
    return _capture_command(args)


if __name__ == "__main__":
    sys.exit(main())
