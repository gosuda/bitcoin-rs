# pyright: strict
"""Filesystem-aware Linux measurement boundary (one target filesystem per run).

One owner identifies the real mount/filesystem/backing-counter scope for a
scratch path and takes read-only cumulative write-counter samples. Four
measurement classes stay separate and are never merged here:

- apparent bytes (file lengths),
- allocated file bytes (the existing Rust ``storage-footprint`` tool owns
  that measurement; it is not duplicated here),
- per-process I/O counters,
- attributable host block-device writes (this module's only counter).

Only a regular single block device behind the target filesystem can yield an
attributable counter, and even then the counter is host-wide for that device:
every writer to the device is included. This collector never attests
isolation and never qualifies a run; the existing harness keeps its strict
qualification gate unless run ownership is actually proved.

Honest scope labeling:

- ``regular_block_device``: mount resolves to one block device with a
  readable kernel sectors-written counter. Available.
- ``zfs_pool``: ZFS dataset. Pool-wide accounting cannot isolate one
  filesystem's physical writes, so the scope is unavailable. Pool aggregate
  commands are informational only and are never converted into a
  per-filesystem value.
- ``composite_anonymous``: overlay/tmpfs/ramfs/network/fuse/9p/virtiofs and
  other anonymous (major 0) mounts with no per-filesystem block counter.
  Unavailable.
- ``ambiguous_multi_device``: btrfs or a stacked device over more than one
  underlying device. The mapping cannot name a single backing counter, so the
  scope is unavailable. Underlying devices are listed, never summed.
- ``unavailable``: mount entry, counter file, permission, or parse failure.
  Unavailable with an explicit reason, never zero.

Read-only bound: this module only reads the mount table, the one chosen
device's counter files, and local topology/queue attribute files listed in
``mechanisms_checked``. It spawns no subprocess, writes nothing, and follows
exactly one counter per scope (a partition's own counter, never the parent
disk added to it, never slaves added together).

Sector unit: the kernel block-layer counter unit is always 512 bytes,
independent of the filesystem logical block size or the device physical
block size. Queue/model attributes are recorded for context only.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import TypedDict

type Json = str | int | float | bool | None | list[Json] | dict[str, Json]
type JsonObject = dict[str, Json]

SECTOR_BYTES = 512

MOUNTINFO_DEFAULT = "/proc/self/mountinfo"
DISKSTATS_DEFAULT = "/proc/diskstats"
SYS_BASE_DEFAULT = Path("/sys/dev/block")

UNATTRIBUTABLE_FSTYPES = frozenset(
    {
        "overlay",
        "tmpfs",
        "ramfs",
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "fuse",
        "fuseblk",
        "9p",
        "virtiofs",
        "ecryptfs",
    }
)

QUEUE_KEYS = (
    "rotational",
    "logical_block_size",
    "physical_block_size",
    "hw_sector_size",
    "write_cache",
    "scheduler",
    "nr_requests",
)

_MAJMIN_RE = re.compile(r"^\d+:\d+$")


class MountInfo(TypedDict):
    mount_id: str
    parent_id: str
    majmin: str
    root: str
    mountpoint: str
    mount_options: str
    fstype: str
    source: str
    super_options: str


class CounterSample(TypedDict):
    sysfs_sectors_written: int
    writes_completed: int
    in_flight: int
    diskstats_sectors_written: int | None


class ScopeDoc(TypedDict, total=False):
    """Precise scope document; every field carries its own narrow type."""

    scratch_realpath: str
    counter_unit: str
    counter_scope: str
    mount: MountInfo | None
    mechanisms_checked: list[str]
    status: str
    scope_kind: str
    reason: str
    mapping: str
    majmin: str
    name: str
    sysfs_stat: str
    partition: bool
    parent_disk: str
    stacked_slaves: list[str]
    holders: list[str]
    shared_mounts: list[str]
    queue: dict[str, str | None]
    model: str | None
    notes: list[str]
    sample_error: str


def unescape_mountinfo(field: str) -> str:
    """Decode kernel mountinfo octal escapes (space, newline, backslash)."""
    raw = re.sub(
        rb"\\([0-7]{3})",
        lambda match: bytes([int(match.group(1), 8)]),
        field.encode("utf-8", errors="surrogateescape"),
    )
    return raw.decode("utf-8", errors="surrogateescape")


def _read_text(path: Path | str, errors: str = "replace") -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors=errors)
    except OSError:
        return None


def read_mountinfo(path: str | Path = MOUNTINFO_DEFAULT) -> list[MountInfo]:
    """Parse the kernel mount table; unreadable input yields an empty list.

    The table is ingested with surrogateescape so non-UTF8 mountpoint bytes
    survive decoding, consistent with the os.fsdecode-derived scratch path
    they are matched against. Replacement decoding would map distinct byte
    sequences onto one placeholder and misroute child mounts to ancestors.
    """
    text = _read_text(path, errors="surrogateescape")
    if text is None:
        return []
    mounts: list[MountInfo] = []
    for line in text.splitlines():
        if " - " not in line:
            continue
        left, right = line.split(" - ", 1)
        left_fields = left.split(" ")
        right_fields = right.split(" ")
        if len(left_fields) < 6 or len(right_fields) < 2:
            continue
        try:
            entry: MountInfo = {
                "mount_id": left_fields[0],
                "parent_id": left_fields[1],
                "majmin": left_fields[2],
                "root": unescape_mountinfo(left_fields[3]),
                "mountpoint": unescape_mountinfo(left_fields[4]),
                "mount_options": left_fields[5],
                "fstype": right_fields[0],
                "source": unescape_mountinfo(right_fields[1]),
                "super_options": right_fields[2] if len(right_fields) > 2 else "",
            }
        except ValueError:
            continue
        mounts.append(entry)
    return mounts


def pick_mount(real: str, mounts: list[MountInfo]) -> MountInfo | None:
    """Longest-prefix mount containing ``real``; ``None`` when no entry does."""
    best: MountInfo | None = None
    for mount in mounts:
        point = mount["mountpoint"]
        inside = (
            real == point or point == "/" or real.startswith(point.rstrip("/") + "/")
        )
        if not inside:
            continue
        if best is None or len(point) >= len(best["mountpoint"]):
            best = mount
    return best


def _child_names(directory: Path) -> list[str] | None:
    try:
        return sorted(child.name for child in directory.iterdir())
    except FileNotFoundError:
        return []
    except OSError:
        return None


def _read_stripped(path: Path) -> str | None:
    text = _read_text(path)
    return text.strip() if text is not None else None


def _is_composite_fstype(fstype: str) -> bool:
    if fstype in UNATTRIBUTABLE_FSTYPES:
        return True
    # Kernel reports some fuse mounts as "fuse.<subtype>"; they share the
    # same no-per-filesystem-counter property as plain "fuse".
    return fstype.split(".")[0] in UNATTRIBUTABLE_FSTYPES


class CounterHandle:
    """Read-only handle for one block device's cumulative sectors counter.

    Exactly one device file is ever read per sample (the scope's own
    ``stat``); parent-disk and underlying-device counters are listed for
    context and never added in.
    """

    def __init__(
        self,
        majmin: str,
        name: str,
        stat_path: Path | str,
        diskstats_path: Path | str = DISKSTATS_DEFAULT,
    ) -> None:
        self.majmin = majmin
        self.name = name
        self.sysfs_stat = Path(stat_path)
        self.diskstats_path = Path(diskstats_path)
        major, _, minor = majmin.partition(":")
        self.major = major
        self.minor = minor

    def read(self) -> CounterSample:
        """Take one cumulative sample; raise on missing/unparsable primary."""
        fields = self.sysfs_stat.read_text(encoding="utf-8", errors="replace").split()
        # /sys/dev/block/<maj:min>/stat layout (stable prefix across kernel
        # versions with optional discard/flush suffix fields): index 4 is
        # writes completed, index 6 is sectors written, index 8 is I/O in
        # flight. The 512-byte unit is the kernel block-layer unit.
        if len(fields) < 9:
            raise ValueError(f"counter file has {len(fields)} fields, need >= 9")
        sample: CounterSample = {
            "sysfs_sectors_written": int(fields[6]),
            "writes_completed": int(fields[4]),
            "in_flight": int(fields[8]),
            "diskstats_sectors_written": None,
        }
        if (
            sample["sysfs_sectors_written"] < 0
            or sample["writes_completed"] < 0
            or sample["in_flight"] < 0
        ):
            raise ValueError("counter file holds a negative value")
        text = _read_text(self.diskstats_path)
        if text is not None:
            for line in text.splitlines():
                parts = line.split()
                # /proc/diskstats field 10 (1-based) is sectors written.
                if (
                    len(parts) >= 10
                    and parts[0] == self.major
                    and parts[1] == self.minor
                ):
                    try:
                        sectors = int(parts[9])
                    except ValueError:
                        break
                    if sectors >= 0:
                        sample["diskstats_sectors_written"] = sectors
                    break
        return sample


def try_read(handle: CounterHandle) -> CounterSample | None:
    """Best-effort single sample; ``None`` when the counter cannot be read."""
    try:
        return handle.read()
    except (OSError, ValueError, IndexError):
        return None


def _counter_int(value: Json) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def delta_bytes(
    before: CounterSample | JsonObject | None,
    after: CounterSample | JsonObject | None,
    key: str = "sysfs_sectors_written",
) -> int | None:
    """Byte delta between two cumulative samples, or ``None`` when unknown.

    ``None`` covers every non-attributable case: missing sample, missing key,
    non-integer value, and counter wrap/reset/recreation (``after < before``).
    A wrap never reports a negative value and never synthesizes zero as a
    measurement; callers treat ``None`` as unavailable.
    """
    if before is None or after is None:
        return None
    if not isinstance(before, dict) or not isinstance(after, dict):
        return None
    first = _counter_int(before.get(key))
    second = _counter_int(after.get(key))
    if first is None or second is None:
        return None
    if second < first:
        return None
    return (second - first) * SECTOR_BYTES


def identify_scope(
    scratch: Path | str,
    override: str | None = None,
    *,
    mountinfo_path: str | Path = MOUNTINFO_DEFAULT,
    sys_base: Path | str = SYS_BASE_DEFAULT,
    diskstats_path: str | Path = DISKSTATS_DEFAULT,
) -> tuple[CounterHandle | None, ScopeDoc]:
    """Identify the backing-counter scope for one filesystem path.

    Returns ``(handle, scope)`` where ``handle`` takes read-only samples
    when ``scope["status"] == "available"`` and is ``None`` otherwise. The
    scope document is JSON-serializable and carries no isolation verdict; the
    harness keeps its own strict gate.
    """
    sys_base_path = Path(sys_base)
    diskstats = Path(diskstats_path)
    real = str(Path(scratch).resolve())
    mechanisms: list[str] = [str(mountinfo_path)]
    info: ScopeDoc = {
        "scratch_realpath": real,
        "counter_unit": "sectors of 512 bytes (kernel block-layer unit)",
        "counter_scope": (
            "host-visible block-device writes when available; "
            "not flash-internal write amplification"
        ),
        "mount": None,
        "mechanisms_checked": mechanisms,
    }
    if _read_text(mountinfo_path, errors="surrogateescape") is None:
        info.update(
            status="unavailable",
            scope_kind="unavailable",
            reason=f"cannot read {mountinfo_path}: mount table is unavailable",
        )
        return None, info
    mounts = read_mountinfo(mountinfo_path)
    mount = pick_mount(real, mounts)
    info["mount"] = mount
    if mount is None:
        info.update(
            status="unavailable",
            scope_kind="unavailable",
            reason=(f"no {mountinfo_path} entry contains the scratch path"),
        )
        return None, info
    if override is not None and not _MAJMIN_RE.match(override):
        info.update(
            status="unavailable",
            scope_kind="unavailable",
            mapping="operator_asserted",
            reason=f"invalid --device override {override!r}: want MAJ:MIN",
        )
        return None, info
    if override is not None and override != mount["majmin"]:
        info.update(
            status="unavailable",
            scope_kind="unavailable",
            mapping="operator_asserted",
            reason=(
                f"override {override} does not match the mount's {mount['majmin']} "
                f"for {mount['mountpoint']}: no backing relationship between the "
                "named device and this filesystem is established, and operator "
                "assertion alone is not proof. Only the mount's own MAJ:MIN is "
                "accepted, and only on the ordinary-device path."
            ),
        )
        return None, info
    chosen = override if override is not None else mount["majmin"]
    info["mapping"] = (
        "operator_asserted" if override is not None else "mountinfo_major_minor"
    )
    fstype = mount["fstype"]
    if fstype == "zfs":
        info.update(
            status="unavailable",
            scope_kind="zfs_pool",
            reason=(
                f"ZFS dataset {mount['source']} on {mount['mountpoint']}: pool-wide "
                "accounting cannot isolate this filesystem's physical writes, and "
                "an aggregate or underlying-device counter cannot be attributed "
                "per filesystem. No pool total is converted into a per-filesystem "
                "value here."
            ),
        )
        return None, info
    if fstype == "btrfs":
        info.update(
            status="unavailable",
            scope_kind="ambiguous_multi_device",
            reason=(
                "btrfs spans one or more devices: a single-device counter cannot "
                "be assumed, and per-device counters cannot be summed into a "
                "filesystem value. No multi-device total is attributed."
            ),
        )
        return None, info
    major_text = chosen.split(":")[0] if ":" in chosen else ""
    major = int(major_text) if major_text.isdigit() else 0
    if _is_composite_fstype(fstype) or major == 0:
        info.update(
            status="unavailable",
            scope_kind="composite_anonymous",
            reason=(
                f"{fstype} on anonymous device {mount['majmin']}: no per-filesystem "
                "block counter maps to this mount, and an aggregate or "
                "underlying-device counter cannot be isolated per filesystem. "
                "This is reported as unavailable, never zero or an estimate."
            ),
        )
        return None, info
    sysdir = sys_base_path / chosen
    stat_path = sysdir / "stat"
    mechanisms.append(str(stat_path))
    mechanisms.append(str(diskstats))
    if not stat_path.exists():
        info.update(
            status="unavailable",
            scope_kind="regular_block_device",
            majmin=chosen,
            sysfs_stat=str(stat_path),
            reason=f"{stat_path} does not exist",
        )
        return None, info
    try:
        real_sys = sysdir.resolve()
    except OSError as error:
        info.update(
            status="unavailable",
            scope_kind="regular_block_device",
            majmin=chosen,
            sysfs_stat=str(stat_path),
            reason=f"cannot resolve {sysdir}: {error}",
        )
        return None, info
    slaves_dir = real_sys / "slaves"
    holders_dir = real_sys / "holders"
    mechanisms.append(str(slaves_dir))
    mechanisms.append(str(holders_dir))
    slaves = _child_names(slaves_dir)
    holders = _child_names(holders_dir)
    if slaves is None or holders is None:
        blocked = slaves_dir if slaves is None else holders_dir
        info.update(
            status="unavailable",
            scope_kind="unavailable",
            majmin=chosen,
            sysfs_stat=str(stat_path),
            reason=(
                f"cannot list {blocked}: device topology is unreadable, "
                "so stacking cannot be ruled out"
            ),
        )
        return None, info
    shared = [
        str(entry["mountpoint"])
        for entry in mounts
        if entry["majmin"] == chosen and entry is not mount
    ]
    partition = (real_sys / "partition").exists()
    disk_dir = real_sys.parent if partition else real_sys
    queue_dir = disk_dir / "queue"
    mechanisms.append(str(queue_dir))
    model_path = disk_dir / "device" / "model"
    mechanisms.append(str(model_path))
    if slaves:
        info.update(
            status="unavailable",
            scope_kind="ambiguous_multi_device",
            majmin=chosen,
            name=real_sys.name,
            sysfs_stat=str(stat_path),
            partition=partition,
            parent_disk=disk_dir.name,
            stacked_slaves=slaves,
            holders=holders,
            shared_mounts=shared,
            reason=(
                f"stacked device over {slaves}: a mapped device is never assumed "
                "to be a single disk, and per-device counters are never summed "
                "into one filesystem value. Mapping is ambiguous by design."
            ),
        )
        return None, info
    handle = CounterHandle(chosen, real_sys.name, stat_path, diskstats)
    try:
        handle.read()
    except (OSError, ValueError, IndexError) as error:
        info.update(
            status="unavailable",
            scope_kind="regular_block_device",
            majmin=chosen,
            name=real_sys.name,
            sysfs_stat=str(stat_path),
            partition=partition,
            parent_disk=disk_dir.name,
            stacked_slaves=slaves,
            holders=holders,
            shared_mounts=shared,
            reason=f"cannot parse {stat_path}: {error}",
        )
        return None, info
    queue: dict[str, str | None] = {}
    for key in QUEUE_KEYS:
        queue[key] = _read_stripped(queue_dir / key)
    notes: list[str] = [
        "the counter is host-wide for this block device: every writer to it is included"
    ]
    if holders:
        notes.append(f"devices {holders} are stacked on this one")
    if shared:
        notes.append(f"other mounts share this device: {shared}")
    if override is not None:
        notes.append("device mapping asserted by the operator (--device)")
    info.update(
        status="available",
        scope_kind="regular_block_device",
        majmin=chosen,
        name=real_sys.name,
        sysfs_stat=str(stat_path),
        partition=partition,
        parent_disk=disk_dir.name,
        stacked_slaves=slaves,
        holders=holders,
        shared_mounts=shared,
        queue=queue,
        model=_read_stripped(model_path),
        notes=notes,
    )
    return handle, info


def _scope_json(scope: ScopeDoc) -> str:
    return json.dumps(scope, indent=2, sort_keys=True)


def _parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = top.add_subparsers(dest="command", required=True)
    for name in ("identify", "sample"):
        cmd = sub.add_parser(
            name,
            help=(
                "identify the backing-counter scope"
                if name == "identify"
                else "identify the scope and take one read-only sample"
            ),
        )
        cmd.add_argument(
            "--path", required=True, help="directory on the filesystem under test"
        )
        cmd.add_argument(
            "--device",
            help="MAJ:MIN override, must equal the mount's own MAJ:MIN; a different device is rejected",
        )
        cmd.add_argument("--mountinfo", default=MOUNTINFO_DEFAULT)
        cmd.add_argument("--sys-base", default=str(SYS_BASE_DEFAULT))
        cmd.add_argument("--diskstats", default=DISKSTATS_DEFAULT)
    return top


def main(argv: list[str] | None = None) -> int:
    """Bounded read-only CLI for parent live observation."""
    args = _parser().parse_args(argv)
    handle, scope = identify_scope(
        args.path,
        args.device,
        mountinfo_path=args.mountinfo,
        sys_base=args.sys_base,
        diskstats_path=args.diskstats,
    )
    if args.command == "identify":
        print(_scope_json(scope))
        return 0
    sample = try_read(handle) if handle is not None else None
    if sample is None and handle is not None:
        scope["sample_error"] = f"cannot parse {handle.sysfs_stat}"
    print(json.dumps({"scope": scope, "sample": sample}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
