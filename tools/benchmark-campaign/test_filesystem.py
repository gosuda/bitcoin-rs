# pyright: strict
"""Contract tests for the filesystem-aware Linux measurement boundary."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))

import filesystem
from filesystem import (
    CounterHandle,
    delta_bytes,
    identify_scope,
    pick_mount,
    read_mountinfo,
    unescape_mountinfo,
)

STAT_FIELDS = ["0"] * 17


class MountSpec:
    def __init__(
        self,
        mount_id: str = "1",
        majmin: str = "8:1",
        point: str = "/",
        fstype: str = "ext4",
        source: str = "/dev/sda1",
    ) -> None:
        self.mount_id = mount_id
        self.majmin = majmin
        self.point = point
        self.fstype = fstype
        self.source = source


def _stat_text(sectors: int, writes: int = 10, inflight: int = 0) -> str:
    fields = list(STAT_FIELDS)
    fields[4] = str(writes)
    fields[6] = str(sectors)
    fields[8] = str(inflight)
    return " ".join(fields) + "\n"


def _mountline(spec: MountSpec) -> str:
    return (
        f"{spec.mount_id} 0 {spec.majmin} / {spec.point} rw,relatime - "
        f"{spec.fstype} {spec.source} rw"
    )


def _write_mountinfo(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class DeviceFixture:
    def __init__(self, stat_text: str = "") -> None:
        self.stat_text = stat_text
        self.slaves: list[str] = []
        self.holders: list[str] = []
        self.partition = False


def _make_device(sys_base: Path, majmin: str, fixture: DeviceFixture) -> Path:
    devdir = sys_base / majmin
    devdir.mkdir(parents=True, exist_ok=True)
    (devdir / "stat").write_text(fixture.stat_text, encoding="utf-8")
    for dirname, entries in (("slaves", fixture.slaves), ("holders", fixture.holders)):
        sub = devdir / dirname
        sub.mkdir(exist_ok=True)
        for entry in entries:
            (sub / entry).write_text("", encoding="utf-8")
    if fixture.partition:
        (devdir / "partition").write_text("", encoding="utf-8")
    queue = devdir / "queue"
    queue.mkdir(exist_ok=True)
    (queue / "rotational").write_text("1\n", encoding="utf-8")
    return devdir / "stat"


def _ext4_device(sectors: int) -> DeviceFixture:
    return DeviceFixture(_stat_text(sectors))


def _standard_mount(majmin: str, point: str) -> MountSpec:
    source = "/dev/" + majmin.replace(":", "_")
    return MountSpec(majmin=majmin, point=point, source=source)


def _standard_table(root: Path, spec: MountSpec) -> Path:
    table = root / "mountinfo"
    _write_mountinfo(table, [_mountline(spec)])
    return table


def _real_scratch(root: Path, name: str = "scratch") -> Path:
    """Create a real scratch directory; ``identify_scope`` stats it."""
    scratch = root / name
    scratch.mkdir(parents=True, exist_ok=True)
    return scratch


def _mount_dict(mount_id: str, majmin: str, point: str) -> filesystem.MountInfo:
    return {
        "mount_id": mount_id,
        "parent_id": "0",
        "majmin": majmin,
        "root": "/",
        "mountpoint": point,
        "mount_options": "rw",
        "fstype": "ext4",
        "source": "/dev/sda1",
        "super_options": "rw",
    }


class MountBoundaryTests(unittest.TestCase):
    def test_longest_prefix_wins(self) -> None:
        mounts = [
            _mount_dict("1", "8:1", "/"),
            _mount_dict("2", "8:2", "/data"),
            _mount_dict("3", "8:3", "/data/sub"),
        ]
        picked = pick_mount("/data/sub/x", mounts)
        assert picked is not None
        self.assertEqual(picked["majmin"], "8:3")
        picked = pick_mount("/data/other", mounts)
        assert picked is not None
        self.assertEqual(picked["majmin"], "8:2")

    def test_sibling_prefix_does_not_match(self) -> None:
        mounts = [_mount_dict("1", "8:1", "/"), _mount_dict("2", "8:2", "/data")]
        picked = pick_mount("/data2/x", mounts)
        assert picked is not None
        self.assertEqual(picked["majmin"], "8:1")

    def test_exact_mountpoint_matches(self) -> None:
        picked = pick_mount("/srv", [_mount_dict("7", "8:9", "/srv")])
        assert picked is not None
        self.assertEqual(picked["majmin"], "8:9")

    def test_no_table_entry_gives_none(self) -> None:
        self.assertIsNone(pick_mount("/nothing/here", []))

    def test_nonutf8_child_mount_maps_to_child(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Surrogateescaped names stay ``str``; ``pathlib`` syscalls
            # re-encode them to the original non-UTF8 bytes.
            raw_child = root / os.fsdecode(b"\xffraw")
            raw_child.mkdir()
            (raw_child / "scratch").mkdir()
            child = str(raw_child)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:2", _ext4_device(11))
            table = root / "mountinfo"
            _write_mountinfo(
                table,
                [
                    _mountline(MountSpec(majmin="8:1", point="/", source="/dev/sda1")),
                    _mountline(
                        MountSpec(
                            majmin="8:2",
                            point=str(root) + r"/\377raw",
                            source="/dev/sdb1",
                        )
                    ),
                ],
            )
            handle, scope = identify_scope(
                child + "/scratch", mountinfo_path=table, sys_base=sys_base
            )
            self.assertEqual(scope["status"], "available")
            self.assertEqual(scope["majmin"], "8:2")
            mount = scope.get("mount")
            assert isinstance(mount, dict)
            self.assertEqual(mount.get("mountpoint"), child)
            assert handle is not None
            self.assertEqual(handle.read()["sysfs_sectors_written"], 11)


class EscapeTests(unittest.TestCase):
    def test_octal_escapes_decode(self) -> None:
        self.assertEqual(unescape_mountinfo(r"/mnt/my\040dir"), "/mnt/my dir")
        self.assertEqual(unescape_mountinfo(r"/mnt/a\012b"), "/mnt/a\nb")
        self.assertEqual(unescape_mountinfo(r"/mnt/a\134b"), r"/mnt/a\b")

    def test_mountinfo_escaped_mountpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            table = Path(tmp) / "mountinfo"
            spec = MountSpec(point=r"/mnt/my\040dir")
            _write_mountinfo(table, [_mountline(spec)])
            mounts = read_mountinfo(table)
        self.assertEqual(len(mounts), 1)
        self.assertEqual(mounts[0]["mountpoint"], "/mnt/my dir")

    def test_mountinfo_splits_only_on_newline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            table = Path(tmp) / "mountinfo"
            table.write_text(
                "1 0 8:1 / /data\x0braw rw,relatime - ext4 /dev/sda1 rw\n"
                "2 0 8:2 / /other\x0craw rw,relatime - ext4 /dev/sda2 rw\n"
                "3 0 8:3 / /car\riageraw rw,relatime - ext4 /dev/sda3 rw\n",
                encoding="utf-8",
            )
            mounts = read_mountinfo(table)
        self.assertEqual(
            [mount["mountpoint"] for mount in mounts],
            ["/data\x0braw", "/other\x0craw", "/car\riageraw"],
        )

    def test_mountinfo_keeps_carriage_return_without_read_text_newline(
        self,
    ) -> None:
        # Python 3.12 Path.read_text has no ``newline`` argument; the reader
        # must still disable newline translation so a raw CR survives.
        with tempfile.TemporaryDirectory() as tmp:
            table = Path(tmp) / "mountinfo"
            table.write_bytes(
                b"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
                b"2 1 8:2 / /car\riage rw - ext4 /dev/sda2 rw\n"
            )

            def _no_newline(
                self: Path, encoding: str | None = None, errors: str | None = None
            ) -> str:
                # 3.12 read_text always applies universal-newline translation.
                text = self.read_bytes().decode(encoding or "utf-8", errors or "strict")
                return text.replace("\r\n", "\n").replace("\r", "\n")

            with mock.patch.object(Path, "read_text", _no_newline):
                mounts = read_mountinfo(table)
        self.assertEqual(
            [mount["mountpoint"] for mount in mounts], ["/", "/car\riage"]
        )

    def test_mountinfo_malformed_lines_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            table = Path(tmp) / "mountinfo"
            table.write_text("garbage without separator\n", encoding="utf-8")
            self.assertEqual(read_mountinfo(table), [])

    def test_mountinfo_missing_file_is_empty(self) -> None:
        self.assertEqual(read_mountinfo("/nonexistent-mountinfo-xyz"), [])

    def test_invalid_octal_escape_skips_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", _ext4_device(4))
            table = root / "mountinfo"
            _write_mountinfo(
                table,
                [
                    _mountline(
                        MountSpec(
                            mount_id="9",
                            majmin="8:9",
                            point=r"/bad\777dir",
                            source="/dev/sdz1",
                        )
                    ),
                    _mountline(MountSpec(majmin="8:1", point="/", source="/dev/sda1")),
                ],
            )
            mounts = read_mountinfo(table)
            self.assertEqual([mount["majmin"] for mount in mounts], ["8:1"])
            _handle, scope = identify_scope(
                "/", mountinfo_path=table, sys_base=sys_base
            )
            self.assertEqual(scope["status"], "available")
            self.assertEqual(scope["majmin"], "8:1")


class CounterTests(unittest.TestCase):
    def test_available_regular_device(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "259:2", _ext4_device(1000))
            diskstats = root / "diskstats"
            diskstats.write_text(
                "259   2 nvme0n1p2 0 0 0 0 10 0 1000 0 0 0 0 0 0 0\n",
                encoding="utf-8",
            )
            table = _standard_table(root, _standard_mount("259:2", "/"))
            scratch = _real_scratch(root)
            handle, scope = identify_scope(
                scratch,
                mountinfo_path=table,
                sys_base=sys_base,
                diskstats_path=diskstats,
            )
            self.assertEqual(scope["status"], "available")
            self.assertEqual(scope["scope_kind"], "regular_block_device")
            self.assertIsNotNone(handle)
            assert handle is not None
            sample = handle.read()
            self.assertEqual(sample["sysfs_sectors_written"], 1000)
            self.assertEqual(sample["diskstats_sectors_written"], 1000)
            self.assertIn("mechanisms_checked", scope)
            self.assertNotIn("isolation", scope)

    def test_diskstats_missing_keeps_sysfs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", _ext4_device(42))
            table = _standard_table(root, _standard_mount("8:1", "/"))
            handle, scope = identify_scope(
                _real_scratch(root),
                mountinfo_path=table,
                sys_base=sys_base,
                diskstats_path=root / "no-diskstats",
            )
            self.assertEqual(scope["status"], "available")
            assert handle is not None
            self.assertIsNone(handle.read()["diskstats_sectors_written"])

    def test_stat_missing_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            table = _standard_table(root, _standard_mount("8:1", "/"))
            handle, scope = identify_scope(
                _real_scratch(root), mountinfo_path=table, sys_base=sys_base
            )
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")
            self.assertIn("reason", scope)

    def test_stat_unparsable_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", DeviceFixture("not a counter file\n"))
            table = _standard_table(root, _standard_mount("8:1", "/"))
            handle, scope = identify_scope(
                _real_scratch(root), mountinfo_path=table, sys_base=sys_base
            )
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")

    def test_short_stat_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", DeviceFixture("1 2 3\n"))
            table = _standard_table(root, _standard_mount("8:1", "/"))
            handle, scope = identify_scope(
                _real_scratch(root), mountinfo_path=table, sys_base=sys_base
            )
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")


class ScopeLabelTests(unittest.TestCase):
    def _scope_for(
        self, fstype: str, majmin: str, override: str | None = None
    ) -> tuple[CounterHandle | None, filesystem.ScopeDoc]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        sys_base = root / "sys"
        sys_base.mkdir()
        _make_device(sys_base, majmin, _ext4_device(5))
        spec = MountSpec(majmin=majmin, source="pool/dataset", fstype=fstype)
        table = _standard_table(root, spec)
        return identify_scope("/", override, mountinfo_path=table, sys_base=sys_base)

    def test_zfs_pool_scope(self) -> None:
        handle, scope = self._scope_for("zfs", "0:42")
        self.assertIsNone(handle)
        self.assertEqual(scope["status"], "unavailable")
        self.assertEqual(scope["scope_kind"], "zfs_pool")
        self.assertIn("pool", str(scope.get("reason", "")))

    def test_zfs_matching_override_stays_unavailable(self) -> None:
        handle, scope = self._scope_for("zfs", "0:42", override="0:42")
        self.assertIsNone(handle)
        self.assertEqual(scope["status"], "unavailable")
        self.assertEqual(scope["scope_kind"], "zfs_pool")

    def test_composite_anonymous_scope(self) -> None:
        for fstype in ("overlay", "tmpfs", "nfs"):
            handle, scope = self._scope_for(fstype, "0:33")
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")
            self.assertEqual(scope["scope_kind"], "composite_anonymous")

    def test_btrfs_is_ambiguous(self) -> None:
        handle, scope = self._scope_for("btrfs", "8:5")
        self.assertIsNone(handle)
        self.assertEqual(scope["status"], "unavailable")
        self.assertEqual(scope["scope_kind"], "ambiguous_multi_device")

    def test_multi_slave_is_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            fixture = DeviceFixture(_stat_text(77))
            fixture.slaves = ["8:1", "8:2"]
            _make_device(sys_base, "253:0", fixture)
            spec = MountSpec(majmin="253:0", source="/dev/dm-0")
            table = _standard_table(root, spec)
            handle, scope = identify_scope("/", mountinfo_path=table, sys_base=sys_base)
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")
            self.assertEqual(scope["scope_kind"], "ambiguous_multi_device")

    def test_single_slave_is_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            fixture = DeviceFixture(_stat_text(77))
            fixture.slaves = ["8:1"]
            _make_device(sys_base, "253:0", fixture)
            spec = MountSpec(majmin="253:0", source="/dev/dm-0")
            table = _standard_table(root, spec)
            handle, scope = identify_scope("/", mountinfo_path=table, sys_base=sys_base)
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")
            self.assertEqual(scope["scope_kind"], "ambiguous_multi_device")

    def test_no_mount_entry_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            table = root / "mountinfo"
            table.write_text("", encoding="utf-8")
            handle, scope = identify_scope(
                _real_scratch(root), mountinfo_path=table, sys_base=root / "sys"
            )
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")

    def test_bad_override_format_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            table = _standard_table(root, _standard_mount("8:1", "/"))
            handle, scope = identify_scope(
                "/", "bogus", mountinfo_path=table, sys_base=sys_base
            )
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")

    def test_matching_override_stays_available(self) -> None:
        handle, scope = self._scope_for("ext4", "8:1", override="8:1")
        self.assertEqual(scope["status"], "available")
        self.assertEqual(scope["mapping"], "operator_asserted")
        assert handle is not None
        self.assertEqual(handle.read()["sysfs_sectors_written"], 5)

    def test_mismatched_override_is_rejected(self) -> None:
        handle, scope = self._scope_for("ext4", "8:1", override="8:2")
        self.assertIsNone(handle)
        self.assertEqual(scope["status"], "unavailable")
        self.assertIn("override", str(scope.get("reason", "")))

    def test_zfs_mismatched_override_is_rejected(self) -> None:
        handle, scope = self._scope_for("zfs", "0:42", override="8:1")
        self.assertIsNone(handle)
        self.assertEqual(scope["status"], "unavailable")
        self.assertIn("override", str(scope.get("reason", "")))

    def test_permission_denied_stat_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", _ext4_device(9))
            table = _standard_table(root, _standard_mount("8:1", "/"))
            real_read = Path.read_text

            def _denied(
                self: Path,
                encoding: str | None = None,
                errors: str | None = None,
                newline: str | None = None,
            ) -> str:
                if self.name == "stat":
                    raise PermissionError(13, "Permission denied")
                return real_read(
                    self, encoding=encoding, errors=errors, newline=newline
                )

            with mock.patch.object(Path, "read_text", _denied):
                handle, scope = identify_scope(
                    "/", mountinfo_path=table, sys_base=sys_base
                )
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")
            self.assertIn("reason", scope)

    def test_unreadable_topology_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", _ext4_device(9))
            table = _standard_table(root, _standard_mount("8:1", "/"))
            real_iterdir = Path.iterdir

            def _denied(self: Path) -> object:
                if self.name == "slaves":
                    raise PermissionError(13, "Permission denied")
                return real_iterdir(self)

            with mock.patch.object(Path, "iterdir", _denied):
                handle, scope = identify_scope(
                    "/", mountinfo_path=table, sys_base=sys_base
                )
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")
            self.assertIn("slaves", str(scope.get("reason", "")))

    def test_unreadable_mountinfo_names_cause(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            table = _standard_table(root, _standard_mount("8:1", "/"))
            real_open = Path.open

            def _denied(self: Path, *args: object, **kwargs: object) -> object:
                if self == table:
                    raise PermissionError(13, "Permission denied")
                return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

            with mock.patch.object(Path, "open", _denied):
                handle, scope = identify_scope(
                    "/", mountinfo_path=table, sys_base=sys_base
                )
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")
            self.assertIn("cannot read", str(scope.get("reason", "")))


class NoDoubleCountTests(unittest.TestCase):
    def test_partition_counter_used_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            (sys_base / "259:0").mkdir(parents=True)
            (sys_base / "259:0" / "stat").write_text(
                _stat_text(99999), encoding="utf-8"
            )
            fixture = DeviceFixture(_stat_text(100))
            fixture.partition = True
            _make_device(sys_base, "259:2", fixture)
            diskstats = root / "diskstats"
            diskstats.write_text(
                "259   0 nvme0n1 0 0 0 0 0 0 99999 0 0 0 0 0 0 0\n"
                "259   2 nvme0n1p2 0 0 0 0 9 0 100 0 0 0 0 0 0 0\n",
                encoding="utf-8",
            )
            table = _standard_table(root, _standard_mount("259:2", "/"))
            handle, scope = identify_scope(
                _real_scratch(root),
                mountinfo_path=table,
                sys_base=sys_base,
                diskstats_path=diskstats,
            )
            assert handle is not None
            self.assertEqual(scope["status"], "available")
            self.assertEqual(scope["scope_kind"], "regular_block_device")
            self.assertEqual(scope["partition"], True)
            sample = handle.read()
            self.assertEqual(sample["sysfs_sectors_written"], 100)
            after: filesystem.CounterSample = {
                "sysfs_sectors_written": 110,
                "writes_completed": sample["writes_completed"],
                "in_flight": sample["in_flight"],
                "diskstats_sectors_written": sample["diskstats_sectors_written"],
            }
            self.assertEqual(delta_bytes(sample, after), 10 * filesystem.SECTOR_BYTES)

    def test_malformed_mount_majmin_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            for majmin in ("\u00b2:1", "\u0663:1", "8", "../8:1"):
                table = _standard_table(root, _standard_mount(majmin, "/"))
                handle, scope = identify_scope(
                    "/", mountinfo_path=table, sys_base=sys_base
                )
                self.assertIsNone(handle)
                self.assertEqual(scope["status"], "unavailable")
                self.assertIn("malformed", str(scope.get("reason", "")))

    def test_partition_of_stacked_device_is_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            disk = root / "devices" / "md0"
            (disk / "slaves" / "sda").mkdir(parents=True)
            (disk / "slaves" / "sdb").mkdir()
            part = disk / "md0p1"
            (part / "slaves").mkdir(parents=True)
            (part / "holders").mkdir()
            (part / "partition").write_text("1\n", encoding="utf-8")
            (part / "stat").write_text(_stat_text(100), encoding="utf-8")
            sys_base.mkdir()
            (sys_base / "259:1").symlink_to(part)
            table = _standard_table(root, _standard_mount("259:1", "/"))
            handle, scope = identify_scope(
                _real_scratch(root), mountinfo_path=table, sys_base=sys_base
            )
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")
            self.assertEqual(scope["scope_kind"], "ambiguous_multi_device")
            self.assertEqual(scope["stacked_slaves"], ["sda", "sdb"])


class DeltaTests(unittest.TestCase):
    def _sample(self, sectors: int) -> filesystem.CounterSample:
        return {
            "sysfs_sectors_written": sectors,
            "writes_completed": 9,
            "in_flight": 0,
            "diskstats_sectors_written": sectors,
        }

    def test_normal_delta_scales_by_sector(self) -> None:
        before = self._sample(100)
        after = self._sample(110)
        self.assertEqual(delta_bytes(before, after), 10 * 512)

    def test_wrap_reset_gives_none(self) -> None:
        self.assertIsNone(delta_bytes(self._sample(500), self._sample(12)))

    def test_missing_inputs_give_none(self) -> None:
        self.assertIsNone(delta_bytes(None, None))
        before = self._sample(5)
        after: filesystem.CounterSample = {
            "sysfs_sectors_written": before["sysfs_sectors_written"],
            "writes_completed": before["writes_completed"],
            "in_flight": before["in_flight"],
            "diskstats_sectors_written": None,
        }
        self.assertIsNone(delta_bytes(before, after, "diskstats_sectors_written"))
        self.assertIsNone(delta_bytes(before, before, "no_such_key"))

    def test_equal_counters_give_zero(self) -> None:
        sample = self._sample(7)
        self.assertEqual(delta_bytes(sample, self._sample(7)), 0)

    def test_cli_identify_and_sample(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", _ext4_device(3))
            table = _standard_table(root, _standard_mount("8:1", "/"))
            base_args = ["--mountinfo", str(table), "--sys-base", str(sys_base)]
            self.assertEqual(
                filesystem.main(["identify", "--path", "/"] + base_args), 0
            )
            self.assertEqual(filesystem.main(["sample", "--path", "/"] + base_args), 0)

    def test_scope_json_serializable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", _ext4_device(3))
            table = _standard_table(root, _standard_mount("8:1", "/"))
            _, scope = identify_scope("/", mountinfo_path=table, sys_base=sys_base)
        json.dumps(scope)


class ScratchValidationTests(unittest.TestCase):
    def _available_fixture(
        self, root: Path
    ) -> tuple[Path, Path, Path]:
        sys_base = root / "sys"
        sys_base.mkdir()
        _make_device(sys_base, "8:1", _ext4_device(5))
        table = _standard_table(root, _standard_mount("8:1", "/"))
        return sys_base, table, _real_scratch(root)

    def test_removed_scratch_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base, table, scratch = self._available_fixture(root)
            scratch.rmdir()
            handle, scope = identify_scope(
                scratch, mountinfo_path=table, sys_base=sys_base
            )
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")
            self.assertIn("cannot stat", str(scope.get("reason", "")))

    def test_file_scratch_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", _ext4_device(5))
            table = _standard_table(root, _standard_mount("8:1", "/"))
            candidate = root / "file-scratch"
            candidate.write_text("not a directory", encoding="utf-8")
            handle, scope = identify_scope(
                candidate, mountinfo_path=table, sys_base=sys_base
            )
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")
            self.assertIn("not a directory", str(scope.get("reason", "")))

    def test_mechanisms_include_scratch_stat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base, table, scratch = self._available_fixture(root)
            handle, scope = identify_scope(
                scratch, mountinfo_path=table, sys_base=sys_base
            )
            self.assertEqual(scope["status"], "available")
            assert handle is not None
            mechanisms = scope.get("mechanisms_checked")
            assert isinstance(mechanisms, list)
            self.assertIn(str(scratch.resolve()), mechanisms)


class MountParseStrictnessTests(unittest.TestCase):
    def test_consecutive_spaces_line_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            table = Path(tmp) / "mountinfo"
            table.write_text(
                "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
                "2  0 8:2 / /data rw,relatime - ext4 /dev/sdb1 rw\n",
                encoding="utf-8",
            )
            mounts = read_mountinfo(table)
            self.assertEqual([mount["majmin"] for mount in mounts], ["8:1"])

    def test_consecutive_spaces_do_not_misattribute_scratch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scratch = _real_scratch(root)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", _ext4_device(5))
            table = root / "mountinfo"
            _write_mountinfo(
                table,
                [
                    _mountline(MountSpec(majmin="8:1", point="/", source="/dev/sda1")),
                    f"9  0 8:9 / {scratch} rw,relatime - ext4 /dev/sdz1 rw",
                ],
            )
            handle, scope = identify_scope(
                scratch, mountinfo_path=table, sys_base=sys_base
            )
            self.assertEqual(scope["status"], "available")
            self.assertEqual(scope["majmin"], "8:1")


class CounterBoundTests(unittest.TestCase):
    def test_huge_sysfs_counter_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", DeviceFixture(_stat_text(1 << 64)))
            handle = CounterHandle(
                "8:1", "sda", sys_base / "8:1" / "stat", root / "no-diskstats"
            )
            with self.assertRaises(ValueError):
                handle.read()

    def test_huge_counter_makes_scope_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", DeviceFixture(_stat_text(1 << 64)))
            table = _standard_table(root, _standard_mount("8:1", "/"))
            handle, scope = identify_scope(
                _real_scratch(root), mountinfo_path=table, sys_base=sys_base
            )
            self.assertIsNone(handle)
            self.assertEqual(scope["status"], "unavailable")
            self.assertIn("2**64", str(scope.get("reason", "")))

    def test_huge_diskstats_value_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sys_base = root / "sys"
            sys_base.mkdir()
            _make_device(sys_base, "8:1", _ext4_device(42))
            diskstats = root / "diskstats"
            diskstats.write_text(
                f"8 1 sda 0 0 0 0 0 0 {1 << 64} 0 0 0 0 0 0\n", encoding="utf-8"
            )
            table = _standard_table(root, _standard_mount("8:1", "/"))
            handle, scope = identify_scope(
                _real_scratch(root),
                mountinfo_path=table,
                sys_base=sys_base,
                diskstats_path=diskstats,
            )
            self.assertEqual(scope["status"], "available")
            assert handle is not None
            self.assertIsNone(handle.read()["diskstats_sectors_written"])

    def test_delta_rejects_out_of_range_counters(self) -> None:
        before: filesystem.CounterSample = {
            "sysfs_sectors_written": 1 << 64,
            "writes_completed": 9,
            "in_flight": 0,
            "diskstats_sectors_written": None,
        }
        after: filesystem.CounterSample = {
            "sysfs_sectors_written": (1 << 64) + 10,
            "writes_completed": 9,
            "in_flight": 0,
            "diskstats_sectors_written": None,
        }
        self.assertIsNone(delta_bytes(before, after))


if __name__ == "__main__":
    unittest.main()
