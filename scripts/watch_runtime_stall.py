#!/usr/bin/env python3
"""Linux, operator-started one-shot watchdog for missing node telemetry.

Requires a dedicated INFO log, matching executable/debug symbols and GDB with
permission to attach. Capture pauses the node while GDB inspects it. No node
locks, RPC, logger or metrics endpoint are used. See docs/operations/runtime-stall.md.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile
import time

READ_LIMIT = 1024 * 1024
GDB_TIMEOUT = 30


def limit_debugger_output() -> None:
    """The single-threaded watchdog constrains its child before exec."""
    limit = 16 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


@dataclass(frozen=True)
class Process:
    pid: int
    start_ticks: str


def snapshot_process(pid: int) -> Process | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except FileNotFoundError:
        return None
    if len(fields) < 20:
        raise ValueError("malformed /proc process identity")
    return None if fields[0] in ("Z", "X") else Process(pid, fields[19])


@dataclass(frozen=True)
class Cursor:
    device: int
    inode: int
    offset: int
    suffix: bytes = b""


def read_progress(log: Path, cursor: Cursor | None) -> tuple[Cursor | None, bool]:
    try:
        stream = log.open("rb")
    except FileNotFoundError:
        if cursor is None:
            raise
        return cursor, False  # Rename-and-recreate rotation may leave a gap.
    with stream:
        stat = os.fstat(stream.fileno())
        if cursor is None:
            # Old log lines cannot masquerade as fresh progress.
            return Cursor(stat.st_dev, stat.st_ino, stat.st_size), False
        offset, suffix = cursor.offset, cursor.suffix
        same_file = (cursor.device, cursor.inode) == (stat.st_dev, stat.st_ino)
        truncated = not same_file or stat.st_size < offset
        if not truncated and suffix:
            # Copy-truncate can refill the log past the previous offset
            # before the next poll: (device, inode) and the size then look
            # unchanged while the bytes under the carried partial line have
            # been replaced, and resuming at the stale offset would skip
            # fresh progress lines. A normal append never rewrites bytes
            # below the previous end of file, so a mismatch means rewrite.
            stream.seek(offset - len(suffix))
            truncated = stream.read(len(suffix)) != suffix
        if truncated:
            offset, suffix = 0, b""
        if stat.st_size - offset > READ_LIMIT:
            offset, suffix = stat.st_size - READ_LIMIT, b""
        stream.seek(offset)
        data = suffix + stream.read(READ_LIMIT)
        end = data.rfind(b"\n")
        complete = data[:end + 1]
        suffix = data[end + 1:][-128:]
        return Cursor(stat.st_dev, stat.st_ino, stream.tell(), suffix), b"sync progress" in complete


def wait_for_stall(identity: Process, log: Path, timeout: float) -> bool:
    cursor, _ = read_progress(log, None)
    last = time.monotonic()
    while snapshot_process(identity.pid) == identity:
        cursor, progressed = read_progress(log, cursor)
        now = time.monotonic()
        if progressed:
            last = now
        elif now - last >= timeout:
            return True
        time.sleep(min(1.0, timeout / 4))
    return False


def write_result(directory: Path, identity: Process, log: Path, debugger_argv: list[str] | None,
                 returncode: int | None, complete: bool, reason: str,
                 identity_changed_after_attach: bool = False) -> None:
    """Every terminal capture outcome records the same auditable identity."""
    payload: dict[str, object] = {
        "pid": identity.pid, "start_ticks": identity.start_ticks,
        "log": str(log), "debugger_argv": debugger_argv, "returncode": returncode,
        "complete": complete, "reason": reason,
        "interpretation": "Capture is evidence to inspect, not a deadlock verdict or automatic lock-owner attribution.",
    }
    if identity_changed_after_attach:
        payload["identity_changed_after_attach"] = True
    (directory / "result.json").write_text(json.dumps(payload, indent=2) + "\n")


def preflight_attach(identity: Process, debugger: str) -> None:
    """Probe attach permission now: a ptrace-denying host would otherwise burn
    the whole --timeout before the real capture failed. The dry attach
    momentarily pauses the target once more before the diagnostic run. The
    target identity is checked around the probe so a recycled PID is never
    attached."""
    if snapshot_process(identity.pid) != identity:
        raise ProcessLookupError(
            f"target exited or PID was reused before attach preflight (PID {identity.pid})")
    handle, name = tempfile.mkstemp(prefix=f"stall-preflight-{identity.pid}-", suffix=".gdb")
    commands = Path(name)
    try:
        with os.fdopen(handle, "w") as stream:
            stream.write(f"set pagination off\nset confirm off\nattach {identity.pid}\ndetach\n")
        # Command-file errors stop the batch, unlike separate -ex commands.
        probe = subprocess.run(
            [debugger, "--batch", "--nx", "--nh",
             "-iex", "set auto-load off", "-iex", "set debuginfod enabled off",
             "-x", str(commands)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=GDB_TIMEOUT)
        if snapshot_process(identity.pid) != identity:
            raise ProcessLookupError(
                f"target exited or PID was reused during attach preflight (PID {identity.pid})")
        output = probe.stdout + probe.stderr
        if "Operation not permitted" in output or "ptrace: " in output:
            raise RuntimeError(
                "ptrace denied during attach preflight; grant GDB permission through "
                "kernel.yama.ptrace_scope or CAP_SYS_PTRACE before starting the watchdog: "
                + output.strip()[-300:])
        if probe.returncode != 0:
            raise RuntimeError(
                "dry attach failed during attach preflight; inspect the debugger output: "
                + output.strip()[-300:])
    finally:
        commands.unlink(missing_ok=True)


def capture(identity: Process, log: Path, output: Path, debugger: str) -> Path:
    if snapshot_process(identity.pid) != identity:
        raise ProcessLookupError("target exited or PID was reused before capture")
    directory = Path(tempfile.mkdtemp(prefix=f"stall-{identity.pid}-", dir=output))
    # A private 0700 directory contains possibly sensitive thread/debugger data.
    try:
        with log.open("rb") as stream:
            stream.seek(max(0, os.fstat(stream.fileno()).st_size - READ_LIMIT))
            (directory / "telemetry-tail.log").write_bytes(stream.read(READ_LIMIT))
    except FileNotFoundError:
        (directory / "telemetry-tail.log").write_text("Log unavailable during rotation.\n")
    proc = Path(f"/proc/{identity.pid}")
    try:
        tasks = []
        for task in (proc / "task").iterdir():
            tasks.append(task)
            if len(tasks) == 257:
                break
    except FileNotFoundError as error:
        # The identity check just passed, so a vanished task directory means
        # the target exited in the gap before the kernel snapshot; the
        # partial directory already holds the telemetry tail and must stay
        # audited instead of stranding an unaudited raise.
        write_result(directory, identity, log, None, None, False,
                     "target exited before kernel snapshot")
        raise ProcessLookupError(
            f"target exited before kernel snapshot; partial evidence: {directory}") from error
    with (directory / "kernel-waits.txt").open("x") as stream:
        stream.write("Kernel waits are not userspace mutex-owner backtraces.\n")
        for index, task in enumerate(tasks):
            if index == 256:
                stream.write("Thread snapshot truncated at 256 threads.\n")
                break
            for name in ("comm", "wchan", "stack"):
                try:
                    with (task / name).open("rb") as source:
                        value = source.read(4096).decode(errors="replace")
                except OSError as error:
                    value = f"unavailable: {error}"
                stream.write(f"\n{task.name}/{name}: {value}\n")
    if snapshot_process(identity.pid) != identity:
        # The partial directory already holds evidence; an unaudited raise
        # would strand it without a result.json explaining the early exit.
        write_result(directory, identity, log, None, None, False,
                     "target exited during kernel snapshot, before debugger attach")
        raise ProcessLookupError(f"target exited before debugger attach; partial evidence: {directory}")
    commands = directory / "capture.gdb"
    # A command-file error stops execution. Separate -ex commands can keep
    # running after a denied attach and even finish with exit status zero.
    commands.write_text(
        "set pagination off\nset confirm off\nset print frame-arguments none\n"
        f"attach {identity.pid}\ninfo threads\nthread apply all -c bt 32\n"
        "detach\necho STALL_CAPTURE_COMPLETE\\n\n"
    )
    argv = [debugger, "--batch", "--nx", "--nh",
            "-iex", "set auto-load off", "-iex", "set debuginfod enabled off",
            "-x", str(commands)]
    native: int | None = None
    interrupted: KeyboardInterrupt | None = None
    with (directory / "threads.txt").open("xb") as stream:
        with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream,
                              stderr=subprocess.STDOUT, start_new_session=True,
                              preexec_fn=limit_debugger_output) as child:
            try:
                native = child.wait(timeout=GDB_TIMEOUT)
            except subprocess.TimeoutExpired:
                pass  # Native None records an incomplete diagnostic.
            except KeyboardInterrupt as error:
                interrupted = error
            finally:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
    if interrupted is not None:
        write_result(directory, identity, log, argv, None, False,
                     "capture stopped after operator interrupt before the debugger finished")
        raise interrupted
    # Re-read identity only after the child exits: PID recycling between
    # attach and dump must not pass as a complete capture of the original
    # start_ticks, so a changed identity forces an incomplete result.
    identity_changed = snapshot_process(identity.pid) != identity
    # Preserve failure output. A refused attach or timeout is not a capture.
    # Count over the whole file: the child is capped at 16 MiB by
    # RLIMIT_FSIZE, while a 1 MiB tail would scroll early thread blocks out
    # of view and hide a thread whose backtrace errored.
    with (directory / "threads.txt").open("rb") as stream:
        threads = stream.read()
    lines = threads.splitlines()
    # `-c` continues past per-thread errors, so an aborted sweep still prints
    # the marker with fewer top frames than thread headers. Only
    # `Thread N (LWP x):` lines count as thread-apply block headers; an
    # attach-time notification is not a block. Any unresolved frame violates
    # the documented matching-symbols precondition.
    headers = sum(1 for line in lines
                  if line.startswith(b"Thread ") and b" (LWP " in line)
    top_frames = sum(1 for line in lines if line.startswith(b"#0 "))
    unresolved = any(line.startswith(b"#") and b" in ?? ()" in line for line in lines)
    complete = (native == 0 and b"STALL_CAPTURE_COMPLETE" in threads
                and headers >= 1 and headers == top_frames
                and not unresolved and not identity_changed)
    write_result(directory, identity, log, argv, native, complete,
                 "sync telemetry missed its monotonic deadline",
                 identity_changed_after_attach=identity_changed)
    if not complete:
        raise RuntimeError(f"debugger capture incomplete; inspect {directory}")
    return directory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="existing private evidence directory")
    parser.add_argument("--timeout", type=float, default=180, help="seconds without sync progress")
    args = parser.parse_args()
    if sys.version_info < (3, 11):
        found = ".".join(str(part) for part in sys.version_info[:3])
        parser.error(f"requires Python 3.11 or newer, found {found}")
    if not sys.platform.startswith("linux") or args.pid <= 0 or not 1 <= args.timeout <= 86400:
        parser.error("requires Linux, a positive PID and timeout from 1 to 86400 seconds")
    try:
        debugger = shutil.which("gdb")
        if debugger is None:
            raise FileNotFoundError("GDB is required; install it before starting the watchdog")
        subprocess.run([debugger, "--version"], stdout=subprocess.DEVNULL,
                       check=True, timeout=5)
        if not args.output.is_dir():
            raise NotADirectoryError(args.output)
        identity = snapshot_process(args.pid)
        if identity is None:
            raise ProcessLookupError(args.pid)
        # WHY: the dry attach trades one momentary pause for failing on a
        # ptrace-denying host before the stall deadline instead of after it.
        preflight_attach(identity, debugger)
        print(f"Watching PID {identity.pid}; one missed-telemetry capture, then exit.", flush=True)
        if not wait_for_stall(identity, args.log, args.timeout):
            print("Original target exited; no debugger attached.")
            return 0
        print(capture(identity, args.log, args.output, debugger))
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
