#!/usr/bin/env python3
"""Own external overlay backend processes and run the real process-harness tests."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import tempfile
import time

IVNP_REVISION = "d5274b4752bd5a37bb35e6bb47796916c21e514c"


def reserve_port(kind=socket.SOCK_STREAM):
    listener = socket.socket(type=kind)
    try:
        listener.bind(("127.0.0.1", 0))
        return listener
    except BaseException:
        listener.close()
        raise


def wait_port(address, process):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("overlay backend exited; inspect the backend log")
        try:
            with socket.create_connection(address, timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError("overlay backend did not open its local control endpoint")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ivnp-revision", action="store_true")
    parser.add_argument("--ivnpd", type=Path)
    parser.add_argument("--tor", type=Path)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--evidence", type=Path, default=Path("target/overlay-interop"))
    args = parser.parse_args()
    if args.ivnp_revision:
        print(IVNP_REVISION)
        return 0
    if not args.ivnpd or not args.tor:
        parser.error("--ivnpd and --tor are required")
    if os.name != "posix":
        parser.error("external overlay campaigns require POSIX process-group cleanup")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    binaries = {"tor": args.tor.resolve(), "ivnpd": args.ivnpd.resolve()}
    (evidence / "backends.json").write_text(json.dumps({
        "ivnp_revision": IVNP_REVISION,
        "binaries": {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                     for name, path in binaries.items()},
        "tor_version": subprocess.check_output([str(binaries["tor"]), "--version"], text=True).strip(),
    }, indent=2) + "\n")
    children = []
    logs = []
    with tempfile.TemporaryDirectory(prefix="bitcoin-rs-overlay-") as directory, ExitStack() as reservations:
        state = Path(directory)
        held = [reservations.enter_context(reserve_port(kind)) for kind in
                (socket.SOCK_STREAM, socket.SOCK_STREAM, socket.SOCK_STREAM, socket.SOCK_DGRAM)]
        socks, control, sam, sam_udp = [listener.getsockname()[1] for listener in held]
        cookie = state / "tor.cookie"
        config = state / "ivnp.conf"
        config.write_text(f"[sam]\nlisten_host = 127.0.0.1\nlisten_port = {sam}\nudp_host = 127.0.0.1\nudp_port = {sam_udp}\n")
        commands = [
            ("tor", [str(binaries["tor"]), "--DataDirectory", str(state / "tor"),
                     "--SocksPort", f"127.0.0.1:{socks}", "--ControlPort", f"127.0.0.1:{control}",
                     "--CookieAuthentication", "1", "--CookieAuthFile", str(cookie)]),
            ("ivnpd", [str(binaries["ivnpd"]), "-config", str(config), "-data-dir", str(state / "ivnp"),
                       "-webui=false", "-http-proxy=false", "-log-level", "warn"]),
        ]
        try:
            for (name, command), ports in zip(commands, (held[:2], held[2:])):
                log = (evidence / f"{name}.log").open("wb")
                logs.append(log)
                # Keep each reservation until immediately before its backend starts.
                # The backend does not accept inherited sockets, so a short handoff
                # race remains; a bind failure is reported by wait_port.
                for listener in ports:
                    listener.close()
                children.append(subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT))
            wait_port(("127.0.0.1", control), children[0])
            wait_port(("127.0.0.1", sam), children[1])
            environment = dict(os.environ, OVERLAY_TOR_PROXY=f"127.0.0.1:{socks}",
                               OVERLAY_TOR_CONTROL=f"127.0.0.1:{control}", OVERLAY_TOR_COOKIE=str(cookie),
                               OVERLAY_IVNP_SAM=f"127.0.0.1:{sam}")
            command = [args.cargo, "test", "--locked", "-p", "bitcoin-rs-e2e", "--test", "overlay_connectivity",
                       "--", "--ignored", "--nocapture", "--test-threads=1"]
            with (evidence / "results.log").open("wb") as log:
                with subprocess.Popen(command, env=environment, stdout=log,
                                      stderr=subprocess.STDOUT, start_new_session=True) as campaign:
                    try:
                        returncode = campaign.wait(timeout=1500)
                    finally:
                        # Cargo, its test binary and the nodes inherit this group.
                        # Also reap surviving descendants after a failed test run.
                        try:
                            os.killpg(campaign.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        campaign.wait()
            print((evidence / "results.log").read_text(errors="replace"))
            return returncode
        finally:
            for child in children:
                child.terminate()
            for child in children:
                try:
                    child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            for log in logs:
                log.close()


if __name__ == "__main__":
    raise SystemExit(main())
