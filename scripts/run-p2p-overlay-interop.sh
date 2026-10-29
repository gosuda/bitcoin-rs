#!/usr/bin/env bash
# Live Tor/I2P overlay interop for bitcoin-rs (#1601).
#
# Starts a private Tor net (loopback ControlPort plus SOCKS) and a private
# i2pd mesh (seven routers, netid 77, distinct 127.0.77.x), then two regtest bitcoin-rs nodes: one
# publishing an onion service (--onion-proxy, --tor-control) and accepting I2P
# (--i2p-sam, --i2p-accept), one dialing over the proxies
# (--proxy, --onion-proxy, --i2p-sam). Proves handshake, headers/blocks in both
# directions over onion and I2P, inbound accepts, and restart identity
# reuse (onion service key and I2P destination keys persist across
# restarts). Records an evidence JSON (schema
# bitcoin-rs-overlay-interop-v1) and prints `overlay interop: PASS`
# only after every assertion holds; a missing daemon, bootstrap, or
# network prerequisite fails the run (the caller reports BLOCKED).
#
# usage: run-p2p-overlay-interop.sh --tor-command <command>
#            --tor-gencert-command <command> --tor-gencert-sha256 <hex> --i2pd-command <path>
#            [--bitcoin-rs-command <command>] [--workdir <dir>]
#            [--evidence <path>] [--timeout-seconds <n>] [--keep]
#
# Pinned externals: Tor 0.4.9.14 release (tor binary); tor-gencert by operator-supplied
# SHA-256 digest (--tor-gencert-sha256; tor-gencert has no --version flag); official i2pd 3.0.0 release.
# Any prerequisite mismatch or missing metadata
# fails closed (non-zero exit).
#
# Host: Linux with python3 >= 3.11 (os.pidfd_open, signal.pidfd_send_signal, asyncio.timeout).
# Every listener binds loopback and no overlay daemon uses public bootstrap.
# Children are
# only ever signaled through validated pidfds (see "Child ownership" below).
#
# Fresh outputs: an explicit --workdir must not exist or must be an empty
# directory owned by the caller, and --evidence must not exist. Both are
# decided before anything is created or launched; nothing is cleared or
# overwritten. Every child starts under a minimal environment (PATH,
# LD_LIBRARY_PATH, a task-owned HOME and TMPDIR), so no operator
# BITCOIN_RS_*, proxy, or other setting reaches a fixture or node.

set -euo pipefail
umask 077

usage() {
  printf '%s\n' \
    "usage: run-p2p-overlay-interop.sh --tor-command <command> --tor-gencert-command <command> --tor-gencert-sha256 <hex> --i2pd-command <path> [--bitcoin-rs-command <command>] [--workdir <dir>] [--evidence <path>] [--timeout-seconds <n>] [--keep]" \
    "" \
    "Required:" \
    "  --tor-command <cmd>       Tor binary (pinned to release 0.4.9.14)" \
    "  --tor-gencert-command <cmd> tor-gencert binary (must match --tor-gencert-sha256; tor-gencert has no --version flag)" \
    "  --tor-gencert-sha256 <hex> Expected SHA-256 of the tor-gencert binary (64 hex chars; fail-closed on mismatch)" \
    "  --i2pd-command <path>      Path to i2pd binary (pinned to official release 3.0.0; supply the binary path, additional arguments are not parsed)" \
    "" \
    "Optional:" \
    "  --bitcoin-rs-command <cmd> Path to bitcoin-rs binary (default: target/debug/bitcoin-rs)" \
    "  --workdir <dir>           Run directory: must not exist, or must be an empty directory you own (created or tightened to 0700, never cleared; default: fresh temporary dir)" \
    "  --evidence <path>         Path to emit evidence JSON; must not exist (default: <workdir>/evidence.json)" \
    "  --timeout-seconds <n>     Operation timeout deadline in seconds (default: 240)" \
    "  --keep                    Keep temporary workdir on exit" \
    "  -h, --help                Show this help message"
}

TOR_COMMAND=""
I2PD_COMMAND=""
TOR_GENCERT_COMMAND=""
TOR_GENCERT_SHA256=""
BITCOIN_RS_COMMAND="target/debug/bitcoin-rs"
WORKDIR=""
AUTO_WORKDIR=0
EVIDENCE=""
TIMEOUT_SECONDS=240
KEEP=0

while (($# > 0)); do
  case "$1" in
    --tor-command)
      [[ $# -ge 2 ]] || { echo "error: --tor-command requires an argument" >&2; usage >&2; exit 2; }
      TOR_COMMAND=$2
      shift 2
      ;;
    --tor-gencert-command)
      [[ $# -ge 2 ]] || { echo "error: --tor-gencert-command requires an argument" >&2; usage >&2; exit 2; }
      TOR_GENCERT_COMMAND=$2
      shift 2
      ;;
    --tor-gencert-sha256)
      [[ $# -ge 2 ]] || { echo "error: --tor-gencert-sha256 requires an argument" >&2; usage >&2; exit 2; }
      TOR_GENCERT_SHA256=$2
      shift 2
      ;;
    --i2pd-command)
      [[ $# -ge 2 ]] || { echo "error: --i2pd-command requires an argument" >&2; usage >&2; exit 2; }
      I2PD_COMMAND=$2
      shift 2
      ;;
    --bitcoin-rs-command)
      [[ $# -ge 2 ]] || { echo "error: --bitcoin-rs-command requires an argument" >&2; usage >&2; exit 2; }
      BITCOIN_RS_COMMAND=$2
      shift 2
      ;;
    --workdir)
      [[ $# -ge 2 ]] || { echo "error: --workdir requires an argument" >&2; usage >&2; exit 2; }
      WORKDIR=$2
      shift 2
      ;;
    --evidence)
      [[ $# -ge 2 ]] || { echo "error: --evidence requires an argument" >&2; usage >&2; exit 2; }
      EVIDENCE=$2
      shift 2
      ;;
    --timeout-seconds)
      [[ $# -ge 2 ]] || { echo "error: --timeout-seconds requires an argument" >&2; usage >&2; exit 2; }
      TIMEOUT_SECONDS=$2
      shift 2
      ;;
    --keep)
      KEEP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${TOR_COMMAND}" || -z "${TOR_GENCERT_COMMAND}" || -z "${TOR_GENCERT_SHA256}" || -z "${I2PD_COMMAND}" ]]; then
  echo "error: --tor-command, --tor-gencert-command, --tor-gencert-sha256, and --i2pd-command are required" >&2
  usage >&2
  exit 2
fi
if [[ ! "${TOR_GENCERT_SHA256}" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "error: --tor-gencert-sha256 must be 64 hex characters" >&2
  usage >&2
  exit 2
fi

# -----------------------------------------------------------------------------
# Fresh output paths (refused before anything is created or launched)
# -----------------------------------------------------------------------------
# No operator data may reach the fixtures and no operator file may be replaced.
# An explicit --workdir must not exist, or must be an empty directory owned by
# this user (never a symbolic link); --evidence must not exist at all. Both are
# decided here, before any mkdir, port allocation, write, or child launch, and
# nothing is deleted or overwritten to make room.
require_empty_dir() { # <path> <flag> -- <path> is a real, empty directory owned by this user
  local path=$1
  local flag=$2
  local listing
  if [[ -L "${path}" || ! -d "${path}" || ! -O "${path}" ]]; then
    echo "error: ${flag} ${path} exists but is not a directory owned by this user (symbolic links are refused)" >&2
    exit 2
  fi
  if [[ "${path}" == -* ]]; then
    path=./${path}
  fi
  listing=$(find "${path}" -mindepth 1 -maxdepth 1 -print -quit) || {
    echo "error: ${flag} ${path} could not be listed; refusing to use it" >&2
    exit 2
  }
  if [[ -n "${listing}" ]]; then
    echo "error: ${flag} ${path} is not empty; refusing to use a directory that already holds files" >&2
    exit 2
  fi
}

WORKDIR_EXISTS=0
if [[ -n "${WORKDIR}" && ( -e "${WORKDIR}" || -L "${WORKDIR}" ) ]]; then
  require_empty_dir "${WORKDIR}" "--workdir"
  WORKDIR_EXISTS=1
fi
if [[ -n "${EVIDENCE}" ]]; then
  if [[ -e "${EVIDENCE}" || -L "${EVIDENCE}" ]]; then
    echo "error: --evidence ${EVIDENCE} already exists; refusing to overwrite it" >&2
    exit 2
  fi
  EVIDENCE_DIR=$(dirname -- "${EVIDENCE}")
  # The parent must exist, unless it is the new --workdir itself.
  if [[ ! -d "${EVIDENCE_DIR}" ]]; then
    if [[ -z "${WORKDIR}" || "$(realpath -m -- "${EVIDENCE_DIR}")" != "$(realpath -m -- "${WORKDIR}")" ]]; then
      echo "error: --evidence parent directory does not exist: ${EVIDENCE_DIR}" >&2
      exit 2
    fi
  fi
fi

# -----------------------------------------------------------------------------
# Child ownership (Linux pidfd; refused before anything is launched)
# -----------------------------------------------------------------------------
# A pid is a name, not an identity: once a child is reaped its number can be
# reissued, and neither `kill -0` nor a PPID read followed by a numeric `kill`
# proves the name still means our child at the instant of the signal. Every
# launched daemon is therefore recorded in OWNED as pid -> "<birth> <label>",
# where birth is the process start time (/proc/<pid>/stat field 22) read by this
# shell itself right after launch, before it forks anything else; with this
# shell as parent, (pid, parent, birth) names exactly one process. Nothing is
# signaled by number. Each stop opens a pidfd, checks parent and birth through
# that handle, and signals, polls, and gives up on the process only through it,
# so a number reissued after the check is harmless.
# `wait` runs only for a child whose exit the handle observed. The helper uses
# the interpreter this script already needs (stdlib os.pidfd_open and
# signal.pidfd_send_signal); a host that cannot supply them is refused up front.
declare -A OWNED=()
REAP_STATUS=""

IFS= read -r -d '' OWNER_PY <<'PY' || true
import math, os, select, signal, sys, time

# selftest | stop <parent> <term-s> <kill-s> {<pid> <birth> <label>}

def note(message):
    print(message, file=sys.stderr, flush=True)

def stat_of(pid):
    # /proc/<pid>/stat: field 4 is the parent, field 22 the start time in clock
    # ticks. comm (field 2) may hold spaces and parentheses, so cut after the
    # last ")".
    with open(f"/proc/{pid}/stat", "rb") as fh:
        raw = fh.read()
    rest = raw[raw.rindex(b")") + 2:].split()
    return int(rest[1]), rest[19].decode()

def handle_pid(fd):
    # fdinfo reads Pid: -1 once the handle's process has been released; until
    # then its number cannot belong to any other process.
    with open(f"/proc/self/fdinfo/{fd}", "rb") as fh:
        for line in fh:
            if line.startswith(b"Pid:"):
                return int(line.split()[1])
    raise OSError("pidfd fdinfo has no Pid line")

def acquire(pid, parent, birth):
    # A pidfd when `pid` is still the child of `parent` started at `birth`; None
    # when it is gone or the number now names another process. The order is the
    # proof: take the handle, read /proc, then read fdinfo. A Pid that still
    # equals `pid` after the /proc read means the number belonged to this
    # handle's process throughout, so the parent and start time read are its
    # own. The helper never owns itself: it is a fresh child of the launching
    # shell, which no recorded identity can name.
    if pid == os.getpid():
        return None
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return None
    try:
        try:
            ppid, born = stat_of(pid)
        except (FileNotFoundError, ProcessLookupError):
            ppid = born = None
        if handle_pid(fd) == pid and ppid == parent and born == birth:
            return fd
    except BaseException:
        os.close(fd)
        raise
    os.close(fd)
    return None

def wait_exit(fds, budget):
    # The handles whose processes are still running after `budget` seconds. A
    # handle polls readable once its process exits and hung up once it is
    # reaped, so any event means "exited".
    pending = set(fds)
    poller = select.poll()
    for fd in pending:
        poller.register(fd, select.POLLIN)
    deadline = time.monotonic() + budget
    while pending:
        events = poller.poll(math.ceil(max(0.0, deadline - time.monotonic()) * 1000))
        if not events:
            break
        for fd, _ in events:
            poller.unregister(fd)
            pending.discard(fd)
    return pending

def stop(parent, term, kill, targets):
    # SIGTERM every verified child and wait up to `term` seconds for all of
    # them, then SIGKILL the survivors through the same handles and wait up to
    # `kill` seconds more. Prints "<pid> exited|gone|stuck" per target and
    # returns non-zero when any is stuck. gone: the pid no longer names the
    # launched child (it was reaped and may be reissued), so nothing was
    # signaled. stuck: the child could not be verified or did not exit; it is
    # reported and never waited on.
    outcome, handles, failed = {}, {}, {}
    for pid, birth, label in targets:
        try:
            fd = acquire(pid, parent, birth)
        except Exception as error:
            outcome[pid] = "stuck"
            note(f"{label} (pid {pid}): ownership could not be verified ({type(error).__name__}: {error}); not signaled")
            continue
        if fd is None:
            outcome[pid] = "gone"
            note(f"{label} (pid {pid}): no longer the launched child; not signaled")
        else:
            handles[fd] = (pid, label)
    pending = set(handles)
    for sig, budget in ((signal.SIGTERM, term), (signal.SIGKILL, kill)):
        if not pending:
            break
        if sig == signal.SIGKILL:
            for fd in sorted(pending):
                pid, label = handles[fd]
                note(f"{label} (pid {pid}): still running {term:g}s after SIGTERM; sending SIGKILL through its handle")
        for fd in sorted(pending):
            try:
                signal.pidfd_send_signal(fd, sig)
            except ProcessLookupError:
                pass
            except OSError as error:
                failed[fd] = error
                pending.discard(fd)
        pending = wait_exit(pending, budget)
    for fd, (pid, label) in handles.items():
        if fd in failed:
            outcome[pid] = "stuck"
            note(f"{label} (pid {pid}): signal through its handle failed ({type(failed[fd]).__name__}: {failed[fd]})")
        elif fd in pending:
            outcome[pid] = "stuck"
            note(f"{label} (pid {pid}): still running {kill:g}s after SIGKILL (uninterruptible kernel state?); not waiting on it")
        else:
            outcome[pid] = "exited"
        os.close(fd)
    for pid, state in outcome.items():
        print(pid, state)
    return 1 if "stuck" in outcome.values() else 0

def selftest():
    if sys.version_info < (3, 11):
        sys.exit(f"python3 >= 3.11 required, found {sys.version.split()[0]}")
    try:
        import asyncio
        asyncio.timeout
    except (ImportError, AttributeError):
        sys.exit("asyncio.timeout unavailable (needs python3 >= 3.11)")
    # The production path against a process this helper does not own and must
    # not disturb: the launching shell. Signal 0 only checks that it exists.
    me = os.getppid()
    ppid, born = stat_of(me)
    fd = acquire(me, ppid, born)
    if fd is None:
        sys.exit(f"pid {me} could not be re-identified through a pidfd (is /proc from another pid namespace?)")
    try:
        signal.pidfd_send_signal(fd, 0)
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        if poller.poll(0):
            sys.exit("the pidfd of a running process polled as exited")
    finally:
        os.close(fd)

def main(argv):
    if argv[:1] == ["selftest"]:
        selftest()
    elif argv[:1] == ["stop"] and len(argv) >= 4 and (len(argv) - 4) % 3 == 0:
        triples = argv[4:]
        targets = [(int(triples[i]), triples[i + 1], triples[i + 2]) for i in range(0, len(triples), 3)]
        sys.exit(stop(int(argv[1]), float(argv[2]), float(argv[3]), targets))
    else:
        sys.exit("usage: selftest | stop <parent> <term-s> <kill-s> {<pid> <birth> <label>}")

try:
    main(sys.argv[1:])
except (AttributeError, OSError) as error:
    sys.exit(f"{type(error).__name__}: {error}")
PY

if ! python3 -c "${OWNER_PY}" selftest; then
  echo "error: Linux pidfd process ownership is unavailable on this host (needs Linux >= 5.3, python3 >= 3.11 with os.pidfd_open, signal.pidfd_send_signal and asyncio.timeout, and a /proc of this pid namespace); not launching children that could not be owned" >&2
  exit 1
fi

own_child() { # <pid> <label> -- record the just-launched child's identity
  local pid
  local label
  local line
  local -a fields
  pid=$1
  label=$2
  # Read here by the shell itself: no process has been spawned since the launch,
  # so the only child of this shell that can carry this number is the one just
  # launched, and an unrelated process that reused it has another parent.
  # Fields after the last ")" of /proc/<pid>/stat: [0] state, [1] parent,
  # [19] start time.
  if ! IFS= read -r line 2>/dev/null <"/proc/${pid}/stat"; then
    echo "error: ${label} (pid ${pid}) has no readable /proc entry (exited during launch?); it will not be signaled by number" >&2
    return 1
  fi
  read -r -a fields <<<"${line##*) }"
  if [[ -z "${fields[19]:-}" || "${fields[1]:-}" != "$$" || "${fields[0]:-}" == [ZX] ]]; then
    echo "error: ${label} (pid ${pid}) is not a live child of this run (state ${fields[0]:-?}, parent ${fields[1]:-?}); it will not be signaled by number" >&2
    return 1
  fi
  OWNED[${pid}]="${fields[19]} ${label}"
}

reap_owned() { # <term-seconds> <kill-seconds> <pid>... -- SIGTERM then SIGKILL owned children through validated handles, then reap
  local term_s
  local kill_s
  local pid
  local outcome
  local outcomes
  local rc
  local -a targets
  term_s=$1
  kill_s=$2
  shift 2
  targets=()
  for pid in "$@"; do
    [[ -n "${pid}" && -n "${OWNED[${pid}]:-}" ]] || continue
    targets+=("${pid}" "${OWNED[${pid}]%% *}" "${OWNED[${pid}]#* }")
  done
  REAP_STATUS=""
  if ((${#targets[@]} == 0)); then
    return 0
  fi
  rc=0
  outcomes=$(python3 -c "${OWNER_PY}" stop "$$" "${term_s}" "${kill_s}" "${targets[@]}") || rc=$?
  while read -r pid outcome; do
    case "${outcome}" in
      exited)
        # The handle observed the exit, so this `wait` cannot block.
        REAP_STATUS=0
        wait "${pid}" 2>/dev/null || REAP_STATUS=$?
        unset 'OWNED[$pid]'
        ;;
      gone)
        # Not observed exiting, so no `wait` and no status.
        unset 'OWNED[$pid]'
        ;;
    esac
  done <<<"${outcomes}"
  return "${rc}"
}

# -----------------------------------------------------------------------------
# Binary & Toolchain Pin Verification (fail-closed)
# -----------------------------------------------------------------------------

# 1. Tor binary & strict release version check
TOR_BIN="${TOR_COMMAND%% *}"
if [[ ! -x "${TOR_BIN}" ]]; then
  echo "error: Tor binary not found or not executable: ${TOR_BIN}" >&2
  exit 1
fi

read -r -a TOR_CMD <<<"${TOR_COMMAND}"
TOR_VER_RAW=$("${TOR_CMD[@]}" --version 2>/dev/null || true)
TOR_FIRST_LINE=$(printf '%s\n' "${TOR_VER_RAW}" | head -n1 | tr -d '\r')
TOR_RELEASE_OK=$(python3 -c '
import sys, re
line = sys.argv[1].strip()
pattern = r"^Tor version 0\.4\.9\.14(?:\s+\(git-[0-9a-fA-F]+\))?\.?$"
sys.exit(0 if re.match(pattern, line) else 1)
' "${TOR_FIRST_LINE}" && echo 1 || echo 0)

if [[ "${TOR_RELEASE_OK}" -ne 1 ]]; then
  echo "error: Tor pin mismatch: expected release 0.4.9.14 (without dev/alpha/rc suffixes), got: '${TOR_FIRST_LINE}'" >&2
  exit 1
fi
TOR_OBSERVED_VERSION=$(python3 -c '
import sys, re
line = sys.argv[1].strip()
m = re.search(r"Tor version ([0-9a-zA-Z.-]+)", line)
print(m.group(1).rstrip(".") if m else line)
' "${TOR_FIRST_LINE}")

# 2. i2pd binary and official 3.0.0 release check (caller provides binary path;
# the full value is used verbatim as the executable path, quoted, with no shell
# evaluation; additional arguments are not parsed. Private fixture arguments
# (datadirs, configs, netid, loopback ports) are appended by the script and
# fixtures only and can never be overridden by caller arguments.)
I2PD_BIN="${I2PD_COMMAND}"
if [[ ! -x "${I2PD_BIN}" || ! -f "${I2PD_BIN}" ]]; then
  echo "error: i2pd binary not found or not executable: ${I2PD_BIN} (supply the binary path, additional arguments are not parsed)" >&2
  exit 1
fi
I2PD_VERSION_RAW=$("${I2PD_BIN}" --version 2>/dev/null || true)
# Exact version tokens, not substrings: one whole output line must equal the
# pinned version, so 3.0.0.1 or 3x0x0 never match. The official release prints
# `i2pd version 3.0.0 (<protocol>)`; that parenthesized numeric protocol
# annotation is accepted and not otherwise enforced.
i2pd_version_line_ok() { # <whole-line regex> -- stdin is the --version output; exit 0 when one full line matches
  python3 -c '
import re, sys
pattern = re.compile(sys.argv[1])
lines = [line.rstrip("\r") for line in sys.stdin.read().split("\n")]
sys.exit(0 if any(pattern.fullmatch(line) for line in lines) else 1)
' "$1"
}
printf '%s\n' "${I2PD_VERSION_RAW}" | i2pd_version_line_ok 'i2pd version 3\.0\.0(?: \([0-9]+(?:\.[0-9]+)*\))?[ \t]*' || { echo "error: i2pd pin mismatch (want official 3.0.0)" >&2; exit 1; }
printf '%s\n' "${I2PD_VERSION_RAW}" | i2pd_version_line_ok 'Boost version 1\.90\.0[ \t]*' || { echo "error: i2pd Boost pin mismatch (want 1.90.0)" >&2; exit 1; }
I2PD_BIN_SHA=$(sha256sum "${I2PD_BIN}" | awk '{print $1}')
if command -v ldd >/dev/null 2>&1; then
  if ! ldd "${I2PD_BIN}" >/dev/null 2>&1; then echo "error: ldd failed for ${I2PD_BIN}" >&2; exit 1; fi
  if ldd "${I2PD_BIN}" 2>/dev/null | grep -q "not found"; then ldd "${I2PD_BIN}" >&2; echo "error: unresolved i2pd libraries" >&2; exit 1; fi
fi
TOR_GENCERT_BIN="${TOR_GENCERT_COMMAND%% *}"
if [[ ! -x "${TOR_GENCERT_BIN}" ]]; then
  echo "error: tor-gencert binary not found or not executable: ${TOR_GENCERT_BIN}" >&2
  exit 1
fi
TOR_GENCERT_SHA=$(sha256sum "${TOR_GENCERT_BIN}" | awk '{print $1}')
if [[ "${TOR_GENCERT_SHA,,}" != "${TOR_GENCERT_SHA256,,}" ]]; then
  echo "error: tor-gencert pin mismatch: binary sha256 ${TOR_GENCERT_SHA} != pinned ${TOR_GENCERT_SHA256}" >&2
  exit 1
fi

# 3. bitcoin-rs binary check
RS_BIN="${BITCOIN_RS_COMMAND%% *}"
if [[ ! -x "${RS_BIN}" ]]; then
  echo "error: bitcoin-rs binary not found or not executable: ${RS_BIN}" >&2
  exit 1
fi

# -----------------------------------------------------------------------------
# Port Allocation & Directory Setup
# -----------------------------------------------------------------------------

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

TOR_SOCKS_REAL_PORT=$(free_port)
TOR_SOCKS_PORT=$(free_port)
TOR_SOCKS_PORT_B=$(free_port)
TOR_CONTROL_PORT=$(free_port)
R0_SAM_PORT=$(free_port)
R1_SAM_PORT=$(free_port)
REC_SAM_PORT_A=$(free_port)
REC_SAM_PORT_B=$(free_port)
A_P2P_PORT=$(free_port)
A_RPC_PORT=$(free_port)
B_P2P_PORT=$(free_port)
B_RPC_PORT=$(free_port)
VPORT=18444
MINING_ADDRESS="bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5"

# First write of the run: a task-owned 0700 directory that held nothing before.
if [[ -z "${WORKDIR}" ]]; then
  WORKDIR=$(mktemp -d ./p2p-overlay-interop.XXXXXX)
  AUTO_WORKDIR=1
elif ((WORKDIR_EXISTS)); then
  require_empty_dir "${WORKDIR}" "--workdir"
  chmod 0700 -- "${WORKDIR}"
else
  mkdir -m 0700 -- "${WORKDIR}" || {
    echo "error: cannot create a fresh --workdir ${WORKDIR} (its parent directory must exist)" >&2
    exit 1
  }
fi
# Absolute from here on: every child gets a task-owned HOME under it.
WORKDIR=$(cd -- "${WORKDIR}" && pwd -P)
if [[ -z "${EVIDENCE}" ]]; then
  EVIDENCE="${WORKDIR}/evidence.json"
fi

TOR_DATADIR="${WORKDIR}/tor-data"
TOR_LOG="${WORKDIR}/tor.log"
I2PD_MESH_DIR="${WORKDIR}/i2pd-mesh"
I2PD_LOG_DIR="${WORKDIR}/i2pd-logs"
RECORDER_LOG="${WORKDIR}/recorder.log"
OBSERVATIONS_FILE="${WORKDIR}/protocol_observations.json"
OBSERVATIONS_DONE="${WORKDIR}/protocol_observations.done"
A_DATADIR="${WORKDIR}/node-a"
B_DATADIR="${WORKDIR}/node-b"
A_LOG="${WORKDIR}/node-a.log"
B_LOG="${WORKDIR}/node-b.log"
A_LOG2="${WORKDIR}/node-a-restart.log"
RPC_USER="interop"
RPC_PASSWORD="interop"

mkdir -p "${TOR_DATADIR}" "${I2PD_MESH_DIR}" "${I2PD_LOG_DIR}" "${A_DATADIR}" "${B_DATADIR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRACKED_RECORDER="${SCRIPT_DIR}/overlay_recorder.py"
TOR_TEMPLATE_DIR="${SCRIPT_DIR}/overlay-tor-templates"
if [[ ! -f "${TRACKED_RECORDER}" ]]; then echo "error: tracked recorder missing: ${TRACKED_RECORDER}" >&2; exit 1; fi
if [[ ! -f "${TOR_TEMPLATE_DIR}/torrc.common.template" ]]; then echo "error: tor templates missing" >&2; exit 1; fi
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/overlay_tor_fixture.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/overlay_i2pd_fixture.sh"
TORNET_DIR="${WORKDIR}/tornet"
RESEED_ZIP="${WORKDIR}/private-reseed.zip"
overlay_tor_fixture_launch "${TOR_TEMPLATE_DIR}" "${TORNET_DIR}"
FIXTURE_I2PD_PORTS="$(overlay_i2pd_fixture_launch "${I2PD_MESH_DIR}" "${RESEED_ZIP}" "${I2PD_BIN}")"
R0_SAM_PORT="$(printf '%s' "${FIXTURE_I2PD_PORTS}" | python3 -c 'import sys; print([p.split("=")[1] for p in sys.stdin.read().split() if p.startswith("r0_sam=")][0])')"
R1_SAM_PORT="$(printf '%s' "${FIXTURE_I2PD_PORTS}" | python3 -c 'import sys; print([p.split("=")[1] for p in sys.stdin.read().split() if p.startswith("r1_sam=")][0])')"

cleanup() {
  local status=$?
  local evidence_in_workdir
  local _evidence_abs
  # Stop every child still owned, which covers every early exit: SIGTERM all
  # through validated handles, wait up to 5 s, SIGKILL the survivors through the
  # same handles, wait up to 5 s more. A child that cannot be shown to have
  # exited is reported and turns the exit status non-zero; it is never assumed
  # gone and never signaled by number.
  if ((${#OWNED[@]} > 0)); then
    if ! reap_owned 5 5 "${!OWNED[@]}"; then
      echo "error: cleanup could not confirm that every child exited (see above)" >&2
      ((status != 0)) || status=1
    fi
  fi
  # Clean up workdir only on success, only if automatically created and
  # --keep not set. Failed runs always retain the workdir for diagnosis.
  # The evidence JSON is the proof of a PASS: when it lives inside the workdir
  # (the default <workdir>/evidence.json or any explicit --evidence under it),
  # deleting the workdir would delete the proof, so success must keep it.
  evidence_in_workdir=0
  if [[ -n "${EVIDENCE:-}" && -n "${WORKDIR:-}" ]]; then
    _evidence_abs=$(realpath -m -- "${EVIDENCE}" 2>/dev/null || true)
    if [[ "${_evidence_abs}" == "${WORKDIR}" || "${_evidence_abs}" == "${WORKDIR}/"* ]]; then
      evidence_in_workdir=1
    fi
  fi
  if ((status == 0)) && [[ "${AUTO_WORKDIR}" -eq 1 && "${KEEP}" -eq 0 && -z "${!OWNED[*]}" ]] && ((evidence_in_workdir == 0)); then
    rm -rf -- "${WORKDIR:?workdir unset}"
  elif [[ -n "${WORKDIR:-}" ]]; then
    echo "workdir kept: ${WORKDIR}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "==> workdir: ${WORKDIR}"
echo "==> tor: release ${TOR_OBSERVED_VERSION} (socks backend ${TOR_SOCKS_REAL_PORT}, recorder socks ${TOR_SOCKS_PORT}, control ${TOR_CONTROL_PORT})"
echo "==> i2pd: 3.0.0 binary ${I2PD_BIN_SHA} (r0 SAM ${R0_SAM_PORT}, r1 SAM ${R1_SAM_PORT}, recorder A ${REC_SAM_PORT_A}, recorder B ${REC_SAM_PORT_B})"

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

wait_tcp() { # <port> <label>
  local port
  local label
  local deadline
  port=$1
  label=$2
  deadline=$((SECONDS + TIMEOUT_SECONDS))
  while ((SECONDS < deadline)); do
    if python3 -c "import socket; s=socket.create_connection(('127.0.0.1', ${port}), timeout=1); s.close()" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  echo "error: timed out waiting for ${label} on port ${port}" >&2
  return 1
}

wait_tor_bootstrap() { # bounded wait for Tor's "Bootstrapped 100% (done): Done" notice; fails at once if the owned Tor exits first
  local owned
  # One finite wait in one interpreter, on a monotonic deadline. It only
  # observes: it reads the log and /proc/<pid>/stat and never signals. The tor
  # child is the one OWNED already names, so the helper takes its recorded start
  # time and this shell as parent, and "still running" means that exact
  # (pid, parent, birth) is live and not a zombie; a reissued number fails that
  # test the same as a reaped one. Without the owner record there is no identity
  # to confirm, so the wait is refused rather than guessed at by number.
  if [[ -z "${TOR_PID:-}" || -z "${OWNED[${TOR_PID}]:-}" ]]; then
    echo "error: tor is not an owned child of this run; refusing to wait on a process whose identity cannot be confirmed" >&2
    return 1
  fi
  owned=${OWNED[${TOR_PID}]}
  python3 - "${TOR_LOG}" "${WORKDIR}/tor-stdout.log" "${TIMEOUT_SECONDS}" "${TOR_PID}" "$$" "${owned%% *}" <<'PY'
import sys, time

# <tor-log> <tor-stdout-log> <budget-s> <pid> <parent> <birth>
log, stdout_log, budget, pid, parent, birth = sys.argv[1:7]
budget = float(budget)
TARGET = b"Bootstrapped 100% (done): Done"
POLL = 0.5

def running():
    # /proc/<pid>/stat: field 3 is the state, field 4 the parent, field 22 the
    # start time in clock ticks. comm (field 2) may hold spaces and
    # parentheses, so cut after the last ")". A missing entry (ENOENT on open,
    # or ESRCH from a read of a process that vanished mid-read) is the kernel
    # saying the process is gone; any other read failure is no answer and
    # fails the wait visibly. The log read below accepts only ENOENT.
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            raw = fh.read()
    except (FileNotFoundError, ProcessLookupError):
        return False
    except OSError as error:
        sys.exit(f"error: cannot observe tor (pid {pid}) through /proc: {type(error).__name__}: {error}")
    rest = raw[raw.rindex(b")") + 2:].split()
    return rest[0] not in (b"Z", b"X") and rest[1].decode() == parent and rest[19].decode() == birth

def bootstrapped():
    # Tor creates its log after it starts, so an absent file is only "not yet".
    # Anything else (permissions, a directory, an I/O error) is a harness fault
    # that must be seen, not mistaken for a slow bootstrap.
    try:
        with open(log, "rb") as fh:
            return TARGET in fh.read()
    except FileNotFoundError:
        return False
    except OSError as error:
        sys.exit(f"error: tor log {log} is unreadable: {type(error).__name__}: {error}")

deadline = time.monotonic() + budget
while True:
    # Liveness is read before the log, so a process seen gone had already
    # written everything the log read below can show: a notice written just
    # before exit still passes, and only an exit with no notice fails.
    alive = running()
    if bootstrapped():
        sys.exit(0)
    if not alive:
        sys.exit(
            f"error: tor bootstrap prerequisite failed: tor (pid {pid}) exited before reporting "
            f"'Bootstrapped 100% (done): Done' (see {log} and {stdout_log})"
        )
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        sys.exit(
            f"error: tor bootstrap prerequisite failed: did not report "
            f"'Bootstrapped 100% (done): Done' within {budget:g}s (see {log})"
        )
    time.sleep(min(POLL, remaining))
PY
}

rs_rpc() { # <rpc port> <method> [params-json]
  local port
  local method
  local params
  port=$1
  method=$2
  params=${3:-[]}
  # -q skips any ~/.curlrc and --noproxy '*' ignores every inherited proxy
  # variable, so the RPC credentials only ever travel to the loopback listener.
  curl -q -s --noproxy '*' --max-time 15 --connect-timeout 5 \
    -u "${RPC_USER}:${RPC_PASSWORD}" \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"1.0\",\"id\":\"interop\",\"method\":\"${method}\",\"params\":${params}}" \
    "http://127.0.0.1:${port}/"
}

rs_result() { # <rpc port> <method> [params-json] -- prints result JSON or fails
  local out
  out=$(rs_rpc "$1" "$2" "${3:-[]}")
  if [[ -z "${out}" ]]; then
    echo "rpc error: empty response from http://127.0.0.1:$1/ (method: $2)" >&2
    return 1
  fi
  printf '%s' "${out}" | python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except Exception as e:
    sys.exit(f"invalid json response: {e}")
if doc.get("error"):
    sys.exit("rpc error: {}".format(doc["error"]))
print(json.dumps(doc.get("result")))'
}

spawn_clean() { # <home> <command> [args...] -- run in a background subshell; it execs <command> under a minimal environment
  # Only PATH, LD_LIBRARY_PATH (when set), and a task-owned HOME and TMPDIR
  # reach the child: no BITCOIN_RS_* setting (RPC_PUBLIC_BIND, CONNECT, ...), no
  # proxy variable, no other operator configuration. `exec` keeps the pid the
  # shell records right after launch, and `env` execs the command in turn.
  local home=$1
  local -a keep
  shift
  keep=("PATH=${PATH}" "HOME=${home}" "TMPDIR=${home}")
  if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
    keep+=("LD_LIBRARY_PATH=${LD_LIBRARY_PATH}")
  fi
  exec env -i "${keep[@]}" "$@"
}

start_node() { # <datadir> <rpc> <p2p> <log> [extra...]
  local datadir
  local rpc
  local p2p
  local log
  local home
  local -a node_cmd
  datadir=$1
  rpc=$2
  p2p=$3
  log=$4
  shift 4
  home="${WORKDIR}/home/${datadir##*/}"
  mkdir -p "${WORKDIR}/home" "${home}"
  read -r -a node_cmd <<<"${BITCOIN_RS_COMMAND}"
  spawn_clean "${home}" "${node_cmd[@]}" \
    --network regtest \
    --data-dir "${datadir}" \
    --rpc-bind "127.0.0.1:${rpc}" \
    --rpc-user "${RPC_USER}" \
    --rpc-password "${RPC_PASSWORD}" \
    --p2p-listen "127.0.0.1:${p2p}" \
    --dns-seeds-enabled=false \
    --log-level info \
    "$@" >"${log}" 2>&1 &
  own_child "$!" "bitcoin-rs (${log##*/})" || exit 1
}

poll_height() { # <rpc port> <want height> <label>
  local port
  local want
  local label
  local deadline
  port=$1
  want=$2
  label=$3
  deadline=$((SECONDS + TIMEOUT_SECONDS))
  while ((SECONDS < deadline)); do
    local height
    height=$(rs_result "${port}" getblockcount 2>/dev/null || echo -1)
    if [[ "${height}" == "${want}" ]]; then
      return 0
    fi
    sleep 0.5
  done
  echo "error: timed out waiting for ${label} to reach height ${want} (last: ${height:-?})" >&2
  return 1
}

poll_peers_empty() { # <rpc port> <label>
  local port
  local label
  local deadline
  port=$1
  label=$2
  deadline=$((SECONDS + TIMEOUT_SECONDS))
  while ((SECONDS < deadline)); do
    local count
    count=$(rs_result "${port}" getpeerinfo 2>/dev/null | python3 -c 'import json, sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo -1)
    if [[ "${count}" -eq 0 ]]; then
      return 0
    fi
    sleep 0.5
  done
  echo "error: timed out waiting for peer table on ${label} to drain (last count: ${count:-?})" >&2
  return 1
}

overlay_addresses() { # <rpc port> -- prints "onion i2p" host strings
  rs_result "$1" getnetworkinfo | python3 -c '
import json, sys
try:
    info = json.load(sys.stdin)
    localaddresses = info.get("localaddresses", [])
    onion = next((a["address"] for a in localaddresses if a.get("address", "").endswith(".onion")), "")
    i2p = next((a["address"] for a in localaddresses if a.get("address", "").endswith(".b32.i2p")), "")
    print(f"{onion} {i2p}")
except Exception:
    print(" ")'
}

recorder_exit_clean() { # <label> <status> <log> -- the handle observed a clean exit (an empty status means the child was already gone)
  if [[ -z "$2" ]]; then
    echo "error: $1 was already gone before finalization, so its exit status is unavailable; refusing to trust observations (see $3)" >&2
    return 1
  fi
  if [[ "$2" -ne 0 ]]; then
    echo "error: $1 failed to finalize (status $2); observation persistence failed (see $3)" >&2
    return 1
  fi
}

verify_recorder_snapshot() { # <label> <snapshot> <marker> -- the marker records a complete finalization of exactly these snapshot bytes
  python3 - "$1" "$2" "$3" <<'PY'
import hashlib, json, sys

label, obs_path, marker_path = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(marker_path, "rb") as fh:
        marker = json.loads(fh.read())
except Exception as error:
    sys.exit(f"error: {label} completion marker unreadable: {error}")
if not isinstance(marker, dict):
    sys.exit(f"error: {label} completion marker is not a JSON object")
if marker.get("schema") != "bitcoin-rs-overlay-observations-v1" or marker.get("complete") is not True:
    sys.exit(f"error: {label} completion marker does not record a complete finalization")
try:
    with open(obs_path, "rb") as fh:
        snapshot = fh.read()
except Exception as error:
    sys.exit(f"error: {label} snapshot unreadable: {error}")
if len(snapshot) != marker.get("observations_bytes"):
    sys.exit(f"error: {label} snapshot length does not match its completion marker")
if hashlib.sha256(snapshot).hexdigest() != marker.get("observations_sha256"):
    sys.exit(f"error: {label} snapshot digest does not match its completion marker")
print(f"==> {label} observations finalized and verified")
PY
}

finalize_recorder() { # stop, reap, and verify the recorder's final snapshot
  local pid
  local status_a
  local status_b
  pid=${RECORDER_PID:-}
  if [[ -z "${pid}" ]]; then
    echo "error: recorder pid unknown; refusing to trust observations" >&2
    return 1
  fi
  if [[ -z "${RECORDER_B_PID:-}" ]]; then
    echo "error: recorder B pid unknown; refusing to trust observations" >&2
    return 1
  fi
  # SIGTERM starts the recorder's own wind-down: it stops accepting, cancels
  # handlers (each closes its sockets within the bounded writer timeout), then
  # publishes the snapshot and completion marker. The wind-down is bounded
  # inside the recorder by FINALIZE_GRACE (15 s), which exits non-zero instead
  # of publishing. The 20 s wait here (that grace plus slack) only backstops a
  # recorder that cannot run its own guard: past it the recorder is killed
  # through its handle, which fails finalization. The exit status, read by
  # `wait` only after the handle observed the exit, alone decides whether the
  # observations may be read; a recorder already gone has no status and fails.
  # REAP_STATUS holds only the latest reap, so each recorder's status is copied
  # out before the next recorder is stopped, and BOTH must have exited 0 with a
  # verified completion marker before anything is read.
  reap_owned 20 5 "${pid}" || {
    echo "error: recorder could not be stopped; refusing to trust observations (see ${RECORDER_LOG})" >&2
    return 1
  }
  status_a=${REAP_STATUS}
  RECORDER_PID=""
  reap_owned 20 5 "${RECORDER_B_PID}" || {
    echo "error: recorder B could not be stopped; refusing to trust observations (see ${RECORDER_LOG}.b)" >&2
    return 1
  }
  status_b=${REAP_STATUS}
  RECORDER_B_PID=""
  recorder_exit_clean "recorder" "${status_a}" "${RECORDER_LOG}" || return 1
  recorder_exit_clean "recorder B" "${status_b}" "${RECORDER_LOG}.b" || return 1
  verify_recorder_snapshot "recorder" "${OBSERVATIONS_FILE}" "${OBSERVATIONS_DONE}" || return 1
  verify_recorder_snapshot "recorder B" "${OBSERVATIONS_FILE}.b" "${OBSERVATIONS_DONE}.b" || return 1
}

# -----------------------------------------------------------------------------
# Launch private Tor net, private i2pd mesh, and Protocol Recorder Relays
# -----------------------------------------------------------------------------

echo "==> starting private Tor net (3 authorities, 3 relays, 1 client)"
TOR_AUTH_PORTS="$(cat "${TORNET_DIR}/auth-ports.inc")"
render_torrc() {
  local nick="$1"
  local ddir="$2"
  local extra="$3"
  mkdir -p "$ddir" || return 1
  python3 - "${TOR_TEMPLATE_DIR}" "${TORNET_DIR}/dir-authorities.inc" "$nick" "$ddir" "$extra" <<'PY' > "${ddir}/torrc" || return 1
from pathlib import Path
import sys

templates = Path(sys.argv[1])
authorities = Path(sys.argv[2]).read_text()
text = (templates / "torrc.common.template").read_text()
text += (templates / sys.argv[5]).read_text()
text = text.replace("__NICK__", sys.argv[3])
text = text.replace("__DATADIR__", sys.argv[4])
text = text.replace("__DIRAUTHORITIES__", authorities.rstrip("\n"))
sys.stdout.write(text)
PY
}
for i in 0 1 2; do
  adir="${TORNET_DIR}/auth$i"
  orport="$(printf '%s' "${TOR_AUTH_PORTS}" | python3 -c 'import sys; print(sys.stdin.read().split()[int(sys.argv[1])*2])' "$i")"
  dirport="$(printf '%s' "${TOR_AUTH_PORTS}" | python3 -c 'import sys; print(sys.stdin.read().split()[int(sys.argv[1])*2+1])' "$i")"
  render_torrc "auth$i" "$adir" "torrc.auth.template"
  sed -i -e "s|__ORPORT__|${orport}|g" -e "s|__DIRPORT__|${dirport}|g" "${adir}/torrc"
done
for i in 0 1 2; do
  rdir="${TORNET_DIR}/relay$i"
  rorport="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
  render_torrc "relay$i" "$rdir" "torrc.relay.template"
  sed -i -e "s|__ORPORT__|${rorport}|g" "${rdir}/torrc"
  printf '%s' "$rorport" > "${rdir}/orport"
done
render_torrc "client" "${TORNET_DIR}/client" "torrc.client.template"
sed -i -e "s|__SOCKSPORT__|${TOR_SOCKS_REAL_PORT}|g" -e "s|__CONTROLPORT__|${TOR_CONTROL_PORT}|g" -e "s|__DATADIR__|${TORNET_DIR}/client|g" "${TORNET_DIR}/client/torrc"
for i in 0 1 2; do
  spawn_clean "${TORNET_DIR}/auth$i" "${TOR_CMD[@]}" --defaults-torrc "${TORNET_DIR}/defaults.torrc" -f "${TORNET_DIR}/auth$i/torrc" >"${TORNET_DIR}/auth$i/stdout.log" 2>&1 &
  own_child "$!" "tor-auth$i" || exit 1
done
for i in 0 1 2; do
  spawn_clean "${TORNET_DIR}/relay$i" "${TOR_CMD[@]}" --defaults-torrc "${TORNET_DIR}/defaults.torrc" -f "${TORNET_DIR}/relay$i/torrc" >"${TORNET_DIR}/relay$i/stdout.log" 2>&1 &
  own_child "$!" "tor-relay$i" || exit 1
done
spawn_clean "${TORNET_DIR}/client" "${TOR_CMD[@]}" --defaults-torrc "${TORNET_DIR}/defaults.torrc" -f "${TORNET_DIR}/client/torrc" >"${WORKDIR}/tor-stdout.log" 2>&1 &
TOR_PID=$!
own_child "${TOR_PID}" "tor-client" || exit 1
TOR_LOG="${TORNET_DIR}/client/notice.log"
export TOR_LOG

echo "==> starting private i2pd mesh (netid 77, r0 SAM ${R0_SAM_PORT}, r1 SAM ${R1_SAM_PORT})"
for n in 0 1 2 3 4 5 6; do
  spawn_clean "${I2PD_MESH_DIR}/r$n" "${I2PD_BIN}" --datadir="${I2PD_MESH_DIR}/r$n/data" --conf="${I2PD_MESH_DIR}/r$n/i2pd.conf" >"${I2PD_LOG_DIR}/r$n.log" 2>&1 &
  own_child "$!" "i2pd-r$n" || exit 1
done

echo "==> starting bounded loopback recorder (tracked scripts/overlay_recorder.py)"
cp -- "${TRACKED_RECORDER}" "${WORKDIR}/overlay_recorder.py"
cp -- "${WORKDIR}/overlay_recorder.py" "${WORKDIR}/overlay_recorder_b.py"

# The workdir was empty when the run began, so no earlier run's snapshot or
# marker exists; nothing is deleted here.
spawn_clean "${WORKDIR}" python3 "${WORKDIR}/overlay_recorder.py" \
  --socks-listen "${TOR_SOCKS_PORT}" \
  --socks-target-host 127.0.0.1 \
  --socks-target-port "${TOR_SOCKS_REAL_PORT}" \
  --sam-listen "${REC_SAM_PORT_A}" \
  --sam-target-host 127.0.0.1 \
  --sam-target-port "${R0_SAM_PORT}" \
  --output "${OBSERVATIONS_FILE}" \
  --done "${OBSERVATIONS_DONE}" >"${RECORDER_LOG}" 2>&1 &
RECORDER_PID=$!
own_child "${RECORDER_PID}" "recorder" || exit 1
spawn_clean "${WORKDIR}" python3 "${WORKDIR}/overlay_recorder_b.py" \
  --socks-listen "${TOR_SOCKS_PORT_B}" \
  --socks-target-host 127.0.0.1 \
  --socks-target-port "${TOR_SOCKS_REAL_PORT}" \
  --sam-listen "${REC_SAM_PORT_B}" \
  --sam-target-host 127.0.0.1 \
  --sam-target-port "${R1_SAM_PORT}" \
  --output "${OBSERVATIONS_FILE}.b" \
  --done "${OBSERVATIONS_DONE}.b" >"${RECORDER_LOG}.b" 2>&1 &
RECORDER_B_PID=$!
own_child "${RECORDER_B_PID}" "recorder-b" || exit 1

wait_tcp "${TOR_CONTROL_PORT}" "tor control"
wait_tcp "${TOR_SOCKS_REAL_PORT}" "tor socks real"
wait_tcp "${R0_SAM_PORT}" "i2pd r0 SAM"
wait_tcp "${R1_SAM_PORT}" "i2pd r1 SAM"
wait_tcp "${TOR_SOCKS_PORT}" "recorder SOCKS proxy"
wait_tcp "${TOR_SOCKS_PORT_B}" "recorder SOCKS proxy B"
wait_tcp "${REC_SAM_PORT_A}" "recorder SAM proxy A"
wait_tcp "${REC_SAM_PORT_B}" "recorder SAM proxy B"

echo "==> waiting for tor bootstrap (100%)"
wait_tor_bootstrap

# -----------------------------------------------------------------------------
# Node A Startup & Overlay Initialization
# -----------------------------------------------------------------------------

echo "==> starting node A (onion service + i2p accept)"
start_node "${A_DATADIR}" "${A_RPC_PORT}" "${A_P2P_PORT}" "${A_LOG}" \
  --onion-proxy "127.0.0.1:${TOR_SOCKS_PORT}" \
  --tor-control "127.0.0.1:${TOR_CONTROL_PORT}" \
  --i2p-sam "127.0.0.1:${REC_SAM_PORT_A}" \
  --i2p-accept
A_PID=$!

echo "==> waiting for node A overlay services"
ONION_A=""
I2P_A=""
deadline=$((SECONDS + TIMEOUT_SECONDS))
while ((SECONDS < deadline)); do
  read -r ONION_A I2P_A <<<"$(overlay_addresses "${A_RPC_PORT}" 2>/dev/null || echo ' ')"
  [[ -n "${ONION_A}" && -n "${I2P_A}" ]] && break
  sleep 1
done
if [[ -z "${ONION_A}" || -z "${I2P_A}" ]]; then
  echo "error: node A did not publish onion+i2p services (onion='${ONION_A}' i2p='${I2P_A}')" >&2
  exit 1
fi
echo "==> node A onion: ${ONION_A}"
echo "==> node A i2p: ${I2P_A}"

# Verify private key files exist and have mode 0600 on disk
# Live transport persists JSON-enveloped keys under the regtest identity dir
# overlay-fabfb5da (crates/node/src/config.rs, crates/p2p/src/overlay.rs).
ONION_KEY_FILE="${A_DATADIR}/overlay-fabfb5da/onion.key"
I2P_KEY_FILE="${A_DATADIR}/overlay-fabfb5da/i2p.key"
[[ -f "${ONION_KEY_FILE}" ]] || { echo "error: onion private key file missing: ${ONION_KEY_FILE}" >&2; exit 1; }
[[ -f "${I2P_KEY_FILE}" ]] || { echo "error: i2p private key file missing: ${I2P_KEY_FILE}" >&2; exit 1; }

ONION_MODE=$(stat -c %a "${ONION_KEY_FILE}" 2>/dev/null || stat -f %Lp "${ONION_KEY_FILE}" 2>/dev/null)
I2P_MODE=$(stat -c %a "${I2P_KEY_FILE}" 2>/dev/null || stat -f %Lp "${I2P_KEY_FILE}" 2>/dev/null)
[[ "${ONION_MODE}" == "600" ]] || { echo "error: onion key file mode is ${ONION_MODE}, expected 600" >&2; exit 1; }
[[ "${I2P_MODE}" == "600" ]] || { echo "error: i2p key file mode is ${I2P_MODE}, expected 600" >&2; exit 1; }

# Record private key hashes locally for restart equality check (NEVER logged or emitted)
KEY_ONION_SHA_PRE=$(sha256sum "${ONION_KEY_FILE}" | awk '{print $1}')
KEY_I2P_SHA_PRE=$(sha256sum "${I2P_KEY_FILE}" | awk '{print $1}')

# Mine initial 5 blocks on Node A
rs_result "${A_RPC_PORT}" generatetoaddress "[5, \"${MINING_ADDRESS}\"]" >/dev/null
poll_height "${A_RPC_PORT}" 5 "node A mining"

# -----------------------------------------------------------------------------
# Node B Startup
# -----------------------------------------------------------------------------

echo "==> starting node B (proxy dialer)"
start_node "${B_DATADIR}" "${B_RPC_PORT}" "${B_P2P_PORT}" "${B_LOG}" \
  --proxy "127.0.0.1:${TOR_SOCKS_PORT_B}" \
  --onion-proxy "127.0.0.1:${TOR_SOCKS_PORT_B}" \
  --i2p-sam "127.0.0.1:${REC_SAM_PORT_B}" \
  --v2transport=false
poll_height "${B_RPC_PORT}" 0 "node B rpc"

# -----------------------------------------------------------------------------
# Leg 1: Isolated Onion Transport
# -----------------------------------------------------------------------------

echo "==> [Leg 1] Node B connects to Node A over Onion (${ONION_A}:${VPORT})"
rs_result "${B_RPC_PORT}" addnode "[\"${ONION_A}:${VPORT}\", \"add\"]" >/dev/null
poll_height "${B_RPC_PORT}" 5 "node B initial sync over onion"

TIP_A=$(rs_result "${A_RPC_PORT}" getbestblockhash | python3 -c 'import json, sys; print(json.load(sys.stdin))')
TIP_B=$(rs_result "${B_RPC_PORT}" getbestblockhash | python3 -c 'import json, sys; print(json.load(sys.stdin))')
[[ "${TIP_A}" == "${TIP_B}" ]] || { echo "error: tip mismatch after onion initial sync" >&2; exit 1; }

# Prove exact peers: Node B must have exactly 1 peer, network == "onion"
B_PEERS=$(rs_result "${B_RPC_PORT}" getpeerinfo)
python3 -c '
import json, sys
peers = json.load(sys.stdin)
if len(peers) != 1:
    sys.exit(f"error: expected exactly 1 peer on node B, got {len(peers)}")
if peers[0].get("network") != "onion":
    sys.exit("error: expected onion peer on node B, got {}".format(peers[0].get("network")))
if peers[0].get("inbound") is not False:
    sys.exit("error: expected outbound connection from node B")
' <<<"${B_PEERS}"

A_PEERS=$(rs_result "${A_RPC_PORT}" getpeerinfo)
python3 -c '
import json, sys
peers = json.load(sys.stdin)
if len(peers) != 1:
    sys.exit(f"error: expected exactly 1 peer on node A, got {len(peers)}")
if peers[0].get("network") != "onion":
    sys.exit("error: expected onion peer on node A, got {}".format(peers[0].get("network")))
if peers[0].get("inbound") is not True:
    sys.exit("error: expected inbound connection on node A")
' <<<"${A_PEERS}"

# Bidirectional block/header propagation over Onion
echo "==> [Leg 1] Bidirectional block/header propagation over Onion (A->B then B->A)"
rs_result "${A_RPC_PORT}" generatetoaddress "[3, \"${MINING_ADDRESS}\"]" >/dev/null
poll_height "${B_RPC_PORT}" 8 "node B catch-up over onion (A->B)"

rs_result "${B_RPC_PORT}" generatetoaddress "[2, \"${MINING_ADDRESS}\"]" >/dev/null
poll_height "${A_RPC_PORT}" 10 "node A catch-up from B over onion (B->A)"

TIP_A=$(rs_result "${A_RPC_PORT}" getbestblockhash | python3 -c 'import json, sys; print(json.load(sys.stdin))')
TIP_B=$(rs_result "${B_RPC_PORT}" getbestblockhash | python3 -c 'import json, sys; print(json.load(sys.stdin))')
[[ "${TIP_A}" == "${TIP_B}" ]] || { echo "error: tip mismatch after bidirectional onion sync" >&2; exit 1; }

# Disconnect Onion leg to isolate transports
echo "==> [Leg 1] Disconnecting Onion peer to enforce transport isolation"
rs_result "${B_RPC_PORT}" addnode "[\"${ONION_A}:${VPORT}\", \"remove\"]" >/dev/null 2>&1 || true
rs_result "${B_RPC_PORT}" disconnectnode "[\"${ONION_A}:${VPORT}\"]" >/dev/null 2>&1 || true
poll_peers_empty "${B_RPC_PORT}" "node B after onion disconnect"
poll_peers_empty "${A_RPC_PORT}" "node A after onion disconnect"

# -----------------------------------------------------------------------------
# Leg 2: Isolated I2P Transport
# -----------------------------------------------------------------------------

echo "==> [Leg 2] Node B connects to Node A over I2P (${I2P_A}:${VPORT})"
# Confirm zero peers on both nodes before connecting
B_PEERS_PRE=$(rs_result "${B_RPC_PORT}" getpeerinfo)
A_PEERS_PRE=$(rs_result "${A_RPC_PORT}" getpeerinfo)
python3 -c '
import json, sys
b = json.loads(sys.argv[1])
a = json.loads(sys.argv[2])
if len(b) != 0:
    sys.exit(f"error: node B has active peers before I2P leg: {b}")
if len(a) != 0:
    sys.exit(f"error: node A has active peers before I2P leg: {a}")
' "${B_PEERS_PRE}" "${A_PEERS_PRE}"

rs_result "${B_RPC_PORT}" addnode "[\"${I2P_A}:${VPORT}\", \"add\"]" >/dev/null

deadline=$((SECONDS + TIMEOUT_SECONDS))
I2P_ESTABLISHED=0
while ((SECONDS < deadline)); do
  B_PEERS=$(rs_result "${B_RPC_PORT}" getpeerinfo 2>/dev/null || echo '[]')
  A_PEERS=$(rs_result "${A_RPC_PORT}" getpeerinfo 2>/dev/null || echo '[]')
  if python3 -c '
import json, sys
b_peers = json.loads(sys.argv[1])
a_peers = json.loads(sys.argv[2])
b_ok = len(b_peers) == 1 and b_peers[0].get("network") == "i2p" and not b_peers[0].get("inbound")
a_ok = len(a_peers) == 1 and a_peers[0].get("network") == "i2p" and a_peers[0].get("inbound")
sys.exit(0 if (b_ok and a_ok) else 1)
' "${B_PEERS}" "${A_PEERS}" 2>/dev/null; then
    I2P_ESTABLISHED=1
    break
  fi
  sleep 1
done
[[ "${I2P_ESTABLISHED}" -eq 1 ]] || { echo "error: failed to establish isolated I2P connection" >&2; exit 1; }

# Prove exact peers on both nodes: exactly 1 peer each, network == "i2p", correct inbound direction
B_PEERS=$(rs_result "${B_RPC_PORT}" getpeerinfo)
A_PEERS=$(rs_result "${A_RPC_PORT}" getpeerinfo)
python3 -c '
import json, sys
b_peers = json.loads(sys.argv[1])
a_peers = json.loads(sys.argv[2])
if len(b_peers) != 1:
    sys.exit(f"error: expected exactly 1 peer on node B, got {len(b_peers)}")
if b_peers[0].get("network") != "i2p":
    sys.exit("error: expected i2p peer on node B, got {}".format(b_peers[0].get("network")))
if b_peers[0].get("inbound") is not False:
    sys.exit("error: expected outbound connection from node B")

if len(a_peers) != 1:
    sys.exit(f"error: expected exactly 1 peer on node A, got {len(a_peers)}")
if a_peers[0].get("network") != "i2p":
    sys.exit("error: expected i2p peer on node A, got {}".format(a_peers[0].get("network")))
if a_peers[0].get("inbound") is not True:
    sys.exit("error: expected inbound connection on node A")
' "${B_PEERS}" "${A_PEERS}"

# Bidirectional block/header propagation over I2P
echo "==> [Leg 2] Bidirectional block/header propagation over I2P (A->B then B->A)"
rs_result "${A_RPC_PORT}" generatetoaddress "[2, \"${MINING_ADDRESS}\"]" >/dev/null
poll_height "${B_RPC_PORT}" 12 "node B catch-up over I2P (A->B)"

rs_result "${B_RPC_PORT}" generatetoaddress "[2, \"${MINING_ADDRESS}\"]" >/dev/null
poll_height "${A_RPC_PORT}" 14 "node A catch-up from B over I2P (B->A)"

TIP_A=$(rs_result "${A_RPC_PORT}" getbestblockhash | python3 -c 'import json, sys; print(json.load(sys.stdin))')
TIP_B=$(rs_result "${B_RPC_PORT}" getbestblockhash | python3 -c 'import json, sys; print(json.load(sys.stdin))')
[[ "${TIP_A}" == "${TIP_B}" ]] || { echo "error: tip mismatch after bidirectional I2P sync" >&2; exit 1; }

# Keep I2P leg up into restart: the stale session proves explicit disconnect
echo "==> [Leg 2] Keeping I2P peer up into restart (explicit disconnect proves stale session)"
printf '%s\n' "i2p_leg_kept_up_into_restart=1" >> "${WORKDIR}/restart-readmit.log"

# -----------------------------------------------------------------------------
# Restart Node A & Verify Identity Reuse
# -----------------------------------------------------------------------------

echo "==> Stopping Node A with bounded wait and process exit confirmation"
reap_owned 15 5 "${A_PID}" || exit 1
if [[ -z "${REAP_STATUS}" ]]; then
  echo "error: node A was already gone before it was stopped; its exit was not observed" >&2
  exit 1
fi

echo "==> Capturing stale Node A session on Node B (still listed, I2P sends no remote FIN)"
STALE_B_PEER_ID=$(rs_result "${B_RPC_PORT}" getpeerinfo | python3 -c 'import json,sys; peers=json.load(sys.stdin); print(peers[0].get("id","") if peers else "")')
if [[ -z "${STALE_B_PEER_ID}" ]]; then
  echo "error: no stale peer listed on Node B after stop" >&2
  exit 1
fi
printf '%s\n' "stale_b_peer_id=${STALE_B_PEER_ID}" >> "${WORKDIR}/restart-readmit.log"
echo "==> Explicit I2P disconnect of stale Node A session on Node B (manual, no automatic retry)"
if ! rs_result "${B_RPC_PORT}" disconnectnode "[\"\", ${STALE_B_PEER_ID}]" >/dev/null; then
  echo "error: explicit disconnectnode failed for stale session" >&2
  exit 1
fi
poll_peers_empty "${B_RPC_PORT}" "node B after explicit stale disconnect" || exit 1
printf '%s\n' "explicit_disconnect=ok peer_zero_observed=ok" >> "${WORKDIR}/restart-readmit.log"
# Baseline the Node A recorder channel after Node A is reaped and before the
# restart launch: the old process is gone so it cannot log between baseline and
# launch, and b32 publication itself waits for the SAM root so sampling after
# launch would already contain the fresh SESSION STATUS OK. Only a greater
# ordinal afterwards proves a fresh post-restart Node A SESSION CREATE
# received RESULT=OK through the owned recorder.
SAM_CREATE_BASELINE=$(grep -E "^sam_session_create_ok ordinal=[0-9]+$" "${RECORDER_LOG}" 2>/dev/null | grep -oE "[0-9]+$" | sort -n | tail -n 1 || true)
if ! [[ "${SAM_CREATE_BASELINE}" =~ ^[0-9]+$ ]]; then
  echo "error: recorder-A baseline ordinal missing or unreadable; refusing to claim a fresh root" >&2
  exit 1
fi
if ((SAM_CREATE_BASELINE < 1)); then
  echo "error: recorder-A baseline ordinal is ${SAM_CREATE_BASELINE}, expected >= 1 (Node A root predates restart)" >&2
  exit 1
fi
printf '%s\n' "sam_create_baseline=${SAM_CREATE_BASELINE} channel=recorder-A" >> "${WORKDIR}/restart-readmit.log"

echo "==> Restarting Node A with preserved data directory"
start_node "${A_DATADIR}" "${A_RPC_PORT}" "${A_P2P_PORT}" "${A_LOG2}" \
  --onion-proxy "127.0.0.1:${TOR_SOCKS_PORT}" \
  --tor-control "127.0.0.1:${TOR_CONTROL_PORT}" \
  --i2p-sam "127.0.0.1:${REC_SAM_PORT_A}" \
  --i2p-accept
A_PID=$!

poll_height "${A_RPC_PORT}" 14 "node A restart height"

ONION_A2=""
I2P_A2=""
deadline=$((SECONDS + TIMEOUT_SECONDS))
while ((SECONDS < deadline)); do
  read -r ONION_A2 I2P_A2 <<<"$(overlay_addresses "${A_RPC_PORT}" 2>/dev/null || echo ' ')"
  [[ -n "${ONION_A2}" && -n "${I2P_A2}" ]] && break
  sleep 1
done
[[ "${ONION_A2}" == "${ONION_A}" ]] || { echo "error: onion public identity changed across restart: '${ONION_A}' vs '${ONION_A2}'" >&2; exit 1; }
[[ "${I2P_A2}" == "${I2P_A}" ]] || { echo "error: i2p public identity changed across restart: '${I2P_A}' vs '${I2P_A2}'" >&2; exit 1; }

# Verify key file mode 0600 and byte-identical retention locally
ONION_MODE2=$(stat -c %a "${ONION_KEY_FILE}" 2>/dev/null || stat -f %Lp "${ONION_KEY_FILE}" 2>/dev/null)
I2P_MODE2=$(stat -c %a "${I2P_KEY_FILE}" 2>/dev/null || stat -f %Lp "${I2P_KEY_FILE}" 2>/dev/null)
[[ "${ONION_MODE2}" == "600" ]] || { echo "error: onion key file mode after restart is ${ONION_MODE2}, expected 600" >&2; exit 1; }
[[ "${I2P_MODE2}" == "600" ]] || { echo "error: i2p key file mode after restart is ${I2P_MODE2}, expected 600" >&2; exit 1; }

KEY_ONION_SHA_POST=$(sha256sum "${ONION_KEY_FILE}" | awk '{print $1}')
KEY_I2P_SHA_POST=$(sha256sum "${I2P_KEY_FILE}" | awk '{print $1}')
[[ "${KEY_ONION_SHA_PRE}" == "${KEY_ONION_SHA_POST}" ]] || { echo "error: onion private key file content changed across restart" >&2; exit 1; }
[[ "${KEY_I2P_SHA_PRE}" == "${KEY_I2P_SHA_POST}" ]] || { echo "error: i2p private key file content changed across restart" >&2; exit 1; }

echo "==> Post-restart Node A SAM root readiness (fresh recorder-observed SESSION CREATE OK)"
# The Node A root runs through REC_SAM_PORT_A, so only RECORDER_LOG (A) can
# prove a fresh post-restart Node A SESSION CREATE received RESULT=OK. A
# transient lookup session on the B-side router proves bridge liveness only
# and never substitutes for the A root. Bounded by the existing per-operation
# timeout; no new delay, no rotation, no weaker check.
SAM_CREATE_FRESH=0
SAM_READY_DEADLINE=$((SECONDS + TIMEOUT_SECONDS))
while ((SECONDS < SAM_READY_DEADLINE)); do
  SAM_CREATE_NOW=$(grep -E "^sam_session_create_ok ordinal=[0-9]+$" "${RECORDER_LOG}" 2>/dev/null | grep -oE "[0-9]+$" | sort -n | tail -n 1 || true)
  if ! [[ "${SAM_CREATE_NOW}" =~ ^[0-9]+$ ]]; then SAM_CREATE_NOW=0; fi
  if ((SAM_CREATE_NOW > SAM_CREATE_BASELINE)); then
    SAM_CREATE_FRESH=1
    printf '%s\n' "sam_root_ready=1 baseline=${SAM_CREATE_BASELINE} now=${SAM_CREATE_NOW} channel=recorder-A" >> "${WORKDIR}/restart-readmit.log"
    break
  fi
  sleep 1
done
if ((SAM_CREATE_FRESH != 1)); then
  echo "error: no fresh Node A SESSION CREATE OK observed on recorder-A after restart (baseline ${SAM_CREATE_BASELINE}); refusing to readmit" >&2
  exit 1
fi
echo "==> Post-restart I2P readmit via verified redial watcher (manual, bounded)"
echo "manual_readmit=watcher_before_onetry max_attempts=30 spacing_s=5 budget_s=300" >> "${WORKDIR}/restart-readmit.log"
echo "==> Post-restart live SAM lookup gate (transient liveness plus hash-bound)"
python3 - "${R1_SAM_PORT}" "${I2P_A}" >> "${WORKDIR}/restart-readmit.log" <<'PY'
import base64, hashlib, socket, sys
port = int(sys.argv[1])
want_b32 = sys.argv[2].split(".")[0].lower()
sock = None
fh = None
def sam_tokens(text):
    tokens = []
    current = []
    quoted = escaped = False
    for char in text.strip():
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char in " \t" and not quoted:
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(char)
    if quoted:
        sys.exit("error: malformed reply: unbalanced quote")
    if current:
        tokens.append("".join(current))
    return tokens
def parse_fields(raw, verb, subverb):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        sys.exit(f"error: malformed {verb} {subverb} reply: non-utf8")
    parts = sam_tokens(text)
    if len(parts) < 2 or parts[0] != verb or parts[1] != subverb:
        sys.exit(f"error: malformed {verb} {subverb} reply")
    fields = {}
    for tok in parts[2:]:
        key, sep, value = tok.partition("=")
        if not sep or not key or key in fields:
            sys.exit(f"error: malformed {verb} {subverb} reply")
        fields[key] = value.strip('"')
    return fields
def result_of(fields):
    result = fields.get("RESULT", "UNKNOWN")
    if not result or len(result) > 32 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_" for c in result):
        return "UNKNOWN"
    return result
def i2p_b64(text):
    # SAM replies use the I2P alphabet ("-" and "~" stand for "+" and "/").
    try:
        return base64.b64decode(text.replace("-", "+").replace("~", "/"), validate=True)
    except ValueError:
        sys.exit("error: SAM destination is not canonical base64")
try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=30)
    sock.settimeout(30)
    fh = sock.makefile("rwb")
    def cmd(line):
        fh.write(line.encode() + b"\n")
        fh.flush()
        raw = fh.readline()
        if not raw:
            sys.exit("error: SAM bridge closed before replying (EOF)")
        return raw
    hello = parse_fields(cmd("HELLO VERSION MIN=3.3 MAX=3.3"), "HELLO", "REPLY")
    if hello.get("RESULT") != "OK" or hello.get("VERSION") != "3.3":
        sys.exit(f"error: SAM hello failed: RESULT={result_of(hello)}")
    gate_id = "readmit-gate"
    created = parse_fields(cmd(f"SESSION CREATE STYLE=STREAM ID={gate_id} DESTINATION=TRANSIENT"), "SESSION", "STATUS")
    if created.get("RESULT") != "OK":
        sys.exit(f"error: SAM session create failed: RESULT={result_of(created)}")
    # SESSION STATUS is a reply, never a request: no STATUS command is sent.
    # This transient CREATE OK proves bridge liveness only, not Node A root
    # freshness (proven separately via the recorder-A ordinal above).
    lookup = parse_fields(cmd(f"NAMING LOOKUP NAME={want_b32}.b32.i2p"), "NAMING", "REPLY")
    if lookup.get("RESULT") != "OK":
        sys.exit(f"error: SAM lookup failed: RESULT={result_of(lookup)}")
    if "VALUE" not in lookup:
        sys.exit("error: SAM lookup reply carries 0 VALUE fields, expected 1")
    raw = i2p_b64(lookup["VALUE"])
    if len(raw) < 387:
        sys.exit(f"error: SAM destination is {len(raw)} bytes, shorter than the 387-byte destination header")
    size = 387 + int.from_bytes(raw[385:387], "big")
    if len(raw) != size:
        sys.exit(f"error: SAM destination is {len(raw)} bytes but its certificate declares {size}")
    digest = hashlib.sha256(raw).digest()
    got = base64.b32encode(digest).decode().lower().rstrip("=")
    if got != want_b32:
        sys.exit("error: hash-bound mismatch")
    print(f"transient_create_ok=1 hash_bound=1 b32={want_b32}")
finally:
    try:
        if fh is not None:
            fh.close()
    except Exception:
        pass
    try:
        if sock is not None:
            sock.close()
    except Exception:
        pass
PY
readmit_observed() { # Node B lists an outbound I2P peer (its table was empty after the explicit stale disconnect, so this is the restarted Node A); sets READMIT_OK
  python3 -c '
import json, sys
peers = json.load(sys.stdin)
sys.exit(0 if any(p.get("network") == "i2p" and p.get("inbound") is False for p in peers) else 1)' <<<"$(rs_result "${B_RPC_PORT}" getpeerinfo 2>/dev/null || echo '[]')" || return 1
  READMIT_OK=1
  printf '%s\n' "readmit_established attempts=${READMIT_ATTEMPTS}" >> "${WORKDIR}/restart-readmit.log"
}
READMIT_OK=0
READMIT_ATTEMPTS=0
READMIT_DEADLINE=$((SECONDS + 300))
printf '%s\n' "watcher_started=1 watcher_before_first_onetry=1" >> "${WORKDIR}/restart-readmit.log"
while ((SECONDS < READMIT_DEADLINE)); do
  if ((READMIT_ATTEMPTS == 0)); then
    rs_result "${B_RPC_PORT}" addnode "[\"${I2P_A}:${VPORT}\", \"onetry\"]" >/dev/null 2>&1 || true
    READMIT_ATTEMPTS=$((READMIT_ATTEMPTS + 1))
    printf '%s\n' "readmit_attempt=1 kind=initial_onetry watcher_started_before=1" >> "${WORKDIR}/restart-readmit.log"
    sleep 5
    continue
  fi
  if readmit_observed; then
    break
  fi
  sleep 5
  if ((READMIT_ATTEMPTS >= 30)); then
    break
  fi
  if tail -n 50 "${B_LOG}" 2>/dev/null | grep -q "outbound connection exited with error"; then
    rs_result "${B_RPC_PORT}" addnode "[\"${I2P_A}:${VPORT}\", \"onetry\"]" >/dev/null 2>&1 || true
    READMIT_ATTEMPTS=$((READMIT_ATTEMPTS + 1))
    printf '%s\n' "readmit_attempt=${READMIT_ATTEMPTS} kind=failure_retry" >> "${WORKDIR}/restart-readmit.log"
  elif ((SECONDS >= READMIT_DEADLINE - 295 + READMIT_ATTEMPTS * 5)); then
    rs_result "${B_RPC_PORT}" addnode "[\"${I2P_A}:${VPORT}\", \"onetry\"]" >/dev/null 2>&1 || true
    READMIT_ATTEMPTS=$((READMIT_ATTEMPTS + 1))
    printf '%s\n' "readmit_attempt=${READMIT_ATTEMPTS} kind=silent_stall_retry" >> "${WORKDIR}/restart-readmit.log"
  fi
done
# The loop also ends on the 30-attempt cap or the 300 s deadline without a
# peer. The last attempt, or one made just before the deadline, still gets one
# observation; if the peer was never seen the run stops here, before the
# recorder is finalized and before any evidence or PASS.
if ((READMIT_OK != 1)) && ! readmit_observed; then
  echo "error: post-restart I2P readmit was never observed (${READMIT_ATTEMPTS} attempts within 30 attempts / 300 s); refusing to finalize or report PASS" >&2
  exit 1
fi
printf '%s\n' "manual_readmit_done=1 automatic_node_claim=0" >> "${WORKDIR}/restart-readmit.log"

# -----------------------------------------------------------------------------
# Finalize the Recorder Before Any Observation Is Read
# -----------------------------------------------------------------------------

echo "==> finalizing bounded recorder (stop, reap, verify completion marker)"
finalize_recorder

echo "==> merging dual recorder snapshots (A plus B) and republishing marker"
python3 - "${OBSERVATIONS_FILE}" "${OBSERVATIONS_FILE}.b" "${OBSERVATIONS_DONE}" <<'PY'
import hashlib, json, sys
main_path, b_path, marker_path = sys.argv[1], sys.argv[2], sys.argv[3]
main = json.load(open(main_path))
b = json.load(open(b_path))
main.setdefault("socks", []).extend(b.get("socks", []))
sam = main.setdefault("sam", {})
bsam = b.get("sam", {})
for key in ("hello", "negotiated_version", "session_create", "naming_lookup", "stream_connect", "stream_accept"):
    if not sam.get(key) and bsam.get(key):
        sam[key] = bsam[key]
raw = json.dumps(main, indent=2).encode()
import os
tmp_main = main_path + ".tmp"
with open(tmp_main, "wb") as fh:
    fh.write(raw)
    fh.flush()
    os.fsync(fh.fileno())
os.replace(tmp_main, main_path)
marker = {"schema": "bitcoin-rs-overlay-observations-v1", "complete": True, "observations_bytes": len(raw), "observations_sha256": hashlib.sha256(raw).hexdigest()}
marker_raw = json.dumps(marker, indent=2).encode()
tmp_marker = marker_path + ".tmp"
with open(tmp_marker, "wb") as fh:
    fh.write(marker_raw)
    fh.flush()
    os.fsync(fh.fileno())
os.replace(tmp_marker, marker_path)
print("merged B observations into main snapshot and republished marker")
PY

# -----------------------------------------------------------------------------
# Verify Recorded Wire Protocol Observations (SOCKS5 & SAM 3.3)
# -----------------------------------------------------------------------------

echo "==> Verifying recorded SOCKS and SAM wire protocol observations"
python3 -c '
import sys, json

obs_file = sys.argv[1]
with open(obs_file) as f:
    obs = json.load(f)

# 1. SOCKS5 verification
socks = obs.get("socks", [])
if not isinstance(socks, list) or len(socks) == 0:
    sys.exit("error: no SOCKS5 connections recorded")
matching_socks = [s for s in socks if s.get("atyp") == 3 and s.get("domain_length") == 62]
if len(matching_socks) == 0:
    sys.exit(f"error: no SOCKS5 connect request with ATYP=3 and length=62 observed (records: {socks})")
if matching_socks[0].get("direction") != "outbound":
    sys.exit("error: expected outbound SOCKS stream")
if not str(matching_socks[0].get("target_domain", "")).endswith(".onion"):
    sys.exit("error: expected .onion target domain")

# 2. SAM bridge verification
sam = obs.get("sam", {})
hello = sam.get("hello")
if not isinstance(hello, str) or "HELLO VERSION" not in hello:
    sys.exit("error: SAM HELLO VERSION was not observed")
negotiated_version = sam.get("negotiated_version")
if negotiated_version != "3.3":
    sys.exit(f"error: expected SAM 3.3, got {negotiated_version}")
if not sam.get("stream_connect"):
    sys.exit("error: SAM STREAM CONNECT was not observed")
if not sam.get("stream_accept"):
    sys.exit("error: SAM STREAM ACCEPT was not observed")
if not sam.get("naming_lookup"):
    sys.exit("error: SAM NAMING LOOKUP was not observed")
session_create = sam.get("session_create")
if not isinstance(session_create, str) or "DESTINATION=[REDACTED]" not in session_create:
    sys.exit("error: session_create was not observed sanitized")
print("==> wire protocol observations verified successfully")
' "${OBSERVATIONS_FILE}"

# -----------------------------------------------------------------------------
# Emit Evidence JSON
# -----------------------------------------------------------------------------

A_INFO=$(rs_result "${A_RPC_PORT}" getnetworkinfo)
B_INFO=$(rs_result "${B_RPC_PORT}" getnetworkinfo)
HEIGHT_A=$(rs_result "${A_RPC_PORT}" getblockcount)
HEIGHT_B=$(rs_result "${B_RPC_PORT}" getblockcount)

I2P_FULL_SHA=$(python3 - "${I2P_KEY_FILE}" "${I2P_A}" <<'PY'
import base64, hashlib, json, sys
try:
    with open(sys.argv[1]) as fh:
        stored = json.load(fh)
except OSError as error:
    sys.exit(f"error: i2p key file unreadable: {type(error).__name__}")
except ValueError:
    sys.exit("error: i2p key file is not JSON")
try:
    fields = stored["key"].split()
except (KeyError, AttributeError):
    sys.exit("error: i2p key file lacks key envelope")
if not fields:
    sys.exit("error: i2p key file is empty")
try:
    raw = base64.b64decode(fields[0].replace("-", "+").replace("~", "/"), validate=True)
except ValueError:
    sys.exit("error: i2p key file is not canonical base64")
if len(raw) < 387:
    sys.exit("error: i2p key file is shorter than a destination header")
size = 387 + int.from_bytes(raw[385:387], "big")
if len(raw) < size:
    sys.exit("error: i2p key file is shorter than the destination its certificate declares")
pub = raw[:size]
digest = hashlib.sha256(pub).digest()
b32 = base64.b32encode(digest).decode().lower().rstrip("=")
want = sys.argv[2].split(".")[0].lower()
if b32 != want:
    sys.exit(f"error: destination hash {b32} != requested b32 {want}")
print(hashlib.sha256(pub).hexdigest())
PY
)
[[ -n "${I2P_FULL_SHA}" ]] || { echo "error: full destination decode failed" >&2; exit 1; }

python3 - "${EVIDENCE}" "${OBSERVATIONS_FILE}" "${I2P_FULL_SHA}" <<PY
import hashlib, json, sys

evidence_path, obs_path, i2p_full_sha = sys.argv[1], sys.argv[2], sys.argv[3]

with open(obs_path) as f:
    obs = json.load(f)

def h(text):
    return hashlib.sha256(text.encode()).hexdigest()

matching_socks_list = [s for s in obs.get("socks", []) if s.get("atyp") == 3 and s.get("domain_length") == 62]
if not matching_socks_list:
    sys.exit("evidence error: no matching SOCKS observation recorded; refusing to emit fake proof")
socks_entry = matching_socks_list[0]
for socks_field in ("atyp", "domain_length", "direction"):
    if socks_entry.get(socks_field) is None:
        sys.exit(f"evidence error: SOCKS observation '{socks_field}' missing; refusing to emit fake proof")

sam_obs = obs.get("sam", {})
for req_field in ["hello", "negotiated_version", "session_create", "naming_lookup", "stream_connect", "stream_accept"]:
    if sam_obs.get(req_field) is None:
        sys.exit(f"evidence error: SAM observation '{req_field}' missing; refusing to emit fake proof")

evidence = {
    "schema": "bitcoin-rs-overlay-interop-v1",
    "tor": {
        "version": "${TOR_OBSERVED_VERSION}",
        "version_raw": "${TOR_FIRST_LINE}",
        "release_verified": ("${TOR_OBSERVED_VERSION}" == "0.4.9.14"),
        "gencert_sha256": "${TOR_GENCERT_SHA}",
        "gencert_sha256_pinned": True,
        "private_fixture": {"authorities": 3, "relays": 3, "testing_network": True},
        "public_bootstrap": False,
        "socks_atyp": socks_entry["atyp"],
        "socks_domain_length": socks_entry["domain_length"],
        "control_endpoint": "127.0.0.1:${TOR_CONTROL_PORT}",
        "onion_service": "${ONION_A}",
        "observed_stream_direction": socks_entry["direction"],
    },
    "sam": {
        "r0_bridge": "127.0.0.1:${R0_SAM_PORT}",
        "r1_bridge": "127.0.0.1:${R1_SAM_PORT}",
        "version": "3.0.0",
        "binary_sha256": "${I2PD_BIN_SHA}",
        "release_pin": "3.0.0 tag 137dde2f asset 75365744e1347a6f1ee1d29eca3a6ee41dcd0c7e14c2f015401b283220b2e993",
        "netid": 77,
        "private_mesh": {"routers": 7, "loopbacks": ["127.0.0.1", "127.0.77.1"]},
        "public_reseed": False,
        "hello": sam_obs["hello"],
        "negotiated_version": sam_obs["negotiated_version"],
        "session_create": sam_obs["session_create"],
        "naming_lookup": sam_obs["naming_lookup"],
        "stream_connect": sam_obs["stream_connect"],
        "stream_accept": sam_obs["stream_accept"],
    },
    "sync": {
        "height_a": int("${HEIGHT_A}"),
        "height_b": int("${HEIGHT_B}"),
        "tip_a": "${TIP_A}",
        "tip_b": "${TIP_B}",
        "onion_bidirectional": True,
        "i2p_bidirectional": True,
    },
    "isolation": {
        "onion_leg_isolated": True,
        "i2p_leg_isolated": True,
    },
    "inbound": {
        "onion_accept": True,
        "i2p_accept": True,
    },
    "restart": {
        "process_exit_confirmed": True,
        "explicit_disconnect": True,
        "peer_zero_observed": True,
        "readmit_onetry": ("${READMIT_OK}" == "1"),
        "automatic_retry_claimed": False,
        "onion_reused": True,
        "i2p_reused": True,
        "onion_service_id_sha256": h("${ONION_A}"),
        "i2p_destination_sha256": i2p_full_sha,
        "onion_key_file_mode": "0600",
        "i2p_key_file_mode": "0600",
        "key_files_retained_byte_identical": True,
    },
    "rpc": {
        "a_getnetworkinfo": json.loads('''${A_INFO}'''),
        "b_getnetworkinfo": json.loads('''${B_INFO}'''),
    },
    "logs": {
        "tor": "${TOR_LOG}",
        "i2pd_mesh": "${I2PD_LOG_DIR}",
        "recorder": "${RECORDER_LOG}",
        "node_a": "${A_LOG}",
        "node_a_restart": "${A_LOG2}",
        "node_b": "${B_LOG}",
    },
}

try:
    with open(evidence_path, "x") as fh:
        json.dump(evidence, fh, indent=2)
except FileExistsError:
    sys.exit(f"evidence error: {evidence_path} already exists; refusing to overwrite it")
print(f"evidence written to {evidence_path}")
PY

echo "==> stopping daemons (SIGTERM then SIGKILL through validated handles, bounded)"
reap_owned 5 5 "${!OWNED[@]}" || exit 1

echo "overlay interop: PASS"
