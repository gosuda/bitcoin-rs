#!/usr/bin/env bash
# Live Tor/I2P overlay interop for bitcoin-rs (#1601).
#
# Starts a pinned Tor (loopback ControlPort + SOCKS) and a pinned IVNP
# (SAM bridge at 127.0.0.1:7656), then two regtest bitcoin-rs nodes: one
# publishing an onion service (--onion, --torcontrol) and accepting I2P
# (--i2psam, --i2pacceptincoming), one dialing over the proxies
# (--proxy, --i2psam). Proves handshake, headers/blocks in both
# directions over onion and I2P, inbound accepts, and restart identity
# reuse (onion service key and I2P destination keys persist across
# restarts). Records an evidence JSON (schema
# bitcoin-rs-overlay-interop-v1) and prints `overlay interop: PASS`
# only after every assertion holds; a missing daemon, bootstrap, or
# network prerequisite fails the run (the caller reports BLOCKED).
#
# usage: run-p2p-overlay-interop.sh --tor-command <command>
#            --ivnp-command <command>
#            [--bitcoin-rs-command <command>] [--workdir <dir>]
#            [--evidence <path>] [--timeout-seconds <n>] [--keep]
#
# Pinned externals: Tor 0.4.9.14 release; IVNP v0.4.1 at commit
# 0a1b746ba98b58510eb5dcde679ca43184f4b60e, upstream built with Go
# 1.27.0 compiler header. Any prerequisite mismatch or missing metadata
# fails closed (non-zero exit).
#
# Host: Linux with python3 >= 3.9 (os.pidfd_open, signal.pidfd_send_signal).
# Every listener binds loopback, but Tor and I2P bootstrap over external
# networks, so the overlay daemons need outbound internet access. Children are
# only ever signaled through validated pidfds (see "Child ownership" below).

set -euo pipefail

usage() {
  printf '%s\n' \
    "usage: run-p2p-overlay-interop.sh --tor-command <command> --ivnp-command <command> [--bitcoin-rs-command <command>] [--workdir <dir>] [--evidence <path>] [--timeout-seconds <n>] [--keep]" \
    "" \
    "Required:" \
    "  --tor-command <cmd>       Tor binary (pinned to release 0.4.9.14)" \
    "  --ivnp-command <cmd>      IVNP binary (pinned to commit 0a1b746ba98b58510eb5dcde679ca43184f4b60e built with Go 1.27.0)" \
    "" \
    "Optional:" \
    "  --bitcoin-rs-command <cmd> Path to bitcoin-rs binary (default: target/debug/bitcoin-rs)" \
    "  --workdir <dir>           Preserve run directory at <dir> (default: temporary dir)" \
    "  --evidence <path>         Path to emit evidence JSON (default: <workdir>/evidence.json)" \
    "  --timeout-seconds <n>     Operation timeout deadline in seconds (default: 240)" \
    "  --keep                    Keep temporary workdir on exit" \
    "  -h, --help                Show this help message"
}

TOR_COMMAND=""
IVNP_COMMAND=""
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
    --ivnp-command)
      [[ $# -ge 2 ]] || { echo "error: --ivnp-command requires an argument" >&2; usage >&2; exit 2; }
      IVNP_COMMAND=$2
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

if [[ -z "${TOR_COMMAND}" || -z "${IVNP_COMMAND}" ]]; then
  echo "error: --tor-command and --ivnp-command are required" >&2
  usage >&2
  exit 2
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
  echo "error: Linux pidfd process ownership is unavailable on this host (needs Linux >= 5.3, python3 >= 3.9 with os.pidfd_open and signal.pidfd_send_signal, and a /proc of this pid namespace); not launching children that could not be owned" >&2
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

TOR_VER_RAW=$("${TOR_COMMAND}" --version 2>/dev/null || true)
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

# 2. IVNP binary & Go compiler / VCS revision check
IVNP_BIN="${IVNP_COMMAND%% *}"
if [[ ! -x "${IVNP_BIN}" ]]; then
  echo "error: IVNP binary not found or not executable: ${IVNP_BIN}" >&2
  exit 1
fi

IVNP_METADATA=$(python3 -c '
import sys, subprocess, json

binary = sys.argv[1]
try:
    out = subprocess.check_output(["go", "version", "-m", binary]).decode("utf-8", "replace")
except Exception as e:
    sys.exit(f"failed to read go version -m: {e}")

lines = out.splitlines()
if not lines:
    sys.exit("empty go version -m output")

first = lines[0].split()
go_header = first[1] if len(first) > 1 else ""

rev = None
mod = None
for l in lines:
    parts = l.strip().split()
    if len(parts) >= 2 and parts[0] == "build":
        for p in parts[1:]:
            if p.startswith("vcs.revision="):
                rev = p.split("=", 1)[1]
            elif p.startswith("vcs.modified="):
                mod = p.split("=", 1)[1]

res = {
    "go_header": go_header,
    "revision": rev,
    "modified": mod,
}
print(json.dumps(res))
' "${IVNP_BIN}" 2>/dev/null || true)

if [[ -z "${IVNP_METADATA}" ]]; then
  echo "error: failed to read Go buildinfo metadata from ${IVNP_BIN}; fails closed" >&2
  exit 1
fi

IVNP_GO_HEADER=$(python3 -c 'import sys, json; print(json.loads(sys.argv[1]).get("go_header") or "")' "${IVNP_METADATA}")
IVNP_REVISION=$(python3 -c 'import sys, json; print(json.loads(sys.argv[1]).get("revision") or "")' "${IVNP_METADATA}")
IVNP_MODIFIED=$(python3 -c 'import sys, json; print(json.loads(sys.argv[1]).get("modified") or "")' "${IVNP_METADATA}")

# Strict Go compiler header check: must be go1.27.0
if [[ "${IVNP_GO_HEADER}" != "go1.27.0" ]]; then
  echo "error: IVNP Go compiler mismatch: binary go-version header must be go1.27.0, got: '${IVNP_GO_HEADER}'" >&2
  exit 1
fi

# Strict commit revision check: must be exact 0a1b746ba98b58510eb5dcde679ca43184f4b60e
if [[ -z "${IVNP_REVISION}" ]]; then
  echo "error: IVNP binary missing vcs.revision metadata; fails closed" >&2
  exit 1
fi
if [[ "${IVNP_REVISION}" != "0a1b746ba98b58510eb5dcde679ca43184f4b60e" ]]; then
  echo "error: IVNP revision mismatch: expected commit 0a1b746ba98b58510eb5dcde679ca43184f4b60e, got: '${IVNP_REVISION}'" >&2
  exit 1
fi
if [[ "${IVNP_MODIFIED}" != "false" ]]; then
  echo "error: IVNP binary build metadata must have vcs.modified=false, got: '${IVNP_MODIFIED:-missing}'; fails closed" >&2
  exit 1
fi

# Observed -version output (strictly verified as "dev" for the pinned source build)
IVNP_VERSION=$("${IVNP_BIN}" -version 2>/dev/null | head -n1 | tr -d '\r')
if [[ -z "${IVNP_VERSION}" ]]; then
  echo "error: failed to execute ${IVNP_BIN} -version; fails closed" >&2
  exit 1
fi
if [[ "${IVNP_VERSION}" != "dev" ]]; then
  echo "error: IVNP binary -version output mismatch: expected 'dev' (pinned source build), got: '${IVNP_VERSION}'" >&2
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
TOR_CONTROL_PORT=$(free_port)
SAM_PORT=7656
REC_SAM_PORT=$(free_port)
A_P2P_PORT=$(free_port)
A_RPC_PORT=$(free_port)
B_P2P_PORT=$(free_port)
B_RPC_PORT=$(free_port)
VPORT=18444
MINING_ADDRESS="bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5"

# Verify pinned SAM port 7656 is free
if ! python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 7656)); s.close()' 2>/dev/null; then
  echo "error: port 7656 is already in use; cannot start IVNP SAM bridge on pinned port" >&2
  exit 1
fi

if [[ -z "${WORKDIR}" ]]; then
  WORKDIR=$(mktemp -d /tmp/p2p-overlay-interop.XXXXXX)
  AUTO_WORKDIR=1
fi
if [[ -z "${EVIDENCE}" ]]; then
  EVIDENCE="${WORKDIR}/evidence.json"
fi

TOR_DATADIR="${WORKDIR}/tor-data"
TOR_LOG="${WORKDIR}/tor.log"
IVNP_DIR="${WORKDIR}/ivnp"
IVNP_LOG="${WORKDIR}/ivnp.log"
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

mkdir -p "${TOR_DATADIR}" "${IVNP_DIR}" "${A_DATADIR}" "${B_DATADIR}"

cleanup() {
  local status=$?
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
  # Clean up workdir only if automatically created and --keep not set
  if [[ "${AUTO_WORKDIR}" -eq 1 && "${KEEP}" -eq 0 && -z "${!OWNED[*]}" ]]; then
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
echo "==> ivnp: revision=${IVNP_REVISION} (go ${IVNP_GO_HEADER}, -version '${IVNP_VERSION}') sam backend 127.0.0.1:${SAM_PORT}, recorder sam ${REC_SAM_PORT}"

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
  curl -s --max-time 15 --connect-timeout 5 \
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

start_node() { # <datadir> <rpc> <p2p> <log> [extra...]
  local datadir
  local rpc
  local p2p
  local log
  datadir=$1
  rpc=$2
  p2p=$3
  log=$4
  shift 4
  # shellcheck disable=SC2086
  ${BITCOIN_RS_COMMAND} \
    --network regtest \
    --data-dir "${datadir}" \
    --rpc-bind "127.0.0.1:${rpc}" \
    --rpc-user "${RPC_USER}" \
    --rpc-password "${RPC_PASSWORD}" \
    --p2p-listen "127.0.0.1:${p2p}" \
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

finalize_recorder() { # stop, reap, and verify the recorder's final snapshot
  local pid
  local status
  pid=${RECORDER_PID:-}
  if [[ -z "${pid}" ]]; then
    echo "error: recorder pid unknown; refusing to trust observations" >&2
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
  reap_owned 20 5 "${pid}" || {
    echo "error: recorder could not be stopped; refusing to trust observations (see ${RECORDER_LOG})" >&2
    return 1
  }
  RECORDER_PID=""
  status=${REAP_STATUS}
  if [[ -z "${status}" ]]; then
    echo "error: recorder was already gone before finalization, so its exit status is unavailable; refusing to trust observations (see ${RECORDER_LOG})" >&2
    return 1
  fi
  if [[ "${status}" -ne 0 ]]; then
    echo "error: recorder failed to finalize (status ${status}); observation persistence failed (see ${RECORDER_LOG})" >&2
    return 1
  fi
  python3 - "${OBSERVATIONS_FILE}" "${OBSERVATIONS_DONE}" <<'PY'
import hashlib, json, sys

obs_path, marker_path = sys.argv[1], sys.argv[2]
try:
    with open(marker_path, "rb") as fh:
        marker = json.loads(fh.read())
except Exception as error:
    sys.exit(f"error: recorder completion marker unreadable: {error}")
if marker.get("schema") != "bitcoin-rs-overlay-observations-v1" or marker.get("complete") is not True:
    sys.exit("error: recorder completion marker does not record a complete finalization")
try:
    with open(obs_path, "rb") as fh:
        snapshot = fh.read()
except Exception as error:
    sys.exit(f"error: recorder snapshot unreadable: {error}")
if len(snapshot) != marker.get("observations_bytes"):
    sys.exit("error: recorder snapshot length does not match its completion marker")
if hashlib.sha256(snapshot).hexdigest() != marker.get("observations_sha256"):
    sys.exit("error: recorder snapshot digest does not match its completion marker")
print("==> recorder observations finalized and verified")
PY
}

# -----------------------------------------------------------------------------
# Launch Tor, IVNP, and Protocol Recorder Relay
# -----------------------------------------------------------------------------

echo "==> starting tor"
rm -f -- "${TOR_LOG}" "${WORKDIR}/tor-stdout.log"
cat > "${WORKDIR}/torrc" <<EOF
DataDirectory ${TOR_DATADIR}
SocksPort 127.0.0.1:${TOR_SOCKS_REAL_PORT}
ControlPort 127.0.0.1:${TOR_CONTROL_PORT}
CookieAuthentication 1
Log notice file ${TOR_LOG}
EOF
# shellcheck disable=SC2086
${TOR_COMMAND} -f "${WORKDIR}/torrc" >"${WORKDIR}/tor-stdout.log" 2>&1 &
# TOR_PID only names the owned child for wait_tor_bootstrap's read-only watch;
# it is never signaled, and OWNED stays the only lifecycle.
TOR_PID=$!
own_child "${TOR_PID}" "tor" || exit 1

echo "==> starting ivnpd (SAM 127.0.0.1:${SAM_PORT})"
# exec makes the owned pid the daemon itself; a bare `cd && cmd` list leaves a
# disposable subshell as the owned process and the real daemon unowned.
# shellcheck disable=SC2086
(cd "${IVNP_DIR}" && exec ${IVNP_COMMAND} -config "${IVNP_DIR}/ivnp.conf" -webui=false -http-proxy=false -data-dir "${IVNP_DIR}/data" >"${IVNP_LOG}" 2>&1) &
own_child "$!" "ivnpd" || exit 1

echo "==> starting bounded loopback recorder/relay"
cat > "${WORKDIR}/overlay_recorder.py" <<'PY'
import asyncio
import argparse
import hashlib
import json
import os
import re
import signal
import sys
import threading

# IO_TIMEOUT bounds handshake reads and every write drain, except the reply to
# SESSION CREATE (SESSION_CREATE_TIMEOUT). It is never a lifetime: an
# established SAM root or relayed stream may sit idle for as long as the run
# lasts and ends only on EOF from either side, a failed bounded write, or
# cancellation of its handler.
IO_TIMEOUT = 30.0

# SESSION_CREATE_TIMEOUT is the one wait for the whole reply to an exact
# SESSION CREATE. The pinned bridge answers it only once its destination is
# ready, which can take the node's whole 120 s readiness wait, and the node's
# root budget (TCP connect + HELLO + that wait + NAMING LOOKUP) is 135 s, fixed
# before it connects. Cutting the reply at IO_TIMEOUT would end a root the node
# is still entitled to wait for; this bound never ends it before the node gives
# up. No other command's reply and no write drain uses it, and it is not an
# idle timer for the established root.
SESSION_CREATE_TIMEOUT = 135.0

# FINALIZE_GRACE bounds the whole finalization: cancel handlers, close sockets,
# publish the snapshot and marker. The guard is a plain thread timer, armed the
# moment a stop is requested, so it also fires when the event loop is blocked in
# a synchronous fsync. Expiry exits non-zero without publishing, and every
# publication step is a temp file plus atomic rename, so nothing half-written can
# ever appear as evidence. The owning shell's reap is therefore bounded too.
FINALIZE_GRACE = 15.0
GUARD = None
PUBLISHED = False
LOOP = None

observations = {
    "socks": [],
    "sam": {
        "hello": None,
        "negotiated_version": None,
        "session_create": None,
        "naming_lookup": False,
        "stream_connect": False,
        "stream_accept": False,
    }
}

# Observation persistence is the recorder's one failure path. Any failed write
# records FAILURE, which is never cleared, and sets STOP so the run winds down;
# FAILURE also suppresses publication. Everything before finalization writes
# only <output>.partial, and finalization publishes exactly twice: the snapshot,
# then a completion marker carrying its digest. The runner trusts evidence only
# from a zero exit plus a marker whose digest matches the snapshot.
FAILURE = None
STOP = None

def hard_exit():
    # The timer may fire just as publication completes; a fully written marker
    # is a success, and anything else is a failure that published nothing.
    if PUBLISHED:
        os._exit(0)
    try:
        sys.stderr.write(
            f"recorder failure: finalization exceeded {FINALIZE_GRACE}s; no evidence published\n"
        )
        sys.stderr.flush()
    except Exception:
        pass
    os._exit(1)

def abort(reason):
    if GUARD is not None:
        GUARD.cancel()
    print(f"recorder failure: {reason}", file=sys.stderr, flush=True)
    return 1

def begin_finalization():
    global GUARD
    if GUARD is None:
        GUARD = threading.Timer(FINALIZE_GRACE, hard_exit)
        GUARD.daemon = True
        GUARD.start()

def request_stop():
    begin_finalization()
    if STOP is not None:
        STOP.set()

def on_stop_signal(_signum, _frame):
    # A real signal handler runs in the main thread even while that thread is
    # blocked in a synchronous write, so the guard is armed before anything can
    # stall. Handing the wake-up to the loop keeps the event thread-safe.
    begin_finalization()
    try:
        LOOP.call_soon_threadsafe(STOP.set)
    except Exception:
        pass

def fail(reason):
    global FAILURE
    if FAILURE is None:
        FAILURE = reason
    request_stop()

def write_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def save_obs(path):
    try:
        write_atomic(path, json.dumps(observations, indent=2).encode())
    except Exception as error:
        fail(f"observation snapshot {path} failed: {type(error).__name__}: {error}")
        raise

def clear_stale(paths):
    for path in paths:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except Exception as error:
            fail(f"cannot clear stale {path}: {type(error).__name__}: {error}")
            return False
    return True

def publish(output, done):
    global PUBLISHED
    try:
        snapshot = json.dumps(observations, indent=2).encode()
        write_atomic(output, snapshot)
    except Exception as error:
        fail(f"observation snapshot {output} failed: {type(error).__name__}: {error}")
        return False
    marker = {
        "schema": "bitcoin-rs-overlay-observations-v1",
        "complete": True,
        "observations_bytes": len(snapshot),
        "observations_sha256": hashlib.sha256(snapshot).hexdigest(),
    }
    try:
        write_atomic(done, json.dumps(marker).encode())
    except Exception as error:
        fail(f"completion marker {done} failed: {type(error).__name__}: {error}")
        return False
    PUBLISHED = True
    return True

def sanitize_sam(line: str) -> str:
    line = re.sub(r"DESTINATION=[^\s]+", "DESTINATION=[REDACTED]", line)
    line = re.sub(r"PASSWORD=[^\s]+", "PASSWORD=[REDACTED]", line)
    return line

async def read_exact(reader, n, timeout=IO_TIMEOUT):
    return await asyncio.wait_for(reader.readexactly(n), timeout=timeout)

async def read_line(reader, timeout=IO_TIMEOUT):
    return await asyncio.wait_for(reader.readline(), timeout=timeout)

async def write_drain(writer, data, timeout=IO_TIMEOUT):
    writer.write(data)
    await asyncio.wait_for(writer.drain(), timeout=timeout)

def result_ok(response):
    return "RESULT=OK" in response.split()

def sam_command(line_str):
    # The two leading words of a SAM command, split on the ASCII single space
    # the node frames them with (crates/p2p/src/sam.rs). Whole tokens only:
    # "SESSION CREATEEVIL" is not "SESSION CREATE", so neither the recorded
    # evidence, the established-root decision, nor the reply deadline can be
    # claimed by a line that merely starts with the same letters. Other
    # spacing (repeated, tab, or Unicode whitespace the "replace" decode can
    # produce) is not known to parse as the same command at the bridge, so it
    # classifies as "" and is neither recorded nor given the long wait.
    words = line_str.split(" ", 2)
    return " ".join(words[:2]) if len(words) >= 2 else ""

def observe_sam_command(line_str):
    sam = observations["sam"]
    sanitized = sanitize_sam(line_str)
    command = sam_command(line_str)
    if command == "HELLO VERSION":
        sam["hello"] = sanitized
    elif command == "SESSION CREATE":
        sam["session_create"] = sanitized
    elif command == "NAMING LOOKUP":
        sam["naming_lookup"] = True
    elif command == "STREAM CONNECT":
        sam["stream_connect"] = True
    elif command == "STREAM ACCEPT":
        sam["stream_accept"] = True

async def pipe(reader, writer):
    # Raw relay of one direction: waiting for the next bytes has no deadline,
    # writing them into the peer does.
    while True:
        data = await reader.read(65536)
        if not data:
            return
        await write_drain(writer, data)

async def forward_sam_commands(r_client, w_target, out_path):
    # Established session root: the node sends its next command whenever it
    # needs one, so the wait has no deadline. Each line is still observed
    # (and redacted) before it is forwarded through a bounded write.
    while True:
        line = await r_client.readline()
        if not line:
            return
        observe_sam_command(line.decode("utf-8", "replace").strip())
        await write_drain(w_target, line)
        save_obs(out_path)

async def close_writers(*writers):
    # Close every transport before awaiting any of them, so a further
    # cancellation during the bounded waits cannot leave a peer socket open.
    live = [w for w in writers if w is not None]
    for w in live:
        try:
            w.close()
        except Exception:
            pass
    for w in live:
        try:
            await asyncio.wait_for(w.wait_closed(), timeout=2.0)
        except Exception:
            pass

async def relay_pair(forward, backward):
    # One relay is two directions. It ends when either direction ends (EOF,
    # failed bounded write, reset): the survivor is cancelled and reaped here
    # and the owning handler then closes both writers, so neither direction
    # outlives the other or the handler that owns the pair.
    tasks = [asyncio.create_task(forward), asyncio.create_task(backward)]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if not task.cancelled() and task.exception() is not None:
                print(f"relay ended: {type(task.exception()).__name__}", file=sys.stderr, flush=True)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

async def handle_socks(r_client, w_client, target_port, out_path):
    w_target = None
    try:
        r_target, w_target = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", target_port), timeout=10.0
        )
    except Exception:
        try:
            w_client.close()
            await asyncio.wait_for(w_client.wait_closed(), timeout=2.0)
        except Exception:
            pass
        return

    try:
        ver = await read_exact(r_client, 1)
        if ver != b"\x05":
            return
        nmethods = (await read_exact(r_client, 1))[0]
        methods = await read_exact(r_client, nmethods)
        await write_drain(w_target, b"\x05" + bytes([nmethods]) + methods)

        s_ver = await read_exact(r_target, 1)
        s_method = await read_exact(r_target, 1)
        await write_drain(w_client, s_ver + s_method)

        if s_method == b"\x02":
            auth_ver = await read_exact(r_client, 1)
            ulen = (await read_exact(r_client, 1))[0]
            uname = await read_exact(r_client, ulen)
            plen = (await read_exact(r_client, 1))[0]
            passwd = await read_exact(r_client, plen)
            await write_drain(w_target, auth_ver + bytes([ulen]) + uname + bytes([plen]) + passwd)
            auth_resp = await read_exact(r_target, 2)
            await write_drain(w_client, auth_resp)

        req_head = await read_exact(r_client, 4)
        atyp = req_head[3]
        obs = {
            "atyp": atyp,
            "atyp_hex": f"0x{atyp:02x}",
            "domain_length": None,
            "domain_length_hex": None,
            "target_domain": None,
            "target_port": None,
            "direction": "outbound",
            "auth_sanitized": s_method == b"\x02",
        }
        if atyp == 0x03:
            dlen_b = await read_exact(r_client, 1)
            dlen = dlen_b[0]
            domain_bytes = await read_exact(r_client, dlen)
            port_bytes = await read_exact(r_client, 2)
            port = int.from_bytes(port_bytes, "big")
            obs["domain_length"] = dlen
            obs["domain_length_hex"] = f"0x{dlen:02x}"
            obs["target_domain"] = domain_bytes.decode("ascii", "replace")
            obs["target_port"] = port
            await write_drain(w_target, req_head + dlen_b + domain_bytes + port_bytes)
        elif atyp == 0x01:
            ip_bytes = await read_exact(r_client, 4)
            port_bytes = await read_exact(r_client, 2)
            await write_drain(w_target, req_head + ip_bytes + port_bytes)
        elif atyp == 0x04:
            ip_bytes = await read_exact(r_client, 16)
            port_bytes = await read_exact(r_client, 2)
            await write_drain(w_target, req_head + ip_bytes + port_bytes)
        else:
            return

        observations["socks"].append(obs)
        save_obs(out_path)

        rep_head = await read_exact(r_target, 4)
        rep_atyp = rep_head[3]
        if rep_atyp == 0x01:
            rep_addr = await read_exact(r_target, 4)
        elif rep_atyp == 0x03:
            rep_dlen = (await read_exact(r_target, 1))[0]
            rep_addr = bytes([rep_dlen]) + (await read_exact(r_target, rep_dlen))
        elif rep_atyp == 0x04:
            rep_addr = await read_exact(r_target, 16)
        else:
            return
        rep_port = await read_exact(r_target, 2)
        await write_drain(w_client, rep_head + rep_addr + rep_port)

        await relay_pair(pipe(r_client, w_target), pipe(r_target, w_client))
    except Exception:
        pass
    finally:
        await close_writers(w_client, w_target)

async def handle_sam(r_client, w_client, target_port, out_path):
    w_target = None
    try:
        r_target, w_target = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", target_port), timeout=10.0
        )
    except Exception:
        try:
            w_client.close()
            await asyncio.wait_for(w_client.wait_closed(), timeout=2.0)
        except Exception:
            pass
        return

    try:
        # Negotiation is lock-step and bounded: one command, one reply. Every
        # wait is limited by IO_TIMEOUT except the reply to an exact SESSION
        # CREATE, whose single wait is SESSION_CREATE_TIMEOUT. It ends when the
        # bridge accepts a STREAM CONNECT/ACCEPT (raw bytes follow) or a
        # SESSION CREATE (the connection becomes the session root and stays
        # open, with no deadline on its idle time).
        established = None
        while established is None:
            line = await read_line(r_client)
            if not line:
                break
            line_str = line.decode("utf-8", "replace").strip()
            command = sam_command(line_str)
            observe_sam_command(line_str)

            await write_drain(w_target, line)

            reply_timeout = SESSION_CREATE_TIMEOUT if command == "SESSION CREATE" else IO_TIMEOUT
            resp_line = await read_line(r_target, reply_timeout)
            if not resp_line:
                break
            resp_str = resp_line.decode("utf-8", "replace").strip()

            if command == "HELLO VERSION" and result_ok(resp_str):
                m = re.search(r"VERSION=([0-9.]+)", resp_str)
                if m:
                    observations["sam"]["negotiated_version"] = m.group(1)

            await write_drain(w_client, resp_line)
            save_obs(out_path)

            if result_ok(resp_str):
                if command in ("STREAM CONNECT", "STREAM ACCEPT"):
                    established = "stream"
                elif command == "SESSION CREATE":
                    established = "session"

        if established == "stream":
            await relay_pair(pipe(r_client, w_target), pipe(r_target, w_client))
        elif established == "session":
            # Later root commands (NAMING LOOKUP, ...) are still observed;
            # replies and any bridge-initiated bytes pass through raw.
            await relay_pair(forward_sam_commands(r_client, w_target, out_path), pipe(r_target, w_client))
    except Exception:
        pass
    finally:
        await close_writers(w_client, w_target)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socks-listen", type=int, required=True)
    parser.add_argument("--socks-target", type=int, required=True)
    parser.add_argument("--sam-listen", type=int, required=True)
    parser.add_argument("--sam-target", type=int, required=True)
    parser.add_argument("--output", type=str, required=True)
    # The runner always passes --done; standalone probes may omit it and get
    # the conventional sibling marker instead. The protocol is identical.
    parser.add_argument("--done", type=str, default=None)
    args = parser.parse_args()
    if not args.done:
        args.done = args.output + ".done"

    global STOP, LOOP
    STOP = asyncio.Event()
    LOOP = asyncio.get_running_loop()

    working = args.output + ".partial"
    if not clear_stale([
        args.output,
        args.output + ".tmp",
        args.done,
        args.done + ".tmp",
        working,
        working + ".tmp",
    ]):
        return abort(FAILURE)
    try:
        save_obs(working)
    except Exception:
        return abort(FAILURE)

    try:
        signal.signal(signal.SIGTERM, on_stop_signal)
        signal.signal(signal.SIGINT, on_stop_signal)
    except (ValueError, OSError) as error:
        fail(f"cannot install stop handlers: {type(error).__name__}: {error}")
        return abort(FAILURE)

    # Every accepted connection runs as a task owned here. asyncio does not
    # track them, and Server.wait_closed() waits for open connections, so
    # cancelling main() must cancel the handlers before the servers close.
    handlers = set()

    def finished(task):
        handlers.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            # Persistence failures already recorded FAILURE; anything else
            # uncaught inside a handler reaches the same single verdict.
            fail(f"connection handler failed: {type(error).__name__}: {error}")

    def serve(handle, target_port):
        def accept(reader, writer):
            task = asyncio.create_task(handle(reader, writer, target_port, working))
            handlers.add(task)
            task.add_done_callback(finished)
        return accept

    socks_srv = await asyncio.start_server(
        serve(handle_socks, args.socks_target), "127.0.0.1", args.socks_listen
    )
    sam_srv = await asyncio.start_server(
        serve(handle_sam, args.sam_target), "127.0.0.1", args.sam_listen
    )
    # The run ends on SIGTERM from the owning shell, on a persistence failure
    # (which sets STOP), or on an accept loop ending. All three converge below.
    serving = [
        asyncio.create_task(socks_srv.serve_forever()),
        asyncio.create_task(sam_srv.serve_forever()),
    ]
    stop_task = asyncio.create_task(STOP.wait())
    done = set()
    try:
        done, _ = await asyncio.wait([*serving, stop_task], return_when=asyncio.FIRST_COMPLETED)
    finally:
        # The guard is armed before any cleanup step, so an unexpected listener
        # exit (which never calls request_stop) is bounded exactly like SIGTERM.
        begin_finalization()

        async def wind_down():
            stop_task.cancel()
            socks_srv.close()
            sam_srv.close()
            for task in serving:
                task.cancel()
            await asyncio.gather(*serving, return_exceptions=True)
            while handlers:
                owned = list(handlers)
                for task in owned:
                    task.cancel()
                await asyncio.gather(*owned, return_exceptions=True)

        # The guard is already armed: request_stop() arms it before setting
        # STOP, and STOP is set here. Awaiting the wind-down keeps its failures
        # visible; the guard covers a stall the loop cannot observe.
        try:
            await wind_down()
        except Exception as error:
            fail(f"wind-down failed: {type(error).__name__}: {error}")

    # A listener that died is not a normal end of run: only STOP (SIGTERM or a
    # recorded failure) may end it, so an accept-loop crash must not publish.
    for task in done:
        if task is stop_task or task.cancelled():
            continue
        error = task.exception()
        fail(
            "listener loop ended unexpectedly"
            if error is None
            else f"listener loop failed: {type(error).__name__}: {error}"
        )

    if FAILURE is not None or not publish(args.output, args.done):
        return abort(FAILURE)

    try:
        os.unlink(working)
    except Exception:
        pass
    if GUARD is not None:
        GUARD.cancel()
    print(f"observations finalized: {args.output}", file=sys.stderr, flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
PY

# No earlier run's snapshot or marker may survive into this run. The recorder
# clears them again itself; this removal also covers a recorder that dies
# before its first write, so nothing stale can be mistaken for evidence.
rm -f -- "${OBSERVATIONS_FILE}" "${OBSERVATIONS_DONE}" \
  "${OBSERVATIONS_FILE}.partial" "${OBSERVATIONS_FILE}.tmp" "${OBSERVATIONS_DONE}.tmp"

python3 "${WORKDIR}/overlay_recorder.py" \
  --socks-listen "${TOR_SOCKS_PORT}" \
  --socks-target "${TOR_SOCKS_REAL_PORT}" \
  --sam-listen "${REC_SAM_PORT}" \
  --sam-target "${SAM_PORT}" \
  --output "${OBSERVATIONS_FILE}" \
  --done "${OBSERVATIONS_DONE}" >"${RECORDER_LOG}" 2>&1 &
RECORDER_PID=$!
own_child "${RECORDER_PID}" "recorder" || exit 1

wait_tcp "${TOR_CONTROL_PORT}" "tor control"
wait_tcp "${TOR_SOCKS_REAL_PORT}" "tor socks real"
wait_tcp "${SAM_PORT}" "ivnp SAM"
wait_tcp "${TOR_SOCKS_PORT}" "recorder SOCKS proxy"
wait_tcp "${REC_SAM_PORT}" "recorder SAM proxy"

echo "==> waiting for tor bootstrap (100%)"
wait_tor_bootstrap

# -----------------------------------------------------------------------------
# Node A Startup & Overlay Initialization
# -----------------------------------------------------------------------------

echo "==> starting node A (onion service + i2p accept)"
start_node "${A_DATADIR}" "${A_RPC_PORT}" "${A_P2P_PORT}" "${A_LOG}" \
  --onion "127.0.0.1:${TOR_SOCKS_PORT}" \
  --torcontrol "127.0.0.1:${TOR_CONTROL_PORT}" \
  --i2psam "127.0.0.1:${REC_SAM_PORT}" \
  --i2pacceptincoming
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
ONION_KEY_FILE="${A_DATADIR}/onion_v3_private_key"
I2P_KEY_FILE="${A_DATADIR}/i2p_private_key"
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
  --proxy "127.0.0.1:${TOR_SOCKS_PORT}" \
  --i2psam "127.0.0.1:${REC_SAM_PORT}" \
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
assert len(peers) == 1, f"expected exactly 1 peer on node B, got {len(peers)}"
assert peers[0]["network"] == "onion", "expected onion peer on node B, got {}".format(peers[0]["network"])
assert not peers[0]["inbound"], "expected outbound connection from node B"
' <<<"${B_PEERS}"

A_PEERS=$(rs_result "${A_RPC_PORT}" getpeerinfo)
python3 -c '
import json, sys
peers = json.load(sys.stdin)
assert len(peers) == 1, f"expected exactly 1 peer on node A, got {len(peers)}"
assert peers[0]["network"] == "onion", "expected onion peer on node A, got {}".format(peers[0]["network"])
assert peers[0]["inbound"], "expected inbound connection on node A"
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
assert len(b) == 0, f"node B has active peers before I2P leg: {b}"
assert len(a) == 0, f"node A has active peers before I2P leg: {a}"
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
assert len(b_peers) == 1, f"expected exactly 1 peer on node B, got {len(b_peers)}"
assert b_peers[0]["network"] == "i2p", "expected i2p peer on node B, got {}".format(b_peers[0]["network"])
assert not b_peers[0]["inbound"], "expected outbound connection from node B"

assert len(a_peers) == 1, f"expected exactly 1 peer on node A, got {len(a_peers)}"
assert a_peers[0]["network"] == "i2p", "expected i2p peer on node A, got {}".format(a_peers[0]["network"])
assert a_peers[0]["inbound"], "expected inbound connection on node A"
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

# Disconnect I2P leg
echo "==> [Leg 2] Disconnecting I2P peer"
rs_result "${B_RPC_PORT}" addnode "[\"${I2P_A}:${VPORT}\", \"remove\"]" >/dev/null 2>&1 || true
rs_result "${B_RPC_PORT}" disconnectnode "[\"${I2P_A}:${VPORT}\"]" >/dev/null 2>&1 || true
poll_peers_empty "${B_RPC_PORT}" "node B after I2P disconnect"
poll_peers_empty "${A_RPC_PORT}" "node A after I2P disconnect"

# -----------------------------------------------------------------------------
# Restart Node A & Verify Identity Reuse
# -----------------------------------------------------------------------------

echo "==> Stopping Node A with bounded wait and process exit confirmation"
reap_owned 15 5 "${A_PID}" || exit 1
if [[ -z "${REAP_STATUS}" ]]; then
  echo "error: node A was already gone before it was stopped; its exit was not observed" >&2
  exit 1
fi

echo "==> Restarting Node A with preserved data directory"
start_node "${A_DATADIR}" "${A_RPC_PORT}" "${A_P2P_PORT}" "${A_LOG2}" \
  --onion "127.0.0.1:${TOR_SOCKS_PORT}" \
  --torcontrol "127.0.0.1:${TOR_CONTROL_PORT}" \
  --i2psam "127.0.0.1:${REC_SAM_PORT}" \
  --i2pacceptincoming
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

# -----------------------------------------------------------------------------
# Finalize the Recorder Before Any Observation Is Read
# -----------------------------------------------------------------------------

echo "==> finalizing bounded recorder (stop, reap, verify completion marker)"
finalize_recorder

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
assert len(socks) > 0, "no SOCKS5 connections recorded"
matching_socks = [s for s in socks if s.get("atyp") == 3 and s.get("domain_length") == 62]
assert len(matching_socks) > 0, f"no SOCKS5 connect request with ATYP=3 and length=62 observed (records: {socks})"
assert matching_socks[0].get("direction") == "outbound", "expected outbound SOCKS stream"
assert matching_socks[0].get("target_domain", "").endswith(".onion"), "expected .onion target domain"

# 2. SAM bridge verification
sam = obs.get("sam", {})
assert sam.get("hello") is not None and "HELLO VERSION" in sam.get("hello"), "SAM HELLO VERSION was not observed"
negotiated_version = sam.get("negotiated_version")
assert negotiated_version == "3.3", f"expected SAM 3.3, got {negotiated_version}"
assert sam.get("stream_connect"), "SAM STREAM CONNECT was not observed"
assert sam.get("stream_accept"), "SAM STREAM ACCEPT was not observed"
assert sam.get("naming_lookup"), "SAM NAMING LOOKUP was not observed"
assert "DESTINATION=[REDACTED]" in (sam.get("session_create") or ""), "session_create should be sanitized"
print("==> wire protocol observations verified successfully")
' "${OBSERVATIONS_FILE}"

# -----------------------------------------------------------------------------
# Emit Evidence JSON
# -----------------------------------------------------------------------------

A_INFO=$(rs_result "${A_RPC_PORT}" getnetworkinfo)
B_INFO=$(rs_result "${B_RPC_PORT}" getnetworkinfo)
HEIGHT_A=$(rs_result "${A_RPC_PORT}" getblockcount)
HEIGHT_B=$(rs_result "${B_RPC_PORT}" getblockcount)

python3 - "${EVIDENCE}" "${OBSERVATIONS_FILE}" <<PY
import hashlib, json, sys

evidence_path = sys.argv[1]
obs_path = sys.argv[2]

with open(obs_path) as f:
    obs = json.load(f)

def h(text):
    return hashlib.sha256(text.encode()).hexdigest()

matching_socks_list = [s for s in obs.get("socks", []) if s.get("atyp") == 3 and s.get("domain_length") == 62]
if not matching_socks_list:
    sys.exit("evidence error: no matching SOCKS observation recorded; refusing to emit fake proof")
socks_entry = matching_socks_list[0]

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
        "socks_atyp": socks_entry["atyp"],
        "socks_atyp_hex": socks_entry["atyp_hex"],
        "socks_domain_length": socks_entry["domain_length"],
        "socks_domain_length_hex": socks_entry["domain_length_hex"],
        "control_endpoint": "127.0.0.1:${TOR_CONTROL_PORT}",
        "onion_service": "${ONION_A}",
        "observed_stream_direction": socks_entry["direction"],
    },
    "sam": {
        "bridge": "127.0.0.1:${SAM_PORT}",
        "hello": sam_obs["hello"],
        "negotiated_version": sam_obs["negotiated_version"],
        "session_create": sam_obs["session_create"],
        "naming_lookup": sam_obs["naming_lookup"],
        "stream_connect": sam_obs["stream_connect"],
        "stream_accept": sam_obs["stream_accept"],
        "ivnp_version": "${IVNP_VERSION}",
        "ivnp_revision": "${IVNP_REVISION}",
        "ivnp_go_header": "${IVNP_GO_HEADER}",
        "ivnp_vcs_modified": ("${IVNP_MODIFIED}" == "true"),
        "ivnp_pinned_commit_verified": ("${IVNP_REVISION}" == "0a1b746ba98b58510eb5dcde679ca43184f4b60e" and "${IVNP_MODIFIED}" == "false"),
        "ivnp_source_qualified_pin": ("${IVNP_VERSION}" == "dev" and "${IVNP_GO_HEADER}" == "go1.27.0"),
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
        "onion_reused": True,
        "i2p_reused": True,
        "onion_service_id_sha256": h("${ONION_A}"),
        "i2p_destination_sha256": h("${I2P_A}"),
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
        "ivnp": "${IVNP_LOG}",
        "recorder": "${RECORDER_LOG}",
        "node_a": "${A_LOG}",
        "node_a_restart": "${A_LOG2}",
        "node_b": "${B_LOG}",
    },
}

with open(evidence_path, "w") as fh:
    json.dump(evidence, fh, indent=2)
print(f"evidence written to {evidence_path}")
PY

echo "==> stopping daemons (SIGTERM then SIGKILL through validated handles, bounded)"
reap_owned 5 5 "${!OWNED[@]}" || exit 1

echo "overlay interop: PASS"
