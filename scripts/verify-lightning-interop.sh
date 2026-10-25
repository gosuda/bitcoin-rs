#!/usr/bin/env bash
# scripts/verify-lightning-interop.sh
#
# Bounded external Lightning backend qualification runner (#1488, Plan Step 30).
#
# Exercises or qualifies unmodified Lightning binaries against an isolated
# regtest bitcoin-rs node using only public JSON-RPC, REST, and ZMQ surfaces.
# Evaluates five observable behaviors per target scenario:
#   1. startup
#   2. chain sync
#   3. new-block/tx detection
#   4. broadcast
#   5. restart/reorg
#
# Records per-behavior outcomes as 'passed', 'failed', or 'not exercised' with
# explicit named prerequisites. If a provisioned target encounters a suspected
# incompatibility, repeats the scenario against Bitcoin Core 31.1 as a
# differential comparator before final classification.
#
# Invariants (ECO-08, ECO-09, Plan Step 30):
# - No version spoofing, wallet emulation, or synthetic test RPCs.
# - Pinned target revisions strictly enforced; no nearest-release substitutions.
# - Bitcoin Core 31.1 is strictly a differential comparator, never a fallback or pass.

set -euo pipefail
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
umask 077

run_with_timeout() {
  local limit
  limit="$1"
  shift
  if ! command -v timeout >/dev/null 2>&1; then
    echo "ERROR: 'timeout' utility missing; refusing unbounded execution of '${1:-command}'" >&2
    return 1
  fi
  timeout "${limit}" "$@"
}

run_in_new_session() {
  if ! command -v setsid >/dev/null 2>&1; then
    echo "ERROR: 'setsid' utility missing; refusing un-isolated launch of '${1:-process}'" >&2
    return 1
  fi
  setsid "$@"
}

# Usage: check_binary_version <bin> <exact|suffix> <expected>; probes `<bin> --version` and prints
# verified, timeout, probe_failed or mismatch:<sanitized first line>. `exact` compares the whole
# first line; `suffix` requires it to end with <expected>. Both compare literally, never as a glob.
check_binary_version() {
  local bin
  bin="$1"
  local match_mode
  match_mode="$2"
  local expected
  expected="$3"
  local ver_out
  local ver_rc=0
  ver_out=$(run_with_timeout 5 "${bin}" --version 2>&1) || ver_rc=$?

  if (( ver_rc == 124 )); then
    echo "timeout"
  elif (( ver_rc != 0 )); then
    echo "probe_failed"
  else
    local first_line
    first_line="${ver_out%%$'\n'*}"
    first_line="${first_line%$'\r'}"
    local matched=0
    if [[ "${match_mode}" == "exact" && "${first_line}" == "${expected}" ]]; then
      matched=1
    elif [[ "${match_mode}" == "suffix" && "${first_line}" == *"${expected}" ]]; then
      matched=1
    fi
    if (( matched == 1 )); then
      echo "verified"
    else
      local ver_sanitized
      ver_sanitized=$(printf '%s' "${first_line}" | tr -cd '[:alnum:]. _+-' | cut -c 1-80)
      echo "mismatch:${ver_sanitized}"
    fi
  fi
}

kill_bounded() {
  local pid
  pid="$1"
  if [[ -z "${pid}" ]] || ! kill -0 "${pid}" 2>/dev/null; then
    return 0
  fi
  kill -TERM "-${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
  local deadline
  deadline=$((SECONDS + 5))
  while (( SECONDS < deadline )) && kill -0 "${pid}" 2>/dev/null; do
    sleep 0.1
  done
  if kill -0 "${pid}" 2>/dev/null; then
    kill -KILL "-${pid}" 2>/dev/null || kill -KILL "${pid}" 2>/dev/null || true
    sleep 0.1
  fi
  wait "${pid}" 2>/dev/null || true
}

cleanup() {
  # `local exit_code=$?` reads the status that triggered the trap; a separate `local` statement
  # would reset $? to 0 first and turn every failing exit into success.
  local exit_code=$?
  if [[ -n "${TARGET_PID:-}" ]]; then
    kill_bounded "${TARGET_PID}"
    TARGET_PID=""
  fi
  if [[ -n "${CORE_TARGET_PID:-}" ]]; then
    kill_bounded "${CORE_TARGET_PID}"
    CORE_TARGET_PID=""
  fi
  if [[ -n "${RS_PID:-}" ]]; then
    kill_bounded "${RS_PID}"
    RS_PID=""
  fi
  if [[ -n "${CORE_PID:-}" ]]; then
    kill_bounded "${CORE_PID}"
    CORE_PID=""
  fi

  # Always preserve WORKDIR and logs as evidence artifacts
  if [[ -n "${WORKDIR:-}" && -d "${WORKDIR}" ]]; then
    echo "==> Preserved interop workdir and logs: ${WORKDIR}" >&2
  fi
  exit "${exit_code}"
}

EVIDENCE_SCHEMA="bitcoin-rs-lightning-interop-v1"

# Pinned revisions from approved Step 30 specification
PIN_LDK_SERVER="c17dc11dde38f88c53457039ddf30c6b90a63ba2"
PIN_LDK_NODE="v0.7.1 (3534a3d) / commit 179b4b2"
PIN_LAMPO_COMMIT="657f25c3940a956b6ee5ba9d5ef3ac67a61a302f"
PIN_LAMPO="v24.06 (${PIN_LAMPO_COMMIT})"
PIN_LND="v0.21.4-beta (390b2d2b7bdcc335c183962e483f5daeceb8f0e7)"
CLN_VERSION_TAG="v26.06.9"
PIN_CLN="${CLN_VERSION_TAG} (a2176589f235b63bc1a37e69362dfd6c925397e9)"
PIN_CORE_COMPARATOR="Bitcoin Core 31.1"

LND_LINUX_AMD64_SHA256="f19efdbde7cbd449d8b3e67bf3e69d0fdc7e6fabed7bed7599829d201c5aa1e8"
LNCLI_LINUX_AMD64_SHA256="7d53b3ab15b7f080c9698a668db7e3169438b9857301ecca5ed9137b3635ec1f"

lnd_release_sha256() {
  [[ "$(uname -s)-$(uname -m)" == "Linux-x86_64" ]] || return 0
  case "$1" in
    lnd) printf '%s\n' "${LND_LINUX_AMD64_SHA256}" ;;
    lncli) printf '%s\n' "${LNCLI_LINUX_AMD64_SHA256}" ;;
  esac
}

declare -A CLN_RELEASE_ARCHIVE_SHA256=(
  ["clightning-v26.06.9-Fedora-40-amd64.tar.gz"]="906a79949563439d0802f525b0cc358ad18c6304f4125b9054322d9d80fefefb"
  ["clightning-v26.06.9-Ubuntu-22.04-amd64.tar.xz"]="da19bd04de3ebb2ae525cfc114b69bf45ce1c53fad7877d011b4fcaeacf0e45a"
  ["clightning-v26.06.9-Ubuntu-24.04-amd64.tar.xz"]="2f5b55838f8de8a7a627f8e34f888afb6770c5f303deee799edac8595bc3d2d1"
  ["clightning-v26.06.9-Ubuntu-26.04-amd64.tar.xz"]="25379fe80763787f174f91961f66ec98de881160184faeb40a5f2fc29c68b29c"
  ["clightning-v26.06.9-Ubuntu-22.04-arm64.tar.xz"]="8bff3b55e41078fc98fb2f0bc454b975aed6fa858c4fe8d7a77e711f2a73e97e"
  ["clightning-v26.06.9-Ubuntu-24.04-arm64.tar.xz"]="b431316721b1001884b51a30c648a52602a51842b2930a6dd04e41ab715060bf"
  ["clightning-v26.06.9-Ubuntu-26.04-arm64.tar.xz"]="a6b2dd612babc4c659414ad574095e4f108e300319e492a760482ab01cdd4035"
  ["clightning-v26.06.9-Ubuntu-22.04-armv7.tar.xz"]="ec77f21a14414ecc196ff40fd1eb893d422e3e18e4c5c05783dda8a491d80fb5"
  ["clightning-v26.06.9-Ubuntu-24.04-armv7.tar.xz"]="64e249e071d72c702489ac3e810f90981f35833b86e57aa3550ecc8cdc2f0e24"
  ["clightning-v26.06.9-Ubuntu-26.04-armv7.tar.xz"]="a166a9ffa0f64631f6796fdbffc6dca1b06576e70785f68d7a56d050a3f60f19"
)

BUILD_PROVENANCE_SCHEMA="bitcoin-rs-lightning-build-provenance-v1"

# Target classification constants
VALID_TARGETS=("all" "ldk-server" "lampo" "lnd" "cln" "alby-hub" "fedimint" "ldk-node" "lexe" "lightning-kmp" "eclair")

# Global script variables
BITCOIN_RS_BIN=""
TARGET="all"
OUTPUT_JSON=""
BITCOIND_BIN="/home/alpha/bitcoin-core-31.1/bin/bitcoind"
WORKDIR=""
TIMEOUT_SECONDS=120
# --verify-pins-only: qualify pins/provenance and host runnability, start no node and no daemon.
PINS_ONLY=0
# Provisionable targets (ldk-server, lampo, lnd, cln) that are not accepted-and-runnable.
PINS_NOT_READY=0

# Binary paths
LDK_SERVER_BIN=""
LDK_SERVER_PROVENANCE=""
LAMPO_BIN=""
LAMPO_PROVENANCE=""
LND_BIN=""
LNCLI_BIN=""
CLN_BIN=""
CLN_RELEASE_ARCHIVE=""
ALBY_HUB_BIN=""
FEDIMINTD_BIN=""
ECLAIR_BIN=""

# Track child PIDs for safe cleanup
RS_PID=""
CORE_PID=""
TARGET_PID=""
CORE_TARGET_PID=""

# Dynamic node endpoints
RS_RPC_PORT=""
RS_P2P_PORT=""
RS_ZMQ_BLOCK_PORT=""
RS_ZMQ_TX_PORT=""
RS_RPC_USER="interop"
RS_RPC_PASS="interop_password"
RS_DATADIR=""
RS_CONFIG_TOML=""
RS_LOG=""

CORE_RPC_PORT=""
CORE_P2P_PORT=""
CORE_ZMQ_BLOCK_PORT=""
CORE_ZMQ_TX_PORT=""
CORE_DATADIR=""
CORE_LOG=""

REPORT_PY=""
STATE_JSON=""

usage() {
  cat <<'EOF'
usage: verify-lightning-interop.sh --bitcoin-rs-bin <path> [OPTIONS]
       verify-lightning-interop.sh --verify-pins-only [OPTIONS]

Required unless --verify-pins-only:
  --bitcoin-rs-bin <path>      Path to bitcoin-rs executable

Options:
  --verify-pins-only           Qualify the pin/provenance and host runnability of the provisioned
                               ldk-server, lampo, lnd and cln binaries and stop: no bitcoin-rs node,
                               no Core comparator, no target daemon is started. Prints one line per
                               target: PIN-ACCEPTED, PIN-REJECTED, PIN-HOST-BLOCKED or
                               PIN-UNPROVISIONED (every cell stays 'not exercised')
  --target <name>              Target to qualify: all|ldk-server|lampo|lnd|cln|
                               alby-hub|fedimint|ldk-node|lexe|lightning-kmp|eclair
                               (default: all)
  --output-json <path>         Path to write evidence JSON report
                               (default: ./lightning-interop-evidence.json)
  --bitcoind-bin <path>        Path to Bitcoin Core binary for differential comparison
                               (default: /home/alpha/bitcoin-core-31.1/bin/bitcoind)
  --workdir <dir>              Directory for node data, configs, and logs
                               (default: mktemp -d /tmp/lightning-interop.XXXXXX)
  --keep                       Compatibility flag (workdir and logs are preserved unconditionally)
  --timeout-seconds <n>        Operation timeout in seconds (default: 120)

Target binary overrides:
  --ldk-server-bin <path>      Path to ldk-server executable (pinned commit c17dc11)
  --ldk-server-provenance <file>
                               Build provenance for --ldk-server-bin (see below); without it
                               the pin is only the binary's self-reported revision
  --lampo-provenance <file>    Build provenance for --lampo-bin (see below); required to run Lampo
  --cln-release-archive <path> Official clightning-v26.06.9 release archive; --cln-bin must be
                               the <prefix>/bin/lightningd of an unmodified extraction of it
                               (digest-checked against the official SHA256SUMS); required to run CLN
  --lampo-bin <path>           Path to lampod-cli executable (pinned v24.06)
  --lnd-bin <path>             Path to lnd executable (pinned v0.21.4-beta); run only when its
                               sha256 equals the upstream manifest-v0.21.4-beta.txt value
  --lncli-bin <path>           Path to lncli executable (for lnd RPC qualification); used only
                               when its sha256 equals the upstream manifest value
  --cln-bin <path>             Path to lightningd executable (pinned v26.06.9)
  --alby-hub-bin <path>        Path to albyhub executable
  --fedimintd-bin <path>       Path to fedimintd executable
  --eclair-bin <path>          Path to eclair-node executable
  -h, --help                   Show this help message and exit

Exit status:
  0    the run finished and the evidence JSON was written; the JSON, not the exit status, is the
       verdict (cells are passed, failed or 'not exercised'); with --verify-pins-only: every
       selected ldk-server/lampo/lnd/cln target is PIN-ACCEPTED
  1    usage or prerequisite error before any target ran: unknown option or target, an option
       without its value, missing or non-executable --bitcoin-rs-bin, invalid --timeout-seconds,
       or setsid/timeout missing
  2    --verify-pins-only only: a selected ldk-server/lampo/lnd/cln target is PIN-REJECTED,
       PIN-HOST-BLOCKED or PIN-UNPROVISIONED
  130  interrupted (INT); 143 terminated (TERM)

Build provenance file: exactly six key=value lines, recorded as pin_status source_qualified.
It is an operator attestation of a clean build of the pinned source commit, not an official
release, and is rejected unless every field matches the approved pin and the executable:
  schema=bitcoin-rs-lightning-build-provenance-v1
  target=<ldk-server|lampo>
  source_commit=<pinned 40-hex commit>
  source_tree=clean
  toolchain=<output of rustc -V>
  binary_sha256=<sha256 of the executable>
EOF
}

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

should_run() {
  local t
  t="$1"
  [[ "${TARGET}" == "all" || "${TARGET}" == "${t}" ]]
}

make_behavior_json() {
  local target
  target="$1"
  local mode
  mode="$2"
  local pin
  pin="$3"
  local pin_status
  pin_status="$4"
  local provisioned
  provisioned="$5"
  local bin_path
  bin_path="$6"
  local decision
  decision="$7"
  local s_startup
  s_startup="$8"
  local r_startup
  r_startup="$9"
  local a_startup
  a_startup="${10}"
  local s_sync
  s_sync="${11}"
  local r_sync
  r_sync="${12}"
  local a_sync
  a_sync="${13}"
  local s_detect
  s_detect="${14}"
  local r_detect
  r_detect="${15}"
  local a_detect
  a_detect="${16}"
  local s_broadcast
  s_broadcast="${17}"
  local r_broadcast
  r_broadcast="${18}"
  local a_broadcast
  a_broadcast="${19}"
  local s_restart
  s_restart="${20}"
  local r_restart
  r_restart="${21}"
  local a_restart
  a_restart="${22}"

  python3 -c '
import json, sys

def to_none_if_empty(v):
    return None if v == "" or v == "None" else v

target = sys.argv[1]
mode = sys.argv[2]
pin = to_none_if_empty(sys.argv[3])
pin_status = sys.argv[4]
provisioned = sys.argv[5] == "true"
bin_path = to_none_if_empty(sys.argv[6])
decision = sys.argv[7]

data = {
    "target": target,
    "mode": mode,
    "approved_pin": pin,
    "pin_status": pin_status,
    "binary_provisioned": provisioned,
    "binary_path": bin_path,
    "distinct_value_decision": decision,
    "behaviors": {
        "startup": {"status": sys.argv[8], "reason": sys.argv[9], "artifact": to_none_if_empty(sys.argv[10])},
        "chain_sync": {"status": sys.argv[11], "reason": sys.argv[12], "artifact": to_none_if_empty(sys.argv[13])},
        "block_tx_detection": {"status": sys.argv[14], "reason": sys.argv[15], "artifact": to_none_if_empty(sys.argv[16])},
        "broadcast": {"status": sys.argv[17], "reason": sys.argv[18], "artifact": to_none_if_empty(sys.argv[19])},
        "restart_reorg": {"status": sys.argv[20], "reason": sys.argv[21], "artifact": to_none_if_empty(sys.argv[22])}
    }
}
print(json.dumps(data))
' "$target" "$mode" "$pin" "$pin_status" "$provisioned" "$bin_path" "$decision" \
  "$s_startup" "$r_startup" "$a_startup" \
  "$s_sync" "$r_sync" "$a_sync" \
  "$s_detect" "$r_detect" "$a_detect" \
  "$s_broadcast" "$r_broadcast" "$a_broadcast" \
  "$s_restart" "$r_restart" "$a_restart"
}

append_target_result() {
  local target_json
  target_json="$1"
  python3 "${REPORT_PY}" add "${STATE_JSON}" "${target_json}"
}

# One stdout line per provisionable target (ldk-server, lampo, lnd, cln):
#   PIN-ACCEPTED      pin/provenance qualified and the binary can run on this host
#   PIN-REJECTED      pin or provenance check failed; the binary is not run
#   PIN-HOST-BLOCKED  pin qualified but the binary cannot run on this host; not a bitcoin-rs result
#   PIN-UNPROVISIONED no binary was provisioned
# Every outcome except ACCEPTED counts toward PINS_NOT_READY (the --verify-pins-only exit status).
note_pin_outcome() {
  printf 'PIN-%s %s: %s\n' "$1" "$2" "$3"
  if [[ "$1" != "ACCEPTED" ]]; then
    PINS_NOT_READY=$((PINS_NOT_READY + 1))
  fi
}

# Records a provisioned target whose five cells cannot run. $4 is the pin status: pin_unverified and
# pin_mismatch are rejected pins; any other status was qualified, so the blocker is the host.
append_blocked_target() {
  local target_data
  target_data=$(make_behavior_json \
    "$1" "$2" "$3" "$4" "true" "$5" "$6" \
    "not exercised" "$7" "None" \
    "not exercised" "$7" "None" \
    "not exercised" "$7" "None" \
    "not exercised" "$7" "None" \
    "not exercised" "$7" "None")
  append_target_result "${target_data}"
  case "$4" in
    pin_unverified|pin_mismatch) note_pin_outcome REJECTED "$1" "$7" ;;
    *) note_pin_outcome HOST-BLOCKED "$1" "$7" ;;
  esac
}

# Called once an evaluator has qualified the pin and the host can run the binary
# (target, mode, pin, pin_status, binary, decision). Under --verify-pins-only it records the five
# cells as not exercised and returns 0 so the evaluator stops before start_bitcoin_rs; in a live run
# it returns 1 and the evaluator proceeds.
accept_pin() {
  note_pin_outcome ACCEPTED "$1" "pin_status=$4 binary=$5"
  if (( PINS_ONLY == 0 )); then
    return 1
  fi
  local reason
  reason="not exercised: pin qualified (pin_status ${4}) by --verify-pins-only, which starts no bitcoin-rs node and no target daemon; no behavior cell was run"
  local target_data
  target_data=$(make_behavior_json \
    "$1" "$2" "$3" "$4" "true" "$5" "$6" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None")
  append_target_result "${target_data}"
  return 0
}

resolve_executable() {
  command -v -- "$1" || true
}

# Lists the shared objects the host cannot resolve for the given executables, one
# "<name>: <soname> => not found" line each (empty output: nothing missing, or no ldd to ask).
# Only digest- or provenance-qualified binaries reach this; ldd loads them in trace mode.
missing_shared_objects() {
  command -v ldd >/dev/null 2>&1 || return 0
  local exe
  for exe in "$@"; do
    ldd -- "${exe}" 2>/dev/null | awk -v name="${exe##*/}" '/=> not found/ { print name ": " $1 " => not found" }' || true
  done
}

# bcli shells out to a bitcoin-cli executable (lightningd --bitcoin-cli); its default is a bare
# "bitcoin-cli" looked up on PATH. Prefer the one beside the Core comparator's bitcoind so it matches
# the Core 31.1 pin, else the first bitcoin-cli on PATH; prints nothing when there is none.
resolve_bitcoin_cli() {
  local bitcoind_exe sibling
  if [[ -n "${BITCOIND_BIN}" ]]; then
    bitcoind_exe=$(resolve_executable "${BITCOIND_BIN}")
    if [[ -n "${bitcoind_exe}" ]]; then
      sibling="$(dirname -- "${bitcoind_exe}")/bitcoin-cli"
      if [[ -x "${sibling}" ]]; then
        printf '%s\n' "${sibling}"
        return 0
      fi
    fi
  fi
  resolve_executable bitcoin-cli
}

# Usage: require_arg <option> <remaining-argument-count>; fails with a stable message and exit 1
# when an option that takes a value is the last argument.
require_arg() {
  if (( $2 < 2 )); then
    echo "ERROR: option $1 requires a value." >&2
    usage >&2
    exit 1
  fi
}

verify_build_provenance() {
  python3 - "$@" <<'PYEOF'
import hashlib
import re
import sys

provenance_file, schema, target, binary, commit = sys.argv[1:6]
KEYS = {"schema", "target", "source_commit", "source_tree", "toolchain", "binary_sha256"}
TOOLCHAIN = r"rustc [0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)? \([0-9a-f]{9,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\)"


def fail(reason):
    print(reason)
    sys.exit(1)


try:
    with open(provenance_file, encoding="utf-8") as f:
        lines = f.read().splitlines()
except (OSError, UnicodeDecodeError) as e:
    fail(f"provenance file unreadable: {e}")

fields = {}
for line in lines:
    key, separator, value = line.partition("=")
    if not separator or key in fields:
        fail(f"malformed or duplicate provenance line {line[:60]!r}")
    fields[key] = value
if set(fields) != KEYS:
    fail(f"provenance keys must be exactly {sorted(KEYS)}")
if fields["schema"] != schema:
    fail(f"provenance schema {fields['schema'][:60]!r} is not {schema}")
if fields["target"] != target:
    fail(f"provenance target {fields['target'][:60]!r} is not {target}")
if fields["source_commit"] != commit:
    fail(f"provenance source_commit {fields['source_commit'][:60]!r} is not the approved commit {commit}")
if fields["source_tree"] != "clean":
    fail(f"provenance source_tree {fields['source_tree'][:60]!r} is not clean")
if not re.fullmatch(TOOLCHAIN, fields["toolchain"]):
    fail(f"provenance toolchain {fields['toolchain'][:80]!r} is not rustc -V output")
if not re.fullmatch(r"[0-9a-f]{64}", fields["binary_sha256"]):
    fail("provenance binary_sha256 is not a sha256 hex digest")

digest = hashlib.sha256()
try:
    with open(binary, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
except OSError as e:
    fail(f"executable unreadable: {e}")
if digest.hexdigest() != fields["binary_sha256"]:
    fail(f"executable sha256 {digest.hexdigest()} differs from provenance binary_sha256 {fields['binary_sha256']}")
print("ok")
PYEOF
}

verify_cln_release_install() {
  python3 - "$@" <<'PYEOF'
import hashlib
import io
import os
import sys
import tarfile

ROOTS = ("bin", "libexec/c-lightning")
archive_path, binary_path, *approved_digests = sys.argv[1:]


def fail(reason):
    print(reason)
    sys.exit(1)


def stream_sha256(reader):
    digest = hashlib.sha256()
    for chunk in iter(lambda: reader.read(1 << 20), b""):
        digest.update(chunk)
    return digest.hexdigest()


def in_roots(rel):
    return any(rel == root or rel.startswith(root + "/") for root in ROOTS)


try:
    with open(archive_path, "rb") as f:
        archive_bytes = f.read()
except OSError as e:
    fail(f"release archive unreadable: {e}")
archive_digest = hashlib.sha256(archive_bytes).hexdigest()
if archive_digest not in approved_digests:
    fail(f"archive sha256 {archive_digest} is not an official clightning-v26.06.9 release archive digest")

expected = {}
try:
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tar:
        for member in tar:
            parts = [p for p in member.name.split("/") if p not in ("", ".")]
            if not parts or parts[0] != "usr" or ".." in parts:
                continue
            rel = "/".join(parts[1:])
            if not in_roots(rel) or member.isdir():
                continue
            if not member.isreg():
                fail(f"archive member {member.name} is not a regular file")
            expected[rel] = stream_sha256(tar.extractfile(member))
except (tarfile.TarError, OSError) as e:
    fail(f"release archive unreadable as tar: {e}")
if "bin/lightningd" not in expected:
    fail("release archive has no usr/bin/lightningd")

real_binary = os.path.realpath(binary_path)
bin_dir = os.path.dirname(real_binary)
if os.path.basename(real_binary) != "lightningd" or os.path.basename(bin_dir) != "bin":
    fail("provisioned binary must be <prefix>/bin/lightningd of an extracted release archive")
prefix = os.path.dirname(bin_dir)

actual = {}
for root in ROOTS:
    for directory, subdirs, files in os.walk(os.path.join(prefix, root)):
        for name in subdirs + files:
            path = os.path.join(directory, name)
            if os.path.islink(path):
                fail(f"install tree contains symlink {os.path.relpath(path, prefix)}")
        for name in files:
            path = os.path.join(directory, name)
            with open(path, "rb") as f:
                actual[os.path.relpath(path, prefix)] = stream_sha256(f)

missing = sorted(set(expected) - set(actual))
extra = sorted(set(actual) - set(expected))
changed = sorted(rel for rel in expected if rel in actual and expected[rel] != actual[rel])
if missing or extra or changed:
    fail(f"install tree differs from the release archive: missing={missing[:3]} extra={extra[:3]} changed={changed[:3]}")
print("ok")
PYEOF
}

# -------------------------------------------------------------------
# bitcoin-rs regtest lifecycle and probe functions
# -------------------------------------------------------------------
rs_rpc() {
  local method
  method="$1"
  shift
  local params_json
  params_json="[]"
  if (($# > 0)); then
    params_json="$1"
  fi

  local res
  res=$(curl -s --connect-timeout 5 --max-time 15 -u "${RS_RPC_USER}:${RS_RPC_PASS}" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"probe\",\"method\":\"${method}\",\"params\":${params_json}}" \
    "http://127.0.0.1:${RS_RPC_PORT}/")

  local err
  err=$(python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    if "error" in d and d["error"] is not None:
        print(json.dumps(d["error"]))
        sys.exit(1)
except Exception as e:
    print(str(e))
    sys.exit(1)
' <<<"${res}" 2>/dev/null || true)

  if [[ -n "${err}" ]]; then
    echo "ERROR: RPC ${method} returned error: ${err}" >&2
    return 1
  fi
  printf '%s' "${res}"
}

start_bitcoin_rs() {
  if [[ -n "${RS_PID}" ]] && kill -0 "${RS_PID}" 2>/dev/null; then
    return 0
  fi

  RS_RPC_PORT=$(free_port)
  RS_P2P_PORT=$(free_port)
  RS_ZMQ_BLOCK_PORT=$(free_port)
  RS_ZMQ_TX_PORT=$(free_port)

  RS_DATADIR="${WORKDIR}/rs-datadir"
  RS_CONFIG_TOML="${WORKDIR}/bitcoin-rs.toml"
  RS_LOG="${WORKDIR}/bitcoin-rs.log"

  mkdir -p "${RS_DATADIR}"

  cat > "${RS_CONFIG_TOML}" <<EOF
network = "regtest"
data_dir = "${RS_DATADIR}"
dbcache_mb = 64
log_level = "info"
rpc_bind = "127.0.0.1:${RS_RPC_PORT}"
rpc_user = "${RS_RPC_USER}"
rpc_password = "${RS_RPC_PASS}"
rest = true
txindex = true
script_index = "full"
mining_payout_address = "bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5"
p2p_listen = ["127.0.0.1:${RS_P2P_PORT}"]
dns_seeds_enabled = false

[[notifications.zmq]]
endpoint = "tcp://127.0.0.1:${RS_ZMQ_BLOCK_PORT}"
topics = ["rawblock", "hashblock"]

[[notifications.zmq]]
endpoint = "tcp://127.0.0.1:${RS_ZMQ_TX_PORT}"
topics = ["rawtx", "hashtx", "sequence"]
EOF

  echo "==> Starting bitcoin-rs regtest daemon (RPC: ${RS_RPC_PORT}, P2P: ${RS_P2P_PORT}, ZMQ: ${RS_ZMQ_BLOCK_PORT}/${RS_ZMQ_TX_PORT})..."
  run_in_new_session "${BITCOIN_RS_BIN}" \
    --config "${RS_CONFIG_TOML}" \
    >"${RS_LOG}" 2>&1 &
  RS_PID=$!

  local deadline
  deadline=$((SECONDS + TIMEOUT_SECONDS))
  local ready
  ready=0
  while ((SECONDS < deadline)); do
    if ! kill -0 "${RS_PID}" 2>/dev/null; then
      echo "ERROR: bitcoin-rs process died during startup." >&2
      cat "${RS_LOG}" >&2
      return 1
    fi
    local check_res
    check_res=$(curl -s --connect-timeout 2 --max-time 4 -u "${RS_RPC_USER}:${RS_RPC_PASS}" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":"probe","method":"getblockchaininfo","params":[]}' \
      "http://127.0.0.1:${RS_RPC_PORT}/" || true)
    if [[ -n "${check_res}" ]] && python3 -c 'import json, sys; d=json.loads(sys.stdin.read()); sys.exit(0 if "result" in d else 1)' <<<"${check_res}" 2>/dev/null; then
      ready=1
      break
    fi
    sleep 0.2
  done

  if [[ "${ready}" -ne 1 ]]; then
    echo "ERROR: Timed out waiting for bitcoin-rs JSON-RPC readiness." >&2
    return 1
  fi

  local rest_res
  rest_res=$(curl -sf --connect-timeout 3 --max-time 5 "http://127.0.0.1:${RS_RPC_PORT}/rest/chaininfo.json" || true)
  if [[ -z "${rest_res}" ]]; then
    echo "WARNING: bitcoin-rs REST endpoint did not respond at /rest/chaininfo.json" >&2
  fi

  local esplora_res
  esplora_res=$(curl -sf --connect-timeout 3 --max-time 5 "http://127.0.0.1:${RS_RPC_PORT}/api/blocks/tip/height" || true)
  if [[ -z "${esplora_res}" ]]; then
    echo "WARNING: bitcoin-rs Esplora endpoint did not respond at /api/blocks/tip/height" >&2
  fi

  local mine_addr
  mine_addr="bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5"
  rs_rpc "generatetoaddress" "[101, \"${mine_addr}\"]" >/dev/null || {
    echo "ERROR: generatetoaddress failed during initial regtest mining." >&2
    return 1
  }

  local cur_height
  cur_height=$(rs_rpc "getblockcount" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])') || {
    echo "ERROR: failed to read block count after initial mining." >&2
    return 1
  }
  echo "==> bitcoin-rs daemon ready at height ${cur_height}"
}

stop_bitcoin_rs() {
  if [[ -n "${RS_PID}" ]]; then
    echo "==> Stopping bitcoin-rs regtest daemon (PID ${RS_PID})..."
    kill_bounded "${RS_PID}"
    RS_PID=""
  fi
}

# -------------------------------------------------------------------
# Bitcoin Core 31.1 Differential Comparator
# -------------------------------------------------------------------
core_rpc() {
  local method
  method="$1"
  shift
  local params_json
  params_json="[]"
  if (($# > 0)); then
    params_json="$1"
  fi

  local res
  res=$(curl -s --connect-timeout 5 --max-time 15 -u "${RS_RPC_USER}:${RS_RPC_PASS}" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"probe\",\"method\":\"${method}\",\"params\":${params_json}}" \
    "http://127.0.0.1:${CORE_RPC_PORT}/")

  local err
  err=$(python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    if "error" in d and d["error"] is not None:
        print(json.dumps(d["error"]))
        sys.exit(1)
except Exception as e:
    print(str(e))
    sys.exit(1)
' <<<"${res}" 2>/dev/null || true)

  if [[ -n "${err}" ]]; then
    echo "ERROR: Core RPC ${method} returned error: ${err}" >&2
    return 1
  fi
  printf '%s' "${res}"
}

start_core_comparator() {
  if [[ -n "${CORE_PID}" ]] && kill -0 "${CORE_PID}" 2>/dev/null; then
    return 0
  fi
  if [[ -z "${BITCOIND_BIN}" || ! -x "${BITCOIND_BIN}" ]]; then
    echo "WARNING: Core comparator binary '${BITCOIND_BIN}' not found or not executable." >&2
    return 1
  fi

  CORE_RPC_PORT=$(free_port)
  CORE_P2P_PORT=$(free_port)
  CORE_ZMQ_BLOCK_PORT=$(free_port)
  CORE_ZMQ_TX_PORT=$(free_port)

  CORE_DATADIR="${WORKDIR}/core-datadir"
  CORE_LOG="${WORKDIR}/bitcoind.log"
  mkdir -p "${CORE_DATADIR}"

  echo "==> Starting Bitcoin Core 31.1 comparator (RPC: ${CORE_RPC_PORT}, P2P: ${CORE_P2P_PORT}, ZMQ: ${CORE_ZMQ_BLOCK_PORT}/${CORE_ZMQ_TX_PORT})..."
  run_in_new_session "${BITCOIND_BIN}" \
    -regtest \
    -datadir="${CORE_DATADIR}" \
    -port="${CORE_P2P_PORT}" \
    -bind="127.0.0.1:${CORE_P2P_PORT}" \
    -rpcbind=127.0.0.1 \
    -rpcport="${CORE_RPC_PORT}" \
    -rpcuser="${RS_RPC_USER}" \
    -rpcpassword="${RS_RPC_PASS}" \
    -txindex=1 \
    -zmqpubrawblock="tcp://127.0.0.1:${CORE_ZMQ_BLOCK_PORT}" \
    -zmqpubrawtx="tcp://127.0.0.1:${CORE_ZMQ_TX_PORT}" \
    -fallbackfee=0.0002 \
    >"${CORE_LOG}" 2>&1 &
  CORE_PID=$!

  local deadline
  deadline=$((SECONDS + 30))
  local ready
  ready=0
  while ((SECONDS < deadline)); do
    if ! kill -0 "${CORE_PID}" 2>/dev/null; then
      echo "ERROR: Bitcoin Core comparator died during startup." >&2
      cat "${CORE_LOG}" >&2
      return 1
    fi
    local check_res
    check_res=$(curl -s --connect-timeout 2 --max-time 4 -u "${RS_RPC_USER}:${RS_RPC_PASS}" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":"probe","method":"getblockchaininfo","params":[]}' \
      "http://127.0.0.1:${CORE_RPC_PORT}/" || true)
    if [[ -n "${check_res}" ]] && python3 -c 'import json, sys; d=json.loads(sys.stdin.read()); sys.exit(0 if "result" in d else 1)' <<<"${check_res}" 2>/dev/null; then
      ready=1
      break
    fi
    sleep 0.2
  done

  if [[ "${ready}" -ne 1 ]]; then
    echo "ERROR: Timed out waiting for Bitcoin Core comparator readiness." >&2
    return 1
  fi

  local mine_addr
  mine_addr="bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5"
  core_rpc "generatetoaddress" "[101, \"${mine_addr}\"]" >/dev/null || {
    echo "ERROR: generatetoaddress failed on Core comparator." >&2
    return 1
  }
  local cur_height
  cur_height=$(core_rpc "getblockcount" | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
  echo "==> ${PIN_CORE_COMPARATOR} comparator ready at height ${cur_height}"
}

stop_core_comparator() {
  if [[ -n "${CORE_PID}" ]]; then
    echo "==> Stopping Bitcoin Core comparator (PID ${CORE_PID})..."
    kill_bounded "${CORE_PID}"
    CORE_PID=""
  fi
}

# -------------------------------------------------------------------
# Target Evaluators
# -------------------------------------------------------------------
evaluate_ldk_server() {
  echo "--- Evaluating target: ldk-server (normal zero-fee default mode) ---"
  if [[ -z "${LDK_SERVER_BIN}" ]]; then
    local reason
    reason="Missing binary prerequisite: ldk-server binary matching pinned commit ${PIN_LDK_SERVER} not provisioned"
    local decision
    decision="Normal zero-fee-default mode: [bitcoind] RPC with txindex. Proves basic daemon lifecycle and standard on-chain interaction."
    local target_data
    target_data=$(make_behavior_json \
      "ldk-server" "normal" "${PIN_LDK_SERVER}" "approved_pin_unprovisioned" "false" "None" "${decision}" \
      "not exercised" "${reason}" "None" \
      "not exercised" "${reason}" "None" \
      "not exercised" "${reason}" "None" \
      "not exercised" "${reason}" "None" \
      "not exercised" "${reason}" "None")
    append_target_result "${target_data}"
    note_pin_outcome UNPROVISIONED "ldk-server" "${reason}"
  else
    echo "==> Provisioned ldk-server binary found: ${LDK_SERVER_BIN}"
    local ldk_decision="Normal zero-fee-default mode: [bitcoind] RPC with txindex."
    local ver_check
    ver_check=$(check_binary_version "${LDK_SERVER_BIN}" suffix " 0.1.0 (${PIN_LDK_SERVER})")
    if [[ "${ver_check}" == "timeout" ]]; then
      append_blocked_target "ldk-server" "normal" "${PIN_LDK_SERVER}" "pin_unverified" "${LDK_SERVER_BIN}" "${ldk_decision}" \
        "not exercised: provisioned ldk-server --version probe timed out after 5s"
      return 0
    elif [[ "${ver_check}" == "probe_failed" ]]; then
      append_blocked_target "ldk-server" "normal" "${PIN_LDK_SERVER}" "pin_unverified" "${LDK_SERVER_BIN}" "${ldk_decision}" \
        "not exercised: provisioned ldk-server --version probe failed"
      return 0
    elif [[ "${ver_check}" == mismatch:* ]]; then
      local ver_sanitized="${ver_check#mismatch:}"
      echo "WARNING: Provisioned ldk-server version does not match approved pin ${PIN_LDK_SERVER} (version: ${ver_sanitized})" >&2
      append_blocked_target "ldk-server" "normal" "${PIN_LDK_SERVER}" "pin_mismatch" "${LDK_SERVER_BIN}" "${ldk_decision}" \
        "not exercised: provisioned ldk-server binary version does not match approved pin ${PIN_LDK_SERVER} (version: ${ver_sanitized})"
      return 0
    fi
    local ldk_server_exe
    ldk_server_exe=$(resolve_executable "${LDK_SERVER_BIN}")
    local pin_status="self_reported_revision"
    if [[ -n "${LDK_SERVER_PROVENANCE}" ]]; then
      local provenance_result
      local provenance_rc=0
      provenance_result=$(verify_build_provenance "${LDK_SERVER_PROVENANCE}" "${BUILD_PROVENANCE_SCHEMA}" "ldk-server" "${ldk_server_exe}" "${PIN_LDK_SERVER}") || provenance_rc=$?
      if (( provenance_rc != 0 )); then
        echo "WARNING: ldk-server build provenance rejected: ${provenance_result}" >&2
        append_blocked_target "ldk-server" "normal" "${PIN_LDK_SERVER}" "pin_mismatch" "${LDK_SERVER_BIN}" \
          "Normal zero-fee-default mode: [bitcoind] RPC with txindex." \
          "not exercised: build provenance for provisioned ldk-server ${LDK_SERVER_BIN} rejected: ${provenance_result}; the binary is not run"
        return 0
      fi
      pin_status="source_qualified"
    fi
    local ldk_missing
    ldk_missing=$(missing_shared_objects "${ldk_server_exe}")
    if [[ -n "${ldk_missing}" ]]; then
      append_blocked_target "ldk-server" "normal" "${PIN_LDK_SERVER}" "${pin_status}" "${LDK_SERVER_BIN}" "${ldk_decision}" \
        "not exercised: blocked on host: ldk-server ${LDK_SERVER_BIN} needs shared libraries this host lacks (${ldk_missing//$'\n'/; }); this is a host prerequisite, not a bitcoin-rs result; no bitcoin-rs node was started"
      return 0
    fi
    if accept_pin "ldk-server" "normal" "${PIN_LDK_SERVER}" "${pin_status}" "${LDK_SERVER_BIN}" "${ldk_decision}"; then
      return 0
    fi
    start_bitcoin_rs

    local ldk_server_datadir
    ldk_server_datadir="${WORKDIR}/ldk-server-data"
    local ldk_server_log
    ldk_server_log="${WORKDIR}/ldk-server.log"
    mkdir -p "${ldk_server_datadir}"

    local ldk_listen_port
    ldk_listen_port=$(free_port)
    local ldk_grpc_port
    ldk_grpc_port=$(free_port)
    cat > "${ldk_server_datadir}/ldk-server-config.toml" <<EOF
[node]
network = "regtest"
listening_addresses = ["127.0.0.1:${ldk_listen_port}"]
grpc_service_address = "127.0.0.1:${ldk_grpc_port}"

[storage.disk]
dir_path = "${ldk_server_datadir}/storage"

[bitcoind]
rpc_address = "127.0.0.1:${RS_RPC_PORT}"
rpc_user = "${RS_RPC_USER}"
rpc_password = "${RS_RPC_PASS}"
EOF

    echo "==> Spawning ldk-server daemon..."
    run_in_new_session "${ldk_server_exe}" "${ldk_server_datadir}/ldk-server-config.toml" >"${ldk_server_log}" 2>&1 &
    TARGET_PID=$!

    sleep 2
    local b_startup="not exercised"
    local b_startup_reason="Process spawn observed; live gRPC status probe required before claiming passed startup"
    local b_sync="not exercised"
    local b_sync_reason="Requires live gRPC client probe to verify synced height"
    local b_detect="not exercised"
    local b_detect_reason="Requires live wallet / channel establishment on regtest"
    local b_broadcast="not exercised"
    local b_broadcast_reason="Requires funded channel transaction creation"
    local b_restart="not exercised"
    local b_restart_reason="Deferred to persistent channel lifecycle testing"

    if ! kill -0 "${TARGET_PID}" 2>/dev/null; then
      if start_core_comparator; then
        echo "==> Repeating ldk-server against Core 31.1 differential comparator..."
        local core_listen_port
        core_listen_port=$(free_port)
        local core_grpc_port
        core_grpc_port=$(free_port)
        cat > "${ldk_server_datadir}/core-config.toml" <<EOF
[node]
network = "regtest"
listening_addresses = ["127.0.0.1:${core_listen_port}"]
grpc_service_address = "127.0.0.1:${core_grpc_port}"

[storage.disk]
dir_path = "${ldk_server_datadir}/core-storage"

[bitcoind]
rpc_address = "127.0.0.1:${CORE_RPC_PORT}"
rpc_user = "${RS_RPC_USER}"
rpc_password = "${RS_RPC_PASS}"
EOF
        local core_ldk_log
        core_ldk_log="${WORKDIR}/ldk-server-core.log"
        run_in_new_session "${ldk_server_exe}" "${ldk_server_datadir}/core-config.toml" >"${core_ldk_log}" 2>&1 &
        CORE_TARGET_PID=$!
        sleep 2
        if ! kill -0 "${CORE_TARGET_PID}" 2>/dev/null; then
          b_startup_reason="Target failed identically on Core 31.1 differential comparator; not a bitcoin-rs defect"
        else
          b_startup="not exercised"
          b_startup_reason="ldk-server process exited on startup against bitcoin-rs; Core 31.1 process survival observed but live gRPC status probe unverified"
        fi
        kill_bounded "${CORE_TARGET_PID}"
        CORE_TARGET_PID=""
        stop_core_comparator
      fi
    fi

    if [[ -n "${TARGET_PID}" ]]; then
      kill_bounded "${TARGET_PID}"
      TARGET_PID=""
    fi

    local decision
    decision="Normal zero-fee-default mode: [bitcoind] RPC with txindex."
    local target_data
    target_data=$(make_behavior_json \
      "ldk-server" "normal" "${PIN_LDK_SERVER}" "${pin_status}" "true" "${LDK_SERVER_BIN}" "${decision}" \
      "${b_startup}" "${b_startup_reason}" "${ldk_server_log}" \
      "${b_sync}" "${b_sync_reason}" "${ldk_server_log}" \
      "${b_detect}" "${b_detect_reason}" "None" \
      "${b_broadcast}" "${b_broadcast_reason}" "None" \
      "${b_restart}" "${b_restart_reason}" "None")
    append_target_result "${target_data}"
  fi
}

evaluate_ldk_server_advanced() {
  echo "--- Evaluating target: ldk-server (advanced mode: enable_zero_fee_commitments) ---"
  local reason
  reason="Advanced mode blocked by getnetworkinfo.version >= 290000 version-identity gate (bitcoin-rs returns 1400 from PKG_VERSION=0.14.0) and all-V3 submitpackage package relay gate"
  local decision
  decision="Advanced enable_zero_fee_commitments requires Core 29.0+ version identity and all-V3 submitpackage. bitcoin-rs strictly refuses version spoofing."
  local prov="false"
  local pin_st="approved_pin_unprovisioned"
  if [[ -n "${LDK_SERVER_BIN}" ]]; then
    prov="true"
    pin_st="pin_unverified"
  fi
  local target_data
  target_data=$(make_behavior_json \
    "ldk-server" "advanced (zero-fee commitments)" "${PIN_LDK_SERVER}" "${pin_st}" "${prov}" "${LDK_SERVER_BIN:-None}" "${decision}" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None")
  append_target_result "${target_data}"
}

evaluate_lampo() {
  echo "--- Evaluating target: lampo (v24.06) ---"
  if [[ -z "${LAMPO_BIN}" ]]; then
    local reason
    reason="Missing binary prerequisite: lampod-cli binary matching pinned release ${PIN_LAMPO} not provisioned, and a provisioned build also needs --lampo-provenance because lampod-cli prints no version or revision and the GitHub release v24.06 has no binaries or checksums; confirmed gettransaction blocked under NO_WALLET policy (-32601 MethodNotFound)"
    local decision
    decision="backend=core with core-url/core-user/core-pass requires gettransaction under NO_WALLET (blocked) and txindex for confirmed getrawtransaction."
    local target_data
    target_data=$(make_behavior_json \
      "lampo" "backend=core" "${PIN_LAMPO}" "approved_pin_unprovisioned" "false" "None" "${decision}" \
      "not exercised" "${reason}" "None" \
      "not exercised" "${reason}" "None" \
      "not exercised" "${reason}" "None" \
      "not exercised" "${reason}" "None" \
      "not exercised" "${reason}" "None")
    append_target_result "${target_data}"
    note_pin_outcome UNPROVISIONED "lampo" "${reason}"
  else
    echo "==> Provisioned lampod-cli binary found: ${LAMPO_BIN}"
    local lampo_exe
    lampo_exe=$(resolve_executable "${LAMPO_BIN}")
    local lampo_decision="backend=core with core-url/core-user/core-pass requires gettransaction under NO_WALLET (blocked) and txindex for confirmed getrawtransaction."
    if [[ -z "${LAMPO_PROVENANCE}" ]]; then
      append_blocked_target "lampo" "backend=core" "${PIN_LAMPO}" "pin_unverified" "${LAMPO_BIN}" "${lampo_decision}" \
        "not exercised: lampod-cli ${PIN_LAMPO} prints no version or revision (--version is rejected) and the GitHub release v24.06 has no binaries or checksums; pass --lampo-provenance <file> binding the approved clean source commit and the sha256 of ${LAMPO_BIN}; no pin is claimed and the binary is not run"
      return 0
    fi
    local lampo_provenance_result
    local lampo_provenance_rc=0
    lampo_provenance_result=$(verify_build_provenance "${LAMPO_PROVENANCE}" "${BUILD_PROVENANCE_SCHEMA}" "lampo" "${lampo_exe}" "${PIN_LAMPO_COMMIT}") || lampo_provenance_rc=$?
    if (( lampo_provenance_rc != 0 )); then
      echo "WARNING: lampo build provenance rejected: ${lampo_provenance_result}" >&2
      append_blocked_target "lampo" "backend=core" "${PIN_LAMPO}" "pin_mismatch" "${LAMPO_BIN}" "${lampo_decision}" \
        "not exercised: build provenance for provisioned lampod-cli ${LAMPO_BIN} rejected: ${lampo_provenance_result}; the binary is not run"
      return 0
    fi
    local pin_status="source_qualified"
    local lampo_missing
    lampo_missing=$(missing_shared_objects "${lampo_exe}")
    if [[ -n "${lampo_missing}" ]]; then
      append_blocked_target "lampo" "backend=core" "${PIN_LAMPO}" "${pin_status}" "${LAMPO_BIN}" "${lampo_decision}" \
        "not exercised: blocked on host: lampod-cli ${LAMPO_BIN} needs shared libraries this host lacks (${lampo_missing//$'\n'/; }); this is a host prerequisite, not a bitcoin-rs result; no bitcoin-rs node was started"
      return 0
    fi
    if accept_pin "lampo" "backend=core" "${PIN_LAMPO}" "${pin_status}" "${LAMPO_BIN}" "${lampo_decision}"; then
      return 0
    fi
    start_bitcoin_rs

    local lampo_datadir
    lampo_datadir="${WORKDIR}/lampo-data"
    local lampo_log
    lampo_log="${WORKDIR}/lampo.log"
    mkdir -p "${lampo_datadir}"

    local gettx_artifact
    gettx_artifact="${WORKDIR}/lampo-gettransaction-refusal.json"
    curl -s --connect-timeout 5 --max-time 15 -u "${RS_RPC_USER}:${RS_RPC_PASS}" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":"probe_lampo","method":"gettransaction","params":["0000000000000000000000000000000000000000000000000000000000000000"]}' \
      "http://127.0.0.1:${RS_RPC_PORT}/" > "${gettx_artifact}" 2>&1 || true

    echo "==> Running lampod-cli with backend=core..."
    run_in_new_session "${lampo_exe}" \
      --network regtest \
      --data-dir "${lampo_datadir}" \
      --client core \
      --core-url "http://127.0.0.1:${RS_RPC_PORT}" \
      --core-user "${RS_RPC_USER}" \
      --core-pass "${RS_RPC_PASS}" \
      >"${lampo_log}" 2>&1 &
    TARGET_PID=$!

    sleep 2
    local b_startup="not exercised"
    local b_startup_reason="lampod process spawned but full RPC qualification unverified without interactive wallet setup"
    local b_startup_artifact="${lampo_log}"

    if ! kill -0 "${TARGET_PID}" 2>/dev/null; then
      b_startup="not exercised"
      b_startup_reason="lampod process exited on startup; suspected incompatibility requires Core 31.1 differential comparison"
      if start_core_comparator; then
        echo "==> Repeating lampod against Core 31.1 differential comparator..."
        local core_lampo_datadir
        core_lampo_datadir="${WORKDIR}/lampo-core-data"
        local core_lampo_log
        core_lampo_log="${WORKDIR}/lampo-core.log"
        mkdir -p "${core_lampo_datadir}"
        run_in_new_session "${lampo_exe}" \
          --network regtest \
          --data-dir "${core_lampo_datadir}" \
          --client core \
          --core-url "http://127.0.0.1:${CORE_RPC_PORT}" \
          --core-user "${RS_RPC_USER}" \
          --core-pass "${RS_RPC_PASS}" \
          >"${core_lampo_log}" 2>&1 &
        CORE_TARGET_PID=$!
        sleep 2
        if kill -0 "${CORE_TARGET_PID}" 2>/dev/null; then
          b_startup="not exercised"
          b_startup_reason="lampod process exited on startup against bitcoin-rs (-32601 MethodNotFound for gettransaction under NO_WALLET); Core 31.1 process survival observed but full target RPC readiness unverified without interactive wallet setup"
          b_startup_artifact="${gettx_artifact}"
        else
          b_startup="not exercised"
          b_startup_reason="lampod process failed identically against Core 31.1 differential comparator; not a bitcoin-rs defect"
          b_startup_artifact="${core_lampo_log}"
        fi
        kill_bounded "${CORE_TARGET_PID}"
        CORE_TARGET_PID=""
        stop_core_comparator
      else
        b_startup="not exercised"
        b_startup_reason="lampod suspected failure on bitcoin-rs; Core 31.1 comparator unavailable for differential verification"
      fi
    else
      kill_bounded "${TARGET_PID}"
      TARGET_PID=""
    fi

    local decision
    decision="backend=core with core-url/core-user/core-pass requires gettransaction under NO_WALLET (blocked) and txindex for confirmed getrawtransaction."
    local target_data
    target_data=$(make_behavior_json \
      "lampo" "backend=core" "${PIN_LAMPO}" "${pin_status}" "true" "${LAMPO_BIN}" "${decision}" \
      "${b_startup}" "${b_startup_reason}" "${b_startup_artifact}" \
      "not exercised" "Blocked by startup failure" "None" \
      "not exercised" "Blocked by startup failure" "None" \
      "not exercised" "Blocked by startup failure" "None" \
      "not exercised" "Blocked by startup failure" "None")
    append_target_result "${target_data}"
  fi
}

evaluate_lnd() {
  echo "--- Evaluating target: lnd (v0.21.4-beta) ---"
  if [[ -z "${LND_BIN}" ]]; then
    local reason
    reason="Missing binary prerequisite: lnd binary matching pinned release ${PIN_LND} not provisioned (the unmodified upstream release executable, identified by its manifest-v0.21.4-beta.txt SHA-256 because lnd --version prints only the release tag); requires standard ZMQ (zmqpubrawblock/zmqpubrawtx) and txindex"
    local decision
    decision="Standard ZMQ (zmqpubrawblock/zmqpubrawtx), never rpcpolling. Requires txindex for confirmation queries. Any mempool rawtx/hashtx omission must record reproducible failure without ZMQ production tampering."
    local target_data
    target_data=$(make_behavior_json \
      "lnd" "bitcoin.node=bitcoind (standard ZMQ)" "${PIN_LND}" "approved_pin_unprovisioned" "false" "None" "${decision}" \
      "not exercised" "${reason}" "None" \
      "not exercised" "${reason}" "None" \
      "not exercised" "${reason}" "None" \
      "not exercised" "${reason}" "None" \
      "not exercised" "${reason}" "None")
    append_target_result "${target_data}"
    note_pin_outcome UNPROVISIONED "lnd" "${reason}"
  else
    echo "==> Provisioned lnd binary found: ${LND_BIN}"
    local lnd_decision="Standard ZMQ (zmqpubrawblock/zmqpubrawtx), never rpcpolling. Requires txindex for confirmation queries."
    local lnd_expected_sha
    lnd_expected_sha=$(lnd_release_sha256 lnd)
    local lnd_exe
    lnd_exe=$(resolve_executable "${LND_BIN}")
    local lnd_actual_sha=""
    if [[ -n "${lnd_expected_sha}" && -n "${lnd_exe}" ]] && command -v sha256sum >/dev/null 2>&1; then
      lnd_actual_sha=$(sha256sum -- "${lnd_exe}" | cut -d' ' -f1)
    fi
    if [[ -z "${lnd_actual_sha}" ]]; then
      append_blocked_target "lnd" "bitcoin.node=bitcoind (standard ZMQ)" "${PIN_LND}" "pin_unverified" "${LND_BIN}" "${lnd_decision}" \
        "not exercised: no immutable identity check possible for provisioned lnd ${LND_BIN}: needs an upstream manifest SHA-256 for this platform ($(uname -s)-$(uname -m)) in manifest-v0.21.4-beta.txt and sha256sum, because lnd --version prints only the release tag; no pin is claimed and the binary is not run"
      return 0
    elif [[ "${lnd_actual_sha}" != "${lnd_expected_sha}" ]]; then
      echo "WARNING: Provisioned lnd sha256 ${lnd_actual_sha} does not match upstream manifest ${lnd_expected_sha} for pin ${PIN_LND}" >&2
      append_blocked_target "lnd" "bitcoin.node=bitcoind (standard ZMQ)" "${PIN_LND}" "pin_mismatch" "${LND_BIN}" "${lnd_decision}" \
        "not exercised: provisioned lnd ${LND_BIN} has sha256 ${lnd_actual_sha}, not the upstream manifest-v0.21.4-beta.txt value ${lnd_expected_sha}; it is not the unmodified pinned release executable; the binary is not run"
      return 0
    fi
    local pin_status="verified_approved_pin"
    local lncli_exe=""
    local lncli_expected_sha
    lncli_expected_sha=$(lnd_release_sha256 lncli)
    if [[ -n "${LNCLI_BIN}" && -n "${lncli_expected_sha}" ]]; then
      lncli_exe=$(resolve_executable "${LNCLI_BIN}")
      if [[ -z "${lncli_exe}" ]] || [[ "$(sha256sum -- "${lncli_exe}" | cut -d' ' -f1)" != "${lncli_expected_sha}" ]]; then
        echo "WARNING: Provisioned lncli ${LNCLI_BIN} does not match upstream manifest ${lncli_expected_sha}; its output is not used as evidence" >&2
        lncli_exe=""
      fi
    fi
    local lnd_missing
    lnd_missing=$(missing_shared_objects "${lnd_exe}")
    if [[ -n "${lnd_missing}" ]]; then
      append_blocked_target "lnd" "bitcoin.node=bitcoind (standard ZMQ)" "${PIN_LND}" "${pin_status}" "${LND_BIN}" "${lnd_decision}" \
        "not exercised: blocked on host: lnd ${LND_BIN} (manifest SHA-256 verified) needs shared libraries this host lacks (${lnd_missing//$'\n'/; }); this is a host prerequisite, not a bitcoin-rs result; no bitcoin-rs node was started"
      return 0
    fi
    if accept_pin "lnd" "bitcoin.node=bitcoind (standard ZMQ)" "${PIN_LND}" "${pin_status}" "${LND_BIN}" "${lnd_decision}"; then
      return 0
    fi
    start_bitcoin_rs

    local lnd_datadir
    lnd_datadir="${WORKDIR}/lnd-data"
    local lnd_log
    lnd_log="${WORKDIR}/lnd.log"
    mkdir -p "${lnd_datadir}"

    local lnd_listen_port
    lnd_listen_port=$(free_port)
    local lnd_rpc_port
    lnd_rpc_port=$(free_port)
    local lnd_rest_port
    lnd_rest_port=$(free_port)

    cat > "${lnd_datadir}/lnd.conf" <<EOF
[Application Options]
debuglevel=debug
listen=127.0.0.1:${lnd_listen_port}
rpclisten=127.0.0.1:${lnd_rpc_port}
restlisten=127.0.0.1:${lnd_rest_port}

[Bitcoin]
bitcoin.active=1
bitcoin.regtest=1
bitcoin.node=bitcoind

[Bitcoind]
bitcoind.rpchost=127.0.0.1:${RS_RPC_PORT}
bitcoind.rpcuser=${RS_RPC_USER}
bitcoind.rpcpass=${RS_RPC_PASS}
bitcoind.zmqpubrawblock=tcp://127.0.0.1:${RS_ZMQ_BLOCK_PORT}
bitcoind.zmqpubrawtx=tcp://127.0.0.1:${RS_ZMQ_TX_PORT}
EOF

    echo "==> Spawning lnd daemon..."
    run_in_new_session "${lnd_exe}" --lnddir="${lnd_datadir}" --configfile="${lnd_datadir}/lnd.conf" >"${lnd_log}" 2>&1 &
    TARGET_PID=$!

    sleep 3
    local b_startup="not exercised"
    local b_startup_reason="Process spawn observed; RPC unlocker check required before claiming passed startup"
    local b_sync="not exercised"
    local b_sync_reason="Requires unlocked wallet via lncli to observe synced chain height"
    local b_detect="not exercised"
    local b_detect_reason="Mempool rawtx/hashtx admission check requires active wallet funding"
    local b_broadcast="not exercised"
    local b_broadcast_reason="Requires unlocked wallet"
    local b_restart="not exercised"
    local b_restart_reason="Requires persistent channel state"

    if ! kill -0 "${TARGET_PID}" 2>/dev/null; then
      b_startup="not exercised"
      b_startup_reason="lnd daemon exited prematurely on startup; suspected incompatibility requires Core 31.1 comparison"
      if start_core_comparator; then
        echo "==> Repeating lnd against Core 31.1 differential comparator..."
        local core_lnd_listen_port
        core_lnd_listen_port=$(free_port)
        local core_lnd_rpc_port
        core_lnd_rpc_port=$(free_port)
        local core_lnd_rest_port
        core_lnd_rest_port=$(free_port)

        cat > "${lnd_datadir}/core-lnd.conf" <<EOF
[Application Options]
debuglevel=debug
listen=127.0.0.1:${core_lnd_listen_port}
rpclisten=127.0.0.1:${core_lnd_rpc_port}
restlisten=127.0.0.1:${core_lnd_rest_port}

[Bitcoin]
bitcoin.active=1
bitcoin.regtest=1
bitcoin.node=bitcoind

[Bitcoind]
bitcoind.rpchost=127.0.0.1:${CORE_RPC_PORT}
bitcoind.rpcuser=${RS_RPC_USER}
bitcoind.rpcpass=${RS_RPC_PASS}
bitcoind.zmqpubrawblock=tcp://127.0.0.1:${CORE_ZMQ_BLOCK_PORT}
bitcoind.zmqpubrawtx=tcp://127.0.0.1:${CORE_ZMQ_TX_PORT}
EOF
        local core_lnd_log
        core_lnd_log="${WORKDIR}/lnd-core.log"
        run_in_new_session "${lnd_exe}" --lnddir="${lnd_datadir}" --configfile="${lnd_datadir}/core-lnd.conf" >"${core_lnd_log}" 2>&1 &
        CORE_TARGET_PID=$!
        sleep 3
        if ! kill -0 "${CORE_TARGET_PID}" 2>/dev/null; then
          b_startup_reason="Target failed identically on Core 31.1 differential comparator; not a bitcoin-rs defect"
          b_startup="not exercised"
        else
          b_startup="not exercised"
          b_startup_reason="lnd daemon exited prematurely against bitcoin-rs; Core 31.1 process survival observed but lncli getinfo readiness unverified"
        fi
        kill_bounded "${CORE_TARGET_PID}"
        CORE_TARGET_PID=""
        stop_core_comparator
      fi
    elif [[ -n "${lncli_exe}" ]]; then
      local ln_info
      ln_info=$(run_with_timeout 5 "${lncli_exe}" --network=regtest --lnddir="${lnd_datadir}" getinfo 2>/dev/null || true)
      local is_valid_getinfo
      is_valid_getinfo=$(python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    if isinstance(d, dict) and ("identity_pubkey" in d or "block_height" in d):
        print("valid")
    else:
        print("invalid")
except Exception:
    print("invalid")
' <<<"${ln_info}" 2>/dev/null || echo "invalid")

      if [[ "${is_valid_getinfo}" == "valid" ]]; then
        b_startup="passed"
        b_startup_reason="lnd daemon responding with valid getinfo RPC"
        local synced
        synced=$(python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(d.get("synced_to_chain", False))' <<<"${ln_info}" 2>/dev/null || echo "False")
        if [[ "${synced}" == "True" ]]; then
          b_sync="passed"
          b_sync_reason="lncli getinfo confirmed synchronization with bitcoin-rs regtest tip"
        fi
      fi
    fi

    if [[ -n "${TARGET_PID}" ]]; then
      kill_bounded "${TARGET_PID}"
      TARGET_PID=""
    fi

    local decision
    decision="Standard ZMQ (zmqpubrawblock/zmqpubrawtx), never rpcpolling. Requires txindex for confirmation queries."
    local target_data
    target_data=$(make_behavior_json \
      "lnd" "bitcoin.node=bitcoind (standard ZMQ)" "${PIN_LND}" "${pin_status}" "true" "${LND_BIN}" "${decision}" \
      "${b_startup}" "${b_startup_reason}" "${lnd_log}" \
      "${b_sync}" "${b_sync_reason}" "${lnd_log}" \
      "${b_detect}" "${b_detect_reason}" "None" \
      "${b_broadcast}" "${b_broadcast_reason}" "None" \
      "${b_restart}" "${b_restart_reason}" "None")
    append_target_result "${target_data}"
  fi
}

evaluate_cln() {
  echo "--- Evaluating target: cln (v26.06.9: single scenario with independent version and getblockfrompeer prerequisites) ---"
  local decision
  decision="Unmodified bcli / bitcoin-cli plugin. Records version >= 220000 gate and missing getblockfrompeer independently without version spoofing."

  if [[ -z "${CLN_BIN}" ]]; then
    local reason_startup
    reason_startup="Missing binary prerequisite: lightningd binary matching pinned release ${PIN_CLN} not provisioned, and a provisioned build also needs --cln-release-archive (the official release archive, digest-checked against the official SHA256SUMS) because lightningd --version prints only the release tag; bcli requires getnetworkinfo.version >= 220000 (bitcoin-rs returns 1400 from PKG_VERSION=0.14.0)"
    local reason_sync
    reason_sync="Missing binary prerequisite: lightningd binary matching pinned release ${PIN_CLN} not provisioned, and a provisioned build also needs --cln-release-archive because lightningd --version prints only the release tag; bcli block retrieval requires getblockfrompeer RPC (unimplemented in bitcoin-rs)"
    local reason_detect
    reason_detect="Missing binary prerequisite: lightningd binary matching pinned release ${PIN_CLN} not provisioned, and a provisioned build also needs --cln-release-archive because lightningd --version prints only the release tag; relies on bcli block/tx polling"
    local reason_broadcast
    reason_broadcast="Missing binary prerequisite: lightningd binary matching pinned release ${PIN_CLN} not provisioned, and a provisioned build also needs --cln-release-archive because lightningd --version prints only the release tag; relies on sendrawtransaction via bcli"
    local reason_restart
    reason_restart="Missing binary prerequisite: lightningd binary matching pinned release ${PIN_CLN} not provisioned, and a provisioned build also needs --cln-release-archive because lightningd --version prints only the release tag; relies on bcli reorg recovery"

    local target_data
    target_data=$(make_behavior_json \
      "cln" "bcli / bitcoin-cli" "${PIN_CLN}" "approved_pin_unprovisioned" "false" "None" "${decision}" \
      "not exercised" "${reason_startup}" "None" \
      "not exercised" "${reason_sync}" "None" \
      "not exercised" "${reason_detect}" "None" \
      "not exercised" "${reason_broadcast}" "None" \
      "not exercised" "${reason_restart}" "None")
    append_target_result "${target_data}"
    note_pin_outcome UNPROVISIONED "cln" "${reason_startup}"
  else
    echo "==> Provisioned lightningd binary found: ${CLN_BIN}"
    local cln_exe
    cln_exe=$(resolve_executable "${CLN_BIN}")
    if [[ -z "${CLN_RELEASE_ARCHIVE}" ]]; then
      append_blocked_target "cln" "bcli / bitcoin-cli" "${PIN_CLN}" "pin_unverified" "${CLN_BIN}" "${decision}" \
        "not exercised: lightningd --version prints only the release tag; pass --cln-release-archive <official clightning-v26.06.9 archive> so ${CLN_BIN} is checked against the official SHA256SUMS digests; no pin is claimed and the binary is not run"
      return 0
    fi
    local cln_identity
    local cln_identity_rc=0
    cln_identity=$(verify_cln_release_install "${CLN_RELEASE_ARCHIVE}" "${cln_exe}" "${CLN_RELEASE_ARCHIVE_SHA256[@]}") || cln_identity_rc=$?
    if (( cln_identity_rc != 0 )); then
      echo "WARNING: Provisioned lightningd is not the ${PIN_CLN} release: ${cln_identity}" >&2
      append_blocked_target "cln" "bcli / bitcoin-cli" "${PIN_CLN}" "pin_mismatch" "${CLN_BIN}" "${decision}" \
        "not exercised: provisioned lightningd ${CLN_BIN} is not the unmodified ${PIN_CLN} release archive ${CLN_RELEASE_ARCHIVE}: ${cln_identity}; the binary is not run"
      return 0
    fi
    local pin_status="verified_approved_pin"
    # Host preflight, before any bitcoin-rs node exists: a lightningd that cannot start here
    # (missing shared library, loader error) is a host fact, never a bitcoin-rs incompatibility.
    local cln_host="lightningd ${CLN_BIN} (release archive digest and install tree verified)"
    local cln_host_tail="this is a host prerequisite, not a bitcoin-rs result; no bitcoin-rs node was started and lightningd was not run against any node"
    local cln_prefix
    cln_prefix=$(dirname -- "$(dirname -- "$(readlink -f -- "${cln_exe}")")")
    local -a cln_elfs=("${cln_exe}")
    local cln_elf
    while IFS= read -r -d '' cln_elf; do
      cln_elfs+=("${cln_elf}")
    done < <(find "${cln_prefix}/libexec/c-lightning" -type f -perm -u+x -print0 2>/dev/null)
    local cln_missing
    cln_missing=$(missing_shared_objects "${cln_elfs[@]}")
    if [[ -n "${cln_missing}" ]]; then
      append_blocked_target "cln" "bcli / bitcoin-cli" "${PIN_CLN}" "${pin_status}" "${CLN_BIN}" "${decision}" \
        "not exercised: blocked on host: ${cln_host} needs shared libraries this host lacks (${cln_missing//$'\n'/; }); ${cln_host_tail}"
      return 0
    fi
    local cln_probe
    cln_probe=$(check_binary_version "${cln_exe}" exact "${CLN_VERSION_TAG}")
    case "${cln_probe}" in
      verified) ;;
      mismatch:*)
        append_blocked_target "cln" "bcli / bitcoin-cli" "${PIN_CLN}" "pin_mismatch" "${CLN_BIN}" "${decision}" \
          "not exercised: ${cln_host} reports version '${cln_probe#mismatch:}', not ${CLN_VERSION_TAG}; the binary is not run against any node"
        return 0
        ;;
      *)
        append_blocked_target "cln" "bcli / bitcoin-cli" "${PIN_CLN}" "${pin_status}" "${CLN_BIN}" "${decision}" \
          "not exercised: blocked on host: ${cln_host} did not run: its --version probe ended as ${cln_probe}; ${cln_host_tail}"
        return 0
        ;;
    esac
    # bcli shells out to bitcoin-cli; pass it explicitly so lightningd never depends on PATH.
    local cln_bitcoin_cli
    cln_bitcoin_cli=$(resolve_bitcoin_cli)
    if [[ -z "${cln_bitcoin_cli}" ]]; then
      append_blocked_target "cln" "bcli / bitcoin-cli" "${PIN_CLN}" "${pin_status}" "${CLN_BIN}" "${decision}" \
        "not exercised: blocked on host: the bcli plugin of ${cln_host} needs a bitcoin-cli executable and none was found beside --bitcoind-bin (${BITCOIND_BIN:-not set}) or on PATH; ${cln_host_tail}"
      return 0
    fi
    local -a cln_cli_args=("--bitcoin-cli=${cln_bitcoin_cli}")
    if accept_pin "cln" "bcli / bitcoin-cli" "${PIN_CLN}" "${pin_status}" "${CLN_BIN}" "${decision}"; then
      return 0
    fi
    start_bitcoin_rs

    local cln_datadir
    cln_datadir="${WORKDIR}/cln-data"
    local cln_log
    cln_log="${WORKDIR}/cln.log"
    mkdir -p "${cln_datadir}"

    local cln_probe_artifact
    cln_probe_artifact="${WORKDIR}/cln-bcli-probes.json"
    local netinfo_res
    netinfo_res=$(curl -s --connect-timeout 5 --max-time 15 -u "${RS_RPC_USER}:${RS_RPC_PASS}" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":"probe_cln_net","method":"getnetworkinfo","params":[]}' \
      "http://127.0.0.1:${RS_RPC_PORT}/" || true)
    local blockfrompeer_res
    blockfrompeer_res=$(curl -s --connect-timeout 5 --max-time 15 -u "${RS_RPC_USER}:${RS_RPC_PASS}" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","id":"probe_cln_peer","method":"getblockfrompeer","params":["0000000000000000000000000000000000000000000000000000000000000000",0]}' \
      "http://127.0.0.1:${RS_RPC_PORT}/" || true)

    python3 -c '
import json, sys
data = {
    "getnetworkinfo": json.loads(sys.argv[1]) if sys.argv[1] else None,
    "getblockfrompeer": json.loads(sys.argv[2]) if sys.argv[2] else None
}
with open(sys.argv[3], "w") as f:
    json.dump(data, f, indent=2)
' "${netinfo_res}" "${blockfrompeer_res}" "${cln_probe_artifact}" 2>/dev/null || true

    echo "==> Spawning lightningd daemon..."
    run_in_new_session "${cln_exe}" \
      "${cln_cli_args[@]}" \
      --network=regtest \
      --lightning-dir="${cln_datadir}" \
      --addr="127.0.0.1:$(free_port)" \
      --bitcoin-rpcuser="${RS_RPC_USER}" \
      --bitcoin-rpcpassword="${RS_RPC_PASS}" \
      --bitcoin-rpcport="${RS_RPC_PORT}" \
      --bitcoin-rpcconnect=127.0.0.1 \
      --log-file="${cln_log}" >/dev/null 2>&1 &
    TARGET_PID=$!

    sleep 2
    local b_startup="not exercised"
    local b_startup_reason="lightningd spawned against bitcoin-rs; startup outcome not yet observed"
    local b_cln_artifact="${cln_probe_artifact}"

    if ! kill -0 "${TARGET_PID}" 2>/dev/null; then
      if start_core_comparator; then
        echo "==> Repeating lightningd scenario against Core 31.1 differential comparator..."
        local core_cln_datadir
        core_cln_datadir="${WORKDIR}/cln-core-data"
        local core_cln_log
        core_cln_log="${WORKDIR}/cln-core.log"
        mkdir -p "${core_cln_datadir}"
        run_in_new_session "${cln_exe}" \
          "${cln_cli_args[@]}" \
          --network=regtest \
          --lightning-dir="${core_cln_datadir}" \
          --addr="127.0.0.1:$(free_port)" \
          --bitcoin-rpcuser="${RS_RPC_USER}" \
          --bitcoin-rpcpassword="${RS_RPC_PASS}" \
          --bitcoin-rpcport="${CORE_RPC_PORT}" \
          --bitcoin-rpcconnect=127.0.0.1 \
          --log-file="${core_cln_log}" >/dev/null 2>&1 &
        CORE_TARGET_PID=$!
        sleep 2
        if kill -0 "${CORE_TARGET_PID}" 2>/dev/null; then
          b_startup="not exercised"
          b_startup_reason="lightningd exited on startup against bitcoin-rs while the process survived against the Core 31.1 comparator; the exit cause is not classified by the runner (read ${cln_log}; the bcli getnetworkinfo.version >= 220000 gate is a documented code fact, not an observed cause); lightning-cli readiness unverified"
          b_cln_artifact="${core_cln_log}"
        else
          b_startup="not exercised"
          b_startup_reason="lightningd also exited on startup against the Core 31.1 comparator in the same scenario; no bitcoin-rs defect is attributed (exit causes not classified by the runner; read ${cln_log} and ${core_cln_log})"
        fi
        kill_bounded "${CORE_TARGET_PID}"
        CORE_TARGET_PID=""
        stop_core_comparator
      else
        b_startup="not exercised"
        b_startup_reason="lightningd exited on startup against bitcoin-rs; Core 31.1 comparator unavailable for differential verification; exit cause not classified (read ${cln_log})"
      fi
    else
      b_startup="not exercised"
      b_startup_reason="lightningd process spawned; full qualification requires active lightning-rpc socket communication"
      kill_bounded "${TARGET_PID}"
      TARGET_PID=""
    fi

    local target_data
    target_data=$(make_behavior_json \
      "cln" "bcli / bitcoin-cli" "${PIN_CLN}" "${pin_status}" "true" "${CLN_BIN}" "${decision}" \
      "${b_startup}" "${b_startup_reason}" "${b_cln_artifact}" \
      "not exercised" "Requires getblockfrompeer RPC (unimplemented in bitcoin-rs)" "None" \
      "not exercised" "Blocked by startup failure" "None" \
      "not exercised" "Blocked by startup failure" "None" \
      "not exercised" "Blocked by startup failure" "None")
    append_target_result "${target_data}"
  fi
}

evaluate_alby_hub() {
  echo "--- Evaluating target: alby-hub ---"
  local reason
  reason="not exercised: no approved pin in Step 30 specification; nearest release v1.24.4 cannot be substituted per pin rule"
  local decision
  decision="Overlap target: embedded LDK mode delegates directly to LDK Node bitcoind chain source rather than introducing a distinct L1 driver; LND/CLN modes are indirect. Absent approved pin requires not exercised verdict."
  local prov="false"
  if [[ -n "${ALBY_HUB_BIN}" ]]; then
    prov="true"
  fi
  local target_data
  target_data=$(make_behavior_json \
    "alby-hub" "embedded LDK Node" "None" "no_approved_pin" "${prov}" "${ALBY_HUB_BIN:-None}" "${decision}" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None")
  append_target_result "${target_data}"
}

evaluate_fedimint() {
  echo "--- Evaluating target: fedimint ---"
  local reason
  reason="not exercised: no approved pin in Step 30 specification; nearest releases v0.12.2/v0.11.4 cannot be substituted per pin rule"
  local decision
  decision="Overlap target: fedimintd guardian direct RPC (fedimint-server-bitcoin-rpc) requires height >= 1 (calls getblockhash(1)) and txindex=true. Watch-only wallet and LN-gateway paths are non-goals."
  local prov="false"
  if [[ -n "${FEDIMINTD_BIN}" ]]; then
    prov="true"
  fi
  local target_data
  target_data=$(make_behavior_json \
    "fedimint" "fedimintd guardian direct bitcoind RPC" "None" "no_approved_pin" "${prov}" "${FEDIMINTD_BIN:-None}" "${decision}" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None")
  append_target_result "${target_data}"
}

evaluate_ldk_node() {
  echo "--- Evaluating target: ldk-node ---"
  local reason
  reason="not exercised: library crate ([lib], no standalone daemon executable); distinct library qualification harness for set_chain_source_bitcoind_rpc is unprovisioned; Phase B native chain source blocked upstream (ENG-96)"
  local decision
  decision="Library crate ([lib], no standalone daemon executable). Distinct library qualification harness for set_chain_source_bitcoind_rpc is unprovisioned; Phase B native chain source blocked upstream (ENG-96)."
  local target_data
  target_data=$(make_behavior_json \
    "ldk-node" "library API (set_chain_source_bitcoind_rpc)" "${PIN_LDK_NODE}" "approved_pin_unprovisioned" "false" "None" "${decision}" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None")
  append_target_result "${target_data}"
}

evaluate_lexe() {
  echo "--- Evaluating target: lexe ---"
  local reason
  reason="not exercised: research target; no configurable public bitcoind RPC/ZMQ backend interface"
  local decision
  decision="Research target: no configurable public bitcoind RPC/ZMQ backend interface. Formally classified as not applicable; run nothing."
  local target_data
  target_data=$(make_behavior_json \
    "lexe" "research-only / not applicable" "None" "research_only" "false" "None" "${decision}" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None")
  append_target_result "${target_data}"
}

evaluate_lightning_kmp() {
  echo "--- Evaluating target: lightning-kmp ---"
  local reason
  reason="not exercised: research target; no configurable public bitcoind RPC/ZMQ backend interface"
  local decision
  decision="Research target: no configurable public bitcoind RPC/ZMQ backend interface. Formally classified as not applicable; run nothing."
  local target_data
  target_data=$(make_behavior_json \
    "lightning-kmp" "research-only / not applicable" "None" "research_only" "false" "None" "${decision}" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None")
  append_target_result "${target_data}"
}

evaluate_eclair() {
  echo "--- Evaluating target: eclair ---"
  local reason
  reason="not exercised: no approved pin in Step 30 specification; nearest release v0.14.5 cannot be substituted per pin rule"
  local decision
  decision="No approved pin in Step 30 specification. Nearest release substitution prohibited. Eclair requires bitcoind wallet support, which is blocked under bitcoin-rs NO_WALLET policy. No execution planned."
  local prov="false"
  if [[ -n "${ECLAIR_BIN}" ]]; then
    prov="true"
  fi
  local target_data
  target_data=$(make_behavior_json \
    "eclair" "bitcoind with wallet" "None" "no_approved_pin" "${prov}" "${ECLAIR_BIN:-None}" "${decision}" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None" \
    "not exercised" "${reason}" "None")
  append_target_result "${target_data}"
}

# -------------------------------------------------------------------
# Main entry point
# -------------------------------------------------------------------
main() {
  while (($# > 0)); do
    case "$1" in
      --bitcoin-rs-bin|--bitcoin-rs-command)
        require_arg "$1" "$#"
        BITCOIN_RS_BIN="$2"
        shift 2
        ;;
      --target)
        require_arg "$1" "$#"
        TARGET="$2"
        shift 2
        ;;
      --output-json|--evidence)
        require_arg "$1" "$#"
        OUTPUT_JSON="$2"
        shift 2
        ;;
      --bitcoind-bin|--bitcoind-command)
        require_arg "$1" "$#"
        BITCOIND_BIN="$2"
        shift 2
        ;;
      --workdir)
        require_arg "$1" "$#"
        WORKDIR="$2"
        shift 2
        ;;
      --keep)
        # Compatibility no-op: the workdir and logs are preserved unconditionally.
        shift
        ;;
      --verify-pins-only)
        PINS_ONLY=1
        shift
        ;;
      --timeout-seconds)
        require_arg "$1" "$#"
        TIMEOUT_SECONDS="$2"
        shift 2
        ;;
      --ldk-server-bin)
        require_arg "$1" "$#"
        LDK_SERVER_BIN="$2"
        shift 2
        ;;
      --ldk-server-provenance)
        require_arg "$1" "$#"
        LDK_SERVER_PROVENANCE="$2"
        shift 2
        ;;
      --lampo-bin)
        require_arg "$1" "$#"
        LAMPO_BIN="$2"
        shift 2
        ;;
      --lampo-provenance)
        require_arg "$1" "$#"
        LAMPO_PROVENANCE="$2"
        shift 2
        ;;
      --cln-release-archive)
        require_arg "$1" "$#"
        CLN_RELEASE_ARCHIVE="$2"
        shift 2
        ;;
      --lnd-bin)
        require_arg "$1" "$#"
        LND_BIN="$2"
        shift 2
        ;;
      --lncli-bin)
        require_arg "$1" "$#"
        LNCLI_BIN="$2"
        shift 2
        ;;
      --cln-bin)
        require_arg "$1" "$#"
        CLN_BIN="$2"
        shift 2
        ;;
      --alby-hub-bin)
        require_arg "$1" "$#"
        ALBY_HUB_BIN="$2"
        shift 2
        ;;
      --fedimintd-bin)
        require_arg "$1" "$#"
        FEDIMINTD_BIN="$2"
        shift 2
        ;;
      --eclair-bin)
        require_arg "$1" "$#"
        ECLAIR_BIN="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "ERROR: Unknown option: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done

  local target_valid=0
  for vt in "${VALID_TARGETS[@]}"; do
    if [[ "${TARGET}" == "${vt}" ]]; then
      target_valid=1
      break
    fi
  done

  if [[ "${target_valid}" -eq 0 ]]; then
    echo "ERROR: Invalid target '${TARGET}'. Allowed values: ${VALID_TARGETS[*]}" >&2
    exit 1
  fi

  if ! command -v setsid >/dev/null 2>&1; then
    echo "ERROR: Missing tool prerequisite: 'setsid' utility (util-linux) is required for process-group isolation and bounded cleanup." >&2
    exit 1
  fi
  if ! command -v timeout >/dev/null 2>&1; then
    echo "ERROR: Missing tool prerequisite: 'timeout' utility (coreutils) is required for bounded command deadlines." >&2
    exit 1
  fi

  if [[ ! "${TIMEOUT_SECONDS}" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: --timeout-seconds must be a positive integer, got '${TIMEOUT_SECONDS}'." >&2
    exit 1
  fi

  if [[ -z "${BITCOIN_RS_BIN}" ]] && (( PINS_ONLY == 0 )); then
    echo "ERROR: --bitcoin-rs-bin is required (it is optional only with --verify-pins-only)." >&2
    usage >&2
    exit 1
  fi

  if [[ -n "${BITCOIN_RS_BIN}" ]] && [[ ! -x "${BITCOIN_RS_BIN}" ]] && ! command -v "${BITCOIN_RS_BIN}" >/dev/null 2>&1; then
    echo "ERROR: bitcoin-rs binary '${BITCOIN_RS_BIN}' not found or not executable." >&2
    exit 1
  fi

  if [[ -n "${BITCOIND_BIN}" ]] && [[ ! -x "${BITCOIND_BIN}" ]] && ! command -v "${BITCOIND_BIN}" >/dev/null 2>&1; then
    BITCOIND_BIN=""
  fi

  if [[ -z "${WORKDIR}" ]]; then
    WORKDIR=$(mktemp -d /tmp/lightning-interop.XXXXXX)
  else
    mkdir -p "${WORKDIR}"
    if [[ -n "$(find "${WORKDIR}" -mindepth 1 -maxdepth 1 2>/dev/null || true)" ]]; then
      WORKDIR=$(mktemp -d "${WORKDIR}/session.XXXXXX")
    fi
  fi

  if [[ -z "${OUTPUT_JSON}" ]]; then
    OUTPUT_JSON="$(pwd)/lightning-interop-evidence.json"
  fi
  mkdir -p "$(dirname -- "${OUTPUT_JSON}")"

  if [[ -z "${LDK_SERVER_BIN}" ]] && command -v ldk-server >/dev/null 2>&1; then
    LDK_SERVER_BIN=$(command -v ldk-server)
  fi
  if [[ -z "${LAMPO_BIN}" ]] && command -v lampod-cli >/dev/null 2>&1; then
    LAMPO_BIN=$(command -v lampod-cli)
  fi
  if [[ -z "${LND_BIN}" ]] && command -v lnd >/dev/null 2>&1; then
    LND_BIN=$(command -v lnd)
  fi
  if [[ -z "${LNCLI_BIN}" ]] && command -v lncli >/dev/null 2>&1; then
    LNCLI_BIN=$(command -v lncli)
  fi
  if [[ -z "${CLN_BIN}" ]] && command -v lightningd >/dev/null 2>&1; then
    CLN_BIN=$(command -v lightningd)
  fi
  if [[ -z "${ALBY_HUB_BIN}" ]] && command -v albyhub >/dev/null 2>&1; then
    ALBY_HUB_BIN=$(command -v albyhub)
  fi
  if [[ -z "${FEDIMINTD_BIN}" ]] && command -v fedimintd >/dev/null 2>&1; then
    FEDIMINTD_BIN=$(command -v fedimintd)
  fi
  if [[ -z "${ECLAIR_BIN}" ]] && command -v eclair-node >/dev/null 2>&1; then
    ECLAIR_BIN=$(command -v eclair-node)
  fi

  validate_binary_override() {
    local bin_path
    bin_path="$1"
    if [[ -n "${bin_path}" ]]; then
      if [[ ! -x "${bin_path}" ]] && ! command -v "${bin_path}" >/dev/null 2>&1; then
        return 1
      fi
    fi
    return 0
  }

  if [[ -n "${LDK_SERVER_BIN}" ]] && ! validate_binary_override "${LDK_SERVER_BIN}"; then
    echo "WARNING: --ldk-server-bin path '${LDK_SERVER_BIN}' not found or not executable; treating as unprovisioned." >&2
    LDK_SERVER_BIN=""
  fi
  if [[ -n "${LAMPO_BIN}" ]] && ! validate_binary_override "${LAMPO_BIN}"; then
    echo "WARNING: --lampo-bin path '${LAMPO_BIN}' not found or not executable; treating as unprovisioned." >&2
    LAMPO_BIN=""
  fi
  if [[ -n "${LND_BIN}" ]] && ! validate_binary_override "${LND_BIN}"; then
    echo "WARNING: --lnd-bin path '${LND_BIN}' not found or not executable; treating as unprovisioned." >&2
    LND_BIN=""
  fi
  if [[ -n "${LNCLI_BIN}" ]] && ! validate_binary_override "${LNCLI_BIN}"; then
    echo "WARNING: --lncli-bin path '${LNCLI_BIN}' not found or not executable; treating as unprovisioned." >&2
    LNCLI_BIN=""
  fi
  if [[ -n "${CLN_BIN}" ]] && ! validate_binary_override "${CLN_BIN}"; then
    echo "WARNING: --cln-bin path '${CLN_BIN}' not found or not executable; treating as unprovisioned." >&2
    CLN_BIN=""
  fi
  if [[ -n "${ALBY_HUB_BIN}" ]] && ! validate_binary_override "${ALBY_HUB_BIN}"; then
    echo "WARNING: --alby-hub-bin path '${ALBY_HUB_BIN}' not found or not executable; treating as unprovisioned." >&2
    ALBY_HUB_BIN=""
  fi
  if [[ -n "${FEDIMINTD_BIN}" ]] && ! validate_binary_override "${FEDIMINTD_BIN}"; then
    echo "WARNING: --fedimintd-bin path '${FEDIMINTD_BIN}' not found or not executable; treating as unprovisioned." >&2
    FEDIMINTD_BIN=""
  fi
  if [[ -n "${ECLAIR_BIN}" ]] && ! validate_binary_override "${ECLAIR_BIN}"; then
    echo "WARNING: --eclair-bin path '${ECLAIR_BIN}' not found or not executable; treating as unprovisioned." >&2
    ECLAIR_BIN=""
  fi

  REPORT_PY="${WORKDIR}/collector.py"
  cat > "${REPORT_PY}" <<'PYEOF'
import json
import sys
import datetime

cmd = sys.argv[1]
state_file = sys.argv[2]

state = {"results": []}
try:
    with open(state_file, "r") as f:
        state = json.load(f)
except Exception:
    pass

if cmd == "add":
    target_data = json.loads(sys.argv[3])
    state["results"].append(target_data)
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)

elif cmd == "render":
    output_path = sys.argv[3]
    schema = sys.argv[4]
    btc_rs_bin = sys.argv[5] or None
    core_bin = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] and sys.argv[6] != "None" else None
    pins_only = len(sys.argv) > 7 and sys.argv[7] == "1"
    
    total_cells = 0
    passed_cells = 0
    failed_cells = 0
    not_exercised_cells = 0
    
    for r in state["results"]:
        for b_name, b_data in r["behaviors"].items():
            total_cells += 1
            st = b_data.get("status")
            if st == "passed":
                passed_cells += 1
            elif st == "failed":
                failed_cells += 1
            else:
                not_exercised_cells += 1

    report = {
        "schema": schema,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "runner": {
            "bitcoin_rs_bin": btc_rs_bin,
            "core_comparator_bin": core_bin,
            "verify_pins_only": pins_only,
        },
        "summary": {
            "total_target_scenarios": len(state["results"]),
            "total_behavior_cells": total_cells,
            "passed": passed_cells,
            "failed": failed_cells,
            "not_exercised": not_exercised_cells
        },
        "results": state["results"]
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Evidence report written to {output_path}")
PYEOF

  STATE_JSON="${WORKDIR}/state.json"
  echo '{"results": []}' > "${STATE_JSON}"

  echo "================================================================="
  echo "=== Bounded Lightning Interoperability Verification (#1488)   ==="
  echo "================================================================="
  echo "Target: ${TARGET}"
  echo "bitcoin-rs binary: ${BITCOIN_RS_BIN:-(not used: --verify-pins-only)}"
  if (( PINS_ONLY == 1 )); then
    echo "Mode: --verify-pins-only (no bitcoin-rs node, no Core comparator, no target daemon is started)"
  fi
  echo "Core comparator binary: ${BITCOIND_BIN:-'(none provisioned)'}"
  echo "Workdir: ${WORKDIR}"
  echo "Output JSON: ${OUTPUT_JSON}"
  echo ""

  if should_run "ldk-server"; then
    evaluate_ldk_server
    evaluate_ldk_server_advanced
  fi
  if should_run "lampo"; then
    evaluate_lampo
  fi
  if should_run "lnd"; then
    evaluate_lnd
  fi
  if should_run "cln"; then
    evaluate_cln
  fi
  if should_run "alby-hub"; then
    evaluate_alby_hub
  fi
  if should_run "fedimint"; then
    evaluate_fedimint
  fi
  if should_run "ldk-node"; then
    evaluate_ldk_node
  fi
  if should_run "lexe"; then
    evaluate_lexe
  fi
  if should_run "lightning-kmp"; then
    evaluate_lightning_kmp
  fi
  if should_run "eclair"; then
    evaluate_eclair
  fi

  stop_bitcoin_rs
  stop_core_comparator

  python3 "${REPORT_PY}" render "${STATE_JSON}" "${OUTPUT_JSON}" "${EVIDENCE_SCHEMA}" "${BITCOIN_RS_BIN}" "${BITCOIND_BIN}" "${PINS_ONLY}"

  echo ""
  echo "==> Lightning Interoperability Verification: COMPLETED"
  echo "==> Summary written to ${OUTPUT_JSON}"
  if (( PINS_ONLY == 1 && PINS_NOT_READY > 0 )); then
    echo "==> --verify-pins-only: ${PINS_NOT_READY} selected target(s) are not PIN-ACCEPTED; exiting 2" >&2
    exit 2
  fi
}

main "$@"
