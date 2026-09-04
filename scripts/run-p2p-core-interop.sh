#!/usr/bin/env bash
# Live Bitcoin Core differential for observable node behavior (#174).
#
# Starts Bitcoin Core (regtest) and a bitcoin-rs node, connects them over the
# P2P v1 transport, verifies header/block sync in both the initial-sync and a
# post-handshake catch-up round, then diffs Core vs bitcoin-rs chain identity
# RPCs (height, best block hash, chain name). Records Core's view of the
# bitcoin-rs peer into an evidence JSON and runs
# `crates/p2p/tests/core_interop_live.rs` against it.
#
# usage: run-p2p-core-interop.sh --bitcoind-command <command>
#            [--bitcoin-rs-command <command>] [--workdir <dir>] [--evidence <path>]
#            [--blocks <n>] [--catchup-blocks <n>] [--timeout-seconds <n>]
#            [--skip-verifier] [--keep]
#
# CI installs the pinned bitcoind with scripts/install-bitcoind.sh and runs
# this driver on main. Locally:
#   scripts/run-p2p-core-interop.sh --bitcoind-command "$(scripts/install-bitcoind.sh)"

set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: run-p2p-core-interop.sh --bitcoind-command <command> [--bitcoin-rs-command <command>] [--workdir <dir>] [--evidence <path>] [--blocks <n>] [--catchup-blocks <n>] [--timeout-seconds <n>] [--skip-verifier] [--keep]'
}

BITCOIND_COMMAND=""
BITCOIN_RS_COMMAND="target/release/bitcoin-rs"
WORKDIR=""
EVIDENCE=""
BLOCKS=101
CATCHUP_BLOCKS=5
TIMEOUT_SECONDS=180
SKIP_VERIFIER=0
KEEP=0

while (($# > 0)); do
  case "$1" in
    --bitcoind-command)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      BITCOIND_COMMAND=$2
      shift 2
      ;;
    --bitcoin-rs-command)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      BITCOIN_RS_COMMAND=$2
      shift 2
      ;;
    --workdir)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      WORKDIR=$2
      KEEP=1
      shift 2
      ;;
    --evidence)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      EVIDENCE=$2
      shift 2
      ;;
    --blocks)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      BLOCKS=$2
      shift 2
      ;;
    --catchup-blocks)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      CATCHUP_BLOCKS=$2
      shift 2
      ;;
    --timeout-seconds)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      TIMEOUT_SECONDS=$2
      shift 2
      ;;
    --skip-verifier)
      SKIP_VERIFIER=1
      shift
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
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${BITCOIND_COMMAND}" ]]; then
  echo "error: --bitcoind-command is required" >&2
  usage >&2
  exit 2
fi

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

CORE_P2P_PORT=$(free_port)
CORE_RPC_PORT=$(free_port)
RS_P2P_PORT=$(free_port)
RS_RPC_PORT=$(free_port)

if [[ -z "${WORKDIR}" ]]; then
  WORKDIR=$(mktemp -d /tmp/p2p-core-interop.XXXXXX)
fi
if [[ -z "${EVIDENCE}" ]]; then
  EVIDENCE="${WORKDIR}/evidence.json"
fi

CORE_DATADIR="${WORKDIR}/core"
RS_DATADIR="${WORKDIR}/rs"
RS_LOG="${WORKDIR}/bitcoin-rs.log"
CORE_LOG="${WORKDIR}/bitcoind.log"
RS_RPC_USER="interop"
RS_RPC_PASSWORD="interop"
EVIDENCE_SCHEMA="bitcoin-rs-core-differential-v1"

BITCOIN_RS_PID=""
CORE_COOKIE_FILE="${CORE_DATADIR}/regtest/.cookie"
CORE_STOPPED=0

core_rpc() {
  local method=$1
  shift
  local cookie params=""
  cookie=$(cat "${CORE_COOKIE_FILE}")
  if (($# > 0)); then
    params=,"\"params\":[$*]"
  fi
  curl -sS --max-time 10 --user "${cookie}" -H 'content-type: text/plain' \
    --data "{\"jsonrpc\":\"1.0\",\"id\":\"interop\",\"method\":\"${method}\"${params}}" \
    "http://127.0.0.1:${CORE_RPC_PORT}"
}

# Prints only the "result" member of a Core RPC response.
core_result() {
  core_rpc "$@" | python3 -c 'import json, sys; print(json.dumps(json.load(sys.stdin)["result"]))'
}

rs_rpc() {
  local method=$1
  shift
  local params=""
  if (($# > 0)); then
    params=,"\"params\":[$*]"
  fi
  curl -sS --max-time 10 --user "${RS_RPC_USER}:${RS_RPC_PASSWORD}" \
    -H 'content-type: text/plain' \
    --data "{\"jsonrpc\":\"1.0\",\"id\":\"interop\",\"method\":\"${method}\"${params}}" \
    "http://127.0.0.1:${RS_RPC_PORT}"
}

# Prints the bitcoin-rs chain tip height, failing loudly on RPC errors.
rs_height() {
  rs_rpc getblockcount | python3 -c 'import json, sys; print(json.load(sys.stdin)["result"])'
}

poll_until() {
  # poll_until <description> <target> — loops until `rs_height` equals target.
  local description=$1
  local target=$2
  local deadline=$((SECONDS + TIMEOUT_SECONDS))
  until [[ "$(rs_height)" == "${target}" ]]; do
    if ((SECONDS >= deadline)); then
      echo "error: timed out waiting for ${description} (want ${target}, have $(rs_height || echo '?'))" >&2
      return 1
    fi
    sleep 0.5
  done
}

cleanup() {
  local status=$?
  if [[ -n "${BITCOIN_RS_PID}" ]] && kill -0 "${BITCOIN_RS_PID}" 2>/dev/null; then
    kill "${BITCOIN_RS_PID}" 2>/dev/null || true
  fi
  if [[ "${CORE_STOPPED}" -ne 1 ]]; then
    core_rpc stop >/dev/null 2>&1 || true
    sleep 1
  fi
  if [[ "${KEEP}" -ne 1 ]]; then
    rm -rf -- "${WORKDIR:?workdir must not be empty}"
  else
    printf 'workdir kept: %s\n' "${WORKDIR}"
  fi
  return "${status}"
}
trap cleanup EXIT

echo "==> workdir: ${WORKDIR}"
echo "==> core p2p: ${CORE_P2P_PORT} rpc: ${CORE_RPC_PORT}; bitcoin-rs p2p: ${RS_P2P_PORT} rpc: ${RS_RPC_PORT}"

mkdir -p "${CORE_DATADIR}" "${RS_DATADIR}"

echo "==> starting bitcoind"
# shellcheck disable=SC2086 # the command may carry its own arguments
${BITCOIND_COMMAND} \
  -regtest \
  -datadir="${CORE_DATADIR}" \
  -port="${CORE_P2P_PORT}" \
  -bind="127.0.0.1:${CORE_P2P_PORT}" \
  -rpcbind=127.0.0.1 \
  -rpcport="${CORE_RPC_PORT}" \
  -dnsseed=0 \
  -listen=1 \
  -nowallet \
  -daemonwait \
  -pid="${WORKDIR}/bitcoind.pid" \
  >"${CORE_LOG}" 2>&1

if [[ ! -f "${CORE_COOKIE_FILE}" ]]; then
  echo "error: bitcoind cookie file never appeared at ${CORE_COOKIE_FILE}" >&2
  exit 1
fi

echo "==> creating wallet and mining ${BLOCKS} initial blocks"
core_rpc createwallet '"interop"' >/dev/null
MINING_ADDRESS=$(core_result getnewaddress)
core_result generatetoaddress "${BLOCKS}" "\"${MINING_ADDRESS}\"" >/dev/null
CORE_HEIGHT=$(core_result getblockcount | python3 -c 'import json, sys; print(json.load(sys.stdin))')
echo "==> core height after initial mine: ${CORE_HEIGHT}"

echo "==> starting bitcoin-rs (connect 127.0.0.1:${CORE_P2P_PORT})"
# shellcheck disable=SC2086 # the command may carry its own arguments
${BITCOIN_RS_COMMAND} \
  --network regtest \
  --data-dir "${RS_DATADIR}" \
  --rpc-bind "127.0.0.1:${RS_RPC_PORT}" \
  --rpc-user "${RS_RPC_USER}" \
  --rpc-password "${RS_RPC_PASSWORD}" \
  --p2p-listen "127.0.0.1:${RS_P2P_PORT}" \
  --connect "127.0.0.1:${CORE_P2P_PORT}" \
  --log-level info \
  >"${RS_LOG}" 2>&1 &
BITCOIN_RS_PID=$!

SECONDS=0
echo "==> waiting for initial sync to height ${CORE_HEIGHT}"
poll_until "initial sync" "${CORE_HEIGHT}"
INITIAL_SYNC_HEIGHT=$(rs_height)
echo "==> initial sync height: ${INITIAL_SYNC_HEIGHT}"

echo "==> mining ${CATCHUP_BLOCKS} catch-up blocks on Core (post-handshake relay proof)"
CATCHUP_FROM=${CORE_HEIGHT}
core_result generatetoaddress "${CATCHUP_BLOCKS}" "\"${MINING_ADDRESS}\"" >/dev/null
CATCHUP_TO=$((CATCHUP_FROM + CATCHUP_BLOCKS))
poll_until "catch-up sync" "${CATCHUP_TO}"
RS_HEIGHT=$(rs_height)
echo "==> bitcoin-rs caught up to ${RS_HEIGHT}"

echo "==> comparing observable chain identity RPCs"
json_string() {
  python3 -c 'import json, sys; print(json.load(sys.stdin))'
}
json_field() {
  local field=$1
  python3 -c 'import json, sys; print(json.load(sys.stdin)["'"${field}"'"])'
}

CORE_TIP=$(core_result getbestblockhash | json_string)
RS_TIP=$(rs_rpc getbestblockhash | python3 -c 'import json, sys; print(json.load(sys.stdin)["result"])')
if [[ "${CORE_TIP}" != "${RS_TIP}" ]]; then
  echo "error: getbestblockhash mismatch: core=${CORE_TIP} bitcoin-rs=${RS_TIP}" >&2
  exit 1
fi

CORE_INFO=$(core_result getblockchaininfo)
RS_INFO=$(rs_rpc getblockchaininfo | python3 -c 'import json, sys; print(json.dumps(json.load(sys.stdin)["result"]))')
CORE_CHAIN=$(printf '%s' "${CORE_INFO}" | json_field chain)
RS_CHAIN=$(printf '%s' "${RS_INFO}" | json_field chain)
CORE_BLOCKS=$(printf '%s' "${CORE_INFO}" | json_field blocks)
RS_BLOCKS=$(printf '%s' "${RS_INFO}" | json_field blocks)
if [[ "${CORE_CHAIN}" != "regtest" || "${RS_CHAIN}" != "regtest" ]]; then
  echo "error: expected regtest, core=${CORE_CHAIN} bitcoin-rs=${RS_CHAIN}" >&2
  exit 1
fi
if [[ "${CORE_BLOCKS}" != "${RS_BLOCKS}" ]]; then
  echo "error: getblockchaininfo.blocks mismatch: core=${CORE_BLOCKS} bitcoin-rs=${RS_BLOCKS}" >&2
  exit 1
fi
echo "==> chain identity matches: ${RS_CHAIN} height ${RS_BLOCKS} tip ${RS_TIP}"

echo "==> collecting Core's view of the bitcoin-rs peer"
PEER_JSON=$(core_result getpeerinfo | python3 -c '
import json, sys
peers = json.load(sys.stdin)
matches = [p for p in peers if "bitcoin-rs" in p.get("subver", "")]
if not matches:
    raise SystemExit("no bitcoin-rs peer in getpeerinfo")
peer = matches[0]
print(json.dumps({"inbound": peer["inbound"], "services": int(peer["services"]), "subver": peer["subver"]}))
')
CORE_SUBVERSION=$(core_result getnetworkinfo | python3 -c 'import json, sys; print(json.load(sys.stdin)["subversion"])')
CORE_STOPPED=1
core_rpc stop >/dev/null || true

python3 - "${EVIDENCE}" "${EVIDENCE_SCHEMA}" "${CORE_SUBVERSION}" \
  "${INITIAL_SYNC_HEIGHT}" "${CATCHUP_FROM}" "${CATCHUP_TO}" "${RS_HEIGHT}" \
  "${PEER_JSON}" "${CORE_TIP}" "${RS_TIP}" "${CORE_CHAIN}" "${CORE_BLOCKS}" "${RS_BLOCKS}" <<'PY'
import json
import sys

(
    path, schema, subversion, initial, catchup_from, catchup_to, rs_height,
    peer, core_tip, rs_tip, chain, core_blocks, rs_blocks,
) = sys.argv[1:14]
evidence = {
    "schema": schema,
    "core_version": subversion,
    "magic": "fabfb5da",
    "peer": json.loads(peer),
    "initial_sync_height": int(initial),
    "catchup_from": int(catchup_from),
    "catchup_to": int(catchup_to),
    "bitcoin_rs_height": int(rs_height),
    "bestblockhash": core_tip,
    "bitcoin_rs_bestblockhash": rs_tip,
    "chain": chain,
    "core_blocks": int(core_blocks),
    "bitcoin_rs_blocks": int(rs_blocks),
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(evidence, handle, indent=2)
    handle.write("\n")
PY

echo "evidence written to ${EVIDENCE}"

if [[ "${SKIP_VERIFIER}" -ne 1 ]]; then
  echo "==> running the ignored verifier test"
  P2P_CORE_INTEROP_EVIDENCE="${EVIDENCE}" env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR \
    cargo test -p bitcoin-rs-p2p --test core_interop_live -- --ignored --nocapture
fi

echo "==> Core differential: PASS"
