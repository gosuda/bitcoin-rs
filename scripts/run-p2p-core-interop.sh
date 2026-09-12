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
BLOCKS=241
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
# Sole producer-side owner of the evidence schema identifier; the verifier
# (crates/p2p/tests/core_interop_live.rs SCHEMA) consumes the value recorded
# in the evidence. Do not add a second definition in this script.
EVIDENCE_SCHEMA="bitcoin-rs-core-differential-v2"

BITCOIN_RS_PID=""
CORE_COOKIE_FILE="${CORE_DATADIR}/regtest/.cookie"
CORE_STOPPED=0

core_rpc() {
  local method=$1
  shift
  local cookie params=""
  cookie=$(cat "${CORE_COOKIE_FILE}")
  if (($# > 0)); then
    # $* must join as a JSON array (commas), not on the default IFS space;
    # each argument is already a raw JSON literal.
    local IFS=,
    params=,"\"params\":[${*}]"
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
    local IFS=,
    params=,"\"params\":[${*}]"
  fi
  curl -sS --max-time 10 --user "${RS_RPC_USER}:${RS_RPC_PASSWORD}" \
    -H 'content-type: text/plain' \
    --data "{\"jsonrpc\":\"1.0\",\"id\":\"interop\",\"method\":\"${method}\"${params}}" \
    "http://127.0.0.1:${RS_RPC_PORT}"
}

# Prints only the "result" member of a Core RPC response.
json_string() {
  python3 -c 'import json, sys; print(json.load(sys.stdin))'
}
json_field() {
  local field=$1
  python3 -c 'import json, sys; print(json.load(sys.stdin)["'"${field}"'"])'
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

# Funds <count> one-output transactions from the wallet and submits them to
# Core's mempool without mining, printing one txid per line. Callers run
# this before bitcoin-rs connects: the node answers tx `inv` with `getdata`
# and admits the bodies, so anything announced after connect would land in
# its mempool and defeat the BIP152 missing-transaction phases.
seed_mempool_txs() {
  local count=$1
  local seed_addr
  seed_addr=$(core_rpc getnewaddress | json_field result)
  local i utxo txid vout amount raw signed hex
  for ((i = 0; i < count; i++)); do
    utxo=$(core_result listunspent 100 999999 "[${MINING_ADDRESS}]" | python3 -c '
import json, sys
utxo = json.load(sys.stdin)[0]
print(utxo["txid"], utxo["vout"], utxo["amount"])
')
    set -- ${utxo}
    txid=$1
    vout=$2
    amount=$3
    raw=$(core_result createrawtransaction \
      "[{\"txid\":\"${txid}\",\"vout\":${vout}}]" \
      "{\"${seed_addr}\":0.0001,${MINING_ADDRESS}:$(python3 -c "print(round(${amount} - 0.0002, 8))")}")
    signed=$(core_result signrawtransactionwithwallet "${raw}")
    hex=$(printf '%s' "${signed}" | json_field hex)
    core_result sendrawtransaction "\"${hex}\"" | json_string
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
  -fallbackfee=0.0002 \
  -debug=cmpctblock \
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
core_result generatetoaddress "${BLOCKS}" "${MINING_ADDRESS}" >/dev/null
CORE_HEIGHT=$(core_result getblockcount | python3 -c 'import json, sys; print(json.load(sys.stdin))')
echo "==> core height after initial mine: ${CORE_HEIGHT}"

echo "==> seeding mempool transactions for the BIP152 phases (announced to nobody)"
B_TXIDS_JSON=$(printf '%s\n' "$(seed_mempool_txs 3)" | python3 -c 'import json, sys; print(json.dumps(sys.stdin.read().split()))')
C_TXIDS_JSON=$(printf '%s\n' "$(seed_mempool_txs 130)" | python3 -c 'import json, sys; print(json.dumps(sys.stdin.read().split()))')
CORE_MEMPOOL=$(core_result getrawmempool | python3 -c 'import json, sys; print(len(json.load(sys.stdin)))')
if [[ "${CORE_MEMPOOL}" -ne 133 ]]; then
  echo "error: expected 133 seeded mempool txs on Core, found ${CORE_MEMPOOL}" >&2
  exit 1
fi
echo "==> seeded 3 getblocktxn-recovery txs and 130 fallback txs"

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

# Near-tip bandwidth/latency are measured against the IBD round: Core's
# per-peer byte counters snapshot now (IBD total) and after the compact
# catch-up phases (delta = near-tip traffic).
IBD_SECONDS=$SECONDS
PEER_IBD_JSON=$(core_result getpeerinfo | python3 -c '
import json, sys
peers = json.load(sys.stdin)
matches = [p for p in peers if "bitcoin-rs" in p.get("subver", "")]
if not matches:
    raise SystemExit("no bitcoin-rs peer in getpeerinfo")
peer = matches[0]
print(json.dumps({"bytes_to_rs": int(peer["bytessent"]), "bytes_from_rs": int(peer["bytesrecv"])}))
')
echo "==> IBD wall time: ${IBD_SECONDS}s"

echo "==> phase A: mining ${CATCHUP_BLOCKS} coinbase-only blocks (full compact reconstruction)"
CATCHUP_FROM=${CORE_HEIGHT}
for _ in $(seq "${CATCHUP_BLOCKS}"); do
  core_result generateblock "${MINING_ADDRESS}" '[]' >/dev/null
done
A_TO=$((CATCHUP_FROM + CATCHUP_BLOCKS))
poll_until "phase A sync" "${A_TO}"
# The seeded txs must be absent from bitcoin-rs: if anything relayed them,
# the phase B/C reconstruction cases silently degenerate to full hits.
RS_MEMPOOL=$(rs_rpc getrawmempool | python3 -c 'import json, sys; print(len(json.load(sys.stdin)["result"]))')
if [[ "${RS_MEMPOOL}" -ne 0 ]]; then
  echo "error: bitcoin-rs mempool holds ${RS_MEMPOOL} txs; seeded txs were relayed" >&2
  exit 1
fi

echo "==> phase B: mining one block over exactly the three seeded txs (getblocktxn recovery)"
core_result generateblock "${MINING_ADDRESS}" "${B_TXIDS_JSON}" >/dev/null
B_TO=$((A_TO + 1))
poll_until "phase B sync" "${B_TO}"

echo "==> phase C: mining one block over exactly the 130 seeded txs (full-block fallback)"
core_result generateblock "${MINING_ADDRESS}" "${C_TXIDS_JSON}" >/dev/null
CATCHUP_TO=$((B_TO + 1))
poll_until "phase C sync" "${CATCHUP_TO}"
NEAR_TIP_SECONDS=$((SECONDS - IBD_SECONDS))
RS_HEIGHT=$(rs_height)
echo "==> bitcoin-rs caught up to ${RS_HEIGHT} (near-tip wall time ${NEAR_TIP_SECONDS}s)"

echo "==> comparing observable chain identity RPCs"

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

echo "==> probing BIP152 serving and disconnect handling with a raw peer"
RAW_PEER_JSON=$(RS_P2P_PORT="${RS_P2P_PORT}" TIP_DISPLAY="${RS_TIP}" python3 <<'PROBE'
import hashlib
import json
import os
import socket
import struct
import time

MAGIC = b"\xfa\xbf\xb5\xda"  # regtest (Network::Regtest.magic wire bytes)
PORT = int(os.environ["RS_P2P_PORT"])
TIP_DISPLAY = os.environ["TIP_DISPLAY"]
RESULT = {
    "served_cmpctblock": False,
    "served_blocktxn": False,
    "cmpct_header_hash_matches_tip": False,
    "malformed_getblocktxn_disconnected": False,
}


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def frame(command, payload):
    checksum = sha256d(payload)[:4]
    head = MAGIC + command.encode().ljust(12, b"\x00") + struct.pack("<I", len(payload)) + checksum
    return head + payload


def varint(value):
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    return b"\xfe" + struct.pack("<I", value)


class Peer:
    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", PORT), timeout=30)

    def read_exact(self, count):
        chunks = b""
        while len(chunks) < count:
            chunk = self.sock.recv(count - len(chunks))
            if not chunk:
                raise ConnectionError("unexpected EOF")
            chunks += chunk
        return chunks

    def read_message(self):
        head = self.read_exact(24)
        if head[:4] != MAGIC:
            raise ConnectionError("bad magic")
        command = head[4:16].rstrip(b"\x00").decode()
        length = struct.unpack("<I", head[16:20])[0]
        return command, self.read_exact(length) if length else b""

    def send(self, command, payload):
        self.sock.sendall(frame(command, payload))

    def version_payload(self):
        addr = struct.pack("<Q", 1) + bytes(16) + struct.pack(">H", 0)
        agent = b"/bip152-probe:0/"
        return (
            struct.pack("<i", 70016)
            + struct.pack("<Q", 1)
            + struct.pack("<q", int(time.time()))
            + addr
            + addr
            + struct.pack("<Q", 1234)
            + varint(len(agent))
            + agent
            + struct.pack("<i", 0)
            + b"\x01"
        )

    def handshake(self):
        self.send("version", self.version_payload())
        while True:
            command, _ = self.read_message()
            if command == "verack":
                break
        self.send("verack", b"")
        self.sock.settimeout(2)
        try:
            while True:
                self.read_message()
        except (socket.timeout, ConnectionError):
            pass
        self.sock.settimeout(30)
        # BIP152 v2 negotiation so the node serves MSG_CMPCT_BLOCK to us.
        self.send("sendcmpct", b"\x01" + struct.pack("<Q", 2))

    def getdata_cmpct(self, tip):
        self.send("getdata", varint(1) + struct.pack("<I", 4) + tip)

    def getblocktxn(self, tip, indexes):
        payload = tip + varint(len(indexes))
        previous = 0
        for index in indexes:
            payload += varint(index - previous)
            previous = index
        self.send("getblocktxn", payload)


tip = bytes.fromhex(TIP_DISPLAY)[::-1]  # display -> wire (internal) order

peer = Peer()
peer.handshake()
peer.getdata_cmpct(tip)
while True:
    command, payload = peer.read_message()
    if command == "cmpctblock":
        RESULT["served_cmpctblock"] = True
        header, nonce = payload[:80], payload[80:88]
        RESULT["cmpct_header_hash_matches_tip"] = sha256d(header)[::-1].hex() == TIP_DISPLAY
        break
peer.getblocktxn(tip, [1])
while True:
    command, payload = peer.read_message()
    if command == "blocktxn":
        RESULT["served_blocktxn"] = True
        break

# A getblocktxn with out-of-range indexes must end the connection (BIP152).
peer = Peer()
peer.handshake()
peer.getblocktxn(tip, [99999999])
try:
    while True:
        peer.read_message()
except ConnectionError:
    RESULT["malformed_getblocktxn_disconnected"] = True

missing = [key for key, value in RESULT.items() if not value]
if missing:
    raise SystemExit("bip152 probe failed: " + ", ".join(missing))
print(json.dumps(RESULT))
PROBE
)
echo "==> collecting Core's view of the bitcoin-rs peer"
PEER_JSON=$(core_result getpeerinfo | python3 -c '
import json, sys
peers = json.load(sys.stdin)
matches = [p for p in peers if "bitcoin-rs" in p.get("subver", "")]
if not matches:
    raise SystemExit("no bitcoin-rs peer in getpeerinfo")
peer = matches[0]
print(json.dumps({
    "inbound": peer["inbound"],
    "services": int(peer["services"]),
    "subver": peer["subver"],
    "bytes_to_rs": int(peer["bytessent"]),
    "bytes_from_rs": int(peer["bytesrecv"]),
    "bip152_hb_to": bool(peer["bip152_hb_to"]),
    "bip152_hb_from": bool(peer["bip152_hb_from"]),
}))
')
CORE_SUBVERSION=$(core_result getnetworkinfo | python3 -c 'import json, sys; print(json.load(sys.stdin)["subversion"])')
CORE_STOPPED=1
core_rpc stop >/dev/null || true

echo "==> counting BIP152 outcomes in the bitcoin-rs log"
count_marker() {
  grep -c "$1" "${RS_LOG}" || true
}
COMPACT_BATCHES=$(count_marker "requested compact blocks near tip")
RECONSTRUCTIONS=$(count_marker "p2p compact block reconstructed")
GETBLOCKTXN_RECOVERIES=$(count_marker "p2p compact reconstruction missing")
FULL_BLOCK_FALLBACKS=$(count_marker "p2p compact reconstruction fallback")
echo "==> compact batches: ${COMPACT_BATCHES}, reconstructed: ${RECONSTRUCTIONS}, getblocktxn: ${GETBLOCKTXN_RECOVERIES}, fallbacks: ${FULL_BLOCK_FALLBACKS}"

python3 - "${EVIDENCE}" "${EVIDENCE_SCHEMA}" "${CORE_SUBVERSION}" \
  "${INITIAL_SYNC_HEIGHT}" "${CATCHUP_FROM}" "${CATCHUP_TO}" "${RS_HEIGHT}" \
  "${PEER_JSON}" "${CORE_TIP}" "${RS_TIP}" "${CORE_CHAIN}" "${CORE_BLOCKS}" "${RS_BLOCKS}" \
  "${PEER_IBD_JSON}" "${IBD_SECONDS}" "${NEAR_TIP_SECONDS}" \
  "${COMPACT_BATCHES}" "${RECONSTRUCTIONS}" "${GETBLOCKTXN_RECOVERIES}" "${FULL_BLOCK_FALLBACKS}" \
  "${RAW_PEER_JSON}" "${CATCHUP_BLOCKS}" <<'PY'
import json
import sys

(
    path, schema, subversion, initial, catchup_from, catchup_to, rs_height,
    peer, core_tip, rs_tip, chain, core_blocks, rs_blocks,
    peer_ibd, ibd_seconds, near_tip_seconds,
    compact_batches, reconstructions, getblocktxn, fallbacks, raw_probe,
    phase_a_blocks,
) = sys.argv[1:23]
ibd = json.loads(peer_ibd)
final = json.loads(peer)
evidence = {
    "schema": schema,
    "core_version": subversion,
    "magic": "fabfb5da",
    "peer": final,
    "initial_sync_height": int(initial),
    "catchup_from": int(catchup_from),
    "catchup_to": int(catchup_to),
    "bitcoin_rs_height": int(rs_height),
    "bestblockhash": core_tip,
    "bitcoin_rs_bestblockhash": rs_tip,
    "chain": chain,
    "core_blocks": int(core_blocks),
    "bitcoin_rs_blocks": int(rs_blocks),
    "performance": {
        "ibd_seconds": int(ibd_seconds),
        "near_tip_seconds": int(near_tip_seconds),
        "ibd_bytes_core_to_rs": ibd["bytes_to_rs"],
        "near_tip_bytes_core_to_rs": final["bytes_to_rs"] - ibd["bytes_to_rs"],
        "ibd_bytes_rs_to_core": ibd["bytes_from_rs"],
        "near_tip_bytes_rs_to_core": final["bytes_from_rs"] - ibd["bytes_from_rs"],
    },
    "compact": {
        "phase_a_blocks": int(phase_a_blocks),
        "near_tip_compact_batches": int(compact_batches),
        "reconstructions_complete": int(reconstructions),
        "getblocktxn_requests": int(getblocktxn),
        "full_block_fallbacks": int(fallbacks),
    },
    "bip152_probe": json.loads(raw_probe),
    "core_bip152": {
        "hb_to": final["bip152_hb_to"],
        "hb_from": final["bip152_hb_from"],
    },
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
