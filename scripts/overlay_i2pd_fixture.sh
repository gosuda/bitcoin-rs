#!/usr/bin/env bash
# Private i2pd fixture helper. One concern: provision seven private routers.
set -euo pipefail
umask 077
trap ':' EXIT; trap 'exit 1' INT TERM

# Key generation runs the daemon under a minimal environment (PATH,
# LD_LIBRARY_PATH when set, and the router directory as HOME) and under
# `timeout -k`: i2pd does not exit by itself, so SIGTERM ends it after
# FIXTURE_KEYGEN_RUN_S seconds (exit 124, the expected outcome) and SIGKILL
# follows FIXTURE_KEYGEN_KILL_S seconds later if it ignored SIGTERM (exit 137,
# a failed keygen).
FIXTURE_KEYGEN_RUN_S=15
FIXTURE_KEYGEN_KILL_S=15

# Usage: overlay_i2pd_fixture_launch <routers_dir> <reseed_zip> <i2pd_bin>
# <routers_dir> must not exist or must be an empty directory; the check
# precedes every write.
overlay_i2pd_fixture_launch() {
  local routers_dir="$1"
  local reseed_zip="$2"
  local i2pd_bin="$3"
  local listing
  local rc
  local keyfile
  local mode
  local -a clean
  if [ ! -x "$i2pd_bin" ]; then
    printf '%s\n' "error: i2pd binary not executable" >&2
    return 1
  fi
  case "$routers_dir" in
    -*) routers_dir="./$routers_dir" ;;
  esac
  if [ -L "$routers_dir" ]; then
    printf '%s\n' "error: routers dir is a symbolic link, refusing" >&2
    return 1
  fi
  if [ -e "$routers_dir" ]; then
    if [ ! -d "$routers_dir" ]; then
      printf '%s\n' "error: routers path exists and is not a directory, refusing" >&2
      return 1
    fi
    listing="$(find "$routers_dir" -mindepth 1 -maxdepth 1 -print -quit)" || {
      printf '%s\n' "error: routers dir could not be listed, refusing" >&2
      return 1
    }
    if [ -n "$listing" ]; then
      printf '%s\n' "error: routers dir non-empty, refusing" >&2
      return 1
    fi
  fi
  mkdir -p "$routers_dir"
  clean=(env -i "PATH=${PATH}")
  if [ -n "${LD_LIBRARY_PATH:-}" ]; then
    clean+=("LD_LIBRARY_PATH=${LD_LIBRARY_PATH}")
  fi
  local n
  for n in 0 1 2 3 4 5 6; do
    local rdir="$routers_dir/r$n"
    local loop="127.0.77.$((n + 1))"
    local tcpport=$((31101 + n))
    local samport=$((31201 + n))
    local samuport=$((31203 + n))
    mkdir -p "$rdir/tunnels.d" "$rdir/data" "$rdir/log"
    cat > "$rdir/i2pd.conf" <<EOF
datadir = ${rdir}/data
certsdir = ${rdir}/certs
tunconf = ${rdir}/tunnels.conf
tunnelsdir = ${rdir}/tunnels.d
pidfile = ${rdir}/i2pd.pid
log = file
logfile = ${rdir}/log/i2pd.log
loglevel = info
daemon = false
service = false
netid = 77
ipv4 = true
ipv6 = false
nat = false
host = ${loop}
address4 = ${loop}
port = ${tcpport}
reservedrange = false
floodfill = true
notransit = false
[ntcp2]
enabled = true
published = true
port = ${tcpport}
[ssu2]
enabled = false
published = false
[http]
enabled = false
[httpproxy]
enabled = false
[socksproxy]
enabled = false
[sam]
enabled = true
address = 127.0.0.1
port = ${samport}
portudp = ${samuport}
[bob]
enabled = false
[i2cp]
enabled = false
[i2pcontrol]
enabled = false
[upnp]
enabled = false
[nettime]
enabled = false
[meshnets]
yggdrasil = false
[addressbook]
enabled = false
[persist]
netdbinterval = 5
[reseed]
verify = false
urls =
yggurls =
zipfile = ${reseed_zip}
EOF
    printf '%s' "$samport" > "$rdir/sam.port"
    touch "$rdir/tunnels.conf"
  done
  local rdir2
  for n in 0 1 2 3 4 5 6; do
    rdir2="$routers_dir/r$n"
    rc=0
    "${clean[@]}" "HOME=$rdir2" timeout -k "${FIXTURE_KEYGEN_KILL_S}s" "${FIXTURE_KEYGEN_RUN_S}s" "$i2pd_bin" --datadir="$rdir2/data" --conf="$rdir2/i2pd.conf" 1>"$rdir2/keygen.log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
      printf '%s\n' "error: i2pd keygen failed rc=$rc (137 = killed after ignoring SIGTERM), see $rdir2/keygen.log" >&2
      return 1
    fi
    for keyfile in "$rdir2/data/router.info" "$rdir2/router.info" "$rdir2/.i2pd/router.info" "$rdir2/data/router.keys" "$rdir2/router.keys" "$rdir2/.i2pd/router.keys"; do
      if [ -f "$keyfile" ]; then
        mode="$(stat -c %a "$keyfile")"
        if [ "$mode" != "600" ]; then
          printf '%s\n' "error: key file mode $mode != 600: $keyfile" >&2
          return 1
        fi
      fi
    done
  done
  python3 - "$routers_dir" "$reseed_zip" <<'PYEOF'
import base64
import hashlib
import os
import sys
import time
routers = sys.argv[1]
out = sys.argv[2]
deadline = time.monotonic() + 60.0
infos = []
for n in range(7):
    base = os.path.join(routers, "r" + str(n))
    candidates = [os.path.join(base, "router.info"), os.path.join(base, "data", "router.info"), os.path.join(base, ".i2pd", "router.info")]
    found = ""
    while time.monotonic() < deadline:
        for src in candidates:
            if os.path.isfile(src) and os.path.getsize(src) > 0:
                found = src
                break
        if found:
            break
        time.sleep(0.5)
    if not found:
        raise SystemExit("missing router.info for r" + str(n))
    infos.append(found)
time.sleep(1.0)
import zipfile
with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
    for src in infos:
        raw = open(src, "rb").read()
        cert_len = int.from_bytes(raw[385:387], "big")
        identity = raw[:387 + cert_len]
        digest = hashlib.sha256(identity).digest()
        name = "routerInfo-" + base64.b64encode(digest).decode() + ".dat"
        zf.writestr(name, raw)
print("reseed zip entries: 7")
PYEOF
  printf '%s\n' "r0_sam=$(cat "$routers_dir/r0/sam.port") r1_sam=$(cat "$routers_dir/r1/sam.port") reseed=$reseed_zip"
}
