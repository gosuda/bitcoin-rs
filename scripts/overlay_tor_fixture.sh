#!/usr/bin/env bash
# Private Tor fixture helper. One concern: build private TestingTorNetwork.
# Caller provides TOR_COMMAND and TOR_GENCERT_COMMAND from same 0.4.9.14 release.
set -euo pipefail
umask 077
trap ':' EXIT; trap 'exit 1' INT TERM

# Every tool the fixture runs starts under a minimal environment (PATH,
# LD_LIBRARY_PATH when set, and a task-owned HOME) and under `timeout -k`, so no
# operator setting reaches it and none can run forever. SIGTERM goes out after
# FIXTURE_TOOL_TERM_S seconds and SIGKILL FIXTURE_TOOL_KILL_S seconds later.
# `timeout` passes the tool's own exit status through, exits 124 when it had to
# send SIGTERM, and 137 when SIGKILL was needed.
FIXTURE_TOOL_TERM_S=60
FIXTURE_TOOL_KILL_S=5

# Usage: overlay_tor_fixture_run <home> <command> [args...]
overlay_tor_fixture_run() {
  local home="$1"
  local -a clean
  shift
  clean=(env -i "PATH=${PATH}" "HOME=${home}")
  if [ -n "${LD_LIBRARY_PATH:-}" ]; then
    clean+=("LD_LIBRARY_PATH=${LD_LIBRARY_PATH}")
  fi
  "${clean[@]}" timeout -k "${FIXTURE_TOOL_KILL_S}s" "${FIXTURE_TOOL_TERM_S}s" "$@"
}

# Usage: overlay_tor_fixture_launch <template_dir> <tornet_dir>
# Requires env: TOR_COMMAND, TOR_GENCERT_COMMAND.
# <tornet_dir> must not exist or must be an empty directory; the check precedes
# every write. Writes <tornet_dir>/defaults.torrc (empty), so no operator
# torrc-defaults file is read by the fixture's Tor processes.
# Order is fixed: tor-gencert creates keys first, then tor --list-fingerprint
# reads the matching fingerprint. Reversing this writes a stale fingerprint.
overlay_tor_fixture_launch() {
  local template_dir="$1"
  local tornet_dir="$2"
  local -a tor_cmd
  local -a gencert_cmd
  local listing
  local rc
  read -r -a tor_cmd <<<"$TOR_COMMAND"
  read -r -a gencert_cmd <<<"$TOR_GENCERT_COMMAND"
  if grep -Ei -q '^[[:space:]]*FallbackDir([[:space:]]|$)' "$template_dir"/torrc.*.template; then
    printf '%s\n' "error: FallbackDir forbidden in private fixture" >&2
    return 1
  fi
  if grep -qF 'accept *:*' "$template_dir"/torrc.*.template; then
    printf '%s\n' "error: exit policy accept forbidden" >&2
    return 1
  fi
  grep -q "TestingTorNetwork 1" "$template_dir/torrc.common.template" || return 1
  grep -q "UseDefaultFallbackDirs 0" "$template_dir/torrc.common.template" || return 1
  case "$tornet_dir" in
    -*) tornet_dir="./$tornet_dir" ;;
  esac
  if [ -L "$tornet_dir" ]; then
    printf '%s\n' "error: tornet dir is a symbolic link, refusing" >&2
    return 1
  fi
  if [ -e "$tornet_dir" ]; then
    if [ ! -d "$tornet_dir" ]; then
      printf '%s\n' "error: tornet path exists and is not a directory, refusing" >&2
      return 1
    fi
    listing="$(find "$tornet_dir" -mindepth 1 -maxdepth 1 -print -quit)" || {
      printf '%s\n' "error: tornet dir could not be listed, refusing" >&2
      return 1
    }
    if [ -n "$listing" ]; then
      printf '%s\n' "error: tornet dir non-empty, refusing" >&2
      return 1
    fi
  fi
  mkdir -p "$tornet_dir"
  : > "$tornet_dir/defaults.torrc"
  local auth_dirs=""
  local i
  for i in 0 1 2; do
    local dd="$tornet_dir/auth$i"
    mkdir -p "$dd/keys"
    local orport
    orport="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
    local dirport
    dirport="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
    rc=0
    printf '%s' "" | overlay_tor_fixture_run "$dd" "${gencert_cmd[@]}" --create-identity-key --passphrase-fd 0 -m 12 -a "127.0.0.1:$dirport" -i "$dd/keys/authority_identity_key" -s "$dd/keys/authority_signing_key" -c "$dd/keys/authority_certificate" || rc=$?
    if [ "$rc" -ne 0 ]; then
      printf '%s\n' "error: tor-gencert failed for auth$i (exit $rc; 124 = timed out, 137 = killed after timeout)" >&2
      return "$rc"
    fi
    chmod 0600 "$dd/keys/authority_identity_key" "$dd/keys/authority_signing_key"
    printf 'DataDirectory %s\nNickname auth%s\nORPort 127.0.0.1:1\nDirPort 0\nSocksPort 0\nTestingTorNetwork 1\nDirAuthority x orport=1 v3ident=0000000000000000000000000000000000000000 127.0.0.1:1 0000000000000000000000000000000000000000\n' "$dd" "$i" > "$dd/fp.torrc"
    rc=0
    overlay_tor_fixture_run "$dd" "${tor_cmd[@]}" --quiet --defaults-torrc "$tornet_dir/defaults.torrc" -f "$dd/fp.torrc" --list-fingerprint >"$dd/fp.stdout.log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
      printf '%s\n' "error: tor --list-fingerprint failed for auth$i (exit $rc; 124 = timed out, 137 = killed after timeout), see $dd/fp.stdout.log" >&2
      return "$rc"
    fi
    auth_dirs="$auth_dirs $dd:$orport:$dirport"
  done
  local da_lines=""
  i=0
  local entry
  for entry in $auth_dirs; do
    local dd="${entry%%:*}"
    local rest="${entry#*:}"
    local orport="${rest%%:*}"
    local dirport="${rest##*:}"
    local fp
    fp="$(awk -v n="auth$i" '$1==n {print $2; exit}' "$dd/fingerprint")"
    local v3
    v3="$(awk '/^fingerprint /{print $2; exit}' "$dd/keys/authority_certificate")"
    if [ -z "$fp" ] || [ -z "$v3" ]; then
      printf '%s\n' "error: missing authority identity" >&2
      return 1
    fi
    da_lines="${da_lines}DirAuthority auth$i orport=${orport} v3ident=${v3} 127.0.0.1:${dirport} ${fp}
"
    i=$((i + 1))
  done
  printf '%s' "$da_lines" > "$tornet_dir/dir-authorities.inc"
  : > "$tornet_dir/auth-ports.inc"
  for entry in $auth_dirs; do
    rest="${entry#*:}"
    printf '%s\n' "$rest" | tr ':' ' ' >> "$tornet_dir/auth-ports.inc"
  done
  printf '%s\n' "$tornet_dir/dir-authorities.inc"
}
