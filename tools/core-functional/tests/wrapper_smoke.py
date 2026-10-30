#!/usr/bin/env python3
"""Smoke test for tools/core-functional/bin/bitcoind-wrapper.

Drives the wrapper end-to-end with a fake BITCOIN_RS_BIN that records the
exec'd argv, using the exact base argv + bitcoin.conf Bitcoin Core v31.1's
framework produces, and asserts on translation, derived conf, cookie, and the
dropped-flags log. Run: python3 tools/core-functional/tests/wrapper_smoke.py
"""

import atexit
import importlib.util
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile

WRAPPER = pathlib.Path(__file__).resolve().parents[1] / "bin" / "bitcoind-wrapper"
SCRATCH = pathlib.Path(tempfile.mkdtemp(prefix="core-functional-smoke."))
atexit.register(shutil.rmtree, SCRATCH, ignore_errors=True)


def write_fake_binary():
    """Fake bitcoin-rs binary: records its argv, one per line, then exits 0."""
    path = SCRATCH / "fakebitcoind"
    path.write_text(
        "#!/usr/bin/env bash\n"
        f"printf '%s\\n' \"$@\" > {SCRATCH / 'argv.txt'}\n",
        encoding="utf-8")
    path.chmod(0o755)
    return path


FAKE_BIN = write_fake_binary()


def fresh_datadir(name):
    path = SCRATCH / name
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def run_wrapper(datadir, extra_argv, framework_conf=None):
    """Invoke the wrapper as a subprocess against the fake binary."""
    if framework_conf is not None:
        (datadir / "bitcoin.conf").write_text(framework_conf)
    env = dict(os.environ)
    env["BITCOIN_RS_BIN"] = str(FAKE_BIN)
    argv_file = SCRATCH / "argv.txt"
    if argv_file.exists():
        argv_file.unlink()
    proc = subprocess.run(
        [str(WRAPPER)] + extra_argv, env=env, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"wrapper failed: {proc.stderr}"
    assert proc.stdout == "" and proc.stderr == "", (
        f"wrapper was not silent: stdout={proc.stdout!r} stderr={proc.stderr!r}")
    argv = argv_file.read_text().splitlines()
    return argv


def drops(datadir):
    path = datadir / "wrapper-dropped-flags.log"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


# Exactly what initialize_datadir() writes for node 0 on regtest (v31.1) and
# what TestNode.start() passes before extra_args, including the framework's
# auto-appended default binds (no explicit -bind in extra_args).
FRAMEWORK_CONF = """regtest=1
[regtest]
port=11000
rpcport=16000
rpcservertimeout=99000
rpcdoccheck=1
rpcthreads=2
fallbackfee=0.0002
server=1
keypool=1
discover=0
dnsseed=0
fixedseeds=0
listenonion=0
peertimeout=999999999
printtoconsole=0
natpmp=0
shrinkdebugfile=0
unsafesqlitesync=1
connect=0
maxconnections=94
par=2
"""

BASE_ARGV = [
    "-datadir={D}", "-logtimemicros", "-debug", "-debugexclude=leveldb",
    "-debugexclude=rand", "-uacomment=testnode0", "-logthreadnames",
    "-bind=0.0.0.0:11000", "-bind=127.0.0.1:21000=onion",
]

failures = []


def check(label, condition, detail=""):
    if condition:
        print(f"  ok   {label}")
    else:
        failures.append(label)
        print(f"  FAIL {label} {detail}")


print("case 1: framework base argv + base conf (regtest defaults)")
datadir = fresh_datadir("node0")
argv = run_wrapper(datadir, [a.format(D=datadir) for a in BASE_ARGV], FRAMEWORK_CONF)
check("network=regtest", "--network=regtest" in argv, argv)
check("derived conf passed", f"--bitcoin-conf={datadir}/bitcoin-rs-derived.conf" in argv, argv)
check("p2p bind from framework -bind", "--p2p-listen=0.0.0.0:11000" in argv, argv)
check("rpc bind from conf rpcport", "--rpc-bind=127.0.0.1:16000" in argv, argv)
check("onion bind dropped", not any("21000" in a for a in argv), argv)
check("no raw -flags survive", not any(a.startswith("-d") for a in argv), argv)
check("uacomment translated", "--uacomment=testnode0" in argv, argv)
derived = (datadir / "bitcoin-rs-derived.conf").read_text()
check("derived conf keeps dnsseed=0", "dnsseed=0" in derived, derived)
check("derived conf has [regtest] section", "[regtest]" in derived, derived)
check("derived conf drops unsupported keys", "server=" not in derived and "connect=0" not in derived, derived)
check("derived conf keeps no rpcport", "rpcport" not in derived, derived)
cookie = datadir / "regtest" / ".cookie"
check("cookie written where framework reads it", cookie.is_file())
if cookie.is_file():
    content = cookie.read_text()
    check("cookie is user:password shaped", content.startswith("__cookie__:") and len(content) == 11 + 64, content)
check("--rpc-cookie points at it", f"--rpc-cookie={cookie}" in argv, argv)
recorded = drops(datadir)
dropped_tokens = {d["token"] for d in recorded}
expected_drops = {"-logtimemicros", "-debug", "-debugexclude=leveldb", "-debugexclude=rand",
                  "-logthreadnames", "-bind=127.0.0.1:21000=onion",
                  "server=1", "connect=0", "fallbackfee=0.0002", "maxconnections=94"}
check("dropped flags are all logged", expected_drops <= dropped_tokens,
      expected_drops - dropped_tokens)
check("drop log is valid JSONL with reasons", all(d.get("reason") for d in recorded))
check("node data dir is the fresh subdir",
      f"--data-dir={datadir}/bitcoin-rs-data" in argv, argv)
check("core layout dirs created 0700",
      (datadir / "regtest").is_dir() and (datadir / "regtest" / "wallets").is_dir()
      and (stat.S_IMODE(os.lstat(datadir / "regtest").st_mode) == 0o700)
      and (stat.S_IMODE(os.lstat(datadir / "regtest" / "wallets").st_mode) == 0o700))

print("case 2: explicit extra_args (txindex, proxy, connect, v2transport off, nolisten)")
datadir = fresh_datadir("node1")
argv = run_wrapper(
    datadir,
    [a.format(D=datadir) for a in BASE_ARGV] + [
        "-txindex=1", "-proxy=127.0.0.1:9050", "-connect=127.0.0.1:18445",
        "-v2transport=0", "-printtoconsole=0", "-maxconnections=10", "-whitelist=127.0.0.1",
    ],
    FRAMEWORK_CONF,
)
check("txindex translated", "--txindex=true" in argv, argv)
check("proxy translated", "--proxy=127.0.0.1:9050" in argv, argv)
check("connect translated", "--connect=127.0.0.1:18445" in argv, argv)
check("v2transport=0 translated", "--v2transport=false" in argv, argv)
check("whitelist dropped", not any("whitelist" in a for a in argv), argv)
check("maxconnections dropped+logged", any(d["token"] == "-maxconnections=10" for d in drops(datadir)))

print("case 3: -nolisten overrides binds and conf listen=0 honored")
datadir = fresh_datadir("node2")
argv = run_wrapper(
    datadir,
    ["-datadir=" + str(datadir), "-nolisten", "-regtest"],
    FRAMEWORK_CONF,
)
check("no listener flags on -nolisten", not any(a.startswith("--p2p-listen") for a in argv), argv)
check("listen=0 in derived conf", "listen=0" in (datadir / "bitcoin-rs-derived.conf").read_text())
datadir = fresh_datadir("node2b")
argv = run_wrapper(datadir, ["-datadir=" + str(datadir), "-regtest"],
                   FRAMEWORK_CONF.replace("listenonion=0", "listenonion=0\nlisten=0"))
check("conf listen=0 suppresses listener", not any(a.startswith("--p2p-listen") for a in argv), argv)

print("case 4: rpcuser/rpcpassword from conf become the cookie credentials")
datadir = fresh_datadir("node3")
argv = run_wrapper(datadir, ["-datadir=" + str(datadir), "-regtest"],
                   FRAMEWORK_CONF + "rpcuser=alice\nrpcpassword=secret-pw\n")
cookie = (datadir / "regtest" / ".cookie").read_text()
check("cookie carries conf credentials", cookie == "alice:secret-pw", cookie)
check("node pointed at cookie", f"--rpc-cookie={datadir}/regtest/.cookie" in argv, argv)

print("case 5: BITCOIN_RS_EXTRA_ARGS appended verbatim")
datadir = fresh_datadir("node4")
env_extra = dict(os.environ)
env_extra["BITCOIN_RS_BIN"] = str(FAKE_BIN)
env_extra["BITCOIN_RS_EXTRA_ARGS"] = "--log-level=debug --storage-backend=fjall"
(datadir / "bitcoin.conf").write_text(FRAMEWORK_CONF)
proc = subprocess.run([str(WRAPPER), "-datadir=" + str(datadir), "-regtest"],
                      env=env_extra, capture_output=True, text=True)
assert proc.returncode == 0, proc.stderr
argv = (SCRATCH / "argv.txt").read_text().splitlines()
check("extra args appended last", argv[-2:] == ["--log-level=debug", "--storage-backend=fjall"], argv)

print("case 6: missing BITCOIN_RS_BIN fails loudly, exits 127")
env_bad = dict(os.environ)
env_bad.pop("BITCOIN_RS_BIN", None)
proc = subprocess.run([str(WRAPPER), "-datadir=/tmp"], env=env_bad, capture_output=True, text=True)
check("exit 127 on missing env", proc.returncode == 127, proc.returncode)
check("clear error message", "BITCOIN_RS_BIN" in proc.stderr, proc.stderr)

print("case 7: -h short-circuits without touching the datadir")
datadir = fresh_datadir("node5")
argv = run_wrapper(datadir, ["-datadir=" + str(datadir), "-h"], FRAMEWORK_CONF)
check("-h becomes --help", "--help" in argv, argv)
check("no cookie written on -h", not (datadir / "regtest").exists())

print("case 8: testnet chain marker maps network + chain dir")
datadir = fresh_datadir("node6")
argv = run_wrapper(datadir, ["-datadir=" + str(datadir), "-testnet"],
                   FRAMEWORK_CONF.replace("regtest=1", "testnet=1").replace("[regtest]", "[test]"))
check("testnet -> --network=testnet3", "--network=testnet3" in argv, argv)
check("cookie under testnet3/", (datadir / "testnet3" / ".cookie").is_file())

print("case 9: bare-IP conf bind gains the conf port (cache node form)")
datadir = fresh_datadir("node7")
argv = run_wrapper(datadir, ["-datadir=" + str(datadir), "-regtest"],
                   FRAMEWORK_CONF + "bind=127.0.0.1\n")
check("bare bind translated with conf port", "--p2p-listen=127.0.0.1:11000" in argv, argv)

print("case 10: no chain marker anywhere defaults to mainnet, cookie at datadir root")
datadir = fresh_datadir("node8")
mainnet_conf = FRAMEWORK_CONF.replace("regtest=1\n[regtest]\n", "")
os.chmod(datadir, 0o755)  # the framework's own datadir mode must be left alone
argv = run_wrapper(datadir, ["-datadir=" + str(datadir)], mainnet_conf)
check("mainnet default network", "--network=mainnet" in argv, argv)
check("cookie at <datadir>/.cookie", (datadir / ".cookie").is_file())
check("wallets dir at datadir root", (datadir / "wallets").is_dir())
check("wallets dir 0700 on mainnet",
      stat.S_IMODE(os.lstat(datadir / "wallets").st_mode) == 0o700)
check("datadir root itself not chmodded (mainnet chain dir is \"\")",
      stat.S_IMODE(os.lstat(datadir).st_mode) == 0o755,
      oct(stat.S_IMODE(os.lstat(datadir).st_mode)))
check("printtoconsole=0 -> silent console", "--log-level=off" in argv, argv)
check("node data dir still the fresh subdir",
      f"--data-dir={datadir}/bitcoin-rs-data" in argv, argv)

print("case 11: -V (short version flag) becomes --version like -version")
datadir = fresh_datadir("node9")
argv = run_wrapper(datadir, ["-datadir=" + str(datadir), "-V"], FRAMEWORK_CONF)
check("-V becomes --version", "--version" in argv, argv)
check("-V short-circuits without layout work", not (datadir / "regtest").exists())

print("case 12: rpcport conf plus repeated -rpcbind emits exactly one --rpc-bind, last wins")
datadir = fresh_datadir("node10")
argv = run_wrapper(
    datadir,
    ["-datadir=" + str(datadir), "-regtest",
     "-rpcbind=127.0.0.1:17000", "-rpcbind=127.0.0.1:18000"],
    FRAMEWORK_CONF,
)
rpc_binds = [a for a in argv if a.startswith("--rpc-bind")]
check("single --rpc-bind emitted", rpc_binds == ["--rpc-bind=127.0.0.1:18000"], rpc_binds)
datadir = fresh_datadir("node10b")
argv = run_wrapper(
    datadir,
    ["-datadir=" + str(datadir), "-regtest", "-rpcbind=127.0.0.1"],
    FRAMEWORK_CONF,
)
rpc_binds = [a for a in argv if a.startswith("--rpc-bind")]
check("bare-IP -rpcbind gains conf rpcport, emitted once",
      rpc_binds == ["--rpc-bind=127.0.0.1:16000"], rpc_binds)

print("case 13: repeated -uacomment appends; conf uacomment suppressed when CLI set it")
datadir = fresh_datadir("node11")
argv = run_wrapper(
    datadir,
    [a.format(D=datadir) for a in BASE_ARGV] + ["-uacomment=foo", "-printtoconsole=0"],
    FRAMEWORK_CONF + "uacomment=fromconf\n",
)
check("uacomment occurrences append", argv.count("--uacomment=testnode0") == 1
      and "--uacomment=foo" in argv, argv)
check("conf uacomment suppressed when CLI set it",
      "uacomment=fromconf" not in (datadir / "bitcoin-rs-derived.conf").read_text())
check("suppression logged", any(d["token"] == "uacomment=fromconf" for d in drops(datadir)))
check("argv printtoconsole=0 -> silent console", "--log-level=off" in argv, argv)
datadir = fresh_datadir("node12")
argv = run_wrapper(datadir, ["-datadir=" + str(datadir), "-regtest"],
                   FRAMEWORK_CONF + "uacomment=fromconf\n")
check("conf-only uacomment carried into derived conf",
      "uacomment=fromconf" in (datadir / "bitcoin-rs-derived.conf").read_text())
check("conf-only uacomment not a CLI flag", not any("uacomment" in a for a in argv), argv)

print()
if failures:
    print("FAILURES:", failures)
    sys.exit(1)
print("all wrapper smoke cases passed")
