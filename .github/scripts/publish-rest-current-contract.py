from pathlib import Path
import subprocess


def run(*args: str) -> str:
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        print(result.stdout, flush=True)
        raise SystemExit(result.returncode)
    return result.stdout


def replace(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text()
    assert text.count(old) == 1, (path, text.count(old), old)
    file.write_text(text.replace(old, new, 1))


base = "de0f6ffff75ddffaa6ed0b59ee4f208cfd2e49b6"
branch = "docs/rest-route-local-consistency"
assert run("git", "rev-parse", "HEAD").strip() == base
assert not run("git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}").strip()
run("git", "switch", "-c", branch)

rest = "crates/rpc/src/rest.rs"
replace(
    rest,
    '''/// REST is deliberately distinct from unknown routes: a disabled gateway and
/// a genuinely unknown path return 404, while malformed header parameters
/// return 400. The enforcer uses 404 on `/rest/*` to diagnose a disabled
/// gateway, so an unknown but well-formed block hash returns an empty 200
/// response instead of a misleading 404. Header query parameters other than
/// `count` are ignored, matching Core's cache-buster-friendly behavior.
''',
    '''/// REST is deliberately distinct from unknown routes: a disabled gateway and
/// a genuinely unknown path return 404, while malformed parameters return 400.
/// Unknown transactions and block bodies return 404; `/rest/headers` instead
/// returns an empty successful body when its well-formed start hash is not on
/// the applied chain. Header query parameters other than `count` are ignored,
/// matching Core's cache-buster-friendly behavior.
''',
)

guide = "docs/rest-interface.md"
text = Path(guide).read_text()
start = text.index("## Coherent views\n")
end = text.index("\nThe REST gateway does not change", start)
replacement = '''## Current consistency and limits

REST does not currently capture one request-wide `ReadStamp` or retry every
response when the chain generation changes. Consistency is route-local and the
handler's actual locks/snapshots define the guarantee.

- `/rest/headers` loads one applied-tip snapshot while holding the block-tree
  read lock, verifies that snapshot still names the locked tip, and walks only
  that active chain. A well-formed unknown, side-branch, orphaned, or
  header-only start hash returns HTTP 200 with an empty JSON array (or empty
  hex/binary body).
- `/rest/getutxos[/checkmempool]` captures the applied height and hash, then
  reads the mempool and requested UTXOs. It does not revalidate a chain
  generation after those reads, so this route is not a request-atomic
  chain/mempool/UTXO snapshot and does not promise a reorg-triggered 503.
- `/rest/mempool/*` and `/rest/tx` use the locking and lookup behavior of their
  existing RPC handlers. Unknown transactions return HTTP 404. The REST layer
  does not add a separate capability-state 503 contract around
  `getrawtransaction`.
- `/rest/block`, `/rest/block/notxdetails`, and `/rest/blockpart` return HTTP
  404 for an unknown well-formed block hash or unavailable pruned body. Full
  block/body materialization is capped at 4,000,000 bytes and shares a
  two-request render budget; only that explicit capacity limit returns HTTP
  503 with the retry message.

Header `count` defaults to 5 and must be in the inclusive range 1–2000.
Out-of-range, negative, non-numeric, and overflowing values return HTTP 400
with Core's invalid-count message. Unknown query parameters are ignored, so
cache-buster parameters do not affect the response.

These are current implementation guarantees, not the target coherent-view
model described elsewhere. A future request-wide stamp must land with the
handler implementation and observable route tests before this guide can claim
that stronger behavior.
'''
Path(guide).write_text(text[:start] + replacement + text[end:])

contract = "docs/contracts/external-api.md"
replace(
    contract,
    '''### `API-04`: Read consistency and query budgeting

- Multi-record queries across chainstate use optimistic tip fencing or
  active-tip verification against `BlockTree`. If a reorg occurs during
  assembly, queries return `503 Service Unavailable` rather than inconsistent
  data.
- Statistical and script index queries are bounded by `QueryBudget` to prevent
  memory exhaustion.
''',
    '''### `API-04`: Route-local read consistency and query budgeting

- There is no current request-wide `ReadStamp` guarantee covering every RPC
  and REST route. Each multi-record handler owns its actual locking, snapshot,
  and retry semantics; a generic reorg-triggered HTTP 503 must not be inferred.
- `/rest/headers` verifies one applied-tip snapshot against `BlockTree` while
  holding the tree read lock. `/rest/getutxos` currently composes applied-tip,
  mempool, and UTXO reads without post-read generation revalidation; it is not
  a request-atomic mixed-state snapshot.
- HTTP 503 is used only by routes with an explicit unavailable/capacity path,
  such as the bounded full-block REST render budget. Unknown `/rest/tx` and
  `/rest/block*` identities follow their route-specific 404 behavior.
- Statistical and script-index query paths that use `QueryBudget` remain
  bounded by that owner; this clause does not extend that budget to unrelated
  REST handlers.
''',
)

run("rustfmt", "--edition", "2024", rest)
run("git", "diff", "--check")
changed = run("git", "diff", "--name-only").splitlines()
assert set(changed) == {rest, guide, contract}, changed
print(run("git", "diff", "--stat"), flush=True)
print(run("git", "diff", "--", rest, guide, contract), flush=True)
run("git", "add", "--", rest, guide, contract)
run(
    "git",
    "-c",
    "user.name=github-actions[bot]",
    "-c",
    "user.email=41898282+github-actions[bot]@users.noreply.github.com",
    "commit",
    "-m",
    "docs(rest): describe route-local consistency instead of a global stamp",
)
run("git", "push", "origin", f"HEAD:refs/heads/{branch}")
print("PUBLISHED_SHA=" + run("git", "rev-parse", "HEAD").strip(), flush=True)
