#!/usr/bin/env python3
"""Validate the checked-in developer page against repository-owned metadata."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs/site/index.html"
CARGO = ROOT / "Cargo.toml"
ARCH = ROOT / "docs/contracts/architecture.md"


def members():
    text = CARGO.read_text()
    block = re.search(r"members\s*=\s*\[(.*?)\]", text, re.S)
    if not block:
        raise SystemExit("workspace members are missing")
    return [x for x in re.findall(r'"([^"]+)"', block.group(1)) if x.startswith("crates/")]


def layers():
    text = ARCH.read_text()
    result = {}
    for number, body in re.findall(r"Layer (\d+).*?\n(.*?)(?=\n    │ Layer|\n  ```)", text, re.S):
        result.update((crate.rsplit("-", 1)[-1], number) for crate in re.findall(r"bitcoin-rs-([a-z0-9-]+)", body))
    # The prose assignments are the authoritative, easy-to-review representation.
    for number, names in re.findall(r"\*\*Layer (\d+) .*?:\*\* ([^\.]+)", text):
        for name in re.findall(r"`bitcoin-rs-([a-z0-9-]+)`", names):
            result[name] = number
    return result


def main():
    page = PAGE.read_text()
    errors = []
    owner = re.findall(r'<meta name="source-revision" content="([0-9a-f]{40})">', page)
    pins = set(re.findall(r"github\.com/gosuda/bitcoin-rs/(?:blob|tree|commit)/([0-9a-f]{40})", page))
    checkout = re.findall(r"git checkout --detach ([0-9a-f]{40})", page)
    if len(owner) != 1 or pins != {owner[0]} or checkout != owner:
        errors.append("source links and checkout do not share the declared revision")
    expected = {p.removeprefix("crates/") for p in members()}
    expected.discard("__does_not_exist__")
    cards = set(re.findall(r"/crates/([^\"/]+)\">\1</a>", page))
    if cards != expected:
        errors.append(f"module cards {sorted(cards)} do not match Cargo.toml {sorted(expected)}")
    if len(re.findall(r'data-filter="(Core|Storage|Services|Surface|Compose)"', page)) != 5:
        errors.append("module filters do not represent the five architecture layers")
    for crate, layer in layers().items():
        if crate in cards and f'data-layer="{ {"0":"Core","1":"Storage","2":"Services","3":"Surface","4":"Compose"}[layer] }"' not in page:
            errors.append(f"module {crate} is not assigned to its architecture layer")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("developer page metadata is consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
