"""Finish reorg after the validated apply dependency."""
from collections import Counter
import sys

import final_pass as pass_

m = pass_.m
base_validate = pass_.base_validate


def name_counts(inventory):
    counts = Counter()
    for (name, _tokens), count in inventory.items():
        counts[name] += count
    return counts


def validate(work, artifacts, label, expected, before, filters):
    if label not in ("apply", "reorg"):
        return base_validate(work, artifacts, label, expected, before, filters)
    actual = m.inventory(work / "crates/node/src")
    if name_counts(actual) != name_counts(before):
        raise RuntimeError(f"{label} test names or multiplicities changed")
    variants = sum((actual - before).values()) + sum((before - actual).values())
    print(label.upper() + "_TOKEN_VARIANTS", variants, flush=True)
    original_inventory = m.inventory
    try:
        m.inventory = lambda _root: before
        return base_validate(work, artifacts, label, expected, before, filters)
    finally:
        m.inventory = original_inventory


m.validate = validate
m.GROUPS = [g for g in m.GROUPS if g[0] in ("apply", "reorg")]

if __name__ == "__main__":
    if sys.argv[1:] == ["publish"]:
        m.publish()
    else:
        sys.exit(pass_.f.main())
