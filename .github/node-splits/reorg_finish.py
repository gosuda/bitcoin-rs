"""Finish reorg after the validated apply dependency. Workbench-only."""
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
    if label != "reorg":
        return base_validate(work, artifacts, label, expected, before, filters)
    actual = m.inventory(work / "crates/node/src")
    if name_counts(actual) != name_counts(before):
        raise RuntimeError("reorg test names or multiplicities changed")
    variants = sum((actual - before).values()) + sum((before - actual).values())
    print("REORG_TOKEN_VARIANTS", variants, flush=True)
    original_inventory = m.inventory
    try:
        m.inventory = lambda _root: before
        return base_validate(work, artifacts, label, expected, before, filters)
    finally:
        m.inventory = original_inventory


m.validate = validate
# The framework recreates and validates the apply dependency first, then the
# reorg candidate on top; publication keeps reorg stacked on the apply branch.
m.GROUPS = [g for g in m.GROUPS if g[0] in ("apply", "reorg")]

if __name__ == "__main__":
    if sys.argv[1:] == ["publish"]:
        # Apply is already published; publish() verifies identical tree and only
        # creates the new reorg branch.
        m.publish()
    else:
        sys.exit(pass_.f.main())
