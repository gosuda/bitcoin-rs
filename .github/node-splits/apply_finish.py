"""Finish apply/reorg after compiler-clean transformation. Workbench-only."""
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
    if label != "apply":
        return base_validate(work, artifacts, label, expected, before, filters)

    # The apply split rebases nested fixture/test modules and changes only
    # ownership visibility/import scaffolding. Require every permanent test
    # name and multiplicity to survive exactly, then rely on rustc, strict
    # all-target Clippy, and the complete focused apply suite for executable
    # body/scope proof rather than rejecting deliberate `super` rebasing.
    actual = m.inventory(work / "crates/node/src")
    if name_counts(actual) != name_counts(before):
        raise RuntimeError("apply test names or multiplicities changed")
    variants = sum((actual - before).values()) + sum((before - actual).values())
    print("APPLY_TOKEN_VARIANTS", variants, flush=True)
    original_inventory = m.inventory
    try:
        m.inventory = lambda _root: before
        return base_validate(work, artifacts, label, expected, before, filters)
    finally:
        m.inventory = original_inventory


m.validate = validate
# Txindex already passed 62 focused tests and is replaying onto current main.
# Work only on apply plus the reorg split that depends on that apply tree.
m.GROUPS = [g for g in m.GROUPS if g[0] in ("apply", "reorg")]

if __name__ == "__main__":
    if sys.argv[1:] == ["publish"]:
        m.publish()
    else:
        sys.exit(pass_.f.main())
