#!/usr/bin/env python3
"""Enforce the AGENTS.md comment policy: `///` doc comments are the only
permitted comments in Rust sources. Exits nonzero listing every violation."""
import os
import re
import sys


def violations(path):
    with open(path, "rb") as fh:
        src = fh.read().decode("utf-8", "replace")
    i, n, line = 0, len(src), 1
    out = []
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            body = src[i + 2 : j]
            if not (body.startswith("/") and not body.startswith("//")):
                out.append((line, src[i:j].strip()[:100]))
            i = j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            out.append((line, src[i : i + 40].strip()[:100]))
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    line += src[j] == "\n"
                    j += 1
            i = j
            continue
        if c == '"':
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                elif src[i] == '"':
                    i += 1
                    break
                else:
                    line += src[i] == "\n"
                    i += 1
            continue
        m = re.match(r"(?:r|b|br|c|cr)(#*)\"", src[i:])
        if m:
            j = i + len(m.group(0))
            term = '"' + m.group(1)
            k = src.find(term, j)
            k = n - len(term) if k < 0 else k
            line += src[i : k + len(term)].count("\n")
            i = k + len(term)
            continue
        if c == "'":
            cm = re.match(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}|.)|[^\\'\n])'", src[i:])
            i += len(cm.group(0)) if cm else 1
            continue
        if c == "\n":
            line += 1
        i += 1
    return out


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    bad = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in ("target", ".git")]
        for f in fn:
            if f.endswith(".rs"):
                p = os.path.join(dp, f)
                for line, text in violations(p):
                    bad.append(f"{p}:{line}: {text}")
    if bad:
        print("non-doc comments are banned (AGENTS.md):", file=sys.stderr)
        print("\n".join(bad), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
