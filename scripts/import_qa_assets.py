#!/usr/bin/env python3
"""Bounded fuzz-seed transformations used by import-qa-assets.sh.

The shell owns acquisition, the byte budget, minimization, and provenance.
This module owns seed framing and per-file atomic publication. Publication
is not a transaction over the corpus and does not claim crash durability.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from collections.abc import Iterator, Sequence


def _seed_paths(source: Path) -> Iterator[Path]:
    # Filenames (direct copies) or content hashes own output identity, not order.
    # Stream entries rather than retaining a directory-sized list of Path objects.
    with os.scandir(source) as entries:
        for entry in entries:
            if entry.is_file(follow_symlinks=False):
                yield Path(entry.path)


def _read_seed(path: Path, limit: int) -> bytes:
    # Revalidate the opened object: the directory entry may change after scandir.
    # NONBLOCK avoids hanging on a raced FIFO before fstat can reject it.
    def open_regular(name: str, flags: int) -> int:
        descriptor = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError(f"Expected regular seed file: {path}")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    with open(path, "rb", opener=open_regular) as source:
        return source.read(limit)


def _publish(output: Path, name: str, seed: bytes) -> None:
    """Replace the directory entry, never follow a pre-existing output symlink."""
    temporary = tempfile.NamedTemporaryFile(prefix=".qa-import-", dir=output, delete=False)
    staged = Path(temporary.name)
    try:
        with temporary as stream:
            stream.write(seed)
            os.fchmod(stream.fileno(), 0o644)
        os.replace(staged, output / name)
    finally:
        staged.unlink(missing_ok=True)


def _emit(output: Path, seed: bytes) -> None:
    _publish(output, hashlib.sha256(seed).hexdigest()[:32], seed)


def _mask_rust_raw_strings(text: str) -> str:
    """Hide raw-string bodies from regexes that locate Rust declarations."""
    raw_start = re.compile(r'(?:b|c)?r(#{0,255})"')
    out: list[str] = []
    index = 0
    while index < len(text):
        raw = raw_start.match(text, index)
        if raw is None:
            out.append(text[index])
            index += 1
            continue
        hashes = raw.group(1)
        terminator = '"' + hashes
        end = text.find(terminator, raw.end())
        if end < 0:
            raise ValueError("Unterminated Rust raw string in script_eval contract")
        literal = text[index:end + len(terminator)]
        out.append("".join("\n" if char == "\n" else " " for char in literal))
        index = end + len(terminator)
    return "".join(out)


def _commands(source: Path) -> dict[str, bytes]:
    text = _mask_rust_raw_strings(_strip_rust_comments(source.read_text()))
    table = re.search(
        r"pub\s+const\s+COMMANDS\s*:\s*&\[Command\]\s*=\s*&\[(.*?)\];",
        text, re.S,
    )
    if table is None:
        raise ValueError("Cannot find the P2P COMMANDS inventory")
    commands = re.findall(r'\bname\s*:\s*"([a-z0-9]{1,12})"', table.group(1))
    if (not commands or len(commands) > 256 or len(set(commands)) != len(commands)
            or len(commands) != len(re.findall(r"\bCommand\s*\{", table.group(1)))):
        raise ValueError("Invalid P2P COMMANDS inventory")
    return {name: bytes([index]) for index, name in enumerate(commands)}


def map_p2p(source: Path, inventory: Path, output: Path, max_bytes: int) -> None:
    if max_bytes < 1:
        raise ValueError("Seed budget is too small for a P2P selector")
    selector = _commands(inventory)
    output.mkdir(parents=True, exist_ok=True)
    imported = skipped_short = unknown_command = 0
    for path in _seed_paths(source):
        blob = _read_seed(path, 24 + max_bytes - 1)
        if len(blob) < 24:
            skipped_short += 1
            continue
        command = blob[4:16].split(b"\0", 1)[0].decode("ascii", "replace")
        selected = selector.get(command)
        if selected is None:
            unknown_command += 1
            continue
        _emit(output, selected + blob[24:])
        imported += 1
    print(f"p2p_message: imported={imported} skipped_short={skipped_short} unknown_command={unknown_command}")


def _frame(selector: int, script_pubkey: bytes, witness: Sequence[bytes]) -> bytes:
    # Empty scriptSig; remaining fields follow script_eval's documented framing.
    parts = [bytes([selector]), b"\0\0", len(script_pubkey).to_bytes(2, "little"),
             script_pubkey, bytes([len(witness)])]
    parts.extend(len(element).to_bytes(2, "little") + element for element in witness)
    return b"".join(parts)


def _strip_rust_comments(text: str) -> str:
    """Remove Rust line/nested-block comments without touching string contents."""
    raw_start = re.compile(r'r(#{0,255})"')
    out: list[str] = []
    index = block_depth = 0
    in_string = False
    while index < len(text):
        if block_depth:
            if text.startswith("/*", index):
                block_depth += 1
                index += 2
            elif text.startswith("*/", index):
                block_depth -= 1
                index += 2
            else:
                out.append("\n" if text[index] == "\n" else " ")
                index += 1
            continue
        if in_string:
            char = text[index]
            out.append(char)
            index += 1
            if char == "\\" and index < len(text):
                out.append(text[index])
                index += 1
            elif char == '"':
                in_string = False
            continue
        raw = raw_start.match(text, index)
        if raw:
            hashes = raw.group(1)
            terminator = '"' + hashes
            end = text.find(terminator, raw.end())
            if end < 0:
                raise ValueError("Unterminated Rust raw string in script_eval contract")
            out.append(text[index:end + len(terminator)])
            index = end + len(terminator)
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            if newline < 0:
                break
            out.append("\n")
            index = newline + 1
        elif text.startswith("/*", index):
            block_depth = 1
            index += 2
        else:
            char = text[index]
            out.append(char)
            in_string = char == '"'
            index += 1
    if block_depth:
        raise ValueError("Unterminated Rust block comment in script_eval contract")
    return "".join(out)


def _split_flags(body: str) -> list[str]:
    entries: list[str] = []
    start = depth = 0
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    for index, char in enumerate(body):
        if char in "([{":
            stack.append(char)
            depth += 1
        elif char in pairs:
            if not stack or stack.pop() != pairs[char]:
                raise ValueError("Invalid script_eval FLAGS inventory")
            depth -= 1
        elif char == "," and depth == 0:
            entry = body[start:index].strip()
            if entry:
                entries.append(entry)
            start = index + 1
    if stack:
        raise ValueError("Invalid script_eval FLAGS inventory")
    tail = body[start:].strip()
    if tail:
        entries.append(tail)
    return entries


def _script_contract(harness: Path) -> tuple[int, int, int]:
    text = _mask_rust_raw_strings(_strip_rust_comments(harness.read_text()))
    limit = re.search(r"const\s+ELEMENT_LEN_MAX\s*:\s*usize\s*=\s*([0-9_]+)\s*;", text)
    flags = re.search(
        r"const\s+FLAGS\s*:\s*\[VerifyFlags\s*;\s*([0-9_]+)\s*\]\s*=\s*\[(.*?)\]\s*;",
        text, re.S,
    )
    if limit is None:
        raise ValueError("Cannot find script_eval ELEMENT_LEN_MAX")
    if flags is None:
        raise ValueError("Cannot find script_eval FLAGS inventory")
    entries = _split_flags(flags.group(2))
    declared = int(flags.group(1).replace("_", ""))
    if not entries or len(entries) != declared or len(entries) > 256:
        raise ValueError("Invalid script_eval FLAGS inventory")
    normalized = [re.sub(r"\s+", "", entry) for entry in entries]
    try:
        none = normalized.index("VerifyFlags::NONE")
        taproot = normalized.index("VerifyFlags::TAPROOT")
    except ValueError as error:
        raise ValueError("script_eval FLAGS must contain NONE and TAPROOT exactly once") from error
    if normalized.count("VerifyFlags::NONE") != 1 or normalized.count("VerifyFlags::TAPROOT") != 1:
        raise ValueError("script_eval FLAGS must contain NONE and TAPROOT exactly once")
    return int(limit.group(1).replace("_", "")), none, taproot


def map_script(sources: Sequence[Path], harness: Path, output: Path, max_bytes: int) -> None:
    element_limit, none_selector, taproot_selector = _script_contract(harness)
    # P2TR framing adds ten bytes relative to the retained source script.
    script_limit = min(element_limit, 0xffff, max_bytes - 10)
    if script_limit < 0:
        raise ValueError("Seed budget is too small for script framing")
    output.mkdir(parents=True, exist_ok=True)
    imported = 0
    for source in sources:
        for path in _seed_paths(source):
            script = _read_seed(path, script_limit)
            _emit(output, _frame(none_selector, script, []))
            if len(script) >= 32 and element_limit >= 34:
                _emit(output, _frame(taproot_selector, b"\x51\x20" + script[:32], [script[32:]]))
            imported += 1
    print(f"script_eval: imported={imported} files (raw + P2TR variants)")


def map_direct(source: Path, output: Path, max_bytes: int, name: str) -> None:
    if max_bytes < 1:
        raise ValueError("Seed budget must be positive")
    output.mkdir(parents=True, exist_ok=True)
    imported = skipped = 0
    for path in _seed_paths(source):
        # Read to the exclusive boundary: this also bounds files that grow after enumeration.
        seed = _read_seed(path, max_bytes)
        if len(seed) >= max_bytes:
            skipped += 1
            continue
        _publish(output, path.name, seed)
        imported += 1
    print(f"[import-qa-assets] {name}: imported={imported} skipped_oversize={skipped} (>= {max_bytes} bytes)")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpora", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--out-base", required=True, type=Path)
    parser.add_argument("--max-seed-bytes", required=True, type=int)
    args = parser.parse_args(argv)
    p2p = args.corpora / "p2p_deserialize_raw_net_msg"
    scripts = [args.corpora / "bitcoin_deserialize_script",
               args.corpora / "bitcoin_script_bytes_to_asm_fmt"]
    direct = [("bitcoin_deserialize_block", "block_validate"),
              ("bitcoin_deserialize_transaction", "tx_validate")]
    try:
        for source in [p2p, *scripts, *(args.corpora / name for name, _ in direct)]:
            if not source.is_dir():
                raise ValueError(f"Expected corpus directory: {source}")
        map_p2p(p2p, args.repo_root / "crates/p2p/src/compat.rs",
                args.out_base / "p2p_message", args.max_seed_bytes)
        map_script(scripts, args.repo_root / "fuzz/fuzz_targets/script_eval.rs",
                   args.out_base / "script_eval", args.max_seed_bytes)
        for source_name, target in direct:
            map_direct(args.corpora / source_name, args.out_base / target,
                       args.max_seed_bytes, target)
    except (OSError, ValueError) as error:
        print(f"[import-qa-assets] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
