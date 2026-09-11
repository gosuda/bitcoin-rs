#!/usr/bin/env python3
"""Derive BIP141 wtxid goldens for the checked-in block fixtures.

A transaction-boundary walk over a raw block followed by double SHA-256 of
each complete serialization, printed in RPC display order (big-endian).
Pre-segwit transactions have wtxid == txid by definition. One-shot
generation tool for crates/primitives/tests/testdata/<height>.wtxids.txt;
the fetcher's cache contract is unchanged (block + txids only).

Usage: derive-wtxids.py <block.bin> [<block2.bin> ...]
"""

import hashlib
import sys

for path in sys.argv[1:]:
    data = open(path, "rb").read()
    pos = 80  # header

    def varint(pos):
        prefix = data[pos]
        if prefix < 0xFD:
            return prefix, pos + 1
        if prefix == 0xFD:
            return int.from_bytes(data[pos + 1:pos + 3], "little"), pos + 3
        if prefix == 0xFE:
            return int.from_bytes(data[pos + 1:pos + 5], "little"), pos + 5
        return int.from_bytes(data[pos + 1:pos + 9], "little"), pos + 9

    count, pos = varint(pos)
    for _ in range(count):
        start = pos
        pos += 4  # version
        marker = data[pos]
        if marker == 0:
            pos += 2  # BIP144 marker || flag
        inputs, pos = varint(pos)
        for _ in range(inputs):
            pos += 36
            script_len, pos = varint(pos)
            pos += script_len + 4
        outputs, pos = varint(pos)
        for _ in range(outputs):
            pos += 8
            script_len, pos = varint(pos)
            pos += script_len
        if marker == 0:
            for _ in range(inputs):
                stack_items, pos = varint(pos)
                for _ in range(stack_items):
                    item_len, pos = varint(pos)
                    pos += item_len
        pos += 4  # lock time
        tx = data[start:pos]
        digest = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
        # RPC display order is big-endian; sha256d is little-endian.
        print(digest[::-1].hex())
