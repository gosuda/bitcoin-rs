"""Decode complete checked manifest transfers; reject truncation or extra bytes."""
from pathlib import Path
import base64
import hashlib
import json
import lzma

root = Path(__file__).resolve().parent
for receipt in sorted(root.glob('*.receipt')):
    spec = json.loads(receipt.read_text())
    stem = receipt.stem
    parts = [root / f'{stem}.part{i}' for i in range(spec['parts'])]
    encoded = ''.join(p.read_text().strip() for p in parts)
    compressed = base64.b64decode(encoded, validate=True)
    decoder = lzma.LZMADecompressor(memlimit=256 * 1024 * 1024)
    raw = decoder.decompress(compressed, max_length=8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024 or not decoder.eof or decoder.unused_data:
        raise RuntimeError('invalid or oversized compressed source manifest')
    if hashlib.sha256(raw).hexdigest() != spec['sha256']:
        raise RuntimeError('source manifest transfer checksum differs: ' + stem)
    json.loads(raw)
    (root / (stem + '.json')).write_bytes(raw)
    print('VERIFIED MANIFEST', stem, len(raw), spec['sha256'], flush=True)
