#!/usr/bin/env python3
"""Helper tools used during analysis of zen_void.bin.

Usage examples (run from workspace root):
  python3 tools/island_tools.py list uvt_crackme_work/stage2/void/zen_void.bin
  python3 tools/island_tools.py tryxor uvt_crackme_work/stage2/void/zen_void.bin 0x2345 0x234b
  python3 tools/island_tools.py applykey uvt_crackme_work/stage2/void/zen_void.bin 0x2a

This file captures the ad-hoc snippets executed in the terminal during the reverse.
"""
import sys
from pathlib import Path
import math


def find_islands(data: bytes, min_len: int = 4):
    out = []
    i = 0
    n = len(data)
    while i < n:
        if data[i] == 0:
            i += 1
            continue
        j = i
        while j < n and data[j] != 0:
            j += 1
        if j - i >= min_len:
            out.append((i, j - i))
        i = j
    return out


def shannon_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    ent = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / n
        ent -= p * math.log2(p)
    return ent


def try_single_byte_xor(block: bytes):
    results = []
    for key in range(1, 256):
        dec = bytes(b ^ key for b in block)
        if all(32 <= c < 127 for c in dec):
            results.append((key, dec.decode()))
    return results


def apply_key_to_islands(path: Path, key: int):
    data = path.read_bytes()
    islands = find_islands(data)
    out = []
    for off, ln in islands:
        block = data[off : off + ln]
        dec = bytes(b ^ key for b in block)
        out.append((off, ln, dec))
    return out


def main():
    if len(sys.argv) < 3:
        print("usage: island_tools.py <cmd> <file> [args]")
        raise SystemExit(2)
    cmd = sys.argv[1]
    p = Path(sys.argv[2])
    data = p.read_bytes()
    if cmd == "list":
        islands = find_islands(data)
        for off, ln in islands:
            sample = data[off : off + min(16, ln)].hex()
            print(f"off=0x{off:08x} len={ln} sample={sample} ent={shannon_entropy(data[off:off+ln]):0.2f}")
    elif cmd == "tryxor":
        if len(sys.argv) != 5:
            print("usage: tryxor <file> <off> <end>")
            raise SystemExit(2)
        off = int(sys.argv[3], 0)
        end = int(sys.argv[4], 0)
        block = data[off:end+1]
        for key, dec in try_single_byte_xor(block):
            print(hex(key), '->', dec)
    elif cmd == "applykey":
        if len(sys.argv) != 4:
            print("usage: applykey <file> <hexkey>")
            raise SystemExit(2)
        key = int(sys.argv[3], 0)
        for off, ln, dec in apply_key_to_islands(p, key):
            printable = ''.join((chr(c) if 32 <= c < 127 else '.') for c in dec)
            print(hex(off), ln, dec.hex(), '->', printable)
    else:
        print('unknown cmd')


if __name__ == '__main__':
    main()
