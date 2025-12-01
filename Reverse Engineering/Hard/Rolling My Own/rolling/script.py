#!/usr/bin/env python3
# solve.py
# Brute-force solver for the 3 unknown 4-char blocks of the 16-char password
# based exactly on the C code you provided.

import hashlib
import itertools
import string
import time

# Allowed characters: lower, upper, digits
ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits

# v13 string from the binary
V13 = b"GpLaMjEWpVOjnnmkRGiledp6Mvcezxls"  # 32 bytes

# Pre-split v13 into 8-byte chunks used by blocks 0..3
V13_CHUNKS = [V13[i*8:(i+1)*8] for i in range(4)]
# We know pass[0:4] == b"D1v1" (given)
KNOWN_PREFIX = b"D1v1"

# Target 16 bytes we need to build (from assembly)
TARGET = bytes([0x48,0x89,0xfe,0x48,
                0xbf,0xf1,0x26,0xdc,
                0xb3,0x07,0x00,0x00,
                0x00,0xff,0xd6,0xc3])

# For each block we will check a 4-byte slice of its MD5:
# block 0 -> MD5(block0)[8..11] must equal TARGET[0:4]
# block 1 -> MD5(block1)[2..5]  must equal TARGET[4:8]
# block 2 -> MD5(block2)[7..10] must equal TARGET[8:12]
# block 3 -> MD5(block3)[1..4]  must equal TARGET[12:16]

CHECKS = [
    (0, 8, 4),   # (target_offset, md5_start, length)
    (4, 2, 4),
    (8, 7, 4),
    (12, 1, 4),
]

def md5_bytes(b: bytes) -> bytes:
    return hashlib.md5(b).digest()  # 16 bytes

def check_block(block_index: int, candidate4: bytes) -> bool:
    """
    block_index: 0..3
    candidate4: 4-byte password slice (bytes)
    returns True if MD5(block) slice matches the expected bytes in TARGET
    """
    block = candidate4 + V13_CHUNKS[block_index]  # 12 bytes
    md = md5_bytes(block)
    _, md_start, length = CHECKS[block_index]
    target_offset, _, _ = CHECKS[block_index]
    want = TARGET[target_offset:target_offset+length]
    got = md[md_start:md_start+length]
    return got == want

def brute_block(block_index: int):
    """
    Brute-force a single 4-char block. Returns list of matches (there can be multiple).
    """
    print(f"[+] Brute forcing block {block_index} (pass positions {block_index*4}..{block_index*4+3})")
    matches = []
    t0 = time.time()
    count = 0
    # iterate over all 62^4 candidates
    for combo in itertools.product(ALPHABET, repeat=4):
        count += 1
        cand = ''.join(combo).encode()
        if check_block(block_index, cand):
            matches.append(cand.decode())
            # don't break — there might be multiple matches; collect them all
            print(f"    [FOUND] block{block_index}: {cand.decode()}")
        # optional progress report every 2 million tries
        if count % 2000000 == 0:
            elapsed = time.time() - t0
            rate = count / elapsed if elapsed > 0 else 0
            print(f"    tried {count:,}  rate {rate:,.0f} it/s")
    elapsed = time.time() - t0
    print(f"[+] Done block {block_index}: tried {count:,} candidates in {elapsed:.1f}s")
    return matches

def main():
    # quick check for block 0 (should match immediately because password prefix known)
    block0 = KNOWN_PREFIX
    ok0 = check_block(0, block0)
    print("Block 0 (known prefix) check:", "OK" if ok0 else "MISMATCH")
    # Brute force blocks 1..3 (indices 1,2,3)
    results = {}
    for bi in (1,2,3):
        matches = brute_block(bi)
        results[bi] = matches
    print("\n=== RESULTS ===")
    print("Known prefix (block0) =", KNOWN_PREFIX.decode())
    for bi in (1,2,3):
        print(f"Block {bi} matches ({len(results[bi])}): {results[bi]}")
    print("\nTo form full password: D1v1 + block1 + block2 + block3 (each block is 4 chars)")
    password = "D1v1" + results[1][0] + results[2][0] + results[3][0]
    print("Example full password:", password)

if __name__ == "__main__":
    main()
