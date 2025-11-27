#!/usr/bin/env python3
# rc4_recover_full.py
# Usage: python3 rc4_recover_full.py ./binary
#
# What it does:
#  - Parses ELF program headers to map VA -> file offset
#  - Extracts C_expected from VA 0x10210 length 0x34
#  - Tries key = b"picoCTF{" and then optional small brute-force on printable charset
#
# Note: run this locally on your binary.

import sys
import struct
import itertools
import os

VA_START = 0x10210
LENGTH = 0x34  # 52 bytes

PRINTABLE = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-."

def elf_va_to_offset(path, va):
    with open(path, "rb") as f:
        e_ident = f.read(16)
        if e_ident[:4] != b'\x7fELF':
            raise RuntimeError("Not an ELF")
        # class
        elf_class = e_ident[4]
        is_64 = (elf_class == 2)
        endian = '<' if e_ident[5] == 1 else '>'  # 1=little, 2=big
        f.seek(0)
        if is_64:
            hdr = f.read(64)
            # e_phoff at offset 32 (8 bytes), e_phentsize at 54 (2 bytes), e_phnum at 56 (2 bytes)
            e_phoff = struct.unpack(endian + "Q", hdr[32:40])[0]
            e_phentsize = struct.unpack(endian + "H", hdr[54:56])[0]
            e_phnum = struct.unpack(endian + "H", hdr[56:58])[0]
            # iterate program headers
            for i in range(e_phnum):
                f.seek(e_phoff + i * e_phentsize)
                ph = f.read(e_phentsize)
                # p_type(4), p_flags(4), p_offset(8), p_vaddr(8), p_paddr(8), p_filesz(8), p_memsz(8), p_align(8)
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(endian + "IIQQQQQQ", ph[:56+8])
                if p_type == 1:  # PT_LOAD
                    if va >= p_vaddr and va < p_vaddr + p_memsz:
                        return p_offset + (va - p_vaddr)
            raise RuntimeError("VA not in any PT_LOAD segment")
        else:
            hdr = f.read(52)
            e_phoff = struct.unpack(endian + "I", hdr[28:32])[0]
            e_phentsize = struct.unpack(endian + "H", hdr[42:44])[0]
            e_phnum = struct.unpack(endian + "H", hdr[44:46])[0]
            for i in range(e_phnum):
                f.seek(e_phoff + i * e_phentsize)
                ph = f.read(e_phentsize)
                # p_type(4), p_offset(4), p_vaddr(4), p_paddr(4), p_filesz(4), p_memsz(4), p_flags(4), p_align(4)
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(endian + "IIIIIIII", ph[:32])
                if p_type == 1:
                    if va >= p_vaddr and va < p_vaddr + p_memsz:
                        return p_offset + (va - p_vaddr)
            raise RuntimeError("VA not in any PT_LOAD segment")

def rc4_init(key: bytes):
    S = list(range(256))
    j = 0
    keylen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % keylen]) & 0xff
        S[i], S[j] = S[j], S[i]
    return S

def rc4_keystream(S, n):
    S = S.copy()
    i = 0
    j = 0
    out = []
    for _ in range(n):
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xff])
    return bytes(out)

def recover_with_key(C_expected, key):
    S = rc4_init(key)
    ks = rc4_keystream(S, len(C_expected))
    P = bytes([c ^ k for c, k in zip(C_expected, ks)])
    return P

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 rc4_recover_full.py ./binary")
        return
    path = sys.argv[1]
    if not os.path.exists(path):
        print("file not found:", path)
        return

    try:
        offset = elf_va_to_offset(path, VA_START)
    except Exception as e:
        print("Error mapping VA -> offset:", e)
        return

    with open(path, "rb") as f:
        f.seek(offset)
        C_expected = f.read(LENGTH)
    print("Extracted C_expected (len={}):".format(len(C_expected)))
    print("hex:", C_expected.hex())
    try:
        print("ascii:", C_expected.decode('ascii', errors='replace'))
    except:
        pass

    # Try standard prefix
    prefix = b"picoCTF{"
    print("\nTrying key = picoCTF{ ...")
    P = recover_with_key(C_expected, prefix)
    print("Recovered (utf-8 attempt):")
    try:
        print(P.decode())
    except:
        print(P)
    if P[:8] == prefix:
        print("SUCCESS: plaintext starts with 'picoCTF{'. Candidate flag:")
        print(P)
        return
    else:
        print("Not a match: first 8 bytes != key")

    # Heuristic: maybe plaintext is printable and first 8 bytes must be printable -> derive key = P[:8] and check consistency
    print("\nHeuristic: derive key = P[:8] using prefix guess or random key and check.")
    derived_key = P[:8]
    print("Derived key (hex):", derived_key.hex(), " ascii:", derived_key)
    P2 = recover_with_key(C_expected, derived_key)
    if P2[:8] == derived_key:
        print("Derived-key self-consistent! Candidate plaintext:")
        print(P2)
        return
    else:
        print("Derived-key NOT self-consistent. Continuing to small brute-force...")

    # Small brute-force over printable charset but LIMIT number of keys to not run forever.
    charset = PRINTABLE
    max_trials = 2000000  # tune as needed; 2 million
    print("\nStarting limited brute force on first-8-bytes (charset size={}, max_trials={})".format(len(charset), max_trials))
    tried = 0
    for candidate in itertools.product(charset, repeat=8):
        tried += 1
        if tried % 200000 == 0:
            print("tried", tried, "keys...")
        key = bytes(candidate)
        P = recover_with_key(C_expected, key)
        if P[:8] == key:
            print("FOUND! key:", key, "plaintext:", P)
            return
        if tried >= max_trials:
            break
    print("Brute force finished (or reached trial limit). No key found.")

if __name__ == "__main__":
    main()
