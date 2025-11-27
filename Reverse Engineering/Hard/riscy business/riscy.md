# breadth

### Information
* Category: RE
* Point:
* Level: Hard

### Description
Try not to take too many riscs when finding the flag.

### Hint
None

### Solution
#### What we got ?
- The problem gives us a binary file. Using `file` to check its type, we will find out it a ELF 64-bit LSB file. But looking closely, its type contain `RVC`, which means the compressed instructions can be seen but in a smaller version. Moreover, it is hardly to be reverse disassembly manually.
- So, try to use Ghidra to decompile it, we will receive the src code: [`decompile.c`]()
- Looking closely to this code, we will find 2 functions `FUN_00010078()` and `FUN_00010080()` implement the RC4 Key Scheduling Algorithm (KSA):

    ```c
    byte bVar1;
    ulong uVar2;
    ulong uVar3;
    long lVar4;
    ulong uVar5;
    byte *pbVar6;
    
    ecall();
    lVar4 = 0;
    do {
        param_1[lVar4] = (byte)lVar4;
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x100);
    uVar2 = 0;
    uVar5 = 0;
    pbVar6 = param_1;
    do {
        uVar3 = uVar2 % param_3;
        bVar1 = *pbVar6;
        uVar2 = uVar2 + 1;
        uVar3 = (ulong)(int)((int)uVar5 + (uint)*(byte *)(uVar3 + param_2) + (uint)bVar1);
        uVar5 = uVar3 & 0xff;
        *pbVar6 = param_1[uVar3 & 0xff];
        param_1[uVar3 & 0xff] = bVar1;
        pbVar6 = pbVar6 + 1;
    } while (uVar2 != 0x100);
    return;
    ```

    - About the function, first, it initializes the state array `param_1` (the S‑box) so that `S[i] = i` for all 0–255. Then it begins the standard RC4 mixing loop: it iterates over all 256 bytes, maintaining an index `uVar5` (the RC4 “j” variable). For each position `i` (`uVar2`), it computes `j = (j + S[i] + key[i mod keylen]) mod 256`, where `param_2` is the key buffer and `param_3` is its length. After updating `j`, it swaps `S[i]` with `S[j]`, progressively scrambling the S‑box based on the key. By the end of the 256‑iteration loop, the S‑box in `param_1` contains the fully mixed RC4 state derived from the provided key, ready for the PRGA step.

- Moving to the function `FUN_000100d2()`, it implements the RC4 PRGA (generate one keystream byte).

    ```c
    char cVar1;
    char cVar2;
    byte bVar3;
    char *pcVar4;
    char *pcVar5;
    
    bVar3 = *(char *)(param_1 + 0x100) + 1;
    *(byte *)(param_1 + 0x100) = bVar3;
    pcVar4 = (char *)((ulong)bVar3 + param_1);
    cVar1 = *pcVar4;
    bVar3 = *(char *)(param_1 + 0x101) + cVar1;
    *(byte *)(param_1 + 0x101) = bVar3;
    pcVar5 = (char *)((ulong)bVar3 + param_1);
    cVar2 = *pcVar5;
    *pcVar4 = cVar2;
    *pcVar5 = cVar1;
    return *(undefined1 *)(param_1 + (ulong)(byte)(cVar1 + cVar2));
    ```

    - About this function, it maintains two indices stored at offsets `0x100` and `0x101` in the state array (`i` and `j`). Each call increments `i` (`bVar3 = S[i] + 1`) and adds the value `S[i]` to `j`, then swaps `S[i]` and `S[j]`, just like the standard RC4 PRGA step. Finally, it produces a keystream byte by returning `S[(S[i] + S[j]) mod 256]`. Repeated calls to this function generate the RC4 keystream, which can then be XORed with the ciphertext to decrypt the message. The use of `param_1 + 0x100/0x101` as indices and the swap ensures the internal state evolves correctly with each byte output.

- Overall, The program takes your input `P` (length L), uses the first 8 bytes `K = P[0:8]` as the RC4 key, produces keystream `KS` of length `L`, computes `C = P ^ KS`, and checks `C == C_expected` (where `C_expected` is a 52-byte constant embedded in the binary). If equal → success.

#### How to get the flag ?

##### Logical relation to reverse
Let:

* `P` = plaintext bytes you type (the input).
* `K` = `P[:8]` (first 8 bytes).
* `KS` = RC4 keystream bytes generated using key `K`.
* `C_expected` = the 52-byte constant stored in binary.

Program computes:

```
C_computed = P ^ KS
```

and checks

```
C_computed == C_expected
```

So:

```
P ^ KS = C_expected
=> P = C_expected ^ KS
```

BUT `KS` depends on `K`, and `K == P[:8]`. So we must find a key `K` such that when we RC4-initialize with `K` and produce `KS` for full length, the computed `P = C_expected ^ KS` satisfies `P[:8] == K`. That is the **self-consistency condition**:

```
Let P(K) = C_expected ^ RC4_keystream(key=K).
If P(K)[:8] == K, then P(K) is a valid solution (flag).
```

So reversing reduces to: find an 8-byte `K` with that property. Typical heuristics:

* Try `K = b"picoCTF{"` (common CTF prefix; exactly 8 bytes).
* Or brute-force `K` over a constrained charset (printable ASCII), checking the self-consistency condition.

##### How to get `c_expected`
`C_expected` is the bytes at VA `0x10210` up to `0x10243` inclusive (length `0x10244 - 0x10210 = 0x34 = 52` bytes). You must extract them from the binary file (not from the C snippet). Reliable method is to map VA → file offset using program headers (ELF) and then read 52 bytes.

##### Decoding Script
Base on the analyze, we have the src code:

> Usage: python3 <file_name>.py ./<binary_file_name>

```python
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
```

Run and get the flag. **The flag is `picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}`**
