#!/usr/bin/env python3
"""
Diablo CTF Solver
Derives the 10-byte XOR key using a known-plaintext attack against "BITSCTF{"
then verifies by running the binary.
"""
import subprocess, os

BINARY = "./challenge"

def get_output(key_bytes: bytes) -> bytes:
    """Run binary with hex-encoded key; return flag bytes after the sentinel line."""
    hex_str = key_bytes.hex()
    fname = "/tmp/final_lic.txt"
    with open(fname, "w") as f:
        f.write(f"LICENSE-{hex_str}\n")
    env = os.environ.copy()
    env["PRINT_FLAG_CHAR"] = "1"
    r = subprocess.run([BINARY, fname], capture_output=True, timeout=10, env=env)
    marker = b"The flag lies here somewhere...\n"
    idx = r.stdout.find(marker)
    if idx >= 0:
        return r.stdout[idx + len(marker):].rstrip()
    return b""

# Step 1: Get the 46 encrypted bytes (XOR with all-zero key = identity)
enc = get_output(bytes(10))
print(f"[*] Encrypted bytes ({len(enc)}): {enc.hex()}")

# Step 2: Known-plaintext attack with flag prefix "BITSCTF{"
prefix = b"BITSCTF{"
key = [enc[i] ^ prefix[i] for i in range(8)]
# key[0..7] = [0x99, 0xF5, 0x67, 0x11, 0x24, 0xD5, 0x20, 0xD5]

# Step 3: Partial decrypt to find key[8] and key[9]
partial = []
for i in range(len(enc)):
    idx = i % 10
    if idx < 8:
        partial.append(chr(enc[i] ^ key[idx]))
    else:
        partial.append('?')
print(f"[*] Partial flag: {''.join(partial)}")
# → BITSCTF{??y3r_by_l??3r_y0u_u??4v3l_my_??cr375}

# Step 4: Infer key[8] and key[9] from leetspeak context
# pos 8 = 'l' (from "l4y3r"),  pos 9 = '4' (from "l4y3r")
key.append(enc[8] ^ ord('l'))   # key[8] = 0x9A ^ 0x6C = 0xF6
key.append(enc[9] ^ ord('4'))   # key[9] = 0x08 ^ 0x34 = 0x3C

# Step 5: Full decryption
flag = ''.join(chr(enc[i] ^ key[i % 10]) for i in range(len(enc)))
print(f"\n[+] KEY:  {bytes(key).hex()}")
print(f"[+] FLAG: {flag}")

# Step 6: Verify by running the binary with the real key
out = get_output(bytes(key))
print(f"\n[+] Binary verification: {out.decode(errors='replace')}")

# Expected output:
# [+] KEY:  99f5671124d520d5f63c
# [+] FLAG: BITSCTF{l4y3r_by_l4y3r_y0u_unr4v3l_my_53cr375}