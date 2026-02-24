#!/usr/bin/env python3
"""Interactive probe - just connect and watch what happens with long timeout."""
from pwn import *

context.log_level = 'debug'

io = remote('20.193.149.152', 1339, timeout=30)

# Wait up to 30 seconds for ANY data from server
log.info("Connected. Waiting up to 30s for server data...")
try:
    data = io.recv(4096, timeout=30)
    log.info(f"Received: {data}")
except EOFError:
    log.info("Server closed connection (EOF)")
except Exception as e:
    log.info(f"Timeout or error: {e}")

# Now try sending and see
log.info("Sending handshake...")
try:
    io.send(b'SYNCv3?')
    data = io.recv(4096, timeout=10)
    log.info(f"Response: {data}")
except Exception as e:
    log.info(f"After send: {e}")

io.close()
