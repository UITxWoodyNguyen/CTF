# 14Tiles — CTF Writeup

**Category:** Reverse Engineering  
**Flag:** `DH{2f740826751e7afd:MKUb2OLLdZiQ4Lp2vz5ZpQ==}`

---

## Overview

**14Tiles** is a reverse-engineering challenge that hides a server-side **Mahjong hand-completion puzzle** inside an ELF64 binary. The player must connect to a remote server, observe a randomised 13-tile hand displayed each round, and correctly identify which tile(s) (numbered 0–7) would complete a winning Mahjong hand — or answer `"None"` if no such tile exists. This must be done correctly **100 times in a row** within a 100-second timeout to receive the flag.

---

## Binary Information

| Field | Value |
|---|---|
| Format | ELF64, x86-64 PIE shared object |
| Compiler | GNU C++ |
| SHA-256 | `39F466149721C0C06F8BBFE62643EE01473085715F56FF519DFC68236C7145B0` |
| Interpreter | `/lib64/ld-linux-x86-64.so.2` |

**Imported C library functions:**
`free`, `malloc`, `puts`, `fopen`, `fread`, `fclose`, `fseek`, `ftell`, `open`, `read`, `signal`, `alarm`, `scanf`, `strncmp`, `exit`, `setvbuf`, `__printf_chk`, `__stack_chk_fail`

---

## Static Analysis

### `main` — Entry Point (line 532)

```asm
; int main(int, char **, char **)
main proc near
    endbr64
    push    rbx
    xor     eax, eax
    mov     ebx, 64h        ; ebx = 100 (loop counter)
    call    sub_1570         ; setup: setvbuf, /dev/urandom, alarm, signal
    nop     dword ptr [rax+00000000h]

loc_1298:                   ; repeat up to 100 times
    xor     eax, eax
    call    sub_1740         ; play one round; returns 1=win, 0=lose
    test    eax, eax
    jz      short loc_12B3   ; if lose: print "Failed :(" and exit
    sub     ebx, 1
    jnz     short loc_1298   ; still rounds left? loop again
    xor     eax, eax
    call    sub_1600         ; all 100 rounds won → print flag
    xor     eax, eax
    pop     rbx
    retn

loc_12B3:
    lea     rdi, s          ; "Failed :("
    call    _puts
    mov     edi, 1
    call    _exit
main endp
```

**Key insight:** The game runs 100 rounds. Win all of them → `sub_1600` reads and prints `./flag`.

---

### `sub_1570` — Initialisation (line 893)

```asm
sub_1570 proc near
    endbr64
    sub     rsp, 8
    ; Set stdin and stdout to fully unbuffered
    mov     rdi, cs:stdin
    xor     ecx, ecx        ; n = 0
    xor     esi, esi        ; buf = NULL
    mov     edx, 2          ; _IONBF
    call    _setvbuf
    mov     rdi, cs:stdout
    xor     ecx, ecx
    xor     esi, esi
    mov     edx, 2
    call    _setvbuf
    ; Open /dev/urandom for randomness
    xor     esi, esi        ; O_RDONLY
    lea     rdi, file       ; "/dev/urandom"
    xor     eax, eax
    call    _open
    mov     cs:fd, eax      ; save fd globally
    cmp     eax, 0FFFFFFFFh
    jz      short loc_15DC  ; on error → fatal
    ; Register SIGALRM handler
    mov     edi, 0Eh        ; SIGALRM (14)
    lea     rsi, handler
    call    _signal
    ; Set 100-second timeout
    mov     edi, 64h        ; 100 seconds
    add     rsp, 8
    jmp     _alarm
sub_1570 endp
```

---

### `handler` — Timeout Handler (line 688)

```asm
handler proc near
    endbr64
    push    rax
    pop     rax
    lea     rdi, aTimeout   ; "Timeout!!!"
    sub     rsp, 8
    call    _puts
    xor     edi, edi
    call    _exit
handler endp
```

If 100 seconds elapse, the server kills the connection.

---

### `sub_1600` — Flag Reader (line 936)

```asm
sub_1600 proc near
    endbr64
    push    r12
    lea     rsi, modes      ; "r"
    lea     rdi, filename   ; "./flag"
    push    rbp
    push    rbx
    call    _fopen
    test    rax, rax
    jz      short loc_168D  ; open failed → fatal
    ; fseek to end to get file size
    mov     edx, 2          ; SEEK_END
    xor     esi, esi
    mov     rbp, rax        ; save FILE*
    mov     rdi, rax
    call    _fseek
    mov     rdi, rbp
    call    _ftell          ; rax = file size
    mov     rdi, rax
    mov     rbx, rax        ; save size
    call    _malloc         ; allocate buffer
    mov     r12, rax
    test    rax, rax
    jz      short loc_168D  ; malloc failed → fatal
    ; rewind and read entire file
    xor     edx, edx        ; SEEK_SET
    xor     esi, esi
    mov     rdi, rbp
    call    _fseek
    mov     rcx, rbp        ; stream
    mov     rdx, rbx        ; n bytes
    mov     esi, 1          ; size=1
    mov     rdi, r12        ; dst buffer
    call    _fread
    cmp     rbx, rax
    jnz     short loc_168D  ; short read → fatal
    ; Print and cleanup
    mov     rdi, r12
    call    _puts
    mov     rdi, r12
    call    _free
    pop     rbx
    mov     rdi, rbp
    pop     rbp
    pop     r12
    jmp     _fclose
sub_1600 endp
```

---

### `sub_1740` — Game Round (line 1055) ← **Core Challenge**

This is the main puzzle function. It performs three phases:

#### Phase 1: Initialize Tile Array

```asm
; Initialize arr[32] where arr[i] = i/4 (4 copies of each tile 0-7)
; Using 32-bit imul trick: i * 0x01010101 fills all 4 bytes with the same value
lea     r13, [rsp+0C8h+var_68]  ; r13 = start of 32-byte tile array
...
loc_1788:
    movzx   edx, al              ; al = index (0-7)
    add     rax, 1
    add     rcx, 4               ; advance by dword
    imul    edx, 1010101h        ; replicate byte: e.g., 3 → 0x03030303
    mov     [rcx-4], edx         ; store 4 identical bytes
    cmp     rax, 8
    jnz     short loc_1788
```

Result: `arr = [0,0,0,0, 1,1,1,1, 2,2,2,2, 3,3,3,3, 4,4,4,4, 5,5,5,5, 6,6,6,6, 7,7,7,7]` (32 bytes)

#### Phase 2: Fisher-Yates Shuffle via `/dev/urandom`

```asm
; For each index rbx = 0 to 31:
loc_17B0:
    ; Read 1 random byte from /dev/urandom
    mov     edi, cs:fd
    mov     edx, 1
    mov     rsi, r12            ; buf
    call    _read
    cmp     rax, 1
    jnz     loc_19B9            ; fatal on error

    movzx   eax, [rsp+0C8h+buf] ; eax = random byte
    mov     ecx, r14d           ; ecx = 32
    sub     ecx, ebx            ; ecx = 32 - current_index
    cdq
    idiv    ecx                 ; edx = random_byte % (32 - index)
    cmp     dl, bl              ; if remainder == index: no swap (identity)
    jz      short loc_17F8
    movsxd  rdx, edx
    ; swap arr[rbx] with arr[edx]
    movzx   eax, byte ptr [rbx+r13]
    movzx   ecx, byte ptr [rsp+rdx+0C8h+var_68]
    mov     [rbx+r13], cl
    mov     byte ptr [rsp+rdx+0C8h+var_68], al

loc_17F8:
    add     rbx, 1
    cmp     rbx, 20h
    jnz     short loc_17B0
```

This is a standard Fisher-Yates shuffle producing a uniformly random permutation of the 32 tiles.

#### Phase 3: Count First 13 Tiles

```asm
; count[tile]++ for each of the first 13 tiles in the shuffled array
lea     rdx, [r13+0Dh]   ; end pointer = arr + 13
...
loc_1818:
    movzx   eax, byte ptr [rbp+0]         ; eax = tile value (0-7)
    add     rbp, 1
    add     dword ptr [rsp+rax*4+0C8h+var_A8], 1  ; count[tile]++
    cmp     rbp, rdx
    jnz     short loc_1818
```

This produces `count[0..7]` — the 13-tile hand histogram.

#### Phase 4: Display Hand

```asm
lea     rdi, aTiles         ; "------ [Tiles] ------"
call    _puts
lea     rsi, asc_203B       ; "   "
mov     edi, 1
call    ___printf_chk       ; print leading spaces (no newline)

; For each tile i = 0..7:
;   for j = 0..count[i]-1:
;     printf("%d", i)

lea     rdi, asc_2042       ; "   \n---------------------"
call    _puts
lea     rdi, aYourAnswer    ; "Your answer?"
call    _puts
```

**Output format example** for counts `[2,3,1,3,2,0,1,1]` (total=13):
```
------ [Tiles] ------
   001112333440026   
---------------------
Your answer?
```

Each digit in the line is the tile type; its count is how many times it appears.

#### Phase 5: Read and Validate Answer

```asm
; Read up to 11 chars
lea     rdi, a11s           ; "%11s"
mov     rsi, rbx            ; buffer (s1)
call    ___isoc99_scanf

; Check for "None" sentinel
mov     edx, 4
lea     rsi, s2             ; "None"
mov     rdi, rbx
call    _strncmp
test    eax, eax
jz      short loc_192C      ; if "None", skip digit parsing

; Parse each character as a tile digit 0-7
loc_1910:
    movzx   eax, byte ptr [rdx]
    sub     eax, 30h            ; eax = digit - '0'
    cmp     al, 7
    ja      short loc_192C      ; > 7: invalid, skip
    movsx   rax, al
    add     rdx, 1
    or      byte ptr [rsp+rax+0C8h+var_7C], 1  ; visited[digit] = 1
    cmp     r13, rdx
    jnz     short loc_1910
```

`visited[0..7]` is a bitmask of which tiles the user claims complete the hand.

#### Phase 6: Verify Each Tile Against the Solver

```asm
; For each tile i = 0..7:
loc_193A:
    mov     eax, [rax]          ; eax = count[i]
    cmp     eax, 4
    jnz     short loc_1978      ; if count[i] != 4, run solver check
    cmp     byte ptr [r8], 0    ; if visited[i] == 0 (user didn't claim this tile)
    jz      short loc_19A0      ; and count==4: OK (can't draw a 5th), continue

loc_194B:
    xor     eax, eax            ; FAIL
    ...

loc_1978:
    ; count[i] != 4: temporarily add 1 and test
    add     eax, 1              ; count[i] + 1
    mov     [rbx], eax
    mov     rdi, [rsp+0C8h+var_C0]  ; tile count array
    mov     edx, 1                   ; pairs = 1
    mov     esi, 4                   ; melds = 4
    call    sub_13E0                 ; returns 1 if winning, 0 if not
    movzx   edx, byte ptr [r8]       ; edx = visited[i]
    cmp     edx, eax                 ; visited[i] must equal solver result
    jnz     short loc_194B           ; mismatch → FAIL
    sub     dword ptr [rbx], 1       ; restore count[i]
```

**The check is strict:** for every tile i (where count[i] < 4), the user's answer must **exactly match** what the solver returns. If the user claims tile `i` completes the hand but it doesn't (or vice versa), the round fails.

---

### `sub_13E0` — Recursive Mahjong Solver (line 707)

This is the heart of the challenge — a backtracking solver checking if `n` melds + `m` pairs can be formed from the tile counts.

**Signature:** `sub_13E0(count_array*, n_melds, n_pairs)`

#### Try Triplets (Pungs)

```asm
; For each tile i with count[i] >= 3:
loc_1435:
    mov     eax, [rbx]              ; count[i]
    cmp     eax, 2
    jle     short loc_1428          ; count <= 2: skip
    mov     ecx, r15d               ; ecx = n-1
    lea     edx, [rax-3]            ; count-3
    or      ecx, ebp                ; (n-1) | m
    mov     [rbx], edx              ; count[i] -= 3
    jnz     short loc_1410          ; if not last meld+pair, recurse

    ; Base case: this was the last meld, no pairs needed → WIN
    ; (n-1 == 0 and m == 0)
    jmp     short loc_1448          ; restore and return 1

loc_1410:
    mov     edx, ebp                ; m
    mov     esi, r15d               ; n-1
    mov     rdi, r12
    call    sub_13E0                ; recurse
    add     dword ptr [rbx], 3      ; restore count
    test    eax, eax
    jnz     loc_155A                ; if child won → propagate win
```

#### Try Sequences (Chows)

```asm
; After exhausting triplets, try 3-consecutive sequences
; For i = 1 to 6, try removing (arr[i-1], arr[i], arr[i+1]):
loc_14E0:
    mov     edx, [rbx]              ; count[i]
    test    edx, edx
    jz      short loc_1540          ; count[i]==0: can't form sequence
    mov     ecx, [rbx+4]            ; count[i+1]
    lea     r14, [rbx+4]
    test    ecx, ecx
    jz      short loc_1529          ; count[i+1]==0: can't form sequence
    ; All three tiles present: remove one of each
    sub     eax, 1                  ; count[i-1]--
    sub     edx, 1                  ; count[i]--
    sub     ecx, 1                  ; count[i+1]--
    mov     [rbx-4], eax
    mov     [rbx], edx
    mov     [rbx+4], ecx
    ; Check base case: last meld, no pairs
    mov     eax, ebp
    or      eax, esi                ; m | (n-1)
    jz      short loc_1550          ; → WIN
    ; Recurse
    call    sub_13E0
    ; Backtrack: restore all three counts
    add     dword ptr [rdi], 1
    add     dword ptr [rbx], 1
    add     dword ptr [r14], 1
```

#### Try Pairs

```asm
; When n == 0 (no melds left), try removing m pairs
loc_1460:
    test    ebp, ebp                ; m == 0?
    jz      short loc_14B0          ; no pairs needed and we're done → FAIL
                                    ; (success was already returned above)
    ; sub ebp, 1 → m-1
    ; For each tile with count >= 2:
loc_1499:
    mov     eax, [rbx]
    cmp     eax, 1
    jle     short loc_1490          ; count <= 1: skip
    lea     edx, [rax-2]            ; count-2
    or      ecx, ebp                ; n_orig | (m-1)
    mov     [rbx], edx
    jnz     short loc_1478          ; not last → recurse
    jmp     short loc_1448          ; last pair removed → WIN
```

---

## Winning Mahjong Hand Definition

A standard winning Mahjong hand of 14 tiles consists of:
- **4 melds** — each is either:
  - A **pung/triplet**: 3 identical tiles (e.g., `[3,3,3]`)
  - A **chow/sequence**: 3 consecutive tile types (e.g., `[2,3,4]`)
- **1 pair**: 2 identical tiles

Since tile types are 0–7 (8 types), sequences like `(5,6,7)` are valid.

---

## Exploit Strategy

For each of the 8 tile types (0–7):
1. If `count[i] >= 4`: skip (can't draw a 5th tile)
2. Temporarily do `count[i] += 1`
3. Run `is_winning(count)` via our Python re-implementation of `sub_13E0`
4. If True: add digit `i` to the answer string
5. Restore `count[i]`

If no tile works, answer `"None"`.

---

## Solver Script

```python
#!/usr/bin/env python3
from pwn import *


def _solve(counts, melds, pairs):
    """Recursive Mahjong validator matching sub_13E0 in main.asm."""
    if melds == 0 and pairs == 0:
        return True

    if melds > 0:
        # Try removing a triplet (pung)
        for i in range(8):
            if counts[i] >= 3:
                counts[i] -= 3
                if _solve(counts, melds - 1, pairs):
                    counts[i] += 3
                    return True
                counts[i] += 3

        # Try removing a sequence (chow): tiles i, i+1, i+2
        for i in range(6):
            if counts[i] > 0 and counts[i+1] > 0 and counts[i+2] > 0:
                counts[i] -= 1; counts[i+1] -= 1; counts[i+2] -= 1
                if _solve(counts, melds - 1, pairs):
                    counts[i] += 1; counts[i+1] += 1; counts[i+2] += 1
                    return True
                counts[i] += 1; counts[i+1] += 1; counts[i+2] += 1

        return False

    # melds == 0: try removing pairs
    for i in range(8):
        if counts[i] >= 2:
            counts[i] -= 2
            if _solve(counts, 0, pairs - 1):
                counts[i] += 2
                return True
            counts[i] += 2

    return False


def is_winning(counts):
    return _solve(list(counts), 4, 1)


def solve_hand(counts):
    """Return the string of completing tile digits, or 'None'."""
    answers = []
    for tile in range(8):
        if counts[tile] >= 4:
            continue
        counts[tile] += 1
        if is_winning(counts):
            answers.append(str(tile))
        counts[tile] -= 1
    return ''.join(answers) if answers else 'None'


def parse_tiles(data):
    """Extract the 13-tile histogram from one round's output."""
    counts = [0] * 8
    in_tiles = False
    for line in data.split('\n'):
        if '[Tiles]' in line:
            in_tiles = True
            continue
        if in_tiles and '---' in line:
            break
        if in_tiles:
            for ch in line:
                if ch.isdigit() and int(ch) < 8:
                    counts[int(ch)] += 1
    return counts


r = remote('host3.dreamhack.games', 18933)

for round_num in range(1, 101):
    data = r.recvuntil(b'Your answer?\n').decode(errors='replace')
    counts = parse_tiles(data)
    answer = solve_hand(counts)
    log.info(f"Round {round_num:3d}: counts={counts} -> {answer}")
    r.sendline(answer.encode())

r.interactive()
```

---

## Sample Run

```
[+] Opening connection to host3.dreamhack.games on port 18933: Done
[*] Round   1: counts=[2, 2, 2, 0, 2, 1, 2, 2] -> 5
[*] Round   2: counts=[3, 2, 2, 1, 0, 2, 1, 2] -> 6
[*] Round   3: counts=[1, 2, 2, 1, 1, 1, 3, 2] -> 0367
...
[*] Round 100: counts=[1, 1, 1, 2, 0, 4, 2, 2] -> 3
[*] Switching to interactive mode
DH{2f740826751e7afd:MKUb2OLLdZiQ4Lp2vz5ZpQ==}
```

---

## Flag

```
DH{2f740826751e7afd:MKUb2OLLdZiQ4Lp2vz5ZpQ==}
```
