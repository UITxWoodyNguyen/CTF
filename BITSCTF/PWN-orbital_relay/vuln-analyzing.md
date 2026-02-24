# Orbital Relay — Vulnerability Analysis

## Vulnerability Class

**Arbitrary Write → Encrypted Function Pointer Overwrite (CWE-123 / CWE-787)**

Combined with an **unauthenticated format-string info leak** via a controlled format buffer.

---

## Root Cause

The `handle_diag` function (Chan 1) parses a TLV stream from the attacker. One of its opcodes, **tag `0x31`**, performs a blind, unchecked 8-byte write to the global `cb_enc`:

```c
// Pseudo-C reconstruction — handle_diag, opcode 0x31
if (tag == 0x31 && size == 8) {
    cb_enc = *(uint64_t *)(payload + value_offset);  // NO validation
}
```

Assembly evidence (`orbital.asm`, `0x19B0–0x19C7`):

```asm
.text:00000000000019B0   cmp  al, 31h        ; tag == 0x31?
.text:00000000000019B2   jnz  short loc_19D0
.text:00000000000019B4   cmp  bl, 8          ; size == 8?
.text:00000000000019B7   jnz  short loc_19D0
.text:00000000000019BC   mov  rax, [r12+rax] ; read 8 bytes from attacker payload
.text:00000000000019C0   mov  cs:cb_enc, rax ; ← overwrite cb_enc, no checks at all
```

`cb_enc` is the XOR-obfuscated function pointer that Chan 9 later decodes and calls:

```asm
; Chan 9 trigger (main, 0x1452–0x145E)
.text:0000000000001452   mov rdi, cs:cb_enc
.text:0000000000001459   call enc_cb          ; enc_cb(cb_enc) → plaintext address
.text:000000000000145E   call rax             ; indirect call → attacker-controlled
```

---

## The Obfuscation Scheme (`enc_cb`)

The binary stores callback pointers XOR-encrypted:

```
enc_cb(x) = (dword_40E0 << 32) ^ x ^ session_state_low32 ^ 0x9E3779B97F4A7C15
```

Because this is a **pure XOR** operation, it is self-inverse:

```
enc_cb(enc_cb(x)) == x
```

So to make Chan 9 jump to `win`, we just need to store `enc_cb(win_addr)` into `cb_enc`.

---

## Info Leak: How to Get `win_addr` and the XOR Key

A second TLV opcode enables the leak:

| Tag | What it does |
|-----|-------------|
| `0x10` | Stream-decrypts N bytes from the payload and **writes the result into the global buffer `st`** |
| `0x40` | Calls `__printf_chk(2, st, dword_40E0, &st, keep_win)` — **`st` is the format string** |

Attacker flow:
1. Send tag `0x10` with an encrypted `%x.%p.%p.` → server writes the format string into `st`.
2. Send tag `0x40` with empty value → server calls `printf(st, ...)`.
3. `printf` leaks: `dword_40E0` (the XOR key word) and `keep_win` (the `win` address loaded via `r8`).

```asm
; handle_diag, tag 0x40 (0x19D0–0x1A10)
.text:00000000000019FF   mov  edx, cs:dword_40E0   ; arg3 = key word
.text:0000000000001A09   mov  r8, cs:keep_win      ; arg5 = win pointer ← LEAKED
.text:0000000000001A10   call ___printf_chk         ; uses st as format string
```

---

## Attack Chain at a Glance

```
[Auth chan 3]          Unlock permission flags (byte4=1, byte5=1)
      │
[Tag 0x22]            Set byte4 = 7  (required by Chan 9 guard)
      │
[Tag 0x10]            Plant format string "%x.%p.%p." into st
      │
[Tag 0x40]  ────────► printf leaks: dword_40E0, win_addr
      │
[Compute]             target_cb = enc_cb(win_addr)
      │
[Tag 0x31]  ────────► cb_enc = target_cb          ← VULN TRIGGERED
      │
[Chan 9]    ────────► enc_cb(target_cb) == win_addr → call win() → flag
```

---

## Impact

| Property  | Value |
|-----------|-------|
| **Primitive** | Arbitrary 8-byte write to a function pointer |
| **Required auth** | Session auth only (Chan 3 — token is computable from public constants) |
| **Mitigation bypassed** | PIE (bypassed via printf leak), pointer obfuscation (XOR is self-inverse) |
| **Result** | Full control of `RIP` → arbitrary code execution |

---

## Fix Recommendations

1. **Remove tag `0x31`** entirely, or restrict it to trusted sessions only.
2. **Validate the written value** against a whitelist of known-good encrypted pointers.
3. **Avoid using `st` directly as a `printf` format string** — use `printf("%s", st)` instead to prevent the format-string leak.
4. **Use a non-trivial MAC for the callback** so that even if `cb_enc` is overwritten, the server verifies integrity before calling it.
