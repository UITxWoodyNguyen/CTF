# CTF Writeup: Nanomites & The Rolling Hash

**Category:** Reverse Engineering  
**Technique:** Debug-Blocker (Nanomites), Modular Arithmetic Inverse  
**Difficulty:** Medium

## 1. Challenge Overview

We are given a binary that splits into two processes. The child process takes input and calculates a hash, but it contains "illegal" instructions that crash the program. The parent process acts as a debugger, catching these crashes, verifying the state, and allowing the child to continue only if the input is correct.

This technique is often called **"Nanomites"**—where the parent process handles exception handling to obfuscate control flow or data verification.

---

## 2. Static Analysis

### The Entry Point (`main`)
The program starts by forking itself.

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3) {
  __pid_t pid = fork();
  if ( !pid )
    sub_131B();      // The Child (Worker)
  sub_14AD(pid);     // The Parent (Debugger/Tracer)
  return 0LL;
}
```
*   **Child (pid == 0):** Runs the actual logic (`sub_131B`).
*   **Parent (pid > 0):** Runs `sub_14AD`, taking the child's PID. This suggests the parent will trace the child.

### The Child Process (`sub_131B`)
Let's analyze the child's behavior step-by-step.

**1. Anti-Debugging / Tracer Check**
```asm
mov     edi, 0          ; request = PTRACE_TRACEME
call    _ptrace
test    rax, rax
jns     short loc_1367
call    _exit           ; Exit if ptrace fails
```
The child calls `ptrace(PTRACE_TRACEME, ...)`.
*   If a debugger (like GDB) is already attached, this fails.
*   If the **Parent** process attaches to it successfully, this passes.
*   This confirms the Parent is debugging the Child.

**2. Input Handling**
The child reads input, removes the newline, and checks the length.
```asm
call    _strlen
cmp     rax, 28h        ; 0x28 = 40 decimal
jz      short loc_1421
```
We know the flag is exactly **40 characters** long.

**3. The Calculation Loop & The `ud2` Trap**
This is the core of the protection mechanism.

```c
// Decompiled Logic
uint64_t seed = 0xCBF29CE484222325; // Initial Seed
for (int i = 0; i < 40; i++) {
    // 1. Update the seed based on the current input char
    seed = sub_12A9(input_string, 1, seed);
    
    // 2. The Trap
    ud2(); 
}
```

**What is `ud2`?**
In x86 assembly, `ud2` stands for **Undefined Instruction**. Executing it raises a `SIGILL` (Illegal Instruction) signal.
*   Normally, this crashes the program.
*   Here, the **Parent** (acting as a debugger) catches the signal.
*   The Parent inspects the Child's registers (specifically the new `seed` value returned by `sub_12A9`).
*   The Parent compares the calculated `seed` against a hardcoded list of "correct" hashes.
*   If it matches, the Parent advances the instruction pointer (RIP) past the `ud2` and resumes the child. If not, it terminates the child.

---

## 3. Reversing the Hash (`sub_12A9`)

To solve the challenge, we don't need to analyze the Parent (`sub_14AD`). We just need to understand how the hash is calculated and reverse it using the expected values the Parent expects.

Let's look at the hashing function `sub_12A9`.

```c
unsigned __int64 __fastcall sub_12A9(__int64 input_ptr, unsigned __int64 len, unsigned __int64 current_seed)
{
  unsigned __int64 v5;
  // ... loop ...
    // The Math:
    v5 = 0x100000001B3LL * (*(unsigned __int8 *)input_char ^ current_seed);
    current_seed = HIDWORD(v5) ^ v5;
  // ...
  return current_seed;
}
```

We can break this down into a math formula. Let $S_{old}$ be the current seed, $C$ be the input character, and $S_{new}$ be the result.

1.  **Mixing:**
    $$V = (C \oplus S_{old}) \times 0\text{x}100000001B3 \pmod{2^{64}}$$
2.  **Scrambling:**
    $$S_{new} = (V \gg 32) \oplus V$$

---

## 4. The Solution Strategy

We have a list of expected $S_{new}$ values (extracted from the binary's `.rodata` section, presumably found by looking at what the Parent process reads). We need to work backward to find $C$.

### Step A: Unscramble $V$ from $S_{new}$
The operation is: `S_new = High(V) ^ V`.
Since $V$ is 64-bit, let's split it into High (32-bit) and Low (32-bit) parts.
*   $V = (H \ll 32) | L$
*   $S_{new} = H \oplus ((H \ll 32) | L)$

This bitwise logic is slightly distinct in C. `HIDWORD(v5)` gets the top 32 bits.
So, effectively:
*   $S_{new\_high} = H$ (The XOR doesn't affect the top 32 bits because `HIDWORD(V)` is effectively `0000...H`)
*   $S_{new\_low} = H \oplus L$

**Recovery:**
1.  $H = S_{new\_high}$
2.  $L = S_{new\_low} \oplus H$
3.  $V = (H \ll 32) | L$

### Step B: Reverse the Multiplication
We have:
$$V = X \times M \pmod{2^{64}}$$
Where $M = 0\text{x}100000001B3$.
To find $X$, we need the **Modular Multiplicative Inverse** of $M$.
$$X = V \times M^{-1} \pmod{2^{64}}$$

In Python, we can calculate this using `pow(M, -1, 2**64)`.

### Step C: Recover the Character
We have:
$$X = C \oplus S_{old}$$
Therefore:
$$C = X \oplus S_{old}$$

---

## 5. The Solution Script

Here is the complete Python script that implements the logic above.

```python
import struct

# --- 1. Data Extraction ---
# These bytes were extracted from the binary (.rodata section).
# They represent the expected state of the 'seed' register at every 'ud2' exception.
hex_data = """
E3 31 62 29 4C AD 63 AF 0B 59 4B 39 6A 13 91 68
48 9E D5 A2 7F 6A DD F9 46 D2 21 D8 E1 33 DA 68
3A 49 E0 0D C2 50 98 4C CE 03 06 93 BD 7A 1A 07
E1 1D 3A CB 20 4B 02 18 44 0E C3 55 B9 37 03 06
2E C0 F4 40 EC E5 85 FA 35 BC A7 F9 72 CD 45 A6
E2 6C 5D 08 5E 6E 58 30 7A 68 0F B5 C8 0F B0 83
EA 08 BF 7A 0B ED 92 D3 99 2D 2A D3 81 52 B1 41
D6 30 D1 1A 99 27 7D CA 37 3B AD 72 28 2E DB E3
02 27 F1 06 BA D6 AA DA CA D6 B7 4A 19 3F 72 81
37 7B 9A 5A F9 31 F8 AC BD B3 47 70 B4 3D 38 84
D0 7D 92 3A 9A 67 44 F3 EC C3 52 69 11 9A B9 EF
6A 6A 86 5C 95 50 24 AB B7 4E 79 6D CC 06 1F 55
66 61 26 18 5E 75 07 1D 4C 75 3B 73 E3 83 0D 7A
B1 3C 64 6E 7C 9A 6C A0 B9 0B 94 68 6F 53 C7 FC
EA 99 2E A9 4E 92 BE 1A E1 CE 42 DA A9 33 6C A0
4B F5 2F 05 9D 9B AA DA 33 0F A6 6F CF 7F DB BF
8A 79 25 1F 7A 7D 09 A8 8C 27 34 41 82 F0 99 AD
6C 5A 24 FB 54 95 BB 30 0B 91 DC 4D 66 1E 19 F3
6A 0A F5 BD D6 FB 3F F0 12 4D A3 F6 E4 1F C3 31
2D E1 A0 26 0F 88 DC 31 4E 5B C2 F9 BE 81 9C 5A
"""

# Convert hex string to a list of 64-bit integers (Little Endian)
byte_stream = bytes.fromhex(hex_data.replace('\n', ' '))
expected_values = []
for i in range(0, len(byte_stream), 8):
    val = struct.unpack('<Q', byte_stream[i:i+8])[0]
    expected_values.append(val)

# --- 2. Constants ---
INITIAL_SEED = 0xCBF29CE484222325
MULTIPLIER = 0x100000001B3
MODULO = 2**64

# --- 3. Precompute Modular Inverse ---
# We need X such that: (MULTIPLIER * X) % MODULO == 1
# This allows us to divide by MULTIPLIER in modular arithmetic.
MULTIPLIER_INV = pow(MULTIPLIER, -1, MODULO)

# --- 4. The Solver Loop ---
current_seed = INITIAL_SEED
flag = ""

print(f"[*] Starting decryption with seed: {hex(current_seed)}")

for target_hash in expected_values:
    # --- Reverse Step A: Unscramble the XOR ---
    # Original: target_hash = HIDWORD(v5) ^ v5
    # High 32 bits of target_hash are just High 32 bits of v5 (clean)
    # Low 32 bits of target_hash are (High_v5 ^ Low_v5)
    
    high = target_hash >> 32
    low_encoded = target_hash & 0xFFFFFFFF
    
    # Recover low part of v5
    low_decoded = low_encoded ^ high
    
    # Reconstruct full v5
    v5 = (high << 32) | low_decoded
    
    # --- Reverse Step B: Reverse the Multiplication ---
    # Original: v5 = (X * MULTIPLIER) % MODULO
    # Reverse:  X  = (v5 * MULTIPLIER_INV) % MODULO
    # Where X is (char ^ current_seed)
    x = (v5 * MULTIPLIER_INV) % MODULO
    
    # --- Reverse Step C: Recover the Char ---
    # Original: X = char ^ current_seed
    # Reverse:  char = X ^ current_seed
    
    # Since char is a single byte, we mask with 0xFF
    char_code = (x ^ current_seed) & 0xFF
    flag += chr(char_code)
    
    # --- Update state ---
    # For the next iteration, the 'current_seed' is the target_hash we just processed
    current_seed = target_hash

print(f"\n[+] Recovered Flag: {flag}")
```

### Script Output
When we run the script, it prints:

```text
[*] Starting decryption with seed: 0xcbf29ce484222325

[+] Recovered Flag: 0xfun{unr3adabl3_c0d3_is_s3cur3_c0d3_XD}
```

---

## 6. Summary

1.  **Analysis:** The binary uses a Parent process to trace a Child. The Child calculates a rolling hash of the input and executes `ud2` (Illegal Instruction) after every character.
2.  **Mechanic:** The Parent intercepts the crash, verifies the hash against a secret table, and resumes execution.
3.  **Math:** The hash function used a large prime multiplier and XOR mixing.
4.  **Crack:** We extracted the secret table and mathematically inverted the hash function (using modular inverse) to recover the flag character by character.


**Final Flag:** `0xfun{unr3adabl3_c0d3_is_s3cur3_c0d3_XD}`
