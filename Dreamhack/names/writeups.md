# CTF Writeup: names (DreamhackCTF) — Detailed English Version

**Challenge Summary:** Reverse an ELF binary that stores names in a 16-way Trie indexed by a custom 16-bit hash. Exploit the absence of collision handling to retrieve the flag by sending a crafted input that collides with the flag's stored hash.

---

## 1. Understanding the Binary's Flow

### 1.1 Program Entry & Initialization

The `main` function (at `0x1833` in the binary) starts by:

1. **Setting up unbuffered I/O** — calls `sub_19ED` which calls `setvbuf` on `stdin`, `stdout`, and `stderr` with mode `2` (fully unbuffered).
2. **Allocating the Trie root** — allocates the root Trie node using `sub_14B2` with argument `0` (null name pointer):

```asm
; main @ line 1189 in main.asm
mov     edi, 0
call    sub_14B2        ; allocate root trie node (no name)
mov     cs:qword_4050, rax  ; store root pointer globally
```

3. **Loading data from `./data.txt`** — opens the file and calls `sub_176A`:

```asm
; main @ line 1191-1199
lea     rax, modes      ; "r"
mov     rsi, rax
lea     rax, filename   ; "./data.txt"
mov     rdi, rax
call    _fopen
mov     [rbp+stream], rax
mov     rdi, rax
call    sub_176A        ; parse data.txt line by line
```

### 1.2 Parsing `data.txt` — Function `sub_176A`

`sub_176A` reads the file line by line using `fgets` (reading up to `0x100` bytes per line):

```asm
; sub_176A @ line 1141-1147
mov     rdx, [rbp+stream]  ; stream = data.txt file pointer
lea     rax, [rbp+s]
mov     esi, 100h           ; n = 256 bytes
mov     rdi, rax
call    _fgets
test    rax, rax
jnz     loc_1791            ; if success, process the line
```

For each line, it:
1. Strips `\r\n` characters using `strcspn` with the reject string `"\r\n"`:
```asm
; sub_176A @ line 1121-1125
lea     rdx, reject     ; "\r\n"
mov     rsi, rdx
mov     rdi, rax        ; s = current line buffer
call    _strcspn
mov     [rbp+rax+s], 0  ; null-terminate at first \r or \n
```

2. Splits the line on the first space using `strchr`:
```asm
; sub_176A @ line 1127-1133
mov     esi, 20h ; ' '
mov     rdi, rax
call    _strchr
mov     [rbp+var_118], rax  ; pointer to the space char
mov     rax, [rbp+var_118]
mov     byte ptr [rax], 0   ; null-terminate the key part
add     [rbp+var_118], 1    ; advance to the name part
```

3. Calls `sub_153D(key_string, name_pointer)` to hash the key and insert the name into the Trie.

### 1.3 Node Allocation — `sub_14B2`

Each Trie node is a structure of `0xC0` bytes (192 bytes) allocated via `malloc`:
- **Bytes 0x00–0x7F** (16 × 8 bytes): An array of 16 child pointers (`qword ptr [rax+rdx*8]`), one per nibble (0–15).
- **Bytes 0x80–0xBF** (64 bytes): A name buffer, copied from the provided string via `strncpy` with `n=63`. If `src == NULL`, the buffer is `memset` to zero.

```asm
; sub_14B2 @ line 797-822
mov     edi, 0C0h   ; size = 192 bytes
call    _malloc
; ... initialize 16 child pointers to 0 ...
; then either strncpy(rax+0x80, src, 63)
;         or   memset(rax+0x80, 0, 64)
```

### 1.4 Hashing & Trie Insertion — `sub_153D`

`sub_153D(key_string, name_ptr)` is the function that inserts a name into the Trie.

**Step 1: Hash the key string.** It reads the global seed from `cs:word_4010` (value `0xCAFE`), then calls `sub_138A`:

```asm
; sub_153D @ line 865-876
movzx   eax, cs:word_4010   ; load seed 0xCAFE
movzx   ebx, ax
mov     rax, [rbp+s]
mov     rdi, rax
call    _strlen              ; get length of key string
mov     rcx, rax            ; rcx = length
mov     rax, [rbp+s]
mov     edx, ebx            ; edx = seed (0xCAFE)
mov     rsi, rcx            ; rsi = length
mov     rdi, rax            ; rdi = key string
call    sub_138A             ; compute 16-bit hash
mov     [rbp+var_2A], ax     ; store hash in var_2A
```

**Step 2: Walk the Trie using 4 nibbles.** The 16-bit hash is consumed nibble by nibble (LSB first), using bits 3:0 at each level. The loop runs 4 times (depth 4):

```asm
; sub_153D @ line 884-921 (the insertion loop)
loc_1594:
    movzx   eax, [rbp+var_2A]
    and     eax, 0Fh            ; extract lowest nibble
    mov     [rbp+var_24], eax   ; nibble = hash & 0xF
    mov     rax, [rbp+var_20]   ; current node pointer
    mov     edx, [rbp+var_24]
    movsxd  rdx, edx
    mov     rax, [rax+rdx*8]    ; child = node->children[nibble]
    test    rax, rax
    jnz     short loc_15E9      ; if child exists, just descend

    cmp     [rbp+var_28], 3     ; are we at the last level (depth == 3)?
    jnz     short loc_15C9
    ; At the leaf level: create node WITH the name
    mov     rax, [rbp+var_40]   ; name_ptr
    mov     rdi, rax
    call    sub_14B2            ; allocate leaf node with name
    mov     [rbp+var_18], rax
    jmp     short loc_15D7

loc_15C9:
    ; At an intermediate level: create node WITHOUT a name
    mov     edi, 0
    call    sub_14B2            ; allocate interior node (name=NULL)
    mov     [rbp+var_18], rax

loc_15D7:
    ; Link the new node into the parent
    mov     rax, [rbp+var_20]
    mov     edx, [rbp+var_24]
    movsxd  rdx, edx
    mov     rcx, [rbp+var_18]
    mov     [rax+rdx*8], rcx    ; parent->children[nibble] = new_node

loc_15E9:
    ; Descend into the child
    mov     rax, [rbp+var_20]
    mov     edx, [rbp+var_24]
    movsxd  rdx, edx
    mov     rax, [rax+rdx*8]
    mov     [rbp+var_20], rax   ; current = current->children[nibble]
    shr     [rbp+var_2A], 4     ; shift hash right by 4 (next nibble)
    add     [rbp+var_28], 1     ; depth++

loc_1604:
    cmp     [rbp+var_28], 3
    jle     short loc_1594      ; loop while depth <= 3
```

> **Key Insight:** There is **no collision check**. If a different key string produces the same 16-bit hash, `sub_153D` will overwrite the leaf node at the same Trie path. The program never stores or compares the original key string.

---

## 2. The Custom Hash Function — `sub_138A`

`sub_138A(string, length, seed)` computes a 16-bit hash. It is called from both `sub_153D` (insertion) and `sub_1612` (lookup).

### 2.1 Helper - `sub_1349` (16-bit "mix" function)

```asm
; sub_1349 @ lines 642-667
sub_1349 proc near
    push    rbp
    mov     rbp, rsp
    mov     eax, edi           ; eax = input (16-bit word)
    mov     [rbp+var_4], ax
    movzx   eax, [rbp+var_4]
    imul    ax, 1234h          ; v *= 0x1234
    mov     [rbp+var_4], ax
    movzx   eax, [rbp+var_4]
    shl     eax, 5             ; edx = v << 5
    mov     edx, eax
    movzx   eax, [rbp+var_4]
    shr     ax, 0Bh            ; eax = v >> 11
    or      eax, edx           ; rotate-left 5: (v<<5)|(v>>11)
    mov     [rbp+var_4], ax
    movzx   eax, [rbp+var_4]
    imul    ax, 5678h          ; v *= 0x5678
    mov     [rbp+var_4], ax
    movzx   eax, [rbp+var_4]
    pop     rbp
    retn
sub_1349 endp
```

In C:
```c
uint16_t sub_1349(uint16_t a1) {
    uint16_t v = (uint16_t)(a1 * 0x1234);
    v = (uint16_t)((v << 5) | (v >> 11));  // rotate-left by 5
    v = (uint16_t)(v * 0x5678);
    return v;
}
```

### 2.2 Main Hash - `sub_138A`

The function processes the string in **16-bit little-endian chunks**. For each chunk:

```asm
; sub_138A - main processing loop @ lines 705-728
loc_13C8:
    mov     rax, [rbp+var_28]
    movzx   eax, word ptr [rax]  ; load 2 bytes as a 16-bit LE word
    mov     [rbp+var_14], ax     ; store as current chunk
    add     [rbp+var_28], 2      ; advance string pointer by 2
    movzx   eax, [rbp+var_14]
    movzx   eax, ax
    mov     edi, eax
    call    sub_1349             ; mix the 16-bit chunk
    xor     [rbp+var_12], ax     ; h ^= sub_1349(chunk)
    ; --- rotate h left by 7 ---
    movzx   eax, [rbp+var_12]
    shl     eax, 7               ; edx = h << 7
    mov     edx, eax
    movzx   eax, [rbp+var_12]
    shr     ax, 9                ; eax = h >> 9
    or      eax, edx             ; h = (h<<7)|(h>>9)  [rotate-left 7]
    mov     [rbp+var_12], ax
    ; --- multiply by 5 and subtract 0x2153 ---
    movzx   edx, [rbp+var_12]
    mov     eax, edx
    shl     eax, 2               ; eax = h * 4
    add     eax, edx             ; eax = h * 5
    sub     ax, 2153h            ; h = h*5 - 0x2153
    mov     [rbp+var_12], ax
    sub     [rbp+var_10], 1      ; count--
```

After the main loop (handling the remaining odd byte if any), the finalization:

```asm
; sub_138A - finalization @ lines 743-765
loc_1440:
    ; process last byte (or 0 if length is even)
    movzx   eax, [rbp+var_14]
    mov     edi, eax
    call    sub_1349
    xor     [rbp+var_12], ax     ; h ^= sub_1349(last_byte)
    mov     rax, [rbp+var_30]    ; rax = length
    xor     [rbp+var_12], ax     ; h ^= length
    ; --- finalizer ---
    movzx   eax, [rbp+var_12]
    shr     ax, 8
    xor     [rbp+var_12], ax     ; h ^= (h >> 8)
    movzx   eax, [rbp+var_12]
    imul    ax, 0DEADh           ; h *= 0xDEAD
    mov     [rbp+var_12], ax
    movzx   eax, [rbp+var_12]
    shr     ax, 5
    xor     [rbp+var_12], ax     ; h ^= (h >> 5)
    movzx   eax, [rbp+var_12]
    imul    ax, 0DEADh           ; h *= 0xDEAD
    mov     [rbp+var_12], ax
    movzx   eax, [rbp+var_12]
    shr     ax, 8
    xor     [rbp+var_12], ax     ; h ^= (h >> 8)
    movzx   eax, [rbp+var_12]   ; return h (in ax)
```

In C, the full hash function is:
```c
uint16_t sub_138A(const char *s, int len, uint16_t seed) {
    uint16_t h = seed;  // initialized with 0xCAFE

    // Main loop: process 2 bytes at a time (little-endian)
    int count = len / 2;
    int i = 0;
    while (count > 0) {
        uint16_t word = (uint8_t)s[i] | ((uint16_t)(uint8_t)s[i+1] << 8);
        i += 2;
        h ^= sub_1349(word);                // XOR with mixed chunk
        h = (uint16_t)((h << 7) | (h >> 9)); // rotate-left 7
        h = (uint16_t)(h * 5 - 0x2153);    // scale and shift
        count--;
    }

    // Handle odd trailing byte
    uint16_t last_word = 0;
    if (len & 1) {
        last_word = (uint8_t)s[i];
    }
    h ^= sub_1349(last_word);
    h ^= (uint16_t)len;       // XOR with length

    // Finalization avalanche
    h ^= (h >> 8);
    h = (uint16_t)(h * 0xDEAD);
    h ^= (h >> 5);
    h = (uint16_t)(h * 0xDEAD);
    h ^= (h >> 8);

    return h;
}
```

---

## 3. Lookup Flow — `sub_1612`

When the user enters input (that is not `"END"`), `main` calls `sub_1612`:

```asm
; main @ line 1225-1230
lea     rax, [rbp+s1]    ; s1 = user input buffer
mov     rdi, rax
call    sub_1612          ; lookup: returns pointer to name, or 0 if not found
mov     [rbp+var_118], rax
cmp     [rbp+var_118], 0
jz      short loc_1955   ; if null → "Not Found..."
```

`sub_1612` hashes the user input identically (`sub_138A` with seed `0xCAFE`) then walks the Trie the same way as insertion, but only **reads** — it returns `NULL` if any child pointer is 0, or returns `node+0x80` (the name buffer pointer) at depth 4:

```asm
; sub_1612 - the lookup traversal @ lines 974-1001
loc_1665:
    movzx   eax, [rbp+var_22]
    and     eax, 0Fh            ; nibble = hash & 0xF
    mov     [rbp+var_1C], eax
    mov     rax, [rbp+var_18]   ; current node
    mov     edx, [rbp+var_1C]
    movsxd  rdx, edx
    mov     rax, [rax+rdx*8]    ; child = node->children[nibble]
    test    rax, rax
    jnz     short loc_1689      ; if child != NULL, continue
    mov     eax, 0
    jmp     short loc_16B2      ; return NULL (not found)

loc_1689:
    mov     rax, [rbp+var_18]
    ...
    mov     rax, [rax+rcx*8]
    mov     [rbp+var_18], rax   ; descend
    shr     [rbp+var_22], 4     ; next nibble
    add     [rbp+var_20], 1     ; depth++

loc_16A4:
    cmp     [rbp+var_20], 3
    jle     short loc_1665      ; loop 4 times

    ; depth == 4 reached: return pointer to name at offset +0x80
    mov     rax, [rbp+var_18]
    sub     rax, 0FFFFFFFFFFFFFF80h  ; = rax + 0x80
```

---

## 4. Dump Mode — `sub_16B8`

If the user sends `"END"`, `main` opens `dump.txt` for writing and calls `sub_16B8` recursively to walk the entire Trie and write all `[hash] [name]` pairs:

```asm
; main @ line 1256-1267
lea     rax, aW         ; "w"
mov     rsi, rax
lea     rax, aDumpTxt   ; "./dump.txt"
mov     rdi, rax
call    _fopen
...
mov     ecx, 0     ; initial partial_hash = 0
mov     edx, 0     ; initial depth = 0
call    sub_16B8   ; recursive trie dump
```

When `sub_16B8` reaches depth 4, it prints the entry. The 16-bit hash is reconstructed from the path taken through the Trie:

```asm
; sub_16B8 @ lines 1034-1043
cmp     [rbp+var_24], 4   ; if depth == 4: this is a leaf
jnz     short loc_1704
mov     rax, [rbp+var_20]
lea     rcx, [rax+80h]    ; rcx = &node->name
movzx   edx, [rbp+var_28] ; edx = accumulated hash bits
mov     rax, [rbp+stream]
lea     rsi, format       ; "%04hx %s\n"
...
call    _fprintf          ; write "[hash] [name]\n" to dump.txt
```

This is how `dump.txt` was generated. Looking at the file, we find the flag entry:
```
0796 DH{H4SHC0LL1S10N_0N_TH3_D4T4_S7RUCTUR3}
```
This tells us the flag is stored at the Trie node reachable by the hash value `0x0796`.

---

## 5. The Vulnerability: Hash Collision

The critical security flaw is in `sub_1612` vs `sub_153D`: **neither function checks or stores the original key string**. The 16-bit hash space has only 65,536 possible values. Any two distinct strings that produce the same 16-bit hash will land on the **same Trie leaf node**. The program will return the stored name regardless of which input was used.

**Target:** Find any short string whose `sub_138A(s, len, 0xCAFE) == 0x0796`.

---

## 6. Exploit — Brute-Force Hash Collision

The brute-force script ([brute.c](./brute.c)) re-implements the hash functions in C and exhaustively searches alphanumeric 3-character strings:

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

uint16_t sub_1349(uint16_t a1) {
    uint16_t v = (uint16_t)(a1 * 0x1234);
    v = (uint16_t)((uint32_t)(v << 5) | (uint32_t)((v >> 11) & 0x1F));
    v = (uint16_t)(v * 0x5678);
    return v;
}

uint16_t sub_138A(const char *s, int len, uint16_t seed) {
    uint16_t h = seed;
    int count = len / 2;
    int i = 0;
    while (count > 0) {
        uint16_t word = (uint8_t)s[i] | ((uint16_t)(uint8_t)s[i+1] << 8);
        i += 2;
        h ^= sub_1349(word);
        uint32_t edx = (uint32_t)h << 7;
        uint32_t eax = (uint32_t)((h >> 9) & 0x7F);
        h = (uint16_t)(eax | edx);
        uint32_t tmp = (uint32_t)h * 5;
        h = (uint16_t)(tmp - 0x2153);
        count--;
    }
    uint16_t last_word = 0;
    if (len & 1) last_word = (uint8_t)s[i];
    h ^= sub_1349(last_word);
    h ^= (uint16_t)len;
    h ^= (h >> 8);
    h = (uint16_t)(h * 0xDEAD);
    h ^= (h >> 5);
    h = (uint16_t)(h * 0xDEAD);
    h ^= (h >> 8);
    return h;
}

int main() {
    char chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int n = strlen(chars);
    char s[4] = {0};
    for(int i=0; i<n; i++)
        for(int j=0; j<n; j++)
            for(int k=0; k<n; k++) {
                s[0]=chars[i]; s[1]=chars[j]; s[2]=chars[k];
                if (sub_138A(s, 3, 0xCAFE) == 0x0796) {
                    printf("FOUND COLLISION: %s\n", s);
                    return 0;
                }
            }
    printf("Not found\n");
    return 0;
}
```

**Compile and run:**
```bash
gcc brute.c -o brute && ./brute
# Output: FOUND COLLISION: i5w
```

**Verify the collision:**
```
sub_138A("i5w", 3, 0xCAFE) == 0x0796  ✓
```

---

## 7. Getting the Flag

Send the colliding string `i5w` to the remote server:

```bash
echo -e "i5w\nEND" | nc host3.dreamhack.games 15126
```

**Server response:**
```
[Custom Storage v0.1]
> Found: DH{H4SHC0LL1S10N_0N_TH3_D4T4_S7RUCTUR3}
Please wait...
>
```

**Flag:** `DH{H4SHC0LL1S10N_0N_TH3_D4T4_S7RUCTUR3}`
