# Rolling My Own

### Information
* Category: RE
* Point:
* Level: Hard

### Description
I don't trust password checkers made by other people, so I wrote my own. It doesn't even need to store the password! If you can crack it I'll give you a flag.

Connect to server via `nc mercury.picoctf.net 57112`

### Hint
- It's based on [this paper](https://link.springer.com/article/10.1007/s11416-006-0011-3)
- Here's the start of the password: `D1v1`

### Solution
#### What we got ?
- The problem gives a binary file and a page. Connect to the server via netcat, we observed this page need a password to return something. Try out this server and we can see that, it will return to `timeout: the monitored command dumped core` if the password is wrong:

    ```
    $ nc mercury.picoctf.net 57112
    Password: 36
    timeout: the monitored command dumped core
    ```
##### Anti-Disassembly summarize
> They give us [a hint](https://github.com/UITxWoodyNguyen/CTF/blob/main/18%2B_Notes/Anti-Disasembling.md) about "anti - disassemble". So let's summarize it:
- The core idea is based on dynamic code generation using a cryptographic hash function.

    - **Mechanism**: A key (e.g., username, machine domain) is combined with a salt and hashed. A subsequence of the hash output is interpreted as machine code/shellcode (the `run`).

        ```
        key ← getUserData()
        hash ← md5(key ⊕ salt)
        run ← hashlb...ub
        goto run
        ```

    - **Targeting**: The code is targeted to run only under specific circumstances determined by the environmental key.

    - **Obscuration**: The executable code is never available for analysis, even in encrypted form, until it successfully runs on the target machine. The original key remains undisclosed.

- So from this summarize, the main task of analyst is determine the usage of code when executed (the value of `run`) and what the target is (find the correct value of `key` - *the password we need to file in this problem*)
- Moreover, if the wrong key is used, `run` is hardly to consist of useful code (*in this problem is the flag we need to find*). The resistant code may simply try to run in anyway, and possible to crash. This is the explanation of the result below when I test the server with a random password.

#### How to get the flag ?

##### Decompile the binary file
> Using Ghidra tool to decompile the binary file. And checking each function.
- `FUN_00100b6a()` - main function:

    ```c
    size_t sVar1;
    void *__ptr;
    code *pcVar2;
    long in_FS_OFFSET;
    int local_100;
    int local_fc;
    int local_e8 [4];
    undefined8 local_d8;
    undefined8 local_d0;
    char local_c8 [47];
    char acStack_99 [65];
    char local_58 [72];
    long local_10;
    
    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    setbuf(stdout,(char *)0x0);
    builtin_strncpy(local_c8,"GpLaMjEWpVOjnnmkRGiledp6Mvcezxls",0x21);
    local_e8[0] = 8;
    local_e8[1] = 2;
    local_e8[2] = 7;
    local_e8[3] = 1;
    memset(acStack_99 + 1,0,0x40);
    memset(local_58,0,0x40);
    printf("Password: ");
    fgets(acStack_99 + 1,0x40,stdin);
    sVar1 = strlen(acStack_99 + 1);
    acStack_99[sVar1] = '\0';
    for (local_100 = 0; local_100 < 4; local_100 = local_100 + 1) {
        strncat(local_58,acStack_99 + (long)(local_100 << 2) + 1,4);
        strncat(local_58,local_c8 + (local_100 << 3),8);
    }
    __ptr = malloc(0x40);
    sVar1 = strlen(local_58);
    FUN_00100e3e(__ptr,local_58,sVar1 & 0xffffffff);
    for (local_100 = 0; local_100 < 4; local_100 = local_100 + 1) {
        for (local_fc = 0; local_fc < 4; local_fc = local_fc + 1) {
        *(undefined1 *)((long)&local_d8 + (long)(local_fc * 4 + local_100)) =
            *(undefined1 *)((long)__ptr + (long)(local_e8[local_fc] + local_fc * 0x10 + local_100));
        }
    }
    pcVar2 = (code *)mmap((void *)0x0,0x10,7,0x22,-1,0);
    *(undefined8 *)pcVar2 = local_d8;
    *(undefined8 *)(pcVar2 + 8) = local_d0;
    (*pcVar2)(FUN_0010102b);
    free(__ptr);
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                        // WARNING: Subroutine does not return
        __stack_chk_fail();
    }
    return 0;
    ```

    - The code takes our input password (contains 64 chars) and save it to `acStack_99 + 1`. Then it runs a loop 4 times to create `local_58` with this logic:
        ```
        key = password
        salt = "abcdef123456"

        take key[block*4 --> block*4+3] 
        take salt[block*8 --> block*8+7]
        append both to `local_58`
        ```
    - After the loops, `local_58` will look like:
        ```
        local_58 = (pass[0...3] + salt[0...7]) + ... + (pass[12...15] + salt[24...31])
        ```

    - From the src code, we can observed that `local_c8` is the components of salt.
    - Next, it extract 16 bytes into `local_d8/local_d0` with this logic:
        ```
        for each block (0..3)
            for each byte (0..3)
                pick one byte from the 64-byte MD5 output
        ```
    - The offset rules: `offset = local_e8[byteIndex] + byteIndex*0x10 + blockIndex`
    - Through this process, each 8 bytes will be stores in `local_d8` and `local_d0`, respectively. This is the shellcode created from the password.
    - Next, the code will write all 16 bytes and execute them as a function:
        ```
        call shellcode(FUN_0010102b)
        ```
    - The shellcode must call `FUN_0010102b` with argument `0x7b3dc26f1` to print the flag.

- `FUN_00100e3e()` - MD5 based transform: this is the raw material for constructing the final 16-byte executable code.
    ```c
    int iVar1;
    long in_FS_OFFSET;
    void *local_a8;
    int local_98;
    int local_94;
    int local_90;
    MD5_CTX local_88;
    uchar local_28 [24];
    long local_10;
    
    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    if (param_3 % 0xc == 0) {
        iVar1 = param_3 / 0xc;
    }
    else {
        iVar1 = param_3 / 0xc + 1;
    }
    local_a8 = param_2;
    for (local_98 = 0; local_98 < iVar1; local_98 = local_98 + 1) {
        local_90 = 0xc;
        if ((local_98 == iVar1 + -1) && (param_3 % 0xc != 0)) {
        local_90 = iVar1 % 0xc;
        }
        MD5_Init(&local_88);
        MD5_Update(&local_88,local_a8,(long)local_90);
        local_a8 = (void *)((long)local_a8 + (long)local_90);
        MD5_Final(local_28,&local_88);
        for (local_94 = 0; local_94 < 0x10; local_94 = local_94 + 1) {
        *(uchar *)((local_98 * 0x10 + local_94) % 0x40 + param_1) = local_28[local_94];
        }
    }
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                        // WARNING: Subroutine does not return
        __stack_chk_fail();
    }
    return;
    ```

    - This code will divide data into 12-byte blocks, and use this process for each block to get a 16-byte MD5 digest:
        ```
        MD5_Init
        MD5_Update(block_of_12_bytes)
        MD5_Final
        ```
    - Finally, it scatter the 16 MD5 bytes into the 64-byte destination by using pattern. So the entire 64-byte buffer becomes a scrambled, interleaved MD5 matrix:
        ```
        dst[(blockIndex*16 + byteIndex) % 64] = md5[byteIndex]
        ```

- `FUN_0010102b()` - check flag function:
    ```c
    FILE *__stream;
    long in_FS_OFFSET;
    char local_98 [136];
    long local_10;
    
    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    if (param_1 == 0x7b3dc26f1) {
        __stream = fopen("flag","r");
        if (__stream == (FILE *)0x0) {
        puts("Flag file not found. Contact an admin.");
                        // WARNING: Subroutine does not return
        exit(1);
        }
        fgets(local_98,0x80,__stream);
        puts(local_98);
    }
    else {
        puts("Hmmmmmm... not quite");
    }
    if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                        // WARNING: Subroutine does not return
        __stack_chk_fail();
    }
    return;
    ```

    - We observed that the flag will only be printed if the argument equals `0x7b3dc26f1`

##### Finding flag's process
- Base on the summarize, the value of `run` is the same as the shellcode. The shellcode has to call the function at `rdi`, which is the function to print the flag, while setting the `rdi` to `0x7b3dc26f1`, since the flag printing function checks for this argument, all while being exactly 16 bytes.
- We have a hint that the password is started with `D1v1`. Using the logic to create `local_58` below and the value of `local_c8 = "GpLaMjEWpVOjnnmkRGiledp6Mvcezxls"`, we can have the first block is `D1v1GpLaMjEW`. Calculating the MD5 hash of first block we will get `23f144e08b603e724889fe489f78fa53`. 
- Base on the starting index in `main`, we find the actual shellcode is `4889fe48`. The assembly is:
    ```asm
    0:  48 89 fe                mov    rsi,rdi
    3:  48                      rex.W 
    ```
- Because of knowking the usage of shellcode, we can predict that the shellcode in assembly will be:
    ```asm
    mov     rsi, rdi
    movabs  rdi, 0x7b3dc26f1
    call    rsi
    ret
    ```
- Try compile the assembly to shellcode, and we will find the full actual shellcode is `\x48\x89\xFE\x48\xBF\xF1\x26\xDC\xB3\x07\x00\x00\x00\xFF\xD6\xC3`
- Base on all the analyze above, we can easily find the logic of this problem. Featuring with the first part of password, we will get this:
    ```
    Part 1: D1v1GpLaMjEW --> 23 f1 44 e0 8b 60 3e 72 48 89 fe 48 9f 78 fa 53 
    Part 2: ????pVOjnnmk --> ?? ?? bf f1 26 dc ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
    Part 3: ????RGiledp6 --> ?? ?? ?? ?? ?? ?? ?? b3 07 00 00 ?? ?? ?? ?? ??
    Part 4: ????Mvcezxls --> ?? 00 ff d6 c3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
    ```
- Now, we need a python script to brute force all case in order to find the `?`. There are about `62^4` cases for each parts. This is the script:
    ```python
    #!/usr/bin/env python3
    # solve.py
    # Brute-force solver for the 3 unknown 4-char blocks of the 16-char password
    # based exactly on the C code you provided.

    import hashlib
    import itertools
    import string
    import time

    # Allowed characters: lower, upper, digits
    ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits

    # v13 string from the binary
    V13 = b"GpLaMjEWpVOjnnmkRGiledp6Mvcezxls"  # 32 bytes

    # Pre-split v13 into 8-byte chunks used by blocks 0..3
    V13_CHUNKS = [V13[i*8:(i+1)*8] for i in range(4)]
    # We know pass[0:4] == b"D1v1" (given)
    KNOWN_PREFIX = b"D1v1"

    # Target 16 bytes we need to build (from assembly)
    TARGET = bytes([0x48,0x89,0xfe,0x48,
                    0xbf,0xf1,0x26,0xdc,
                    0xb3,0x07,0x00,0x00,
                    0x00,0xff,0xd6,0xc3])

    # For each block we will check a 4-byte slice of its MD5:
    # block 0 -> MD5(block0)[8..11] must equal TARGET[0:4]
    # block 1 -> MD5(block1)[2..5]  must equal TARGET[4:8]
    # block 2 -> MD5(block2)[7..10] must equal TARGET[8:12]
    # block 3 -> MD5(block3)[1..4]  must equal TARGET[12:16]

    CHECKS = [
        (0, 8, 4),   # (target_offset, md5_start, length)
        (4, 2, 4),
        (8, 7, 4),
        (12, 1, 4),
    ]

    def md5_bytes(b: bytes) -> bytes:
        return hashlib.md5(b).digest()  # 16 bytes

    def check_block(block_index: int, candidate4: bytes) -> bool:
        """
        block_index: 0..3
        candidate4: 4-byte password slice (bytes)
        returns True if MD5(block) slice matches the expected bytes in TARGET
        """
        block = candidate4 + V13_CHUNKS[block_index]  # 12 bytes
        md = md5_bytes(block)
        _, md_start, length = CHECKS[block_index]
        target_offset, _, _ = CHECKS[block_index]
        want = TARGET[target_offset:target_offset+length]
        got = md[md_start:md_start+length]
        return got == want

    def brute_block(block_index: int):
        """
        Brute-force a single 4-char block. Returns list of matches (there can be multiple).
        """
        print(f"[+] Brute forcing block {block_index} (pass positions {block_index*4}..{block_index*4+3})")
        matches = []
        t0 = time.time()
        count = 0
        # iterate over all 62^4 candidates
        for combo in itertools.product(ALPHABET, repeat=4):
            count += 1
            cand = ''.join(combo).encode()
            if check_block(block_index, cand):
                matches.append(cand.decode())
                # don't break — there might be multiple matches; collect them all
                print(f"    [FOUND] block{block_index}: {cand.decode()}")
            # optional progress report every 2 million tries
            if count % 2000000 == 0:
                elapsed = time.time() - t0
                rate = count / elapsed if elapsed > 0 else 0
                print(f"    tried {count:,}  rate {rate:,.0f} it/s")
        elapsed = time.time() - t0
        print(f"[+] Done block {block_index}: tried {count:,} candidates in {elapsed:.1f}s")
        return matches

    def main():
        # quick check for block 0 (should match immediately because password prefix known)
        block0 = KNOWN_PREFIX
        ok0 = check_block(0, block0)
        print("Block 0 (known prefix) check:", "OK" if ok0 else "MISMATCH")
        # Brute force blocks 1..3 (indices 1,2,3)
        results = {}
        for bi in (1,2,3):
            matches = brute_block(bi)
            results[bi] = matches
        print("\n=== RESULTS ===")
        print("Known prefix (block0) =", KNOWN_PREFIX.decode())
        for bi in (1,2,3):
            print(f"Block {bi} matches ({len(results[bi])}): {results[bi]}")
        print("\nTo form full password: D1v1 + block1 + block2 + block3 (each block is 4 chars)")
        password = "D1v1" + results[1][0] + results[2][0] + results[3][0]
        print("Example full password:", password)

    if __name__ == "__main__":
        main()
    ```

- Brute force to get the password and flag:
    
    ![Flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Hard/Rolling%20My%20Own/Screenshot%202025-12-01%20121103.png?raw=true)
