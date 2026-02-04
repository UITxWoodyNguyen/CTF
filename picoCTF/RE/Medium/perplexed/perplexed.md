# perplexed

### Information
* Category: RE
* Point:
* Level: Medium

### Description
Download the binary
### Hint
No hint

### Solution
#### What we got ?
- The problem gives us a binary file. Using `file` command to check its type, and the result is a ELF 64-bit file.
- Try to decompile it with Ghidra tools, we found this src code in `main`:
    ```c
    printf("Enter the password: ");
    fgets(local_118,0x100,stdin);
    local_c = check(local_118);
    bVar1 = local_c != 1;
    if (bVar1) {
        puts("Correct!! :D");
    }
    else {
        puts("Wrong :(");
    }
    return !bVar1;
    ```
- We observed that this file required a correct password to pass the password check throughout `check()` function.

#### How to get the flag ?
- First, check the `info functions` and try disassembling the `check()` with `gdb` :
> Remember to set the `disassembly-flavor` into `intel`, instead of its default flavor `AT&T`

    ![Info](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/perplexed/perp1.png?raw=true)

    ![Asm](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/perplexed/perp2.png?raw=true)

- Base on this code:

    - First, we find the line:
        ```assembly
        0x000000000040116f <+25>:	cmp    rax,0x1b
        0x0000000000401173 <+29>:	je     0x40117f <check+41>
        ```
        > Explanation: This function ensures that the input is exactly 27 bytes long (`0x1b = 27`). If the input is not valid, the program will immediately reject the password.
    
    - Next, the function initialize 3 64-bit constants into the memory:
        ```assembly
        0x000000000040117f <+41>:	movabs rax,0x617b2375f81ea7e1
        0x0000000000401189 <+51>:	movabs rdx,0xd269df5b5afc9db9
        0x000000000040119b <+69>:	movabs rax,0xf467edf4ed1bfed2
        ```
    
    - In fact, if we have three 64-bit constant (`const_1, const_2, const_3`), we would expect it will be stored respectively in this way:
        | Address | Value |
        | :---: | :---: |
        | `0 -> 7`: `0x00` to `0x07` | `const_1` (8 bytes) |
        | `8 -> 15`: `0x08` to `0x0f` | `const_2` (8 bytes) |
        | `16 -> 23`: `0x10` to `0x17` | `const_3` (8 bytes) |
    - However, looking closely the 2 value of `const_2` and `const_3`, the first bytes of `const_3` has the same value as the last byte of `const_2` (both has the value equal to `d2`). So `const_3` will start at adrr offset `0x0F (15)`, not `0x10 (16)`. Now it has only **23 bytes** not **24 bytes** (from 0 to 22) is filled.
    - Moreover, this function require a 27-byte input, so value `00` will be auto filled from byte 23 to 26. Now, the memory will look like this:
        | Byte | Value |
        | :---: | :---: |
        | `0 --> 7` | `e1 a7 1e f8 75 23 7b 61` |
        | `8 --> 14` | `b9 9d fc 5a 5b df 69` |
        | `15 --> 22` | `d2 fe 1b ed f4 ed 67 f4` |
        | `23 --> 26` | `00 00 00 00` |
- Base on the table, we have the code to get the flag:
    ```python
    # Your input (local_58 extracted earlier)
    data = b'\xe1\xa7\x1e\xf8u#{a\xb9\x9d\xfcZ[\xdfi\xd2\xfe\x1b\xed\xf4\xedg\xf4'

    # 1. Build full bitstring (use all bytes)
    bitstream = "".join(format(b, "08b") for b in data)

    # 2. We only need first 27 * 7 = 189 bits
    needed_bits = bitstream[:27 * 7]

    # 3. Split into 27 chunks of 7 bits
    chunks = [needed_bits[i:i+7] for i in range(0, len(needed_bits), 7)]

    # 4. Convert each 7-bit value to ASCII
    password = "".join(chr(int(chunk, 2)) for chunk in chunks)

    print("27 chunks of 7 bits:")
    for i, c in enumerate(chunks):
        print(i, c, "->", chr(int(c, 2)))

    print("\nReconstructed 27-byte password:")
    print(password)
    ```
    
