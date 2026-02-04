# GDB Baby

### Information
* Category: Reverse Engineering
* Point:
* Level: Medium

## Step 1
### Description
Can you figure out what is in the eax register at the end of the main function? Put your answer in the picoCTF flag format: picoCTF{n} where n is the contents of the eax register in the decimal number base. If the answer was 0x11 your flag would be picoCTF{17}.

### Hint
- gdb is a very good debugger to use for this problem and many others!
- main is actually a recognized symbol that can be used with gdb commands.

### Solution
The problem gives us an executable file and our task is do reverse engineering to get the eax register value in the decimal number base.
#### What we got ?
- First, checkout what is the type of this file by using `file` command. Then we can see this is a `.ELF` file.
```
file debugger0_a
debugger0_a: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=15a10290db2cd2ec0c123cf80b88ed7d7f5cf9ff, for GNU/Linux 3.2.0, not stripped.
```

#### How to get the flag ?
- First, open this file by using `GDB` and check what is containing in this file by using `info functions`:

    ![Info](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/GDB%20Baby/baby1-1.png?raw=true)

- Our target in this problem is the `main`, which is located at address `0x1129`. But before disassembling, because the default style of GDB is AT&T,  we need to set the disassembly style into the `Intel disassembly style` by using 
    ```
    set disassembly-flavour intel
    ```
- Next, try disassemble the main function:
    ```
    disassemble main
    ```
- Then we will find the EAX register value in hex is `0x86342`. Try to convert it into dec number and we will get the flag.

    ![Flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/GDB%20Baby/baby1-2.png?raw=true)

- In the other way, try to decompile the file by using Ghidra tools, and we will have the source code of main function. Try to find the dec value of that hex value and get the flag.:
    ```c
    undefined8 main(void) {
        return 0x86342;
    }
    ```
---
## Step 2
### Description
Same as Step 1.
### Hint
You could calculate eax yourself, or you could set a breakpoint for after the calculcation and inspect eax to let the program do the heavy-lifting for you.

### Solution
#### What we got ?
- The problem give us an `.ELF` file same as Step 1. Try to decompile it with Ghidra tools, then we will receive a [`decompile.c`](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/GDB%20Baby/decompileB.c) file.

#### How to get the flag ?
- Checkout this file, we will find the `main`:
    ```c
    int main(void) {
        undefined4 local_10;
        undefined4 local_c;
        
        local_c = 0x1e0da;
        for (local_10 = 0; local_10 < 0x25f; local_10 = local_10 + 1) {
            local_c = local_c + local_10;
        }
        return local_c;
    }
    ```
- We observed that the `local_c` dec value will be the flag we need to find. So lets try to analyze the code's process:

    - This function initializes a variable `local_c` with the hexadecimal value `0x1e0da`, then enters a loop where another variable, `local_10`, starts at 0 and increments by 1 until it reaches (but does not include) `0x25f`. During each iteration, the loop adds the current value of `local_10` to `local_c`. 
    - In essence, the function is accumulating the sum of all integers from 0 up to 606 and adding that total to the initial constant stored in `local_c`. After completing the loop, the function returns the final accumulated value.
- Base on this, we have the code :
    ```c
    #include <stdint.h>
    #include <stdio.h>

    int main(void) {
        int32_t local_c = 123098;   // 0x1E0DA in decimal
        for (int32_t i = 0; i < 607; ++i) {   // 0x25F = 607
            local_c += i;
        }
        printf("picoCTF{%d}\n", local_c);   // print decimal : picoCTF{307019}
    }
    ```
---
## Step 3
### Description
Now for something a little different. `0x2262c96b` is loaded into memory in the main function. Examine byte-wise the memory that the constant is loaded in by using the GDB command `x/4xb addr`. The flag is the four bytes as they are stored in memory. If you find the bytes `0x11 0x22 0x33 0x44` in the memory location, your flag would be: `picoCTF{0x11223344}`.

### Hint
- You'll need to breakpoint the instruction after the memory load.
- Use the gdb command `x/4xb addr` with the memory location as the address addr to examine. GDB manual page.
- Any registers in addr should be prepended with `$` like `$rbp`.
- Don't use square brackets for `addr`
- What is endianness?

### Solution
#### What we got ?
- Same as Step 1 and Step 2.

#### How to get the flag ?
- First, we need to grant execute permission for the owner by using `chmod`:
    ```
    chmod u+x debugger0_c
    ```
- Next, run GDB and try to disassemble the `main` in the same way as Step 1:

    ![Disassemble](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/GDB%20Baby/baby3-1.png?raw=true)

- Base on the first hint, try to breakpoint the `main` and subsequently run the program by using `run`:

    ![Break-Run](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/GDB%20Baby/baby3-2.png?raw=true)

- As the program halts at our breakpoint, it’s apparent from the screenshot that the final value in the EAX register is fetched from memory. To confirm this, we set another breakpoint at the instruction address 0x40111f (where EAX is set) using and continue execusion:
    ```c
    break *0x40111f 
    ```
    ```c
    c // continue exc
    ```
- After doing this, we can checkout the contents of registers eax. However, this is not the flag. 
- Following the hints, we can inspect the actual memory content with:
    ```c
    x/4xb $rbp -4
    ```
- It will return to 4 hex value. Combine off of them and we will get the flag.

    ![All Process](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/GDB%20Baby/baby3-3.png?raw=true)

## Step 4
### Description
`main` calls a function that **multiplies** `eax` by a constant. The flag for this challenge is that constant in decimal base. If the constant you find is `0x1000`, the flag will be `picoCTF{4096}`.

### Hint
A function can be referenced by either its name or its starting address in gdb.

### Solution
#### What we got ?
- This problem has a difference, since the `debugger` file is a ELF 64-bit LSB file (check by using `file` command). It shows that the file is a 64-bit LSB executable in the ELF format, and it has not been stripped of its debugging information.

    ![LSB](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/GDB%20Baby/baby4-1.png?raw=true)

#### How to get the flag
- Try to disassemble `main`, we find out at address `0x401142 <+38>`, the `func1` is called.

    ![main](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/GDB%20Baby/baby-2.png?raw=true)

- Next, try to disassemble `func1`, at address `0x01114 <+14>`, it has the line `imul eax,eax,0x3269`, which means multiple eax by `0x3269`. Base on the description, `0x3269` is the constant hex value we need to find. Decode this val to get the flag.

    ![func1](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/GDB%20Baby/baby4-3.png?raw=true)
