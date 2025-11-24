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

    ![Info]()

- Our target in this problem is the `main`, which is located at address `0x1129`. But before disassembling, because the default style of GDB is AT&T,  we need to set the disassembly style into the `Intel disassembly style` by using 
    ```
    set disassembly-flavour intel
    ```
- Next, try disassemble the main function:
    ```
    disassemble main
    ```
- Then we will find the EAX register value in hex is `0x86342`. Try to convert it into dec number and we will get the flag.

    ![Flag]()

- In the other way, try to decompile the file by using Ghidra tools, and we will have the source code of main function. Try to find the dec value of that hex value and get the flag.:
    ```c
    undefined8 main(void) {
        return 0x86342;
    }
    ```
---
## Step 2
