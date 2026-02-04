# Ready Gladiator 

### Information
* Category: RE
* Point:
* Level: Medium

### Description
- Part 1: I have been learning to use the Windows API to do cool stuff! Can you wake up my program to get the flag?
- Part 2: I've been learning more Windows API functions to do my bidding. Hmm... I swear this program was supposed to create a file and write the flag directly to the file. Can you try and intercept the file writing function to see what went wrong?

> Extract password: picoctf

## Part 1

### Hint
- Frida is an easy-to-install, lightweight binary instrumentation toolkit
- Try using the CLI tools like frida-trace to auto-generate handlers

### Solution
#### What we got ?
- First, try unzip the `.zip` file downloaded from the problem, we will have a `.exe` file. Using `rabin2` command to check for the sections inside the file:

    ```
    rabin2 -S <file_name.exe>
    ```

    ![rabin2](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Binary%20Instrumention/bin1.png?raw=true)

- We can see from the result, the binary file has 7 sections. However, the `.ATOM` is suspicious since we typically don't see in windows portable executables.

#### How to get the flag ?
- First, using `binwalk` to get the unpacked executable. The result shows that we can see some compressed data at addr `0x6000`, which is the same as `.ATOM`.

    ![binwalk](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Binary%20Instrumention/bin11.png?raw=true)

- Change directory after unpackaging, we will find the file `6000`. Using `file` to check it, we can see it contains 6 sections, so we can assume that it's safe to proceed thinking its unpacked.

    ![strings](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Binary%20Instrumention/bin12.png?raw=true)

- Using `strings` to see the contents, and `egrep` for the flag. We will find a line contains `base64` data, try decode to get the correct flag.

    ![flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Binary%20Instrumention/bin13.png?raw=true)

---
## Part 2
### Hint
- Frida is an easy-to-install, lightweight binary instrumentation toolkit
- Try using the CLI tools like frida-trace to auto-generate handlers
- You can specify the exact function name you want to trace

### Solution
#### What we got ?
Same as Part 1.

![](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Binary%20Instrumention/bin2.png?raw=true)

#### How to get the flag ?
- Same as Part 1. However, we cannot using `egrep` since there is no signal like `flag` or `picoCTF` to find. Check the src file we will find this line :
    ```
    <Insert path here>
    cGljb0NURntmcjFkYV9mMHJfYjFuX2luNXRydW0zbnQ0dGlvbiFfYjIxYWVmMzl9
    RSDS
    C:\Users\kiran\source\repos\BinaryInstrumentation3\x64\Release\BinaryInstrumentation3.pdb
    ```
- Try do decode with base64 to get the final flag. 

    ![Flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Binary%20Instrumention/bin21.png?raw=true)
