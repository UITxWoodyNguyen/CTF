# FactCheck

### Information
* Category: Reverse Engineering
* Point:
* Level: Medium

### Description
This binary is putting together some important piece of information... Can you uncover that information?

### Hint
No Hints.

### Solution
#### What we got ?
- The problem give us a binary file. Using Ghidra tools to decompile this file, we will receive [`ghidra.cpp`](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/FactCheck/ghidra.cpp)

- About this decompiled file:

    - There is a part of the flag:
    ```c
    string(local_248,"picoCTF{wELF_d0N3_mate_",&local_249)
    ```
    - Moreover, this code generate many single character, which can be a part of flag:
    ```c
    std::string::string(local_228,"7",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 00101345 to 00101349 has its CatchHandler @ 001019b1
    std::string::string(local_208,"5",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 00101380 to 00101384 has its CatchHandler @ 001019cc
    std::string::string(local_1e8,"9",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 001013bb to 001013bf has its CatchHandler @ 001019e7
    std::string::string(local_1c8,"3",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 001013f6 to 001013fa has its CatchHandler @ 00101a02
    std::string::string(local_1a8,"0",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 00101431 to 00101435 has its CatchHandler @ 00101a1d
    std::string::string(local_188,"4",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 0010146c to 00101470 has its CatchHandler @ 00101a38
    std::string::string(local_168,"a",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 001014a7 to 001014ab has its CatchHandler @ 00101a53
    std::string::string(local_148,"e",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 001014e2 to 001014e6 has its CatchHandler @ 00101a6e
    std::string::string(local_128,"a",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 0010151d to 00101521 has its CatchHandler @ 00101a89
    std::string::string(local_108,"d",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 00101558 to 0010155c has its CatchHandler @ 00101aa4
    std::string::string(local_e8,"b",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 00101593 to 00101597 has its CatchHandler @ 00101abf
    std::string::string(local_c8,"2",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 001015ce to 001015d2 has its CatchHandler @ 00101ada
    std::string::string(local_a8,"6",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 00101606 to 0010160a has its CatchHandler @ 00101af5
    std::string::string(local_88,"4",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 0010163e to 00101642 has its CatchHandler @ 00101b0d
    std::string::string(local_68,"3",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    std::allocator<char>::allocator();
                        // try { // try from 00101676 to 0010167a has its CatchHandler @ 00101b25
    std::string::string(local_48,"8",&local_249);
    std::allocator<char>::~allocator((allocator<char> *)&local_249);
    ```
    - So, we can observed that each `local_` is matched with a single character, respectively. For example, base on this code, `local_228` is matched with `7`.

    - In addition, there are some conditions:
    ```c
    pcVar2 = (char *)std::string::operator[]((ulong)local_208); // local_208 = '5'
    if (*pcVar2 < 'B') {
        std::string::operator+=(local_248,local_c8); // local_c8 = '2' --> Add "2"
    }
    pcVar2 = (char *)std::string::operator[]((ulong)local_a8); // local_a8 = '6'
    if (*pcVar2 != 'A') {
        std::string::operator+=(local_248,local_68); // local_68 = '3' --> Add "3"
    }
    pcVar2 = (char *)std::string::operator[]((ulong)local_1c8); // local_1c8 = "3"
    cVar1 = *pcVar2;
    pcVar2 = (char *)std::string::operator[]((ulong)local_148); // local_148 = 'e'
    if ((int)cVar1 - (int)*pcVar2 == 3) {
        std::string::operator+=(local_248,local_1c8); // condition false --> not add "3"
    }
    ```

#### How to get the flag ?
- Base on the condition, we have the code to get the flag:
```c++
#include <iostream>
#include <string>

int main() {
    // Start with the prefix
    std::string flag = "picoCTF{wELF_d0N3_mate_";

    // Individual characters (or small strings)
    char local_208 = '5';
    char local_1e8 = '9';
    char local_1c8 = '3';
    char local_1a8 = '0';
    char local_188 = '4';
    char local_168 = 'a';
    char local_148 = 'e';
    char local_128 = 'a';
    char local_108 = 'd';
    char local_e8  = 'b';
    char local_c8  = '2';
    char local_a8  = '6';
    char local_88  = '4';
    char local_68  = '3';
    char local_48  = '8';
    char local_228 = '7';

    // Conditional concatenation
    if (local_208 < 'B') {
        flag += local_c8; // '2'
    }

    if (local_a8 != 'A') {
        flag += local_68; // '3'
    }

    if ((local_1c8 - local_148) == 3) {
        flag += local_1c8; // not added in this case
    }

    // Append the remaining characters in order
    flag += local_1e8;  // '9'
    flag += local_188;  // '4'
    if (local_168 == 'G') {
        flag += local_168; // not added here
    }
    flag += local_1a8;  // '0'
    flag += local_88;   // '4'
    flag += local_228;  // '7'
    flag += local_128;  // 'a'

    // Closing brace
    flag += '}';

    // Print the flag
    std::cout << flag << std::endl;

    return 0;
}
```
- Run this code to get the flag.

![Flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/FactCheck/fact.png?raw=true)

