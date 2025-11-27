# Reverse Engineering

## Source of Problem
- picoCTF: https://play.picoctf.org

## Problems
### Level: Medium
| Problem  | About | Tools | System |
| ----- |-----| ---- | ---- |
| Chronohack | Brute-Force, Time Attacking, python | | Windows, Linux |
| Classic Crackme 0x100 | Decompiler, Math, Cryptography | [Ghidra Tools](https://dogbolt.org)| Windows, Linux |
| FactCheck | Decompiler, Mapping | [Ghidra Tools](https://dogbolt.org) | Windows, Linux |
| Packer | Packing, Decompress, Linux Command, Cryptography | IDA, [Cyberchef](https://gchq.github.io/CyberChef/) | Windows, Linux |
| Picker (I, II, III) | Secret Function, Cryptography, python | | Windows, Linux |
| Quantum Scrambler | Cryptography, python | | Windows, Linux |
| Tap into Hash | Cryptography, python | | Windows, Linux |
| weirdSnake | python bytecode, decompile | | Windows, Linux |
| WinAntiDbg0x100 | Anti-debug | IDA, x32dbg | Windows |
| WinAntiDbg0x200 | Anti-debug | IDA, x32dbg | Windows |
| WinAntiDbg0x300 | Anti-debug, Binary patching | IDA, x64dbg, HxD, DIE | Windows |
| GDB Baby (1,2,3,4) | Disassemble, Cryptography | IDA, gdb, shell | Windows, Linux |
| Bit-O-Asm (1,2,3,4) | Assembly Reading Foundation | | Try it if you know how to code! |
| Ascii FTW | Decompile, Assembly, Cryptography | IDA, gdb, shell | Windows, Linux |
| Virtual Machine 0 | Reading 3D file, mathematics, python | 3D Reading | Try it if you know how to count and basic maths |
| Timer | APK Decompile | apktools, shell | Linux |
| Safe Opener 2| Java Decompile | | Windows, Linux |
| Unpackme (py, upx) | Packing, decompile, python | UPX, IDA, Ghidra | Windows, Linux |
| | | | |



### Level: Hard
| Problem  | About | Tools | System |
| ----- |-----| ---- | ---- |
| Keygenme | Crypto | IDA | Windows |
| Wizardlike | Binary patching | IDA, HxD | Windows |
| not-crypto | Crypto | IDA | Window, Linux |
| breadth | Binary Comparison, Decompile | IDA, Ghidra | Linux |

## RE Resources
- GDB Tools:
  - https://ctf101.org/reverse-engineering/what-is-gdb/
  - https://www.tutorialspoint.com/gnu_debugger/index.htm
- Binary Operations: https://book.rada.re/tools/radiff2/datadiff.html
- Decoding/Encoding: https://gchq.github.io/CyberChef/
- Decompiling Online (usable for file's memory less than **2MB**): https://dogbolt.org
- HxD: https://mh-nexus.de/en/downloads.php?product=HxD20
- IDA: https://hex-rays.com/pricing?section=individuals
- x32/x64dbg: https://x64dbg.com/
