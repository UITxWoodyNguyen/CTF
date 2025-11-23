# Classic Crackme 0x100

### Information
* Category: Reverse Engineering
* Point:
* Level: Medium

### Description
Crack the Binary file locally and recover the password. Use the same password on the server to get the flag! 
Access the server using `nc titan.picoctf.net <port>`

### Hint
- Let the machine figure out the symbols!

### Solution
#### What we got ?
- First, decompiler the binary file by using https://dogbolt.org and we will receive a [`crackme.cpp`]() file.

#### How to get the flag ?
