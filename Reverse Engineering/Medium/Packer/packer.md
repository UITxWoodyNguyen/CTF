# Packer

### Information
* Category: Reverse Engineering
* Point:
* Level: Medium

### Description
Reverse this linux executable?

### Hint
What can we do to reduce the size of a binary after compiling it.

### Solution
#### What we got ?
The problem gives us a binary file.

#### How to get the flag ?
- First, using `strings` command to find out what method is used to compressed the binary file.
```
strings out | less
```
- Checking closely, we will see that the binary is compressed or packed by using UPX:

![UPX]()

- So, we can use `upx` command to decompress this file:
```c
upx -d ./out 
// -d: decompress
```

- After being decompressed, the contents of the binary file is printable, so that we can use `strings` and `egrep` command to find the flag:

![Flag]()

- Using [Cyberchef](https://gchq.github.io/CyberChef/) tool to decode the flag.
