# breadth

### Information
* Category: RE
* Point:
* Level: Hard

### Description
Surely this is what people mean when they say "horizontal scaling," right? 

**TOP SECRET INFO:** 
Our operatives managed to exfiltrate an in-development version of this challenge, where the function with the real flag had a mistake in it. Can you help us get the flag?

### Hint
None

### Solution
#### What we got ?
- We are given 2 ELF 64-bit LSB file. Using IDA to decompile both of them, we can see some similarities in 2 files:

    - First, try to run 2 files respectively, it return the same result:

        ![Same](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Hard/breadth/breadth/1.png?raw=true)

    - Check out some of functions in 2 files, we will see that most of them is return to the same answer:
    
        - `breadth.v1`:

        ![main_1](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Hard/breadth/breadth/2.png?raw=true)

        - `breadth.v2`:

        ![main_2](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Hard/breadth/breadth/3.png?raw=true)

    - Moreover, check the src code in hex view, we will see lots of flag in format `picoCTF{}`. However, they are not the correct flag.

        ![Flag](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Hard/breadth/breadth/4.png?raw=true)

#### How to get the flag ?
> Base on what we got, the question is are there any difference between 2 file?
- First, using `radiff2` command to compare 2 binary files. Moreover, `radiff2 -u` will output the difference in a unified format.
- Try it and we will se the difference, with the red line is the data of `breadth.v1` and the green line is belong to `breadth.v2`:

    ![diff](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Hard/breadth/breadth/5.png?raw=true)

- We observed that the function storing the correct flag is stored in one of these offset in 2 binary files. So we need to check out only 4 offset to find the correct flag. 
- However, the offset takes from `radiff2` is not the same as the offset takes from IDA. The explanation can be seen via [`differOffset.md`](https://github.com/UITxWoodyNguyen/CTF/blob/main/18%2B_Notes/differOffset.md).
- Because of this reason, we need to edit the offset by delete a character or replace it by a hex number ([`0...9`] or [`A...F`]). 
- Trying to find 2 offsets in 2 files respectively, we will find the flag is stored in `fcnkKTQpF()` function:

    ![Find](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Hard/breadth/breadth/6.png?raw=true)

    ![Flag0](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Hard/breadth/breadth/7.png?raw=true)

    ![Flag1](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Hard/breadth/breadth/8.png?raw=true)
