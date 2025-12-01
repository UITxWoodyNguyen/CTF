# hashcrack

### Information
- Category: Cryptography
- Points: 
- Level: Easy

### Description
For this problem, when connect to the server, we need to hashcracking some password to get the flag. The server can be connected via `nc verbal-sleep.picoctf.net <port>`

### Hint
- Understanding [hashes](https://primer.picoctf.org/#_hashing) is very crucial.
- Can you identify the hash algorithm? Look carefully at the length and structure of each hash identified.
- Tried using any hash cracking tools?

## Solution
We use [crackstation](https://crackstation.net/) tool to crack the password Here is the cracking result:
![](https://media.discordapp.net/attachments/961544480366931969/1432620836799647856/image.png?ex=6901b7a0&is=69006620&hm=76a8c7055640796fef315ed820b4336df0d69d55ddfa2715b0ed1c31fed7b81f&=&format=webp&quality=lossless&width=1008&height=650)

When we got 3 times correct, the server will return the flag.

**The flag is `picoCTF{UseStr0nG_h@shEs_&PaSswDs!_5b836723}`**
