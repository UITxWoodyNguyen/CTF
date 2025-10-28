# The numbers
### Information
* Category: Cryptography
* Points: 
* Level: Easy

### Description
The problem give us this picture

![](https://media.discordapp.net/attachments/961544480366931969/1432331280640643173/image.png?ex=6900a9f4&is=68ff5874&hm=4c5026508f10598f8134c5446d7dd24ae8e3e12b722a5d5927904e4c270185ff&=&format=webp&quality=lossless&width=883&height=390)

### Hint
* The flag is in the format PICOCTF{}

## Solution
* We we can see that each numbers in the picture is the position of a letter in latin alphabet, which contains 26 letters.
* For example:
    * A --> 1
    * B --> 2
    * C --> 3
* Base on this, we can easily replace the number with the letter. With the letter `"{"` and `"}"`, we do not need to decode.
* Here is the decoding process:
    * 16 → P
    * 9 → I
    * 3 → C
    * 15 → O
    * 3 → C
    * 20 → T
    * 6 → F
    * 20 → T
    * 8 → H
    * 5 → E
    * 14 → N
    * 21 → U
    * 13 → M
    * 2 → B
    * 5 → E
    * 18 → R
    * 19 → S
    * 13 → M
    * 1 → A
    * 19 → S
    * 15 → O
    * 14 → N
      
**The flag is: `PICOCTF{THENUMBERSMASON}`**
