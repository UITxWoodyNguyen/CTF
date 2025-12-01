# interencdec
### Information
- Category: Cryptography
- Points: 
- Level: Easy

### Description
Can you get the real meaning from this file?
### Hint
- Engaging in various decoding processes is of utmost importance

## Solution
- We use `cat` command to check what is contain in this file. Here is the result:
    `YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclgyZzBOMm8yYXpZNWZRPT0nCg==`
- Next, using this command to decode:

    `echo YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclgyZzBOMm8yYXpZNWZRPT0nCg== | base64 --decode` 
- Continue to decode with the same method, we receive the text that has the same format with the flag.
- Using the [dcode](https://www.dcode.fr/caesar-cipher) tool to get the flag.
