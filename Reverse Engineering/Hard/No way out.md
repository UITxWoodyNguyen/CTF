# Wizardlike
### Information
* Category: Reverse Engineering
* Level: Hard

### Description
Do you seek your destiny in these deplorable dungeons? If so, you may want to look elsewhere. Many have gone before you and honestly, they've cleared out the place of all monsters, ne'erdowells, bandits and every other sort of evil foe. The dungeons themselves have seen better days too. There's a lot of missing floors and key passages blocked off. You'd have to be a real wizard to make any progress in this sorry excuse for a dungeon!
Download the game.
'w', 'a', 's', 'd' moves your character and 'Q' quits. You'll need to improvise some wizardly abilities to find the flag in this dungeon crawl. '.' is floor, '#' are walls, '<' are stairs up to previous level, and '>' are stairs down to next level.

### Hint
* Different tools are better at different things. Ghidra is awesome at static analysis, but radare2 is amazing at debugging.
* With the right focus and preparation, you can teleport to anywhere on the map.

## Solution:
### Encrypting code explanation:
- `b16_encode` function:
    - Each letter “c” in plaintext string is changed into ASCII code, then presented as 8-bit binary.
    - Separate 8-bit in to 2 groups of 4-bits:
        - `binary[:4]` (high bit) → be changed into number → mapping with an character in `ALPHABET`
        - `binary[4:]` (low bit) → do the same as high bit
    
    ⇒ Each letter will be mapped with 2 others letters in ALPHABET
    
    - For example: “A” converted into ASCII code is 65 = “01000001”
        - “0100” = 4 → “e”
        - “0001” = 1 → “b”
        
        ⇒ A → “eb”
        
- `shift` function:
    - `c` and `k` is the characters, and `t1` and `t2` is the position
        - Code to get the position of a character: 
        `pos = ord(c) - LOWERCASE_OFFSET`
    - The main purpose is move `c` right `t2` steps in the alphabet.
- Main function:
    - `flag` is the plaintext (string need to be encrypted)
    - `b16` is the **encoded string** of flag.
    - For each letter in `b16`, encrypt with the key word: `key[i % len(key)]`.
    - Push the encrypted letters back of `enc`.

> **⇒ We need to reverse the process and Brute Force all 16 keys**
- Here is the decryption code:

    `decrypt.py`:
    ```python
    import string

    LOWERCASE_OFFSET = ord('a')
    ALPHABET = string.ascii_lowercase[:16]  # 'a' to 'p'

    # decode_function
    def b16_decode(encoded_str):
        decode_string = ""
        for char in range(0, len(encoded_str), 2):
            step = ""
            first_char = "{:04b}".format(ALPHABET.index(encoded_str[char]))
            step += first_char
            second_char = "{:04b}".format(ALPHABET.index(encoded_str[char + 1]))
            step += second_char
            byte_value = int(step, 2)
            decode_string += chr(byte_value)
        return decode_string

    def unshift(char, key):
        t2 = ord(char) - LOWERCASE_OFFSET
        t1 = ord(key) - LOWERCASE_OFFSET
        t3 = (t2 - t1) % len(ALPHABET)
        return ALPHABET[t3]

    def decrypt(encrypted_str, key):
        decrypted_str = ""
        for i, char in enumerate(encrypted_str):
            decrypted_str += unshift(char, key[i % len(key)])
        decrypted_str = b16_decode(decrypted_str)
        return decrypted_str

    encrypted_message = "mnlkfnknljlfmhjimkmhjmlhjomhmmjkjpmmjmjkjpjogjmjpjoojnjojmmkmlmijhmjmmj"

    for key in ALPHABET:
        decrypted_message = decrypt(encrypted_message, key)
        print(f"key: {key}, Decrypted Message: {decrypted_message}")
        # print("picoCTF{" + decrypted_message + "}")
    ```
- Code explanation:
    - `b16_decode` function (reverse process of `b16_encode` function above):
        - Get 2 consecutive characters in the encoded string → get their index
        - Convert each index into 4-bit and merge into 2 group (4-bit + 4-bit = 8-bit = 1 byte)
        - Change into ASCII code
    - `unshift` function: `unshift(c,k) = (c - k) mod 16`
    - `decrypt` function:
        - For each characters in `encrypted_str`, using unshift function to eliminate [Vigenère cipher](https://www.geeksforgeeks.org/dsa/vigenere-cipher/)
        - Using `b16_decode` to get the plaintext (not be ASCII encoded)
