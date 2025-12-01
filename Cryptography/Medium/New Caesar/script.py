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
