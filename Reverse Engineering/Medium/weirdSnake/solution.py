input_lst = [
    4, 54, 41, 0, 112, 32, 25, 49, 33, 3,
    0, 0, 57, 32, 108, 23, 48, 4, 9, 70,
    7, 110, 36, 8, 108, 7, 49, 10, 4, 86,
    43, 104, 44, 91, 7, 18, 106, 124, 89, 78
]

key_str = "t_Jo3"
flag = ""
for i in range(len(input_lst)):
    flag += chr(input_lst[i] ^ ord(key_str[i % len(key_str)]))
print(flag)
