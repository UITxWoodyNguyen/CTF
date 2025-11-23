# weirdSnake

### Information
* Category: Reverse Engineering
* Point:
* Level: Medium

### Description
I have a friend that enjoys coding and he hasn't stopped talking about a snake recently He left this file on my computer and dares me to uncover a secret phrase from it. Can you assist? 

### Hint
- Download and try to reverse the python bytecode.
- https://docs.python.org/3/library/dis.html

### Solution
#### What we got ?
- First, we try to check what is the type of this file by using `file` command. And we can see, this is an ASCII text file. Using `strings` to get all the data from this file, then we will have the [`raw_data.txt`](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/weirdSnake/raw_data.txt) file.

![Ascii](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/weirdSnake/snake.png?raw=true)

#### How to get the flag ?
- We observed that, this is a python bytecode file. So let's try to analyze it:

    - This is the first part of code:
        ```python
        1     0 LOAD_CONST               0 (4)
              2 LOAD_CONST               1 (54)
              4 LOAD_CONST               2 (41)
              6 LOAD_CONST               3 (0)
              8 LOAD_CONST               4 (112)
             10 LOAD_CONST               5 (32)
             12 LOAD_CONST               6 (25)
             14 LOAD_CONST               7 (49)
             16 LOAD_CONST               8 (33)
             18 LOAD_CONST               9 (3)
             20 LOAD_CONST               3 (0)
             22 LOAD_CONST               3 (0)
             24 LOAD_CONST              10 (57)
             26 LOAD_CONST               5 (32)
             28 LOAD_CONST              11 (108)
             30 LOAD_CONST              12 (23)
             32 LOAD_CONST              13 (48)
             34 LOAD_CONST               0 (4)
             36 LOAD_CONST              14 (9)
             38 LOAD_CONST              15 (70)
             40 LOAD_CONST              16 (7)
             42 LOAD_CONST              17 (110)
             44 LOAD_CONST              18 (36)
             46 LOAD_CONST              19 (8)
             48 LOAD_CONST              11 (108)
             50 LOAD_CONST              16 (7)
             52 LOAD_CONST               7 (49)
             54 LOAD_CONST              20 (10)
             56 LOAD_CONST               0 (4)
             58 LOAD_CONST              21 (86)
             60 LOAD_CONST              22 (43)
             62 LOAD_CONST              23 (104)
             64 LOAD_CONST              24 (44)
             66 LOAD_CONST              25 (91)
             68 LOAD_CONST              16 (7)
             70 LOAD_CONST              26 (18)
             72 LOAD_CONST              27 (106)
             74 LOAD_CONST              28 (124)
             76 LOAD_CONST              29 (89)
             78 LOAD_CONST              30 (78)
             80 BUILD_LIST              40
             82 STORE_NAME               0 (input_list)
        ```
        - `LOAD_CONST` is responsible for loading a constant value onto the top of the evaluation stack. And `BUILD_LIST` is responsible for making a list. So the python code will look like this:
            ```python
            input_lst = [
                4, 54, 41, 0, 112, 32, 25, 49, 33, 3,
                0, 0, 57, 32, 108, 23, 48, 4, 9, 70,
                7, 110, 36, 8, 108, 7, 49, 10, 4, 86,
                43, 104, 44, 91, 7, 18, 106, 124, 89, 78
            ]
            ```
    - Moving to the second part:
        ```python
        2          84 LOAD_CONST              31 ('J')
                    86 STORE_NAME               1 (key_str)
        3          88 LOAD_CONST              32 ('_')
                    90 LOAD_NAME                1 (key_str)
                    92 BINARY_ADD
                    94 STORE_NAME               1 (key_str)
        4          96 LOAD_NAME                1 (key_str)
                    98 LOAD_CONST              33 ('o')
                    100 BINARY_ADD
                    102 STORE_NAME               1 (key_str)
        5         104 LOAD_NAME                1 (key_str)
                    106 LOAD_CONST              34 ('3')
                    108 BINARY_ADD
                    110 STORE_NAME               1 (key_str)
        6         112 LOAD_CONST              35 ('t')
                    114 LOAD_NAME                1 (key_str)
                    116 BINARY_ADD
                    118 STORE_NAME               1 (key_str)
        ```
        - This part will get the `key_str`, with the `BINARY_ADD` is an instruction that performs addition on the top two values of the Python Virtual Machine's stack.
        - This part will return `key_str = "t_Jo3""`
    - Next, moving to the processing part:
        ```python
        Disassembly of <code object <listcomp> at 0x7ff3b9776d40, file "snake.py", line 9>:
        9           0 BUILD_LIST               0
                    2 LOAD_FAST                0 (.0)
                >>    4 FOR_ITER                12 (to 18)
                    6 STORE_FAST               1 (char)
                    8 LOAD_GLOBAL              0 (ord)
                    10 LOAD_FAST                1 (char)
                    12 CALL_FUNCTION            1
                    14 LIST_APPEND              2
                    16 JUMP_ABSOLUTE            4
                >>   18 RETURN_VALUE
        Disassembly of <code object <listcomp> at 0x7ff3b9776df0, file "snake.py", line 15>:
        15           0 BUILD_LIST               0
                    2 LOAD_FAST                0 (.0)
                >>    4 FOR_ITER                16 (to 22)
                    6 UNPACK_SEQUENCE          2
                    8 STORE_FAST               1 (a)
                    10 STORE_FAST               2 (b)
                    12 LOAD_FAST                1 (a)
                    14 LOAD_FAST                2 (b)
                    16 BINARY_XOR
                    18 LIST_APPEND              2
                    20 JUMP_ABSOLUTE            4
                >>   22 RETURN_VALUE
        ```
        - With the part start from `line 9`, it has the `CALL_FUNCTION` combine with the data, which mean the code is use the function. This will return a list of ASCII codes of each character in the input iterable.
            ```python
            ord(char) for char in iterable
            ```
        - Moving to the remaining part, it has the `BINARY XOR`, so we can sure it will iterate over an iterable that yields pairs (a, b), unpacks them, XORs them, and appends the result.
            ```python
            [a ^ b for (a, b) in iterable]
            ```
- Base on the analysis, we get the code to get the flag:
    ```python
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
    ```
- Run this code and the flag is **`picoCTF{N0t_sO_coNfus1ng_sn@ke_7f44f566}`**
