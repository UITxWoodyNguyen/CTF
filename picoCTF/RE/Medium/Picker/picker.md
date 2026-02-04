# Picker

### Information
* Category: Reverse Engineering
* Point:
* Level: Medium

## Picker I
### Description
This service can provide you with a random number, but can it do anything else?
Connect to the program with netcat: `$ nc saturn.picoctf.net <port>`

### Hint
Can you point the program to a function that does something useful for you?

### Solution
#### What we got ?
- The problem tells us to connect to the server via netcat. Moreover, it provides us with the [source code](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Picker/picker_I/picker-I.py).
- We can observed that, this code requires a random input (maybe numbers or , maybe a name of function).
- We also have `C/C++` code in this source code. However, we don't have to care about it.

#### How to get the flag ?
- We observed that, we can run the function we want instead of `getRandomumber()`. Moreover, only the `win()` function can return to a list of hex value, which can be the flag of this problem. When connect to the server via netcat and use `"win"` as the input, we received a list of hex value:
```
Try entering "getRandomNumber" without the double quotes...
==> win
0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x34 0x5f 0x64 0x31 0x34 0x6d 0x30 0x6e 0x64 0x5f 0x31 0x6e 0x5f 0x37 0x68 0x33 0x5f 0x72 0x30 0x75 0x67 0x68 0x5f 0x36 0x65 0x30 0x34 0x34 0x34 0x30 0x64 0x7d 
```

- Convert this list into text, then we will get the flag:
```python
hex_vals = [
    0x70, 0x69, 0x63, 0x6f, 0x43, 0x54, 0x46, 0x7b, 0x34, 0x5f, 0x64,
    0x31, 0x34, 0x6d, 0x30, 0x6e, 0x64, 0x5f, 0x31, 0x6e, 0x5f, 0x37,
    0x68, 0x33, 0x5f, 0x72, 0x30, 0x75, 0x67, 0x68, 0x5f, 0x36, 0x65,
    0x30, 0x34, 0x34, 0x34, 0x30, 0x64, 0x7d
]

decoded = ''.join(chr(x) for x in hex_vals)
print(decoded)
```
---
## Picker II
### Description
Can you figure out how this program works to get the flag?
Connect to the program with netcat: `$ nc saturn.picoctf.net <port>`

### Hint
- Can you do what `win` does with your input to the program?

### Solution
#### What we got ?
- First, check the [source code](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Picker/picker_II/picker-II.py) of this problem.
- We observed that, the script basically provides an input loop where the user types a function name (same ans "Picker I). However, the difference in this source code is the `filter()` function, which prevent users from running the `win()` function.
```python
def filter(user_input):
  if 'win' in user_input:
    return False
  return True
```

#### How to get the flag ?
- We can see the contents of the flag is read in the `win()` function, but it can be run because of the `filter()` function.
- So we have tried to print out the flag after it being read by using this command:
```
print(open('flag.txt', 'r').read())
```

![Result](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Picker/picker_II/image-II-1.png?raw=true)

---
## Picker III
### Description
Can you figure out how this program works to get the flag?
Connect to the program with netcat: `$ nc saturn.picoctf.net <port>`

### Hint
Is there any way to modify the function table?

### Solution
#### What we got ?
- First, check the server's [source code](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Picker/picker_III/picker-III.py).
- Overall, this code sets up a fixed-size function table and only allows calling functions through numeric choices, but the variable read/write system still allows arbitrary code execution through `eval` and `exec`, meaning an attacker can modify the function table or variables to eventually call the `win()` function and leak the flag.
- So we can observed that, the `win()` can be the key to get the flag

#### How to get the flag ?
- First, using "?" to figure out the usage of this code

![Usage](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Picker/picker_III/pick-III_1.png?raw=true)

- Moreover, the program allows changing the value of global variables via `exec()` in `write_variable()`. So we can use this function to change the `getRandomNumver()` to `win()`. After changing, the code retrun to a list of hex value, we can decode in the same way as "Picker I".

![Change](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Picker/picker_III/picker-III.png?raw=true)

```python
hex_vals = [
    0x70, 0x69, 0x63, 0x6f, 0x43, 0x54, 0x46, 0x7b, 0x37, 0x68, 0x31, 0x35, 0x5f, 0x31, 0x35, 0x5f, 0x77, 0x68, 0x34, 0x37, 0x5f, 0x77, 0x33, 0x5f, 0x67, 0x33, 0x37, 0x5f, 0x77, 0x31, 0x37, 0x68, 0x5f, 0x75, 0x35, 0x33, 0x72, 0x35, 0x5f, 0x31, 0x6e, 0x5f, 0x63, 0x68, 0x34, 0x72, 0x67, 0x33, 0x5f, 0x61, 0x31, 0x38, 0x36, 0x66, 0x39, 0x61, 0x63, 0x7d
]

decoded = ''.join(chr(x) for x in hex_vals)
print(decoded)
```
