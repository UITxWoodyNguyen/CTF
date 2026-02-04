# Classic Crackme 0x100

### Information
* Category: Reverse Engineering
* Point:
* Level: Medium

### Description
Crack the Binary file locally and recover the password. Use the same password on the server to get the flag! 
Access the server using `nc titan.picoctf.net <port>`

### Hint
- Let the machine figure out the symbols!

### Solution
#### What we got ?
- First, decompiler the binary file by using Ghidra tools at https://dogbolt.org and we will receive a [`crackme.c`](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Classic%20Crackme%200x100/crack/crackme.c) file.
- So what is the process of this code ?

    - We have found the correct password. However, it has been transformed:
    ```c
    builtin_strncpy(output,"kgxmwpbpuqtorzapjhfmebmccvwycyvewpxiheifvnuqsrgexl",0x33);
    ```
    - Moreover, we can see the encryption process of the password:
    ```c
    sVar3 = strlen(output);
    for (; i < 3; i = i + 1) {
        for (i_1 = 0; i_1 < (int)sVar3; i_1 = i_1 + 1) {
        uVar1 = (i_1 % 0xff >> 1 & 0x55U) + (i_1 % 0xff & 0x55U);
        uVar1 = ((int)uVar1 >> 2 & 0x33U) + (uVar1 & 0x33);
        iVar2 = ((int)uVar1 >> 4) + input[i_1] + -0x61 + (uVar1 & 0xf);
        input[i_1] = (char)iVar2 + (char)(iVar2 / 0x1a) * -0x1a + 'a';
        }
    }
    ```
    - For each character in the password:
        
        - `uVar1` computes a deterministic pattern based on the index `i_1`. It resembles bit-twiddling used in parity/bit-count calculations.
        - The program adds `uVar1` and (`uVar1 & 0xf`) to the character value.
        - The result is wrapped back into the range `'a'..'z'` using modulo 26.
        - This transformation repeats **3 times**.
    - So we need to reverse this process to get the raw password.

#### How to get the flag ?
- Base on the usage of the above code, we have the decrypt code:
```python
# recover.py - đảo ngược phép biến đổi để lấy mật khẩu gốc

output = "kgxmwpbpuqtorzapjhfmebmccvwycyvewpxiheifvnuqsrgexl"

def compute_u(i):
    i = i & 0xff
    u = ((i >> 1) & 0x55) + (i & 0x55)
    u = ((u >> 2) & 0x33) + (u & 0x33)
    return u

def shift_for_index(i):
    u = compute_u(i)
    return ((u >> 4) + (u & 0xf))

def invert_one_round(s):
    """Áp dụng phép đảo ngược 1 vòng lên chuỗi s (trừ shift modulo 26)."""
    res = []
    for i, ch in enumerate(s):
        sh = shift_for_index(i)
        val = (ord(ch) - 97 - sh) % 26
        res.append(chr(val + 97))
    return "".join(res)

def forward_one_round(s):
    """Áp dụng phép tiến 1 vòng lên chuỗi s (cộng shift modulo 26)."""
    res = []
    for i, ch in enumerate(s):
        sh = shift_for_index(i)
        val = (ord(ch) - 97 + sh) % 26
        res.append(chr(val + 97))
    return "".join(res)

def main():
    cur = output
    # Đảo ngược 3 lần (vì chương trình gốc áp dụng 3 lần)
    for _ in range(3):
        cur = invert_one_round(cur)

    password = cur
    print("Recovered password to input:")
    print(password)
    print()

if __name__ == "__main__":
    main()
```

- Run this code and we will receive the correct raw password.
```
password = "kdugtjvgrknflqrdgbzdysdqwmnmtmjptjrzbvztpelejfuprc"
```
- Connect to the server via netcat and use this password to get the flag.
![Answer](https://github.com/UITxWoodyNguyen/CTF/blob/main/Reverse%20Engineering/Medium/Classic%20Crackme%200x100/crack/Screenshot%20From%202025-11-23%2007-00-01.png?raw=true)
