#!/usr/bin/env python3
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

