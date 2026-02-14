# Vigenère

### Thông tin

-   Category: Cryptography
-   Points:
-   Level: Medium

------------------------------------------------------------------------

### Mô tả

Hãy giải mã thông điệp sau bằng khóa **"CYLAB"**.

Ciphertext:

    rgnoDVD{O0NU_WQ3_G1G3O3T3_A1AH3S_cc82272b}

------------------------------------------------------------------------

### Gợi ý

-   Đây là một dạng mã hóa cổ điển.
-   Khóa sẽ được lặp lại tuần hoàn.

------------------------------------------------------------------------

## Lời giải

Bài này sử dụng **mã Vigenère**, một dạng mã thay thế đa bảng chữ cái.

Trong Vigenère:

-   Mỗi ký tự của khóa tương ứng với một giá trị dịch (shift).
-   Nếu khóa ngắn hơn ciphertext thì khóa sẽ lặp lại.
-   Công thức giải mã:

P = (C - K) mod 26

Trong đó: - C: giá trị ký tự ciphertext - K: giá trị dịch từ khóa - P:
ký tự plaintext

------------------------------------------------------------------------

### Bước 1 --- Chuyển khóa thành giá trị dịch

Khóa: CYLAB

  Ký tự   Shift
  ------- -------
  C       2
  Y       24
  L       11
  A       0
  B       1

Khóa sẽ lặp lại trong suốt quá trình giải mã.

------------------------------------------------------------------------

### Bước 2 --- Logic giải mã

Với mỗi ký tự:

1.  Kiểm tra xem có phải chữ cái không.
2.  Xác định base ('A' hoặc 'a') để giữ nguyên hoa/thường.
3.  Tính shift từ ký tự khóa.
4.  Áp dụng công thức:

((ord(c) - ord(base) - shift + 26) % 26) + ord(base)

5.  Chuyển lại thành ký tự.

------------------------------------------------------------------------

### Script Python

``` python
def vigenere_decrypt(cipher, key):
    result = ""
    key_index = 0

    for c in cipher:
        if c.isalpha():
            base = 'A' if c.isupper() else 'a'
            shift = ord(key[key_index % len(key)].lower()) - ord('a')
            decrypted = chr((ord(c) - ord(base) - shift + 26) % 26 + ord(base))
            result += decrypted
            key_index += 1
        else:
            result += c

    return result


cipher = "rgnoDVD{O0NU_WQ3_G1G3O3T3_A1AH3S_cc82272b}"
key = "CYLAB"

print(vigenere_decrypt(cipher, key))
```

------------------------------------------------------------------------

### Flag cuối cùng

    picoCTF{D0NT_US3_V1G3N3R3_C1PH3R_ae82272q}
