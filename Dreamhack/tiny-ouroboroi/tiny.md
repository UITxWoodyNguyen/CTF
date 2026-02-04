# tiny-ouroboroi

## Information

- Category: RE
- Level: 2
- Problem Source: Dreamhack

## Solution

### What we got ?

- Ta nhận được một file `.zip` từ đề bài. Tiến hành giải nén, ta nhận được một file output với định dạng `.bin` và một file `main`của chương trình chính.
- Tiến hành decompile file main bằng IDA và kiểm tra source code. Cụ thể:
    - `main`:
    
    ```c
    __int64 __fastcall main(int a1, char **a2, char **a3)
    {
      unsigned int i; // [rsp+4h] [rbp-91Ch]
      int j; // [rsp+8h] [rbp-918h]
      int v6; // [rsp+Ch] [rbp-914h]
      _QWORD v7[256]; // [rsp+10h] [rbp-910h] BYREF
      char s[264]; // [rsp+810h] [rbp-110h] BYREF
      unsigned __int64 v9; // [rsp+918h] [rbp-8h]
    
      v9 = __readfsqword(0x28u);
      __isoc99_scanf(&unk_2004, s, a3);
      v6 = strlen(s);
      for ( i = 0; (int)i < v6; ++i )
      {
        sub_11C9(&v7[i], (unsigned int)s[i]);
        sub_126C(&v7[i], i);
        if ( (i & 1) != 0 )
          sub_12A5(&v7[i]);
      }
      for ( j = 0; j < v6; ++j )
        sub_12EE(&v7[j]);
      return 0;
    }
    ```
    
    - Ta nhận thấy main sẽ đọc input vào một string và thực hiện mã hoá qua bốn hàm `sub_11C9(), sub_126C(), sub_12A5(), sub_12EE()`.
    
    ```c
    _DWORD *__fastcall sub_11C9(void **a1, char a2)
    {
      int i; // [rsp+14h] [rbp-Ch]
      _DWORD *v4; // [rsp+18h] [rbp-8h]
    
      for ( i = 0; i <= 7; ++i )
      {
        if ( i )
        {
          *(_QWORD *)v4 = malloc(0x10u);
          v4 = *(_DWORD **)v4;
        }
        else
        {
          *a1 = malloc(0x10u);
          v4 = *a1;
        }
        v4[2] = ((a2 >> (7 - i)) & 1) != 0;
      }
      *(_QWORD *)v4 = *a1;
      return v4;
    }
    ```
    
    - Đối với `sub_11C9()`,  hàm sẽ thực hiện chuyển input thành cấu trúc bit. Cụ thể, hàm sẽ tạo một Linked List vòng gồm 8 node, mỗi node chứa 1 bit của ký tự input (từ bit cao đến thấp). Mỗi node có trường thứ 3 (`v4[2]`) lưu giá trị bit tương ứng. Kết quả sẽ trả về con trỏ đầu List.
    
    ```c
    __int64 __fastcall sub_126C(_QWORD **a1, int a2)
    {
      __int64 result; // rax
      unsigned int i; // [rsp+18h] [rbp-4h]
    
      for ( i = 0; ; ++i )
      {
        result = i;
        if ( (int)i >= a2 )
          break;
        *a1 = (_QWORD *)**a1;
      }
      return result;
    }
    ```
    
    - Đối với `sub_126C()`, hàm sẽ thực hiện rotate left theo từng kí tự cho mỗi vị trí. Cụ thể, hàm thực hiện dịch vòng con trỏ trong danh sách liên kết sang trái `a2` lần (a2 là chỉ số ký tự trong chuỗi). Hàm không thay đổi giá trị bit, chỉ thay đổi vị trí bắt đầu của danh sách.
    
    ```c
    __int64 *__fastcall sub_12A5(__int64 **a1)
    {
      __int64 *result; // rax
      __int64 *v2; // [rsp+10h] [rbp-8h]
    
      v2 = *a1;
      do
      {
        *((_DWORD *)v2 + 2) = *((_DWORD *)v2 + 2) == 0;
        v2 = (__int64 *)*v2;
        result = *a1;
      }
      while ( v2 != *a1 );
      return result;
    }
    ```
    
    - Đối với `sub_12A5()`, nếu chỉ số ký tự là lẻ, hàm này sẽ đảo bit của từng node trong danh sách liên kết (0 thành 1, 1 thành 0).
    
    ```c
    int __fastcall sub_12EE(__int64 **a1)
    {
      char v2; // [rsp+17h] [rbp-9h]
      __int64 *v3; // [rsp+18h] [rbp-8h]
    
      v2 = 0;
      v3 = *a1;
      do
      {
        v2 = *((_DWORD *)v3 + 2) | (2 * v2);
        v3 = (__int64 *)*v3;
      }
      while ( v3 != *a1 );
      return putchar(v2);
    }
    ```
    
    - Đối với `sub_12EE()`, hàm thực hiện duyệt qua từng node trong danh sách liên kết, ghép lại thành 1 byte (bit shift và OR), và in ra kí tự tương ứng với byte đó.
- Tiến hành kiểm tra file output bằng cat, ta nhận thấy mỗi byte sẽ ứng với một kí tự đã được mã hoá từ input.

### How to get flag ?

- Từ phần phân tích, ta có script lấy flag như sau
    
    ```python
    def invert_bits(bits):
        return [0 if b else 1 for b in bits]
    
    def rotate_bits(bits, n):
        n = n % 8
        return bits[n:] + bits[:n]
    
    def bits_to_byte(bits):
        val = 0
        for b in bits:
            val = (val << 1) | b
        return val
    
    def byte_to_bits(c):
        return [(c >> (7 - i)) & 1 for i in range(8)]
    
    def encode_char(ch, idx):
        bits = byte_to_bits(ch)
        bits = rotate_bits(bits, idx)
        if idx % 2 == 1:
            bits = invert_bits(bits)
        return bits_to_byte(bits)
    
    with open("output.bin", "rb") as f:
        data = f.read()
        recovered = ""
        for idx, out_byte in enumerate(data):
            found = False
            for c in range(32, 127):  # printable ASCII
                if encode_char(c, idx) == out_byte:
                    recovered += chr(c)
                    found = True
                    break
            if not found:
                recovered += '?'
        print("Recovered input:", recovered)
    ```
    
- Flag tìm được là **`DH{bac93c27e6c3578afd93d2eec7edb24e61da8e9c99567ecec9e7f554093b0cdc}`**
