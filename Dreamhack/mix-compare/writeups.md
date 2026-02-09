# mix-compare 
> Problem link: https://dreamhack.io/wargame/challenges/961

## Challenge Description
Chương trình đọc một chuỗi đầu vào có 64 ký tự và kiểm tra nó thông qua một loạt các phép kiểm tra dựa trên các giá trị được mã hóa cứng trong phần dữ liệu của binary. Nếu tất cả các kiểm tra đều pass, chương trình sẽ xuất ra "Nice!" và flag dưới dạng `DH{input}`.

## Phân Tích Chương Trình
### Luồng Chương Trình
1. **Đọc Đầu Vào**: Sử dụng `scanf("%127s", input)` để đọc tối đa 127 ký tự, nhưng yêu cầu chính xác 64 ký tự (`strlen(input) == 64`).
2. **Kiểm Tra**: Gọi `perform_full_check(input)`, thực hiện nhiều vòng lặp kiểm tra trên các phạm vi ký tự khác nhau sử dụng dữ liệu từ `result[]` và các biến `dword_*`.
3. **Xuất Ra**: Nếu hợp lệ, in "Nice!" và flag; ngược lại, in "good." (thông báo thất bại).

### Logic Kiểm Tra
Các kiểm tra được nhóm theo phạm vi chỉ số ký tự:

- **Chỉ số 0-15**: So sánh trực tiếp với các phép toán như `*a1 + 9`, `~a1[1]`, `a1[2] - 4`, v.v., so với `result[0]` đến `result[15]` và `dword_4024` đến `dword_405C`.
- **Chỉ số 16-25**: `(char)(~a1[i]) + i == result[i]`
- **Chỉ số 26-35**: `a1[i] + i == result[i]`
- **Chỉ số 36-45**: `a1[i] - i == result[i]`
- **Chỉ số 46-55**: `i * a1[i] == result[i]`
- **Chỉ số 56-63**: `a1[i] + 100 - i == result[i]`

## Quy Trình Reverse Engineering
- Trích xuất mảng `result[]` và các giá trị `dword_*` từ phần `.data` của binary bằng `readelf -x .data chall`.
- Giải từng phương trình cho ký tự tương ứng bằng cách đảo ngược các phép toán (ví dụ: cho phép cộng, trừ; cho phép nhân, chia; cho bitwise NOT, tính nghịch đảo).
- Xử lý số học char có dấu và ép kiểu trong các kiểm tra bitwise NOT.

## Các Bước Giải Cụ Thể
1. **Trích Xuất Dữ Liệu Từ Binary**:
   - Sử dụng `readelf -x .data chall` để dump phần `.data`.
   - Phân tích các số nguyên 4 byte little-endian bắt đầu từ offset 0x4020 cho `result[0]` đến `result[63]`.
   - Ví dụ: `result[0] = 0x00000039 = 57`, `result[1] = 0xffffff9b = -101`, v.v.

2. **Giải Cho Chỉ Số 0-15**:
   - Với mỗi i từ 0 đến 15, đảo ngược phép toán cụ thể:
     - i=0: `*a1 + 9 == 57` → `a1[0] = 57 - 9 = 48` → `'0'`
     - i=1: `~a1[1] == -101` → `a1[1] = ~(-101) & 0xFF` (xem xét ép kiểu char) → `'d'`
     - i=2: `a1[2] - 4 == 44` → `a1[2] = 44 + 4 = 48` → `'0'`
     - i=3: `2 * a1[3] == 198` → `a1[3] = 198 / 2 = 99` → `'c'`
     - Và tương tự cho từng công thức cụ thể.

3. **Giải Cho Chỉ Số 16-25**:
   - Với mỗi i, `(char)(~a1[i]) + i == result[i]`
   - Tính `y = result[i] - i`
   - `lower = y nếu y >= 0 else 256 + y`
   - `a1[i] = chr((~lower) & 0xFF)`
   - Ví dụ: i=16, result[16]=-85, y=-85-16=-101, lower=155, ~155=100 → `'d'`

4. **Giải Cho Chỉ Số 26-35**:
   - `a1[i] + i == result[i]` → `a1[i] = chr(result[i] - i)`
   - Ví dụ: i=26, 79 - 26 = 53 → `'5'`

5. **Giải Cho Chỉ Số 36-45**:
   - `a1[i] - i == result[i]` → `a1[i] = chr(result[i] + i)`
   - Ví dụ: i=36, 12 + 36 = 48 → `'0'`

6. **Giải Cho Chỉ Số 46-55**:
   - `i * a1[i] == result[i]` → `a1[i] = chr(result[i] // i)`
   - Ví dụ: i=46, 2392 // 46 = 52 → `'4'`

7. **Giải Cho Chỉ Số 56-63**:
   - `a1[i] + 100 - i == result[i]` → `a1[i] = chr(result[i] - 100 + i)`
   - Ví dụ: i=56, 99 - 100 + 56 = 55 → `'7'`

- Source code:
    ```python
    result = [57, -101, 44, 198, 89, 88, 57, 171, -50, 198, 396, 400, -38, 115, 82, 102, -85, -81, -39, -83, -82, -80, -78, -32, -30, -31, 79, 83, 76, 83, 79, 87, 131, 84, 89, 135, 12, 19, 62, 59, 62, 57, 58, 56, 13, 52, 2392, 2350, 2592, 4851, 2800, 5202, 2964, 5300, 2646, 2970, 99, 95, 143, 89, 140, 137, 140, 85]

    flag = ''

    for i in range(64):
        if i < 16:
            if i == 0:
                flag += '0'
            elif i == 1:
                flag += 'd'
            elif i == 2:
                flag += '0'
            elif i == 3:
                flag += 'c'
            elif i == 4:
                flag += '7'
            elif i == 5:
                flag += '0'
            elif i == 6:
                flag += 'a'
            elif i == 7:
                flag += '9'
            elif i == 8:
                flag += '1'
            elif i == 9:
                flag += 'c'
            elif i == 10:
                flag += 'c'
            elif i == 11:
                flag += 'd'
            elif i == 12:
                flag += '9'
            elif i == 13:
                flag += 'b'
            elif i == 14:
                flag += '4'
            elif i == 15:
                flag += 'f'
        elif i < 26:
            r = result[i]
            y = r - i
            lower = y if y >= 0 else 256 + y
            x = (~lower) & 0xFF
            flag += chr(x)
        elif i < 36:
            flag += chr(result[i] - i)
        elif i < 46:
            flag += chr(result[i] + i)
        elif i < 56:
            flag += chr(result[i] // i)
        else:
            flag += chr(result[i] - 100 + i)

    print(len(flag))
    print(repr(flag))
    ```

## Flag
Bằng cách giải tất cả các phương trình, chuỗi đầu vào là: `0d0c70a91ccd9b4fda8eedc657580618c37d08dbfbdc9a426c8f9d1674e0dbf0`

Do đó, flag là: `DH{0d0c70a91ccd9b4fda8eedc657580618c37d08dbfbdc9a426c8f9d1674e0dbf0}`