# Lệnh số học

## Lệnh cộng
### `add`
- Syntax:
    ```asm
    add     a, b, c     // a,b,c: Register's Name
    ```
- Meaning:
    ```c++
    reg[a] = reg[b] + reg[c]
    ```
    - Lệnh `add` sẽ thực hiện cộng giá trị trên register `b` và `c`, sau đó đưa tổng vào register `a`.
    - Ví dụ:
        ```asm
        // $t1 = 1; $t2 = 2
        add     $t0, $t1, $t2
        ```
        - Khi đó giá trị trong register `$t0` là `1 + 2 = 3`
### `addi`
- Syntax:
    ```asm
    addi    rt, rs, val     // rt, rs: Register's Name;  val: current value
    ```
- Meaning:
    ```c++
    reg[rt] = reg[rs] + signVal
    ```
    - Lệnh `addi` sẽ thực hiện cộng giá trị lưu trên register `rs` với giá trị `val`, sau đó lưu vào register `rt`.
    - Giới hạn cho giá trị `val` là 16 bit (2 bytes). Giá trị `val` trước khi được cộng với register `rs` sẽ được mở rộng có dấu, biểu diễn **bù 2** (`val --> signVal`) thành số 32 bit (4 bytes).
    - Khi giá trị `val` vượt quá giới hạn của số 16 bit có dấu (`[-32,768 to 32,767]`), lệnh sẽ bị báo lỗi (Overflow).
    - Ví dụ:
        ```
        a)	addi $t0, $t1, 3
        b)	addi $t0, $t1, -3
        c)	addi $t0, $t1, 32768
        Giả sử giá trị đang chứa trong thanh ghi $t1 cho cả 3 câu đều là 4

        Kết quả:
        a) Sau khi addi thực hiện xong, giá trị của $t0 là 7
        Quy trình lệnh thực hiện:
        số tức thời là 3(10) = 0000 0000 0000 0011(2) (số 16 bit có dấu)
        SignExtImm của 3(10) = 0000 0000 0000 0000 0000 0000 0000 0011(2)
        Giá trị thanh ghi $t1   = 0000 0000 0000 0000 0000 0000 0000 0100(2)

        Giá trị trong $t1 + SingExtImm của 3(10) = 0000 0000 0000 0000 0000 0000 0000 0111(2)

        b) Sau khi addi thực hiện xong, giá trị của $t0 là 1
        Quy trình lệnh thực hiện:
        số tức thời là -3(10) = 1111 1111 1111 1101(2) (số 16 bit có dấu, biểu diễn theo bù 2)
        SignExtImm của 3(10) = 1111 1111 1111 1111 1111 1111 1111 1101 (2)
        Giá trị thanh ghi $t1   = 0000 0000 0000 0000 0000 0000 0000 0100(2)

        Giá trị trong $t1 + SingExtImm của 3(10) = 0000 0000 0000 0000 0000 0000 0000 0001(2)

        c) Lệnh bị báo lỗi, do 32768 ra khỏi giới hạn của số 16 bits có dấu
        ```

### `addiu` - `addu`
- Syntax:
    ```asm
    addu    rd, rs, rt      // rd, rs, rt: Register's Name
    addiu   rt, rs, val     // rt, rs: Register's Name;  val: current value
    ```
- Meaning:
    - `addu` hoạt động giống với `add`
    - `addiu` hoạt động giống với `addi`
    - 2 lệnh này không xét kết quả có bị overflow hay không, trong khi đó addi và add sẽ báo khi overflow xuất hiện 

## Lệnh trừ
### `sub`
- Syntax:
    ```asm
    sub     rd, rs, rt      // rd, rs, rt: Register's Name
    ```
- Meaning: 
    ```c++
    reg[rd] = reg[rs] - reg[rt]
    ```
    - Lệnh này thực hiện trừ giá trị trong 2 register `rs` và `rt`, sau đó lưu vào register `rd`.
### `subu`
- Syntax:
    ```asm
    subu     rd, rs, rt      // rd, rs, rt: Register's Name
    ```
- Meaning: Tương tự `sub`, tuy nhiên `subu` sẽ không xét Overflow.