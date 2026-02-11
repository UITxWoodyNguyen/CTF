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
    - 2 lệnh này không xét kết quả có bị overflow hay không, trong khi đó `addi` và `add` sẽ báo khi overflow xuất hiện 

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

## Lệnh so sánh
### `slt/sltu` (Set less than)
- Syntax:
    ```asm
    slt     rd, rs, rt      // rd, rs, rt: Register's Name
    sltu    rd, rs, rt      
    ```
- Meaning:
    ```c++
    reg[rd] = (reg[rs] < reg[rt]) ? 1 : 0;
    ```
    - Lệnh sẽ thực hiện so sánh 2 giá trị trên 2 register `rs` và `rt`. Nếu giá trị trên `rs` bé hơn `rt`, giá trị của register `rd` sẽ nhận là 1, ngược lại là 0.
    - `slt` thực hiện trên số có dấu
    - `sltu` thực hiện trên số không dấu.
- Ví dụ:
    ```
    a. slt $t0, $t1, $t2
    Giả sử $t1 = 0xfffffff1, $t2 = 0x00000073
    Kết quả: $t0 = 1
        Lệnh slt so sánh theo kiểu so sánh 2 số có dấu dạng bù 2
    $t1 = 0xfffffff1 = 1111 1111 1111 1111 1111 1111 1111 0001(2) = -15(10)
    $t2 = 0x00000073 = 01110011(2) = 115(10)
        Vậy $t1 < $t2 --> giá trị trong thanh ghi $t0 = 1

    b. sltu $t0, $t1, $t2
    Giả sử $t1 = 0xfffffff1, $t2 = 0x00000073
    Kết quả: $t0 = 0
    Lệnh slt so sánh theo kiểu so sánh 2 số không dấu
    $t1 = 0xfffffff1 = 1111 1111 1111 1111 1111 1111 1111 0001(2) = 4294967281(10)
    $t2 = 0x00000073 = 01110011(2) = 115(10)
        Vậy $t1 > $t2 --> giá trị trong thanh ghi $t0 = 0
    ```

### `slti/sltiu`
- Syntax:
    ```asm
    slti     rd, rs, val      // rd, rs: Register's Name
    sltiu    rd, rs, val      // val: current value
    ```
- Meaning:
    ```c++
    reg[rd] = (reg[rs] < val) ? 1 : 0;
    ```
    - Lệnh sẽ thực hiện so sánh giá trị trên register `rs` với một giá trị tức thời `val`. Nếu giá trị trên `rs` bé hơn `val`, giá trị trên register `rd` sẽ nhận là 1, ngược lại là 0.
    - Giá trị tức thời được cho phép trong giới hạn 16 bits, mở rộng lên 32 bits khi thực hiện so sánh.
    - `slti` so sánh số ở dạng **bù 2**
    - `sltiu` so sánh theo kiểu không dấu.
- Ví dụ:
    ```
    c. slti $t0, $t1, 0x73
    Giả sử $t1 = 0xfffffff1
    Kết quả: $t0 = 1
        Lệnh slt so sánh theo kiểu so sánh 2 số có dấu dạng bù 2
    $t1 = 0xfffffff1 = 1111 1111 1111 1111 1111 1111 1111 0001(2) = -15(10)
    Số tức thời = 0x73 = 01110011(2) 
    SignExtImm(0x73) = 0000 0000 0000 0000 0000 0000 0111 0011(2) = 115(10)
        Vậy $t1 < $t2 --> giá trị trong thanh ghi $t0 = 1

    d. sltiu $t0, $t1, 0x83
    Giả sử $t1 = 0xfffffff1
    Kết quả: $t0 = 0
    Lệnh slt so sánh theo kiểu so sánh 2 số không dấu
    $t1 = 0xfffffff1 = 1111 1111 1111 1111 1111 1111 1111 0001(2) = 4294967281(10)
    $t2 = 0x83 = 10000011(2)
    SignExtImm(0x83) = 1111 1111 1111 1111 1111 1111 1000 0011(2) = 4294967171(10)
        Vậy $t1 > $t2 --> giá trị trong thanh ghi $t0 = 0
    ```

## Summarize
| Command | Syntax | Usage | Special |
| :--: | :--: | :--: | :--: |
| `add` | `add  $a, $b, $c` | Cộng giá trị trên 2 thanh ghi | Thông báo **Overflow** ngay khi phát hiện (vd: dương + dương ra số âm...) |
| `addi` | `addi $a, $b, val` | Cộng giá trị trên 1 thanh ghi với một giá trị tức thời | Giới hạn của giá trị tức thời là 16bit. Thông báo **Overflow** ngay khi phát hiện |
| `addu` | `addu  $a, $b, $c` | Cộng giá trị trên 2 thanh ghi | Không báo **Overflow**, vẫn thực hiện phép tính bình thường |
| `addiu` | `addiu  $a, $b, val` | Cộng giá trị trên 1 thanh ghi với một giá trị tức thời | Giới hạn của giá trị tức thời là 16bit. Không thông báo **Overflow**, vẫn thực hiện phép tính bình thường |
| `sub` | `sub  $a, $b, $c` | Trừ giá trị trên 2 thanh ghi | Thông báo khi kết quả bị **Overflow** |
| `subu` | `subu  $a, $b, $c` | Trừ giá trị trên 2 thanh ghi | Không thông báo khi kết quả bị **Overflow** |
| `slt` | `slt $a, $b, $c` | So sánh giá trị trên 2 thanh ghi `$b` và `$c`. `$a = 1` khi `$b < $c`, ngược lại bằng 0 | Thực hiện so sánh trên số **có dấu dạng bù 2** |
| `sltu` | `sltu $a, $b, $c` | So sánh giá trị trên 2 thanh ghi `$b` và `$c`. `$a = 1` khi `$b < $c`, ngược lại bằng 0 | Thực hiện so sánh trên số **không dấu** |
| `slti` | `slti $a, $b, val` | So sánh giá trị trên thanh ghi `$b` với giá trị tức thời `val`. `$a = 1` khi `$b < val`, ngược lại bằng 0 | Limitation của giá trị tức thời là 16 bits, mở rộng lên 32 bits khi so sánh. Thực hiện phép so sánh trên số **có dấu dạng bù 2** |
| `sltiu` | `sltiu $a, $b, val` | So sánh giá trị trên thanh ghi `$b` với giá trị tức thời `val`. `$a = 1` khi `$b < val`, ngược lại bằng 0 | Limitation của giá trị tức thời là 16 bits, mở rộng lên 32 bits khi so sánh. Thực hiện phép so sánh trên số **không dấu** | 