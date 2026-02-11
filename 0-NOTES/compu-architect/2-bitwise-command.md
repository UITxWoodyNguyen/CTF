# Lệnh logic

## `and/andi`
- Syntax:
    ```asm
    and     rd, rs, rt      // rd, rs, rt: Register's Name
    andi    rd, rs, val     // rd, rs: Register's Name; val: Current value (16 bits)
    ```
- Meaning:
    ```c++
    // and command
    reg[rd] = res[rs] & reg[rt];

    // andi command
    reg[rd] = reg[rs] & val;
    ```

    - `and` sẽ thực hiện phép logic AND với giá trị trên 2 register `rs` và `rt`, sau đó lưu vào register `rd`.
    - `andi` sẽ thực hiện phép logic AND giá trị trên register `rs` và giá trị tức thời `val`, sau đó lưu vào register `rd`.
    - Giá trị tức thời `val` có giới hạn đầu vào 16 bits, mở rộng lên 32 bits (fill 16 bit `0` vào bit thứ 16 đến 31) khi thực hiện phép AND.
    - `val` **không là số âm**

## `or/ori/nor`
- Syntax:
    ```asm
    or      rd, rs, rt
    ori     rd, rs, val
    nor     rd, rs, rt
    ```
- Meaning: tương tự lệnh `and`, thay thể phép logic AND bằng OR/NOR.
    ```c++
    // or command
    reg[rd] = reg[rs] | reg[rt];

    // ori command
    reg[rd] = res[rs] | val;

    // nor command
    reg[rd] = ~(reg[rs] | reg[rt]);
    ```
- Quy tắc mở rộng giá trị tức thời không đổi (`16 bits --> 32 bits`, fill 16 bits `0` vào bit thứ 16 đến 31).

## `sll/srl` (Shift left/right logical)
- Syntax:
    ```asm
    sll     rd, rs, count
    srl     rd, rs, count
    ```
- Meaning:
    ```c++
    // sll command
    reg[rd] = reg[rs] << count; // dịch trái "count" bit, sau đó lưu vào rd

    // srl command
    reg[rd] = reg[rs] >> count; // dịch phải "count" bit, sau đó lưu vào rd
    ```