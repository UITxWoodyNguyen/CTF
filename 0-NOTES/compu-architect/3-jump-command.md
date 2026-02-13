# Lệnh nhánh/nhảy (Branch/Jump)

## `beq`
- Syntax:
    ```asm
    beq     rs, rt, label/imm
    ```
- Meaning:
    ```c++
    if (reg[rs] == reg[rt]) {
        do: *label;
    }
    ```

    - Lệnh `beq` sẽ thực hiện kiểm tra giá trị 2 thanh ghi `rs`, `rt`. Nếu bằng nhau sẽ thực hiện nhảy/lệnh nhánh (chạy `label`).
    - **Case 1**: `label` là một nhãn được viết bằng chữ. Ví dụ:
        ```asm
        beq     $t1, $t2, label_A
        add     $s0, $t3, $t4
        addi    $s0, $t2, 5

        label_A:    or      $t1, $t2, $t3
                    subu    $t3, $t4, $t5
        ```
        - Trong case này, nếu giá trị trên 2 thanh ghi `$t1` và `$t2` bằng nhau, máy tính sẽ nhảy đến nhãn `label_A` để thực hiện lần lượt `or`, `subu`.
        - Sau khi tất cả các lệnh thuộc nhãn `label_A` được thực hiện, máy tính mới thực hiện tiếp các lệnh tiếp theo (không quay ngược lại)
        - Mã giả cho case này:
            ```c++
            void try (int &a, int b, int &c, int d, int e) {
                a = b | c;
                c = d - e;
            }

            int main () {
                // variable here ...
                // for example a = 3, b = 3
                if (a == b) try(a, b, c, d, e);
            }
            ```
        - Ngược lại, nếu giá trị trên 2 thanh ghi `$t1` và `$t2` khác nhau, máy tính sẽ thực thi các lệnh theo trình tự từ trên xuống dưới. Flow cụ thể:
            ```c++
            void try (int &a, int b, int &c, int d, int e) {
                a = b | c;
                c = d - e;
            }

            int main () {
                // variable here ...
                // for example a = 2, b = 3
                if (a == b) try(a, b, c, d, e); // skip, since a != b
                sum = c + d;
                sum = b + 5;
                try(a, b, c, d, e);
            }
            ```
    - **Case 2**: `label` là số cụ thể. Ví dụ
        ```asm
        beq     $t1, $t2, 2
        add     $s0, $t3, $t4
        addi    $s0, $t2, 5
        or      $t1, $t2, $t3
        subu    $t3, $t4, $t5
        ```
        - Cách so sánh tương tự như **Case 1**, tuy nhiên lúc này `label` là một số nguyên cụ thể nên máy tính sẽ thực hiện lệnh **cách lệnh `beq` 2 lệnh** (nếu so sánh đúng), sau đó thực hiện tiếp các lệnh tiếp theo (không quay ngược lại)
        - Thực tế:
            ```
            - Step 0:
                | beq | add | addi | or | subu |    // Command
                |  0  |  1  |   2  |  3 |  4   |    // Command's pos
                   |
                  *pc
            - Step 1: compare $t1, $t2 --> true
                | beq | add | addi | or | subu |
                |  0  |  1  |   2  |  3 |  4   |
                                      |
                                     *pc
            - Step 2: Continue the flow to the end
                | beq | add | addi | or | subu |
                |  0  |  1  |   2  |  3 |  4   |
                                           |
                                          *pc
            ```
        - Ngược lại, nếu so sánh sai, máy tính sẽ thực hiện lần lượt các lệnh từ trên xuống dưới

## `bne`
- Syntax:
    ```asm
    bne     rs, rt, label
    ```
- Meaning:
    ```c++
    if (reg[rs] != reg[rt]) {
        do: *label
    }
    ```

## `bge/bgt`
- Syntax:
    ```asm
    bge     rs, rt, label
    bgt     rs, rt, label
    ```
- Meaning:
    ```c++
    // bge command
    if (reg[rs] >= reg[rt]) {
        do: *label
    }

    // bgt command
    if (reg[rs] > reg[rt]) {
        do: *label
    }
    ```

## `ble/blt`
- Syntax:
    ```asm
    ble     rs, rt, label
    blt     rs, rt, label
    ```
- Meaning:
    ```c++
    // bge command
    if (reg[rs] <= reg[rt]) {
        do: *label
    }

    // bgt command
    if (reg[rs] < reg[rt]) {
        do: *label
    }
    ```