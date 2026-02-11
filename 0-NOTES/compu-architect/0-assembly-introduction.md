# MIPS Notes

## Kí hiệu số
- Trong MIPS, kí hiệu `0x` được sử dụng chỉ hệ 16 (Hexadecimal):
    ```bash
    0xFFFF = FFFF (16) = 65.535 (10)
    ```
- Số bình thường (không chứa kí hiệu `0x`) sẽ được hiểu ở hệ thập phân (Decimal)

## Register (Thanh ghi)
- Bộ xử lý bao gồm 32 registers, mỗi register 32 bits.
- Mỗi registers sẽ có tên gợi nhớ và số thứ tự tương ứng. Cụ thể
    | Name | Reg-Number | Usage | Presered Across a call |
    | :--: | :--: | :--: | :--: |
    | `$zero` | `0` | `const value = 0` | N.A |
    | `$at` | `1` | Assembler Temporary (Trình biên dịch tạm thời) | No |
    | `$v0 - $v1` | `2, 3` | Value of function results and Expression Evaluation (Kết quả hàm và đánh giá biểu thức) | No |
    | `$a0 - $a3` | `[4...7]` | Arguments (Đối số) | No |
    | `$t0 - $t7` | `[8...15]` | Temporaries (Chứa giá trị tạm thời) | No |
    | `$s0 - $s7` | `[16...23]` | Saved Temporaries (Lưu giá trị tạm thời) | No |
    | `$t8 - $t9` | `24, 25` | Temporaries (Chứa giá trị tạm thời) | No |
    | `$k0 - $k1` | `26, 27` | Reversed for OS Kernel (Đảo ngược cho nhân hệ điều hành) | No |
    | `$gp` | `28` | Global Pointer | Yes |
    | `$sp` | `29` | Stack Pointer | Yes |
    | `$fp` | `30` | Frame Pointer | Yes |
    | `$ra` | `31` | Return Address | Yes |

    - Các Register từ 28 đến 31 cần được lưu trữ lại khi thực hiện gọi hàm con