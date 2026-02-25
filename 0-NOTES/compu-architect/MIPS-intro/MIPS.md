---
title: MIPS Instruction Set (Dịch sang tiếng Việt)
source: https://cscie95.dce.harvard.edu/fall2023/slides/MIPS%20Instruction%20Set.pdf
translator: GitHub Copilot (hỗ trợ bởi trợ lý AI)
---

--- PAGE 1 ---
MIPS Instruction Set
Giáo sư James L. Frankel
Đại học Harvard
Phiên bản 5:52 PM 10-Nov-2020
Copyright © 2015-2020 James L. Frankel. Bảo lưu mọi quyền.

--- PAGE 2 ---
Tổng quan CPU
- **CPU** là viết tắt của Bộ xử lý Trung tâm (Central Processing Unit)
- CPU là đơn vị thực hiện tính toán của máy tính
- CPU không bao gồm bộ nhớ hoặc các thiết bị Nhập/Xuất (I/O)
- Kích thước từ: 32-bit (tức là mỗi từ gồm bốn byte)
- Không có Processor Status Word (PSW)
  - PSW thường chứa các cờ (như carry, overflow, negative), cờ cho phép ngắt, cờ chế độ thực thi đặc quyền, mức ưu tiên ngắt hiện tại, v.v.
- Các thanh ghi được truy cập ở tốc độ thực thi lệnh
- Truy cập bộ nhớ chậm hơn so với truy cập thanh ghi
- Dữ liệu và mã chương trình của người dùng nằm trong bộ nhớ; dữ liệu được di chuyển vào thanh ghi trước khi thực hiện các phép toán trên đó

--- PAGE 3 ---
Sơ đồ khối đơn giản

CPU    |    Bộ nhớ
-------|----------------
Thanh ghi (Registers)
ALU
Sequencer
I/O Devices   PC  HI LO

--- PAGE 4 ---
Thanh ghi CPU
- **Thanh ghi chung (General Purpose Registers - GPR)**
  - 32 thanh ghi GPR 32-bit
  - Đánh số từ 0 đến 31; ký hiệu $0 đến $31
  - Một số được sử dụng bởi phần cứng
  - Tất cả đều có quy ước sử dụng do phần mềm quy định
- **Thanh ghi nhân chia (Multiply/Divide Registers)**
  - Dùng bởi các lệnh nhân và chia phần cứng
  - Thanh ghi HI 32-bit
  - Thanh ghi LO 32-bit
- **Program Counter (PC)**
  - PC 32-bit chứa địa chỉ của lệnh kế tiếp sẽ thực thi
  - Trong quá trình lấy lệnh, PC được tăng để trỏ tới lệnh kế tiếp

--- PAGE 5 ---
Thanh ghi chung (Chi tiết)
- `$0` luôn đọc về giá trị 0; các giá trị ghi vào `$0` bị bỏ qua
- `$1` (tên `$at`) dành cho trình hợp ngữ (assembler)
- `$2` và `$3` (tên `$v0` & `$v1`) dùng để đánh giá biểu thức và cũng dùng để trả giá trị từ hàm
- `$4` đến `$7` (tên `$a0` đến `$a3`) dùng để truyền 4 tham số thực tới hàm (parameters 1–4)
- `$8` đến `$15` và `$24` `$25` (tên `$t0`–`$t7`, `$t8`, `$t9`) dùng cho biến tạm (temporaries) không được lưu bởi hàm được gọi
- `$16` đến `$23` (tên `$s0`–`$s7`) dùng cho biến tạm **phải** được hàm được gọi lưu lại (saved)
- `$26` và `$27` (tên `$k0`, `$k1`) dành cho hệ điều hành
- `$28` (tên `$gp`) dùng để trỏ tới biến toàn cục
- `$29` (tên `$sp`) là con trỏ ngăn xếp (stack pointer)
- `$30` (tên `$fp`) là con trỏ khung (frame pointer)
- `$31` (tên `$ra`) chứa địa chỉ trả về

--- PAGE 6 ---
Sử dụng phần cứng các thanh ghi chung
- Trong CPU, tất cả thanh ghi đều là chung và có thể dùng hoán đổi cho nhau ngoại trừ:
  - `$0` luôn đọc là 0; các ghi vào `$0` bị bỏ qua
  - `$31` (`$ra`) chứa địa chỉ trả về
- Các lệnh gọi thủ tục (call) đặt địa chỉ của lệnh tiếp theo (địa chỉ trả về) vào `$ra`
- Thuật ngữ *subroutine* thường dùng để chỉ procedure hoặc function ở mức hợp ngữ

--- PAGE 7 ---
Địa chỉ bộ nhớ
- Bộ nhớ trong MIPS được đánh địa chỉ theo byte (byte-addressable)
  - Mỗi byte trong bộ nhớ có số thứ tự liên tiếp
- MIPS yêu cầu căn chỉnh (alignment) cho các truy cập bộ nhớ
  - Một từ 32-bit phải nằm ở địa chỉ được căn chỉnh theo từ (word aligned)
  - Địa chỉ của một từ là địa chỉ byte có chỉ số nhỏ nhất trong từ đó
  - Điều này nghĩa là hai bit thấp nhất của một địa chỉ từ phải là 0
  - Một half-word 16-bit phải nằm ở địa chỉ được căn chỉnh theo half-word
  - Địa chỉ half-word có bit thấp nhất phải là 0
- Truy cập byte 8-bit không yêu cầu căn chỉnh

--- PAGE 8 ---
Địa chỉ trả về (Return Address)
- Vì các lệnh gọi subroutine ghi đè `$ra` bằng địa chỉ trả về, bất kỳ subroutine nào gọi subroutine khác phải lưu `$ra` trước khi gọi lồng nhau
- Để cho phép gọi lồng nhau và đệ quy, bất kỳ hàm nào gọi hàm khác thường lưu `$ra` lên ngăn xếp (bằng thao tác tương đương push/pop)
- Sau này sẽ bàn kỹ về quy ước gọi hàm (calling conventions)

--- PAGE 9 ---
Thanh ghi tạm thời và thanh ghi được lưu
- Quy ước phần mềm phân biệt giữa thanh ghi tạm thời (`$t`n) và thanh ghi được lưu (`$s`n)
- Theo quy ước, một subroutine phải lưu (trên ngăn xếp) bất kỳ thanh ghi `$s` nào mà nó sử dụng
- Một subroutine không bắt buộc phải lưu bất kỳ thanh ghi `$t` nào nó sử dụng
- Tất nhiên subroutine có thể dùng cả `$t` và `$s`
- Trong đoạn mã không gọi subroutine, cả `$t` và `$s` giữ nguyên giá trị
- Nếu gọi subroutine, các thanh ghi `$t` không đảm bảo giữ nguyên giá trị qua cuộc gọi
- Do đó, nếu caller muốn giữ giá trị `$t` qua cuộc gọi, caller phải push các `$t` cần thiết trước khi gọi và pop sau khi gọi

--- PAGE 10 ---
Trách nhiệm đối với thanh ghi tạm thời và được lưu
- *Caller* là đoạn mã gọi subroutine
- *Callee* là subroutine được gọi
- Trách nhiệm:
  - Caller chịu trách nhiệm lưu và phục hồi bất kỳ thanh ghi `$t` nào mà nó cần giữ qua các cuộc gọi
  - Callee chịu trách nhiệm lưu và phục hồi bất kỳ thanh ghi `$s` nào mà nó thay đổi

--- PAGE 11 ---
Ngăn xếp (Stack)
- Thanh ghi `$sp` dùng để quản lý ngăn xếp
  - `$sp` trỏ tới từ trên cùng của ngăn xếp
- Ngăn xếp tăng về hướng địa chỉ thấp hơn (stack grows toward lower addresses)
- Vì vậy, thao tác *push* thực hiện bằng:
  1. Giảm `$sp` đi 4
  2. Lưu từ cần push vào ô nhớ được trỏ bởi `$sp`
- Thao tác *pop* thực hiện bằng:
  1. Đọc từ trên cùng của ngăn xếp (tại `$sp`)
  2. Tăng `$sp` lên 4

--- PAGE 12 ---
Định dạng lệnh CPU
- I-Type (Immediate)
- J-Type (Jump)
- R-Type (Register)

--- PAGE 13 ---
I-Type

```
31         26 25    21 20    16 15                 0
| op (6) | rs (5) | rt (5) |       immediate (16)     |
```

--- PAGE 14 ---
J-Type

```
31         26 25                          0
| op (6) |        target (26)             |
```

--- PAGE 15 ---
R-Type

```
31    26 25    21 20    16 15    11 10     6 5      0
| op(6)| rs(5)| rt(5)| rd(5)| shamt(5)| funct(6)|
```

--- PAGE 16 ---
Tóm tắt lệnh
- Lệnh Load & Store di chuyển dữ liệu giữa bộ nhớ và thanh ghi
  - Tất cả đều là I-type
- Lệnh tính toán (arith, logic, shift) hoạt động trên thanh ghi
  - Có cả R-type và I-type
- Lệnh nhảy & phân nhánh (jump & branch) ảnh hưởng luồng điều khiển (có thể thay đổi PC)
  - Jumps là J-type hoặc R-type
  - Branches là I-type

--- PAGE 17 ---
Lệnh bất biến (Immutable Instructions)
- Trong các máy tính hiện đại, khi lệnh đã được nạp vào bộ nhớ để thực thi, chúng **không thể** bị sửa đổi
  - Tức là không thể thay đổi mã lệnh trong vùng thực thi
- Điều này không bắt buộc trong bộ lệnh mới mà bạn thiết kế
- Điều này hàm ý rằng trong các máy hiện đại, dữ liệu và lệnh không trộn lẫn trong bộ nhớ tại thời điểm chạy
- Dữ liệu và lệnh có thể trộn lẫn trong chương trình hợp ngữ miễn là trình hợp ngữ (assembler) tách được phần lệnh và phần dữ liệu thành các phân đoạn riêng (ví dụ: text segment và data segment)

--- PAGE 18 ---
Định dạng ngôn ngữ hợp ngữ
- Lệnh bắt đầu bằng opcode
- Opcode thường được thụt vào (thường 1 tab)
- Opcode theo sau bởi khoảng trắng (thường 1 tab)
- Sau tab là các toán hạng (operands) phù hợp với opcode
- Hầu hết lệnh lấy toán hạng đích (destination) là toán hạng đầu tiên
  - Ví dụ: `addu rd, rs, rt` → `rd` là đích, `rs` & `rt` là nguồn

--- PAGE 19 ---
Vai trò của trình hợp ngữ (assembler)
- Assembler nhận một file chứa chương trình viết bằng ngôn ngữ hợp ngữ và tạo ra file chứa cùng chương trình ở dạng mã máy (số)
- Các vai trò khác của assembler:
  - Cho phép lập trình viên dùng nhãn (labels) trên lệnh và dữ liệu và tham chiếu tới các nhãn đó
  - Nhờ vậy, lập trình viên thường không cần dùng địa chỉ số
  - Cho phép gán các giá trị hằng số số và tham chiếu chúng
  - Chuyển hằng ký tự và chuỗi thành mã ký tự tương ứng
  - Chấp nhận chú thích (comments)
  - Có thể mở rộng bộ lệnh bằng pseudo-instructions
  - Có thể chấp nhận các chỉ thị assembler (assembler directives)

--- PAGE 20 ---
Thông tin mô tả Kiến trúc tập lệnh (ISA)
- Mô tả mỗi lệnh sẽ:
  - Nêu tên opcode
  - Xác định định dạng tổng thể của lệnh
  - Xác định cú pháp ngôn ngữ hợp ngữ
  - Mô tả ngắn gọn bằng tiếng Anh về chức năng lệnh
  - Mô tả theo ký hiệu toán học chức năng lệnh
  - Hiển thị chính xác cách mã hóa lệnh trong biểu diễn máy

--- PAGE 21 ---
Lệnh Add
- **ADD**, R-Type
- Cú pháp: `ADD rd, rs, rt`
- Mô tả: Nội dung của `GPR[rs]` và `GPR[rt]` được cộng để tạo kết quả 32-bit. Kết quả được đặt vào `GPR[rd]`.
  - Nếu xảy ra tràn số nguyên (2's-complement overflow) thì phát ngoại lệ overflow; thanh ghi đích `rd` **không** được sửa khi ngoại lệ overflow xảy ra.
- Hoạt động: `GPR[rd] ← GPR[rs] + GPR[rt]`

--- PAGE 22 ---
ADD Instruction Fields

```
31         26 25    21 20    16 15    11 10     6 5      0
|  SPECIAL(6)=000000 | rs(5) | rt(5) | rd(5) | shamt(5)=0 | funct(6)=100000 |
```

--- PAGE 23 ---
Lệnh Add Unsigned
- **ADDU**, R-Type
- Cú pháp: `ADDU rd, rs, rt`
- Mô tả: Nội dung `GPR[rs]` + `GPR[rt]` tạo kết quả 32-bit, đặt vào `GPR[rd]`.
  - Không bao giờ phát sinh ngoại lệ overflow.
- Hoạt động: `GPR[rd] ← GPR[rs] + GPR[rt]`

--- PAGE 24 ---
ADDU Instruction Fields

```
31         26 25    21 20    16 15    11 10     6 5      0
|  SPECIAL(6)=000000 | rs(5) | rt(5) | rd(5) | shamt(5)=0 | funct(6)=100001 |
```

--- PAGE 25 ---
Các lệnh R-Type ba toán hạng
- ADD: Cộng
- ADDU: Cộng không dấu
- SUB: Trừ (GPR[rs] - GPR[rt])
- SUBU: Trừ không dấu (GPR[rs] - GPR[rt])
- SLT: Set on Less Than (nếu GPR[rs] < GPR[rt]) — so sánh theo số nguyên có dấu 32-bit; kết quả 1 nếu đúng, 0 nếu sai
- SLTU: Set on Less Than Unsigned — so sánh theo số không dấu 32-bit; kết quả 1 nếu đúng, 0 nếu sai
- AND: Phép AND bit-thực
- OR: Phép OR bit-thực
- XOR: Phép XOR bit-thực
- NOR: Phép NOR bit-thực

--- PAGE 26 ---
Lệnh Multiply
- **MULT**, R-Type hai toán hạng
- Cú pháp: `MULT rs, rt`
- Mô tả: Nội dung `GPR[rs]` và `GPR[rt]` nhân như giá trị 32-bit có dấu (2's complement). Không bao giờ phát sinh ngoại lệ overflow.
  - Lệnh này chỉ hợp lệ khi `rd = 0`.
  - Khi kết thúc, phần thấp của kết quả đôi (low order word) được đưa vào `LO`, phần cao được đưa vào `HI`.
  - Nếu các lệnh trước đó là `MFHI` hoặc `MFLO`, kết quả có thể không xác định. Để đảm bảo đúng, cần tách đọc HI/LO và ghi bằng tối thiểu hai lệnh khác.
- Hoạt động: tính tích t = GPR[rs] * GPR[rt]
  - LO ← t[31..0]
  - HI ← t[63..32]

--- PAGE 27 ---
MULT Instruction Fields

```
31         26 25    21 20    16 15    11 10     6 5      0
|  SPECIAL(6)=000000 | rs(5) | rt(5) | rd=0 | shamt=0 | funct=011000 |
```

--- PAGE 28 ---
Lệnh Move From HI
- **MFHI**, R-Type một toán hạng
- Cú pháp: `MFHI rd`
- Mô tả: Nội dung thanh ghi đặc biệt `HI` được đặt vào `GPR[rd]`.
  - Để đảm bảo hoạt động đúng khi có ngắt, hai lệnh sau `MFHI` không được là các lệnh thay đổi `HI`: `MULT`, `MULTU`, `DIV`, `DIVU`, `MTHI`.
- Hoạt động: `GPR[rd] ← HI`

--- PAGE 29 ---
MFHI Instruction Fields

```
31         26 25    21 20    16 15    11 10     6 5      0
|  SPECIAL(6)=000000 | rs=0 | rt=0 | rd(5) | shamt=0 | funct=010000 |
```

--- PAGE 30 ---
Các lệnh Multiply/Divide R-Type
- MULT: Multiply
- MULTU: Multiply Unsigned (tương tự MULT nhưng coi rs & rt là số không dấu)
- DIV: Chia — chia GPR[rs] cho GPR[rt], LO ← thương, HI ← phần dư (rs & rt coi là số có dấu)
- DIVU: Chia không dấu (rs & rt coi là số không dấu)
- MFHI: Move From HI
- MFLO: Move From LO
- MTHI: Move To HI
- MTLO: Move To LO

--- PAGE 31 ---
Lệnh Shift Right Logical
- **SRL**, R-Type shift
- Cú pháp: `SRL rd, rt, sa`
- Mô tả: Nội dung `GPR[rt]` dịch phải `sa` bit, chèn 0 vào các bit bậc cao. Kết quả 32-bit đặt vào `GPR[rd]`.
- Hoạt động: `GPR[rd] ← 0^sa || GPR[rt][31..sa]` (chèn `sa` số 0 ở bậc cao)

--- PAGE 32 ---
SRL Instruction Fields

```
31         26 25    21 20    16 15    11 10     6 5      0
|  SPECIAL(6)=000000 | rs=0 | rt(5) | rd(5) | shamt(5) | funct=000010 |
```

--- PAGE 33 ---
Lệnh Shift Right Arithmetic
- **SRA**, R-Type shift
- Cú pháp: `SRA rd, rt, sa`
- Mô tả: Nội dung `GPR[rt]` dịch phải `sa` bit, mở rộng dấu (sign-extend) bit bậc cao. Kết quả 32-bit đặt vào `GPR[rd]`.
- Hoạt động: `GPR[rd] ← (GPR[rt][31])^sa || GPR[rt][31..sa]` (mở rộng dấu)

--- PAGE 34 ---
SRA Instruction Fields

```
31         26 25    21 20    16 15    11 10     6 5      0
|  SPECIAL(6)=000000 | rs=0 | rt(5) | rd(5) | shamt(5) | funct=000011 |
```

--- PAGE 35 ---
Lệnh Shift Right Logical Variable
- **SRLV**, R-Type
- Cú pháp: `SRLV rd, rt, rs`
- Mô tả: `GPR[rt]` được dịch phải bởi số bit được chỉ định bởi 5 bit thấp của `GPR[rs]`, chèn 0 ở bit bậc cao. Kết quả 32-bit đặt vào `GPR[rd]`.
- Hoạt động: `s ← GPR[rs][4..0]` then `GPR[rd] ← 0^s || GPR[rt][31..s]`

--- PAGE 36 ---
SRLV Instruction Fields

```
31         26 25    21 20    16 15    11 10     6 5      0
|  SPECIAL(6)=000000 | rs(5) | rt(5) | rd(5) | shamt=0 | funct=000110 |
```

--- PAGE 37 ---
Các lệnh Shift R-Type
- SLL: Shift Left Logical
- SRL: Shift Right Logical
- SRA: Shift Right Arithmetic
- SLLV: Shift Left Logical Variable
- SRLV: Shift Right Logical Variable
- SRAV: Shift Right Arithmetic Variable

--- PAGE 38 ---
Lệnh Add Immediate
- **ADDI**, I-Type
- Cú pháp: `ADDI rt, rs, immediate`
- Mô tả: Hằng 16-bit được mở rộng dấu (sign-extended) và cộng vào `GPR[rs]` để tạo kết quả 32-bit. Kết quả đặt vào `GPR[rt]`.
  - Nếu xảy ra overflow (2's-complement), ngoại lệ overflow xảy ra; `rt` không bị sửa khi ngoại lệ xảy ra.
- Hoạt động: `GPR[rt] ← GPR[rs] + sign_extend(immediate)`

--- PAGE 39 ---
ADDI Instruction Fields

```
31         26 25    21 20    16 15                 0
|  op(6)=001000 | rs(5) | rt(5) |       immediate (16)     |
```

--- PAGE 40 ---
Các lệnh ALU I-Type
- ADDI: Add Immediate
- ADDIU: Add Immediate Unsigned
  - Hằng 16-bit được sign-extended
  - ADDIU không phát sinh ngoại lệ overflow
- SLTI: Set on Less Than Immediate (so sánh GPR[rs] < immediate) — immediate sign-extended
- SLTIU: Set on Less Than Immediate Unsigned (so sánh không dấu) — immediate sign-extended
- ANDI: Bitwise AND Immediate — immediate zero-extended
- ORI: Bitwise OR Immediate — immediate zero-extended
- XORI: Bitwise XOR Immediate — immediate zero-extended
- LUI: Load Upper Immediate
  - `LUI rt, immediate` — trường `rs` phải bằng 0 (SBZ = should be zero)
  - immediate 16-bit được dịch trái 16 bit; 16 bit thấp đặt bằng 0; kết quả lưu vào `rt`

--- PAGE 41 ---
Lệnh Branch on Equal
- **BEQ**, I-Type
- Cú pháp: `BEQ rs, rt, offset`
- Mô tả: Địa chỉ nhánh được tính bằng tổng địa chỉ của lệnh trong *delay slot* và offset 16-bit (shift trái 2 bit và sign-extend tới 32-bit). So sánh `GPR[rs]` và `GPR[rt]`; nếu bằng thì chương trình nhảy tới địa chỉ mục tiêu, có độ trễ một lệnh (delay slot).
- Hoạt động (tóm tắt):
  - `targetOffset ← sign_extend(offset) << 2`
  - `condition ← (GPR[rs] == GPR[rt])`
  - Nếu `condition` thì `PC ← PC + targetOffset` (sau delay slot)

--- PAGE 42 ---
BEQ Instruction Fields

```
31         26 25    21 20    16 15                 0
|  op(6)=000100 | rs(5) | rt(5) |       offset (16)       |
```

--- PAGE 43 ---
Các lệnh Branch I-Type
- BEQ: Branch on Equal
- BNE: Branch on Not Equal
- Các lệnh sau chỉ chỉ định một thanh ghi:
  - Cú pháp: `OPCODE rs, offset` (trường `rt` phải là 0 — SBZ)
  - Xử lý `GPR[rs]` như số nguyên có dấu
- BLEZ: Branch on Less Than or Equal to Zero
- BGTZ: Branch on Greater Than Zero
- BLTZ: Branch on Less Than Zero
- BGEZ: Branch on Greater Than or Equal to Zero
- BLTZAL: Branch on Less Than Zero and Link
- BGEZAL: Branch on Greater Than or Equal to Zero and Link

--- PAGE 44 ---
Các lệnh "And Link"
- Các lệnh And Link đặt địa chỉ của lệnh sau delay slot vào thanh ghi link (`$ra` hoặc `$31`) một cách vô điều kiện (dù nhánh có xảy ra hay không, `$ra` vẫn được cập nhật)
- Thanh ghi `rs` không thể là `$31`
- Do đó, các lệnh And Link dùng để gọi subroutine

--- PAGE 45 ---
Trường offset trong lệnh Branch
- Các lệnh phải nằm ở địa chỉ căn chỉnh theo từ (word-aligned)
  - Do đó, hai bit thấp của địa chỉ lệnh luôn là 0
- Địa chỉ mục tiêu của branch/jump phải word-aligned
- Field offset được shift trái hai bit để đảm bảo word-alignment và mở rộng phạm vi nhánh gấp 4 lần so với offset không shift
- Trường offset rộng 16 bit (giá trị -32768..32767)
  - Sau shift <<2 thì phạm vi là -32768*4 .. 32767*4 (tính theo byte)
  - Cho phép phạm vi nhánh tối đa từ 32,768 lệnh trước lệnh trong delay slot đến 32,767 lệnh sau lệnh trong delay slot

--- PAGE 46 ---
Lệnh Jump
- **J**, J-Type
- Cú pháp: `J target`
- Mô tả: Trường target 26-bit được shift trái 2 bit và kết hợp với 4 bit cao của địa chỉ lệnh trong delay slot để tạo địa chỉ nhảy. Chương trình nhảy vô điều kiện tới địa chỉ này, có delay một lệnh.
- Hoạt động: `PC ← PC[31..28] || (target << 2)` (sau delay slot)

--- PAGE 47 ---
J Instruction Fields

```
31         26 25                          0
|  op(6)=000010 |        target (26)             |
```

--- PAGE 48 ---
Lệnh Jump And Link
- **JAL**, J-Type
- Cú pháp: `JAL target`
- Mô tả: Tương tự `J`, nhưng địa chỉ của lệnh sau delay slot được lưu vào thanh ghi link `GPR[31]`.
- Hoạt động:
  - `GPR[31] ← PC + 8` (địa chỉ lệnh sau delay slot)
  - `PC ← PC[31..28] || (target << 2)` (sau delay slot)

--- PAGE 49 ---
JAL Instruction Fields

```
31         26 25                          0
|  op(6)=000011 |        target (26)             |
```

--- PAGE 50 ---
Lệnh Jump Register
- **JR**, R-Type
- Cú pháp: `JR rs`
- Mô tả: Chương trình nhảy vô điều kiện tới địa chỉ chứa trong `GPR[rs]`, có delay một lệnh. Lệnh chỉ hợp lệ nếu `rd = 0`.
  - Hai bit thấp của địa chỉ trong `rs` phải là 0 (word-aligned)
- Hoạt động: `PC ← GPR[rs]` (sau delay slot)

--- PAGE 51 ---
JR Instruction Fields

```
31    26 25    21 20    16 15    11 10     6 5      0
| SPECIAL(6)=000000 | rs(5) | rt=0 | rd=0 | shamt=0 | funct=001000 |
```

--- PAGE 52 ---
Lệnh Jump And Link Register
- **JALR**, R-Type
- Cú pháp: `JALR rs, rd`
- Mô tả: Nhảy tới địa chỉ trong `GPR[rs]`, và địa chỉ của lệnh sau delay slot được đặt vào `GPR[rd]`. `rs` và `rd` không được bằng nhau.
  - Hai bit thấp của địa chỉ trong `rs` phải là 0
- Hoạt động:
  - `GPR[rd] ← PC + 8`
  - `PC ← GPR[rs]` (sau delay slot)

--- PAGE 53 ---
JALR Instruction Fields

```
31    26 25    21 20    16 15    11 10     6 5      0
| SPECIAL(6)=000000 | rs(5) | rt=0 | rd(5) | shamt=0 | funct=001001 |
```

--- PAGE 54 ---
Lệnh Jump (tổng hợp)
- J: Jump
- JAL: Jump And Link
- JR: Jump Register
- JALR: Jump And Link Register

--- PAGE 55 ---
Lệnh Load Word
- **LW**, I-Type
- Cú pháp: `LW rt, offset(base)`
- Mô tả: Offset 16-bit được sign-extended và cộng với `GPR[base]` để tạo địa chỉ hiệu dụng. Từ (word) tại địa chỉ đó được tải vào `GPR[rt]`.
  - Hai bit thấp của địa chỉ hiệu dụng phải là 0 (word-aligned)
- Hoạt động (tóm tắt):
  - `vAddr ← sign_extend(offset) + GPR[base]`
  - `mem ← LoadMemory(WORD, vAddr)`
  - (T+1) `GPR[rt] ← mem`

--- PAGE 56 ---
LW Instruction Fields

```
31         26 25    21 20    16 15                 0
|  op(6)=100011 | base(5) | rt(5) |       offset (16)     |
```

--- PAGE 57 ---
Lệnh Load và Store
- LB: Load Byte
- LBU: Load Byte Unsigned
- LH: Load Halfword
- LHU: Load Halfword Unsigned
- LW: Load Word
- Các lệnh Store có cú pháp giống Load: `OPCODE rt, offset(base)` nhưng ở store, toán hạng trái (`rt`) là nguồn (source) — giá trị `GPR[rt]` được lưu vào bộ nhớ tại `GPR[base] + sign_extend(offset)`
- SB: Store Byte
- SH: Store Halfword
- SW: Store Word

--- PAGE 58 ---
Trường offset của Load/Store
- Đối với Load và Store, field offset **không** được shift trái trước khi cộng với `base`
  - Điều này giới hạn phạm vi halfword và word có thể truy cập bằng Load/Store, nhưng làm các lệnh đồng nhất
  - Một thiết kế khác có thể cho phép gấp đôi phạm vi khi truy cập halfwords và gấp bốn khi truy cập words

--- PAGE 59 ---
Triển khai Push
- Không có lệnh thao tác ngăn xếp chuyên dụng
- Push `$reg` lên ngăn xếp thực hiện bằng:
  - `addiu $sp, $sp, -4` # giảm `$sp` cho một từ
  - `sw $reg, 0($sp)` # lưu `$reg` lên ngăn xếp
- Push ba thanh ghi thực hiện bằng:
  - `addiu $sp, $sp, -12` # giảm `$sp` cho ba từ
  - `sw $firstReg, 8($sp)`
  - `sw $secondReg, 4($sp)`
  - `sw $thirdReg, 0($sp)`

--- PAGE 60 ---
Triển khai Pop
- Không có lệnh thao tác ngăn xếp chuyên dụng
- Pop `$reg` khỏi ngăn xếp thực hiện bằng:
  - `lw $reg, 0($sp)` # load `$reg` từ ngăn xếp
  - `addiu $sp, $sp, 4` # tăng `$sp` cho một từ
- Pop ba thanh ghi thực hiện bằng:
  - `lw $thirdReg, 0($sp)`
  - `lw $secondReg, 4($sp)`
  - `lw $firstReg, 8($sp)`
  - `addiu $sp, $sp, 12`
