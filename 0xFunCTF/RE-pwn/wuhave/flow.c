#include <stdio.h>
#include <stdint.h>

int main(int argc, const char **argv, const char **envp) {
    uint64_t *address_to_write; // [rsp+8h] [rbp-18h] - Tương đương v4
    uint64_t value_buffer[2];   // [rsp+10h] [rbp-10h] - Tương đương v5

    // Thiết lập canary để bảo vệ stack (tương ứng __readfsqword(0x28u))
    // Trong C thuần, trình biên dịch sẽ tự thêm phần này nếu bật stack protection.

    // Tắt bộ đệm cho stdout để dữ liệu in ra ngay lập tức
    setbuf(stdout, NULL);

    // Bước 1: Yêu cầu người dùng nhập một địa chỉ bộ nhớ (Where)
    puts("Show me what you GOT!");
    scanf("%lu", &address_to_write); 

    // Bước 2: Yêu cầu người dùng nhập giá trị muốn ghi (What)
    puts("Show me what you GOT! I want to see what you GOT!");
    scanf("%lu", &value_buffer[0]);

    // Bước 3: THỰC HIỆN GHI (Lỗ hổng chết người)
    // Gán giá trị vừa nhập vào địa chỉ bộ nhớ vừa cung cấp
    *address_to_write = value_buffer[0];

    puts("Goodbye!");
    return 0;
}