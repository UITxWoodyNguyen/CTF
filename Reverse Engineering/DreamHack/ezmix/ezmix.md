# ezmix

## Information

- Category: RE
- Level: 2
- Source Problem: DreamHack

## Solution

## What we got ?

- Thực hiện decompile file chương trình bằng IDA, ta nhận được `main` như sau:
    
    ```c
    __int64 __fastcall main(int a1, char **a2, char **a3)
    {
      size_t v3; // rax
      unsigned int v5; // [rsp+14h] [rbp-51Ch]
      FILE *stream; // [rsp+18h] [rbp-518h]
      FILE *streama; // [rsp+18h] [rbp-518h]
      char s[256]; // [rsp+20h] [rbp-510h] BYREF
      _BYTE ptr[1032]; // [rsp+120h] [rbp-410h] BYREF
      unsigned __int64 v10; // [rsp+528h] [rbp-8h]
    
      v10 = __readfsqword(0x28u);
      if ( a1 <= 2 )
      {
        printf("Usage: %s [program] [output]\n", *a2);
        exit(0);
      }
      stream = fopen(a2[1], "rb");
      v5 = fread(ptr, 1u, 0x400u, stream);
      fclose(stream);
      sub_136C(ptr, v5, s);
      streama = fopen(a2[2], "wb");
      v3 = strlen(s);
      fwrite(s, v3, 1u, streama);
      fclose(streama);
      return 0;
    }
    ```
    
- Ta thấy process mã hoá sẽ được xử lý trong `sub_136C()`:
    
    ```c
    __int64 __fastcall sub_136C(__int64 a1, int a2, char *a3)
    {
      int v3; // eax
      __int64 result; // rax
      unsigned __int8 v6; // [rsp+27h] [rbp-9h]
      unsigned int v7; // [rsp+28h] [rbp-8h]
      unsigned int i; // [rsp+2Ch] [rbp-4h]
    
      v7 = 0;
      for ( i = 0; ; i += 2 )
      {
        result = i;
        if ( (int)i >= a2 )
          break;
        v6 = *(_BYTE *)((int)i + 1LL + a1);
        v3 = *(unsigned __int8 *)((int)i + a1);
        if ( v3 == 4 )
        {
          printf("Insert your string: ");
          fgets(a3, 256, stdin);
          a3[strcspn(a3, "\n")] = 0;
          v7 = strlen(a3);
        }
        else
        {
          if ( *(unsigned __int8 *)((int)i + a1) > 4u )
            goto LABEL_12;
          switch ( v3 )
          {
            case 3:
              sub_1301(sub_12C2, v6, a3, v7);
              break;
            case 1:
              sub_1301(sub_1289, v6, a3, v7);
              break;
            case 2:
              sub_1301(sub_12A7, v6, a3, v7);
              break;
            default:
    LABEL_12:
              puts("Error!");
              exit(1);
          }
        }
      }
      return result;
    }
    ```
    
- Ta nhận thấy có tổng cộng 4 lựa chọn cho user. Cụ thể
    
    ```c
    __int64 __fastcall sub_1301(__int64 (__fastcall *a1)(_QWORD, _QWORD), unsigned __int8 a2, __int64 a3, int a4)
    {
      __int64 result; // rax
      unsigned int i; // [rsp+2Ch] [rbp-14h]
    
      for ( i = 0; ; ++i )
      {
        result = i;
        if ( (int)i >= a4 )
          break;
        *(_BYTE *)((int)i + a3) = a1(*(unsigned __int8 *)((int)i + a3), a2);
      }
      return result;
    }
    
    __int64 __fastcall sub_12C2(unsigned __int8 a1, char a2) {
      return ((int)a1 >> (a2 & 7)) | (a1 << (8 - (a2 & 7)));
    }
    
    __int64 __fastcall sub_1289(unsigned __int8 a1, unsigned __int8 a2) {
      return a1 + (unsigned int)a2;
    }
    
    char __fastcall sub_12A7(char a1, char a2) {
      return a2 ^ a1;
    }
    ```
    
    - 4: Nhập chuỗi mới từ bàn phím (plaintext)
    - 1: Cộng từng ký tự chuỗi với tham số
    - 2: XOR từng ký tự chuỗi với tham số
    - 3: Xoay phải từng ký tự chuỗi theo số bit là tham số
- Kết quả sẽ trả về file `output.bin`

### How to get flag ?

- Thực hiện reverse các thao tác mã hoá theo thứ tự từ cuối về đầu. Cụ thể:
    - Lệnh 1: Trừ tham số
    - Lệnh 2: XOR lại với tham số (XOR là nghịch đảo chính nó)
    - Lệnh 3: Xoay trái (ngược lại xoay phải) với tham số
    - Lệnh 4: Bỏ qua (không làm gì khi giải mã)
- Kết quả sẽ là flag cần tìm.
- Script cụ thể:
    
    ```cpp
    #include <iostream>
    #include <fstream>
    #include <vector>
    #include <string>
    
    // Xoay trái 1 byte
    unsigned char rol(unsigned char val, unsigned char shift) {
        shift &= 7;
        return (val << shift) | (val >> (8 - shift));
    }
    
    int main() {
        const char* scriptFile = "program.bin"; // File script điều khiển (file .bin gốc)
        const char* inputFile = "output.bin";  // File đã mã hóa
        const char* outputFile = "recovered.txt"; // File kết quả giải mã
    
        // Đọc script
        std::ifstream script(scriptFile, std::ios::binary);
        if (!script) {
            std::cerr << "Không thể mở script điều khiển!\n";
            return 1;
        }
        std::vector<unsigned char> ops((std::istreambuf_iterator<char>(script)), std::istreambuf_iterator<char>());
        script.close();
        // Đọc dữ liệu mã hóa
        std::ifstream in(inputFile, std::ios::binary);
        if (!in) {
            std::cerr << "Không thể mở file mã hóa!\n";
            return 1;
        }
        std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();
    
        // Tìm chuỗi đầu tiên (sau lệnh 4)
        std::string s = data;
        size_t op_count = ops.size();
        size_t idx = 0;
        std::vector<std::pair<unsigned char, unsigned char>> op_pairs;
        while (idx + 1 < op_count) {
            unsigned char cmd = ops[idx];
            unsigned char param = ops[idx + 1];
            op_pairs.push_back({cmd, param});
            idx += 2;
        }
    
        // Áp dụng NGƯỢC các thao tác (từ cuối về đầu)
        for (int i = (int)op_pairs.size() - 1; i >= 0; --i) {
            unsigned char cmd = op_pairs[i].first;
            unsigned char param = op_pairs[i].second;
            if (cmd == 4) {
                // Lệnh nhập chuỗi, bỏ qua khi giải mã
                continue;
            } else if (cmd == 1) {
                // Giải mã: trừ param
                for (size_t j = 0; j < s.size(); ++j) {
                    s[j] = (unsigned char)(s[j] - param);
                }
            } else if (cmd == 2) {
                // Giải mã: XOR lại với param
                for (size_t j = 0; j < s.size(); ++j) {
                    s[j] = (unsigned char)(s[j] ^ param);
                }
            } else if (cmd == 3) {
                // Giải mã: xoay trái
                for (size_t j = 0; j < s.size(); ++j) {
                    s[j] = rol((unsigned char)s[j], param);
                }
            } else {
                std::cerr << "Lệnh không hợp lệ trong script!\n";
                return 1;
            }
        }
    
        // Ghi kết quả
        std::ofstream out(outputFile);
        if (!out) {
            std::cerr << "Không thể ghi file kết quả!\n";
            return 1;
        }
        out << s;
        out.close();
        std::cout << "Đã giải mã xong, kết quả lưu ở recovered.txt\n";
        return 0;
    }
    ```
