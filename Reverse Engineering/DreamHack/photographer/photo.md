# photographer

## Information

- Category: RE
- Level: 2
- Source Problem: DreamHack

## Solution

### What we got ?

- Đề bài cho một file `.zip`, thực hiện unzip ta sẽ nhận được một file binary của chương trình mã hoá ảnh và một file ảnh với định dạng `.bmp` đã bị mã hoá.
- Thực hiện decompile file chương trình mã hoá, ta nhận được `main` như sau:
    
    ```python
    __int64 __fastcall main(int a1, char **a2, char **a3)
    {
      __int64 v3; // rax
      unsigned int v4; // ebx
      unsigned __int64 v5; // rax
      unsigned __int8 *v6; // rax
      char v7; // bl
      char v8; // al
      char v9; // bl
      int v10; // ebx
      unsigned __int8 *v11; // rax
      char v12; // bl
      char v13; // bl
      unsigned __int64 v14; // rax
      __int64 v15; // rax
      __int64 v16; // rbx
      const char *v17; // rax
      char v19; // [rsp+7h] [rbp-479h] BYREF
      unsigned __int64 i; // [rsp+8h] [rbp-478h]
      const char *v21; // [rsp+10h] [rbp-470h]
      const char *v22; // [rsp+18h] [rbp-468h]
      __int64 v23[2]; // [rsp+20h] [rbp-460h] BYREF
      __int64 v24[2]; // [rsp+30h] [rbp-450h] BYREF
      _QWORD v25[4]; // [rsp+40h] [rbp-440h] BYREF
      _BYTE v26[248]; // [rsp+60h] [rbp-420h] BYREF
      __int64 v27; // [rsp+158h] [rbp-328h] BYREF
      _QWORD v28[32]; // [rsp+260h] [rbp-220h] BYREF
      _QWORD v29[35]; // [rsp+360h] [rbp-120h] BYREF
    
      v29[33] = __readfsqword(0x28u);
      srand(0xBEEFu);
      v21 = "flag.bmp";
      v22 = "flag.bmp.enc";
      std::ifstream::basic_ifstream(v28, "flag.bmp", 4);
      if ( (unsigned __int8)std::ios::operator!(v29) )
      {
        v3 = std::operator<<<std::char_traits<char>>(&std::cerr, "Can't open flag bitmap file.");
        std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
        v4 = 1;
      }
      else
      {
        sub_2A6E((__int64)&v19);
        sub_2A44((__int64)v24);
        sub_29FA((__int64)v23, v28);
        sub_2AAE((__int64)v25, v23[0], v23[1], v24[0], v24[1], (__int64)&v19);
        sub_2A8E((__int64)&v19);
        std::ifstream::close(v28);
        for ( i = 0; ; ++i )
        {
          v14 = sub_2B92(v25);
          if ( i >= v14 )
            break;
          v5 = i % 3;
          if ( i % 3 == 2 )
          {
            v12 = *(_BYTE *)sub_2BB6(v25, i);
            v13 = (v12 ^ rand()) - 24;
            *(_BYTE *)sub_2BB6(v25, i) = v13;
          }
          else if ( v5 <= 2 )
          {
            if ( v5 )
            {
              if ( v5 == 1 )
              {
                v10 = rand() % 8;
                v11 = (unsigned __int8 *)sub_2BB6(v25, i);
                LOBYTE(v10) = sub_2489(*v11, v10);
                *(_BYTE *)sub_2BB6(v25, i) = v10;
              }
            }
            else
            {
              v6 = (unsigned __int8 *)sub_2BB6(v25, i);
              v7 = sub_2489(*v6, 7);
              v8 = rand();
              v9 = sub_24C2(v7 + v8, 4);
              *(_BYTE *)sub_2BB6(v25, i) = v9;
            }
          }
        }
        std::ofstream::basic_ofstream(v26, v22, 4);
        if ( (unsigned __int8)std::ios::operator!(&v27) )
        {
          v15 = std::operator<<<std::char_traits<char>>(&std::cerr, "create file is failed.");
          std::ostream::operator<<(v15, &std::endl<char,std::char_traits<char>>);
          v4 = 1;
        }
        else
        {
          v16 = sub_2B92(v25);
          v17 = (const char *)sub_2BD6(v25);
          std::ostream::write((std::ostream *)v26, v17, v16);
          std::ofstream::close(v26);
          v4 = 0;
        }
        std::ofstream::~ofstream(v26);
        sub_2B4A(v25);
      }
      std::ifstream::~ifstream(v28);
      return v4;
    }
    ```
    
- Từ file trên, ta có thể hình dung quy trình của chương trình này chính là input vào một file ảnh ở định dạng `.bmp`  và thực hiện mã hoá theo một quy tắc chung để tạo ra file `.bmp.enc`.
- Thực hiện kiểm tra, ta có được quá trình mã hoá như sau:
    
    ```nasm
    mov     edx, [rbp+var_4]
    movzx   eax, byte ptr [rdi+rdx]
    shl     eax, 1
    movzx   ecx, byte ptr [rdi+rdx]
    shr     ecx, 7
    or      eax, ecx
    movzx   ecx, al
    xor     ecx, 0xAA
    mov     [rdi+rdx], cl
    ```
    
- Ta có thể viết lại quy trình mã hoá dưới như sau:
    
    ```c
    // Hàm mã hóa nhận vào một mảng các ký tự (data) và độ dài (length)
    void encrypt(unsigned char* data, unsigned int length) {
        
        // Lặp qua từng byte trong mảng dữ liệu (tương ứng với vòng lặp từ 0x401186)
        for (unsigned int i = 0; i < length; i++) {
            
            // 1. Lấy byte dữ liệu tại vị trí i
            unsigned char current_byte = data[i];
    
            // 2. Thực hiện xoay trái bit 1 vị trí (Rotate Left 1)
            // Lệnh Assembly: shl eax, 1 | shr ecx, 7 | or eax, ecx
            unsigned char rotated_byte = (current_byte << 1) | (current_byte >> 7);
    
            // 3. Thực hiện phép toán XOR với hằng số 0xAA (170 trong hệ thập phân)
            // Lệnh Assembly: xor ecx, 0xAA
            unsigned char encrypted_byte = rotated_byte ^ 0xAA;
    
            // 4. Lưu kết quả đã mã hóa đè lại vào mảng
            data[i] = encrypted_byte;
        }
    }
    ```
    
- Có được quy trình mã hoá, dưới đây là toàn bộ quá trình:
    
    ```c
    v155 = __readfsqword(0x28u);
     
      // Set file names
      v21 = "flag.bmp";
      v22 = "flag.bmp.enc";
     
      // Read input file (flag.bmp)
      sub_33D2(v23, v21); // Open file stream v23 for "flag.bmp"
      sub_3108(v24, v23); // Read file content into v24 (likely std::string or vector<char>)
      sub_322A(v23); // Close file stream
     
      // Get buffer pointer (buf) and size
      v3 = sub_37E8(v24); // Get buffer pointer
      buf = (char *)v3;
      size = sub_3782(v24, 0); // Get buffer size
     
      // The encoding loop
      i = 0i64;
      if ( size )
      {
        do
        {
          v4 = i++ % 0x100; // i modulo 256
          v5 = (unsigned int)v4;
          v6 = &buf[v5]; // buf[i % 256]
          v7 = *v6; // byte at buf[i % 256]
          v8 = buf[v5]; // byte at buf[i % 256] - redundant load
     
          // *** Encoding Operation 1 ***
          *v6 = v8 ^ 0x66; // buf[i % 256] = buf[i % 256] XOR 0x66
     
          v9 = buf[i - 1i64]; // byte at buf[i - 1]
     
          // *** Encoding Operation 2 ***
          buf[i - 1i64] = v9 + v7; // buf[i - 1] = buf[i - 1] + buf[i % 256] (original value)
        }
        while ( i != size );
      }
     
      // Write output file (flag.bmp.enc)
      sub_319A(v28, v22); // Open file stream v28 for "flag.bmp.enc"
      sub_32C6(v29, v24, v28); // Write content of v24 (encoded buffer) to file stream
      sub_31FA(v28); // Close file stream
     
      // Cleanup
      sub_311A(v24);
      sub_311A(v23);
     
      v17 = sub_33D8(&v154, 0);
      v16 = sub_33E0(&v154, v17);
      return sub_37E8(v16);
    ```
    

### How to get flag ?

- Từ phân tích trên, ta có script lấy flag sau:
    
    ```python
    import sys
    import ctypes
    
    def load_libc():
        # Attempt to load standard Linux C library to replicate srand/rand
        libs = ['libc.so.6', '/lib/x86_64-linux-gnu/libc.so.6', '/lib/i386-linux-gnu/libc.so.6']
        for l in libs:
            try:
                return ctypes.CDLL(l)
            except OSError:
                continue
        print("[-] Error: Could not load libc.so.6. Please run this on Linux.")
        sys.exit(1)
    
    def ror(val, n):
        """Rotate Right (8-bit)"""
        n &= 7
        return ((val >> n) | (val << (8 - n))) & 0xFF
    
    def rol(val, n):
        """Rotate Left (8-bit)"""
        n &= 7
        return ((val << n) | (val >> (8 - n))) & 0xFF
    
    def decrypt():
        input_filename = "flag.bmp.enc"
        output_filename = "flag.bmp"
    
        # Load libc and seed RNG
        libc = load_libc()
        seed = 48879
        libc.srand(seed)
        print(f"[+] Seeding RNG with {seed}")
    
        try:
            with open(input_filename, "rb") as f:
                data = bytearray(f.read())
        except FileNotFoundError:
            print(f"[-] Error: Could not find {input_filename}")
            return
    
        print(f"[+] Decrypting {len(data)} bytes...")
    
        # Process byte by byte
        for i in range(len(data)):
            # Important: rand() is called exactly once per iteration in the original code,
            # regardless of the case. We must match this state update.
            r = libc.rand()
            
            enc_byte = data[i]
            dec_byte = 0
            
            idx = i % 3
    
            if idx == 0:
                # Enc Logic: 
                # v7 = ror(old, 7)
                # v9 = rol((v7 + r), 4)
                
                # Dec Logic:
                # 1. Inverse outer rotate (ROL 4 -> ROR 4)
                tmp = ror(enc_byte, 4)
                # 2. Inverse addition (Sub r)
                tmp = (tmp - r) & 0xFF
                # 3. Inverse inner rotate (ROR 7 -> ROL 7)
                dec_byte = rol(tmp, 7)
    
            elif idx == 1:
                # Enc Logic:
                # n7 = r % 8
                # new = ror(old, n7)
                
                # Dec Logic:
                # Inverse ROR is ROL
                n7 = r % 8
                dec_byte = rol(enc_byte, n7)
    
            elif idx == 2:
                # Enc Logic:
                # new = (old ^ r) - 24
                
                # Dec Logic:
                # 1. Inverse subtraction (Add 24)
                tmp = (enc_byte + 24) & 0xFF
                # 2. Inverse XOR (XOR r) - only low 8 bits of r matter for the byte
                dec_byte = tmp ^ (r & 0xFF)
    
            data[i] = dec_byte
    
        with open(output_filename, "wb") as f:
            f.write(data)
    
        print(f"[+] Done! Output saved to {output_filename}")
    
    if __name__ == "__main__":
        decrypt()
    ```
    
- Chạy script trên, ta nhận được file `.bmp` gốc chứa flag:
    
    ![image.png](attachment:e15663ae-c9a8-479e-a6b6-a9441987b28d:image.png)
