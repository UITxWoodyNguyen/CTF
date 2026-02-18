# Easy as GDB

### Information
* Category: Reverse Engineering
* Level: Hard

## Analyzing
The problem gives us a binary, try to check its type, we find that this is a stripped ELF-32 bit binary file:
```bash
$ file brute
brute: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=ff636afc0b293bfac96a4e3ab84124974f4f0e68, stripped
```

Next, try to decompile the binary with IDA, we observed that the process of this binary contains 3 functions:
- The first function is `sub_82B()`:
    ```c
    char *__cdecl sub_82B(char *src, size_t n)
    {
        unsigned int i; // [esp+0h] [ebp-18h]
        char *dest; // [esp+Ch] [ebp-Ch]
        size_t na; // [esp+24h] [ebp+Ch]

        na = (n & 0xFFFFFFFC) + 4;
        dest = (char *)malloc(na + 1);
        strncpy(dest, src, na);
        for ( i = 180154381; i < 0xDEADBEEF; i += 2075469 )
            sub_6BD(dest, na, i);
        return dest;
    }

    unsigned int __cdecl sub_6BD(int a1, unsigned int a2, int a3)
    {
        unsigned int result; // eax
        unsigned int i; // [esp+14h] [ebp-14h]
        _BYTE v5[4]; // [esp+18h] [ebp-10h]
        unsigned int v6; // [esp+1Ch] [ebp-Ch]

        v6 = __readgsdword(0x14u);
        v5[0] = HIBYTE(a3);
        v5[1] = BYTE2(a3);
        v5[2] = BYTE1(a3);
        v5[3] = a3;
        for ( i = 0; i < a2; ++i )
            *(_BYTE *)(a1 + i) ^= v5[i & 3];
        result = __readgsdword(0x14u) ^ v6;
        if ( result )
            sub_B20();
        return result;
    }

    void __noreturn sub_B20()
    {
        __asm { add     ebx, (offset off_1FB8 - $) }
    }
    ```

    We observed that this function is used for XOR decryption, with it's sub function `sub_68D` is used to XOR each 4 bytes. Base on this, we can re-sub the raw code like this:
    ```c
    // --- [Hàm gốc: sub_6BD] ---
    // Thực hiện phép XOR 4-byte
    void xor_transform(char *data, unsigned int len, unsigned int key) {
        unsigned char key_bytes[4];
        key_bytes[0] = (unsigned char)((key >> 24) & 0xFF);
        key_bytes[1] = (unsigned char)((key >> 16) & 0xFF);
        key_bytes[2] = (unsigned char)((key >> 8) & 0xFF);
        key_bytes[3] = (unsigned char)(key & 0xFF);

        for (unsigned int i = 0; i < len; ++i) {
            data[i] ^= key_bytes[i % 4];
        }
    }

    // --- [Hàm gốc: sub_82B] ---
    // Giải mã đa vòng XOR
    char* decrypt_data(char *src, size_t n) {
        size_t aligned_size = (n & 0xFFFFFFFC) + 4;
        char *dest = (char *)malloc(aligned_size + 1);
        if (!dest) return NULL;

        memset(dest, 0, aligned_size + 1);
        strncpy(dest, src, aligned_size);

        // Vòng lặp XOR từ 0x0ABCFE0D đến 0xDEADBEEF
        for (unsigned int current_key = 180154381; current_key < 0xDEADBEEF; current_key += 2075469) {
            xor_transform(dest, aligned_size, current_key);
        }
        return dest;
    }
    ```
- The `sub_7C2` function is used for shuffle element, which get the swap operation from `sub_751`:
    ```c
    // --- [Hàm gốc: sub_751] ---
    // Hoán đổi các byte dựa trên bước nhảy (stride)
    unsigned int swap_elements(uint8_t *data_ptr, int length, int stride) {
        unsigned int result;
        uint8_t temp;
        unsigned int i;

        for (i = 0; ; i += stride) {
            result = length - stride + 1;
            if (i >= result) break;

            temp = data_ptr[i];
            data_ptr[i] = data_ptr[i + stride - 1];
            data_ptr[i + stride - 1] = temp;
        }
        return result;
    }

    // --- [Hàm gốc: sub_7C2] ---
    // Xáo trộn toàn bộ mảng theo hướng tiến hoặc lùi
    unsigned int shuffle_data(uint8_t *data_ptr, unsigned int length, int direction) {
        unsigned int result = 0;
        if (direction <= 0) {
            // Hướng lùi: Stride giảm dần
            for (int i = length - 1; i > 0; --i) {
                result = swap_elements(data_ptr, length, i);
            }
        } else {
            // Hướng tiến: Stride tăng dần
            for (unsigned int j = 1; j < length; ++j) {
                swap_elements(data_ptr, length, j);
                result = j;
            }
        }
        return result;
    }
    ```
- The `sub_82B` function is used for decrypt data:
    ```c
    // --- [Hàm gốc: sub_82B] ---
    // Giải mã đa vòng XOR
    char* decrypt_data(char *src, size_t n) {
        size_t aligned_size = (n & 0xFFFFFFFC) + 4;
        char *dest = (char *)malloc(aligned_size + 1);
        if (!dest) return NULL;

        memset(dest, 0, aligned_size + 1);
        strncpy(dest, src, aligned_size);

        // Vòng lặp XOR từ 0x0ABCFE0D đến 0xDEADBEEF
        for (unsigned int current_key = 180154381; current_key < 0xDEADBEEF; current_key += 2075469) {
            xor_transform(dest, aligned_size, current_key);
        }
        return dest;
    }
    ```
- Finally, the flag checker is done by `sub_8C4`:
    ```c
    int validate_solution(char *src, size_t n) {
        char *user_data = (char *)calloc(n + 1, 1);
        char *target_data = (char *)calloc(n + 1, 1);
        
        strncpy(user_data, src, n);
        strncpy(target_data, aZNh, n);

        // Cả hai đều được xáo trộn ngược trước khi so sánh
        shuffle_data((uint8_t *)user_data, n, -1);
        shuffle_data((uint8_t *)target_data, n, -1);

        puts("checking solution...");
        int is_correct = 1;
        for (size_t i = 0; i < n; ++i) {
            if (user_data[i] != target_data[i]) {
                is_correct = -1;
                break;
            }
        }

        free(user_data);
        free(target_data);
        return is_correct;
    }
    ```

This is the full flow of this binary:
```c
int validate_flag() {
    char *input_buffer = (char *)calloc(512, 1);
    if (!input_buffer) return -1;

    printf("input the flag: ");
    if (fgets(input_buffer, 512, stdin) == NULL) {
        free(input_buffer);
        return -1;
    }

    // Xóa ký tự xuống dòng từ fgets
    input_buffer[strcspn(input_buffer, "\n")] = 0;

    // Tính độ dài flag mục tiêu
    size_t flag_len = strnlen(&unk_2008, 512);

    // 1. Biến đổi dữ liệu nguồn (Decrypt XOR)
    char *transformed_data = decrypt_data(&unk_2008, flag_len);

    // 2. Xáo trộn dữ liệu vừa giải mã (Shuffle Forward)
    shuffle_data((uint8_t *)transformed_data, flag_len, 1);

    // 3. So sánh Input với chuỗi đích thông qua xáo trộn ngược
    if (validate_solution(input_buffer, flag_len) == 1) {
        puts("Correct!");
    } else {
        puts("Incorrect.");
    }

    free(input_buffer);
    free(transformed_data);
    return 0;
}
```

We observed that this binary will get the flag in input, then it try to change the data then compare it with the target data to print the `Correct/Incorrect` output.

## Solution
First, check all the section headers of this binary. We will find the `.data` at offset `0x2000`:
```bash
$ readelf -S brute
There are 27 section headers, starting at offset 0x113c:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        00000154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            00000168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.bu[...] NOTE            00000188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        000001ac 0001ac 000020 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          000001cc 0001cc 000100 10   A  6   1  4
  [ 6] .dynstr           STRTAB          000002cc 0002cc 0000e7 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          000003b4 0003b4 000020 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         000003d4 0003d4 000040 00   A  6   1  4
  [ 9] .rel.dyn          REL             00000414 000414 000048 08   A  5   0  4
  [10] .rel.plt          REL             0000045c 00045c 000048 08  AI  5  22  4
  [11] .init             PROGBITS        000004a4 0004a4 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        000004d0 0004d0 0000a0 04  AX  0   0 16
  [13] .plt.got          PROGBITS        00000570 000570 000010 08  AX  0   0  8
  [14] .text             PROGBITS        00000580 000580 0005b4 00  AX  0   0 16
  [15] .fini             PROGBITS        00000b34 000b34 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        00000b48 000b48 000042 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        00000b8c 000b8c 00006c 00   A  0   0  4
  [18] .eh_frame         PROGBITS        00000bf8 000bf8 0001c4 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      00001eb8 000eb8 000004 04  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      00001ebc 000ebc 000004 04  WA  0   0  4
  [21] .dynamic          DYNAMIC         00001ec0 000ec0 0000f8 08  WA  6   0  4
  [22] .got              PROGBITS        00001fb8 000fb8 000048 04  WA  0   0  4
  [23] .data             PROGBITS        00002000 001000 000026 00  WA  0   0  4
  [24] .bss              NOBITS          00002026 001026 000002 00  WA  0   0  1
  [25] .comment          PROGBITS        00000000 001026 000029 01  MS  0   0  1
  [26] .shstrtab         STRTAB          00000000 00104f 0000ec 00      0   0  1
```

Base on the IDA, we find that the symbol `aZNh` is used to get the target flag's length. Base on this, we use `objdump` to find the offset of this symbol and get the raw bytes. This is the result:
```bash
objdump -s -j .data -j .rodata brute

brute:     file format elf32-i386

Contents of section .rodata:
 0b48 03000000 01000200 63686563 6b696e67  ........checking
 0b58 20736f6c 7574696f 6e2e2e2e 00696e70   solution....inp
 0b68 75742074 68652066 6c61673a 2000436f  ut the flag: .Co
 0b78 72726563 74210049 6e636f72 72656374  rrect!.Incorrect
 0b88 2e00                                 ..
Contents of section .data:
 2000 00000000 04200000 7a2e6e68 1d65167c  ..... ..z.nh.e.|
 2010 6d436f36 36621a45 43324061 58015865  mCo66b.EC2@aX.Xe
 2020 62665330 3b17                        bfS0;.
```

Base in this, the symbol `aZNh` is located at `0x2008` and its raw bytes, which is used in the binary is :
```
7a 2e 6e 68 1d 65 16 7c 6d 43 6f 36 36 62 1a 45 43 32 40 61 58 01 58 65 62 66 53 30 3b 17
```

So, we can get the `aZNh` and do a reverse shuffle to get the flag. This is the source code:
```python
data = bytes([0x7a,0x2e,0x6e,0x68,0x1d,0x65,0x16,0x7c,0x6d,0x43,0x6f,0x36,0x36,0x62,0x1a,0x45,0x43,0x32,0x40,0x61,0x58,0x01,0x58,0x65,0x62,0x66,0x53,0x30,0x3b,0x17])
# Hàm reverse shuffle (nghịch đảo của forward shuffle)
def swap_elements(arr,length,stride):
    i=0
    while True:
        result = length - stride + 1
        if i >= result: break
        a=i; b=i+stride-1
        arr[a],arr[b] = arr[b],arr[a]
        i += stride

def shuffle_reverse(b):
    arr = list(b)
    for s in range(len(arr)-1,0,-1):
        swap_elements(arr,len(arr),s)
    return bytes(arr)

R = shuffle_reverse(data)

# XOR multi-pass (theo code): từ 180154381, step 2075469, tới < 0xDEADBEEF
start = 180154381
end = 0xDEADBEEF
step = 2075469
n = len(R)
aligned_size = (n & 0xFFFFFFFC) + 4
aligned = bytearray(R + b"\x00"*(aligned_size-n))
for key in range(start, end, step):
    kb = [(key >> 24) & 0xFF, (key >> 16) & 0xFF, (key >> 8) & 0xFF, key & 0xFF]
    for i in range(aligned_size):
        aligned[i] ^= kb[i % 4]

flag = bytes(aligned[:n]).decode()
print(flag)
```

This is the result:
```bash
$ python3 solve.py
picoCTF{I_5D3_A11DA7_5fb8f91e}
```