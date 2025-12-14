# Easy as GDB
### Information
* Category: Reverse Engineering
* Point: 160
* Level: Hard

### Description

The flag has got to be checked somewhere... File: [`brute`](https://mercury.picoctf.net/static/84a60a8ccee38ac906f28075221fa2e6/brute)

## Solution:

Open `brute` in IDA, navigate to function `start`. We see that it pushes `main` function at the end of the code. And `off_1FF8` points to function `sub_9AF` so we will examine this.

```asm
.text:00000580                 public start
.text:00000580 start           proc near               ; DATA XREF: LOAD:00000018↑o
.text:00000580                 xor     ebp, ebp
.text:00000582                 pop     esi
.text:00000583                 mov     ecx, esp
.text:00000585                 and     esp, 0FFFFFFF0h
.text:00000588                 push    eax
.text:00000589                 push    esp             ; stack_end
.text:0000058A                 push    edx             ; rtld_fini
.text:0000058B                 call    sub_5B2
.text:00000590                 add     ebx, (offset off_1FB8 - $) ; loads GOT entries
.text:00000596                 lea     eax, (nullsub_1 - 1FB8h)[ebx]
.text:0000059C                 push    eax             ; fini
.text:0000059D                 lea     eax, (sub_AB0 - 1FB8h)[ebx]
.text:000005A3                 push    eax             ; init
.text:000005A4                 push    ecx             ; ubp_av
.text:000005A5                 push    esi             ; argc
.text:000005A6                 push    ds:(off_1FF8 - 1FB8h)[ebx] ; main
.text:000005AC                 call    ___libc_start_main
.text:000005B1                 hlt
.text:000005B1 start           endp
```

At `sub_9AF`, the function does several things:
- Prints `"input the flag: "`.
    ```asm
    .text:000009E9                 lea     eax, (aInputTheFlag - 1FB8h)[ebx] ; "input the flag: "
    .text:000009EF                 push    eax             ; format
    .text:000009F0                 call    _printf ; printf("input the flag: ")
    ```
- Take in user's input.
    ```asm
    .text:00000A06                 push    edx             ; stream
    .text:00000A07                 push    eax             ; n = 512
    .text:00000A08                 push    [ebp+s]         ; s
    .text:00000A0B                 call    _fgets ; fgets(s, 512, stdin)
    ```
- Get the length of `aZNh` through `_strnlen` and use it as an argument to function `sub_82B`.
    ```asm
    add     esp, 10h
    .text:00000A16                 push    [ebp+nmemb]
    .text:00000A19                 lea     eax, (aZNh - 1FB8h)[ebx] ; "z.nh"
    .text:00000A1F                 push    eax
    .text:00000A20                 call    _strnlen ; strnlen(z.nh, 512)
    ```
- Call `sub_82B(user_input, aZNh_length)`.
    ```asm
    .text:00000A2E                 push    [ebp+n]         ; n
    .text:00000A31                 push    [ebp+s]         ; src
    .text:00000A34                 call    sub_82B ; sub_82B(src, n)
    ```
- Call `sub_7C2(sub_82B_returned_value, aZNh_length, 1)`.
    ```asm
    .text:00000A42                 push    1               ; a3
    .text:00000A44                 push    [ebp+n]         ; 2
    .text:00000A47                 push    [ebp+src]       ; src
    .text:00000A4A                 call    sub_7C2 ; sub_7C2(src, length, 1)
    ```
- Call `sub_8C4(sub_82B_returned_value_modified_by_sub_7C2, aZNh_length)` and gets its returned value. If it is `1`, the function prints `"Correct!"` otherwise `"Incorrect."`.
    ```asm
    .text:00000A55                 push    [ebp+n]         ; n
    .text:00000A58                 push    [ebp+src]       ; src
    .text:00000A5B                 call    sub_8C4 ; sub_8C4(src, length)
    ```

Move on to function `sub_82B`, this function performs a loop from `0xABCF00D` to `0xDEADBEEF`, each loop increases the counter by `0x1FAB4D` and calls `sub_6BD`, which is likely doing some crypto algorithms to `dest`.

```c
char *__cdecl sub_82B(char *src, size_t n)
{
  unsigned int i; // [esp+0h] [ebp-18h]
  char *dest; // [esp+Ch] [ebp-Ch]
  size_t na; // [esp+24h] [ebp+Ch]

  na = (n & 0xFFFFFFFC) + 4;                    // get nearest multiple of 4
  dest = (char *)malloc(na + 1);
  strncpy(dest, src, na);
  for ( i = 0xABCF00D; i < 0xDEADBEEF; i += 0x1FAB4D )
    sub_6BD(dest, na, i);
  return dest;
}
```

Examining `sub_6BD`, this function implements repeating-key XOR cipher. It takes `dest` and XOR it with a 4-byte key derived from `i` argument.

```c
unsigned int __cdecl sub_6BD(char *dest, size_t na, unsigned int i)
{
  unsigned int result; // eax
  size_t j; // [esp+14h] [ebp-14h]
  _BYTE v5[4]; // [esp+18h] [ebp-10h]
  unsigned int v6; // [esp+1Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  v5[0] = HIBYTE(i);
  v5[1] = BYTE2(i);
  v5[2] = BYTE1(i);
  v5[3] = i;
  for ( j = 0; j < na; ++j )
    dest[j] ^= v5[j & 3];
  result = __readgsdword(0x14u) ^ v6;
  if ( result )
    sub_B20();
  return result;
}
```

So we have done analysing `sub_82B`, let's continue to inspect `sub_7C2`, which is called after `sub_82B`. It creates a loop base on `a3`, which is likely the conditional flag. When `a3 <= 0`, it loops from `n - 1` to `0`, calling `sub_751` at each iteration. Otherwise it loops from `1` to `n - 1`. Overall, the function looks like it is a director for a shuffle algorithm at `sub_751`.

```c
unsigned int __cdecl sub_7C2(char *src, unsigned int n, int a3)
{
  unsigned int j_1; // eax
  unsigned int j; // [esp+8h] [ebp-8h]
  int i; // [esp+Ch] [ebp-4h]

  if ( a3 <= 0 )
  {
    j_1 = n - 1;
    for ( i = n - 1; i > 0; --i )
      j_1 = sub_751(src, n, i);
  }
  else
  {
    for ( j = 1; ; ++j )
    {
      j_1 = j;
      if ( n <= j )
        break;
      sub_751(src, n, j);
    }
  }
  return j_1;
}
```

To be sure, we inspect `sub_751`. It loops through `src`, jumps `i` at each time, for each block of size `i`, it swaps the first and last bytes of that block. So this is indeed the shuffle algorithm!

```c
unsigned int __cdecl sub_751(char *src, unsigned int n, int i)
{
  unsigned int j_1; // eax
  char v4; // [esp+Bh] [ebp-5h]
  unsigned int j; // [esp+Ch] [ebp-4h]

  for ( j = 0; ; j += i )
  {
    j_1 = n - i + 1;
    if ( j >= j_1 )
      break;
    v4 = src[j];
    src[j] = src[j - 1 + i];
    src[j - 1 + i] = v4;
  }
  return j_1;
}
```

Moving on to the last function that we have to analyse: `sub_8C4`. This function just compares the transformed user's input with the hardcoded data `aZNh`.

```c
int __cdecl sub_8C4(char *src, size_t n)
{
  int v3; // [esp+0h] [ebp-18h]
  size_t i; // [esp+4h] [ebp-14h]
  char *dest; // [esp+8h] [ebp-10h]
  char *dest_1; // [esp+Ch] [ebp-Ch]

  dest = (char *)calloc(n + 1, 1u);
  strncpy(dest, src, n);
  sub_7C2(dest, n, -1);
  dest_1 = (char *)calloc(n + 1, 1u);
  strncpy(dest_1, aZNh, n);
  sub_7C2(dest_1, n, -1);
  puts("checking solution...");
  v3 = 1;
  for ( i = 0; i < n; ++i )
  {
    if ( dest[i] != dest_1[i] )
      return -1;
  }
  return v3;
}
```

Since we have analysed all core functions, we can create a script that can get the flag for us. Here is cpp script for that:

```cpp
#include <iostream>
#include <cstring>
#include <cstdlib>
using namespace std;

void reverse_segments(char* arr, int size, int step) {
    for (int j = 0; j + step <= size; j += step) {
        swap(arr[j], arr[j + step - 1]);
    }
}

void process_array(char* arr, int size, int direction) {
    if (direction <= 0) {
        for (int i = size - 1; i > 0; --i) {
            reverse_segments(arr, size, i);
        }
    } else {
        for (int i = 1; i < size; ++i) {
            reverse_segments(arr, size, i);
        }
    }
}

void xor_encrypt(char* data, int length, unsigned int key) {
    unsigned char key_bytes[4];
    key_bytes[0] = (key >> 24) & 0xFF;
    key_bytes[1] = (key >> 16) & 0xFF;
    key_bytes[2] = (key >> 8) & 0xFF;
    key_bytes[3] = key & 0xFF;
    
    for (int j = 0; j < length; ++j) {
        data[j] ^= key_bytes[j & 3];
    }
}

char* decode_string(char* src, int n) {
    int aligned_size = (n & 0xFFFFFFFC) + 4;
    char* dest = (char*)malloc(aligned_size + 1);
    strncpy(dest, src, aligned_size);
    
    for (unsigned int i = 180154381; i < 3735928559; i += 2075469) {
        xor_encrypt(dest, aligned_size, i);
    }
    
    return dest;
}

int main() {
    char chars[] = {
        0x7A, 0x2E, 0x6E, 0x68, 0x1D, 0x65, 0x16, 0x7C, 0x6D, 0x43, 
        0x6F, 0x36, 0x32, 0x62, 0x12, 0x16, 0x43, 0x34, 0x40, 0x3E, 
        0x58, 0x01, 0x58, 0x3F, 0x62, 0x3F, 0x53, 0x30, 0x6E, 0x17
    }; // aZNh taken from IDA
    process_array(chars, sizeof(chars), -1); // because the xor algorithm is forward in the program, we have to shuffle the data backward so that we can correctly decode it
    char* decoded = decode_string(chars, sizeof(chars));

    for (int i = 0; i < sizeof(chars); ++i) {
        cout << decoded[i];
    }
    cout << endl;

    return 0;
}
```


Run it and we got our flag `picoCTF{I_5D3_A11DA7_358a9150}`.

