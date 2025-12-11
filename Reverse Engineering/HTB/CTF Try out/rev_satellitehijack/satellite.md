# Satellite Hijack
### Information
* Category: Reverse Engineering
* Level: Hard
* Point: 975

### Description

The crew has located a dilapidated pre-war bunker. Deep within, a dusty control panel reveals that it was once used for communication with a low-orbit observation satellite. During the war, actors on all sides infiltrated and hacked each others systems and software, inserting backdoors to cripple or take control of critical machinery. It seems like this panel has been tampered with to prevent the control codes necessary to operate the satellite from being transmitted - can you recover the codes and take control of the satellite to locate enemy factions?

## Solution:

Open `satellite` in IDA, go to function `main` and decompile it. The function prints the banner and sending user's input by calling `send_satellite_message`, which is an imported function.

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  _QWORD buf[129]; // [rsp+0h] [rbp-410h] BYREF
  ssize_t v4; // [rsp+408h] [rbp-8h]

  setbuf(_bss_start, 0LL);
  puts(banner);
  send_satellite_message(0LL, (__int64)"START");
  memset(buf, 0, 1024);
  while ( 1 )
  {
    while ( 1 )
    {
      putchar(62);                              // '>'
      putchar(32);                              // ' '
      v4 = read(1, buf, 0x400uLL);
      if ( v4 >= 0 )
        break;
      puts("ERROR READING DATA");
    }
    if ( v4 > 0 )
      *((_BYTE *)buf + v4 - 1) = 0;             // set last char of v4 to '\0'
    printf("Sending `%s`\n", (const char *)buf);
    send_satellite_message(0LL, (__int64)buf);
  }
}
```

Beside that, we can't find anything more useful, the archive has another file named `library.so`, so open it in IDA. There are two functions with bolded name: `sub_24DB` and `sub_21A9`, so we will go through them first. At function `sub_24DB`, it takes in two arguments: `n4` and `s`, then append `s` to `qword_5080[n4]`. However, there is a bug in allocating memory for the new appended string, making the null terminator is written pass the heap by one byte. This corrupts the header of the next adjacent heap chunk, clearing its `PREV_INUSE` bit. This makes the allocator believes that the current chunk (`dest`) is free when the next chunk is being freed, leading to a heap consolidation vulnerability.

```c
size_t __fastcall sub_24DB(unsigned int n4, const char *s)
{
  size_t v3; // rax
  size_t size; // rdx
  char *sa; // [rsp+10h] [rbp-20h]
  char *dest; // [rsp+28h] [rbp-8h]

  if ( n4 > 4 )                                 // qword_5080 has 5 elements [0 .. 4]
    return -2LL;
  if ( !*s )                                    // check whether string is empty
    return -22LL;
  sa = (char *)qword_5080[n4];
  if ( sa )
    v3 = strlen(sa);                            // get length
  else
    v3 = 0LL;
  size = strlen(s) + v3;                        // calc new length, but missing 1 byte because strlen doesn't count '\0'
  dest = (char *)realloc(sa, size);             // allocate new memory 
  if ( sa )
    strcat(dest, s);                            // append s to it, but the null terminator will be written one byte pass the heap
  else
    strcpy(dest, s);
  qword_5080[n4] = dest;
  return strlen(dest);
}
```

Press `X` to find the function's references, we found that it gets called at `sub_25D0`. It checks for environment `SAT_PROD_ENVIRONMENT`, if that is existed, it calls `sub_23E3`.

```c
size_t (__fastcall *sub_25D0())(unsigned int n4, const char *s)
{
  unsigned int i; // [rsp+Ch] [rbp-24h]
  char name[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  strcpy(name, "TBU`QSPE`FOWJSPONFOU");
  for ( i = 0; i <= 0x13; ++i )
    --name[i];                                  // SAT_PROD_ENVIRONMENT
  if ( getenv(name) )
    sub_23E3();
  return sub_24DB;
}
```

At `sub_23E3`, it gets the `read` function from the program and attempts to overwrite it with the one from `src`. 

```c
_QWORD *sub_23E3()
{
  _QWORD *result; // rax
  unsigned __int64 v1; // [rsp+8h] [rbp-18h]
  _QWORD *v2; // [rsp+10h] [rbp-10h]
  void *dest; // [rsp+18h] [rbp-8h]

  v1 = getauxval(3uLL) & 0xFFFFFFFFFFFFF000LL;  // get base address of exe memory page
  v2 = (_QWORD *)sub_21A9(v1, "read");          // search for "read" object in the memory
  dest = mmap(0LL, (((char *)sub_21A9 - (char *)src) & 0xFFFFFFFFFFFFF000LL) + 4096, 7, 34, -1, 0LL);// allocates memory for coping src
  memcpy(dest, src, (char *)sub_21A9 - (char *)src);
  memfrob(dest, (char *)sub_21A9 - (char *)src);// xor each byte in src with 0x2A
  result = v2;
  *v2 = dest;                                   // overwrite "read" with dest
  return result;
}
```

We take `src` data and xor each byte in it with `0x2A` to see what it is. Here is the cpp code to do it.

```cpp
#include <iostream>
using namespace std;

unsigned char src[] = {
  0x6B, 0x7D, 0x6B, 0x7C, 0x6B, 0x7F, 0x6B, 0x7E, 0x7F, 0x79, 
  0x62, 0xA9, 0xC6, 0x22, 0xA3, 0xD1, 0x63, 0xA3, 0xDF, 0x62, 
  0xA3, 0xFF, 0xC2, 0xA3, 0x2B, 0x2A, 0x2A, 0x63, 0xA3, 0xEE, 
  0xA9, 0xD1, 0x2B, 0x5F, 0x7D, 0x62, 0xAF, 0xEA, 0x52, 0x78, 
  0x63, 0xA3, 0xED, 0x62, 0xA9, 0xD2, 0x2E, 0x5C, 0x63, 0x63, 
  0xA7, 0x77, 0x2E, 0x67, 0xA7, 0x5E, 0x2F, 0x2A, 0x66, 0x2B, 
  0xC7, 0xC1, 0x23, 0x62, 0xA9, 0xE9, 0x2B, 0x66, 0x13, 0xD9, 
  0x5E, 0x18, 0xAB, 0x51, 0xD6, 0x62, 0x7E, 0x68, 0x51, 0x5F, 
  0xC4, 0x62, 0xA3, 0xC4, 0x62, 0x03, 0xF4, 0x62, 0xA3, 0xF5, 
  0xC2, 0x07, 0x2A, 0x2A, 0x2A, 0xAF, 0xEA, 0x5E, 0xF6, 0x66, 
  0xA3, 0xD0, 0x94, 0x2A, 0x2A, 0x2A, 0x2A, 0x66, 0xA3, 0xC5, 
  0xC2, 0xBC, 0x2A, 0x2A, 0x2A, 0x63, 0xED, 0xEE, 0xD5, 0xD5, 
  0xD5, 0xD5, 0x66, 0xA3, 0xCA, 0x62, 0xA9, 0xEE, 0x22, 0x71, 
  0x77, 0x6B, 0x76, 0x6B, 0x77, 0x6B, 0x74, 0x6B, 0x75, 0xE9, 
  0x62, 0x92, 0x46, 0x1F, 0x51, 0x1A, 0x5C, 0x1A, 0x73, 0x1D, 
  0x62, 0x90, 0x4C, 0x7C, 0x4C, 0x15, 0x5F, 0x14, 0x56, 0x10, 
  0x62, 0xA3, 0x6E, 0x0E, 0xF2, 0x62, 0xA3, 0x7E, 0x0E, 0xCA, 
  0x62, 0x92, 0x14, 0x56, 0x10, 0x65, 0x0B, 0x56, 0x66, 0x52, 
  0x62, 0x90, 0x0B, 0x45, 0x0E, 0x40, 0x06, 0x11, 0x4C, 0x2A, 
  0x62, 0xA3, 0x6E, 0x0E, 0xCF, 0x62, 0xA3, 0x7E, 0x0E, 0xC7, 
  0x92, 0x2A, 0x2A, 0x2A, 0x2A, 0x62, 0xA7, 0x66, 0x0E, 0xF2, 
  0x62, 0xAF, 0xDC, 0x5E, 0x0F, 0x25, 0x9C, 0x3E, 0x2D, 0x18, 
  0x3E, 0x22, 0x62, 0x25, 0x94, 0xF8, 0x62, 0x13, 0xE8, 0x5F, 
  0x36, 0x62, 0xA9, 0xEA, 0x2B, 0x62, 0x13, 0xEC, 0x5E, 0x27, 
  0x62, 0xA9, 0xD2, 0x36, 0x5F, 0xCB, 0x92, 0x2B, 0x2A, 0x2A, 
  0x2A, 0xE9, 0xE9, 0x92, 0x2A, 0x2A, 0x2A, 0x2A, 0xE9, 0x92, 
  0x2A, 0x2A, 0x2A, 0x2A, 0xE9, 0x62, 0xAF, 0xF8, 0x5E, 0x38, 
  0x62, 0xA3, 0xD2, 0x62, 0x2B, 0xFD, 0x6A, 0xA2, 0x1A, 0x62, 
  0xA9, 0xEA, 0x2B, 0x62, 0x13, 0xD2, 0x5F, 0xDE, 0xE9, 0x6B, 
  0x7C, 0x6B, 0x7F, 0x6B, 0x7E, 0x7F, 0x79, 0x6B, 0xA3, 0xD1, 
  0x62, 0xA3, 0x5E, 0x0E, 0xF2, 0x62, 0xA3, 0x7E, 0x0E, 0xCA, 
  0x62, 0xA3, 0x66, 0x0E, 0xC2, 0x66, 0xA3, 0x6E, 0x0E, 0xDA, 
  0x66, 0xA3, 0x66, 0x0E, 0xD2, 0x62, 0xA7, 0x6E, 0x0E, 0x1A, 
  0x62, 0xA3, 0x6E, 0x0E, 0xEA, 0x62, 0xA7, 0x6E, 0x0E, 0xFA, 
  0x62, 0xA3, 0x6E, 0x0E, 0xE2, 0x62, 0xA3, 0xD9, 0x62, 0xA3, 
  0xFF, 0x63, 0xA3, 0xE6, 0x67, 0xA3, 0xEF, 0xED, 0x6E, 0x0E, 
  0x92, 0x1A, 0x2A, 0x2A, 0x2A, 0x67, 0xA3, 0xE4, 0x62, 0xA1, 
  0x66, 0x0E, 0xEA, 0x62, 0xA7, 0x6B, 0x22, 0x62, 0xA3, 0x6E, 
  0x0E, 0xEA, 0x6E, 0xA3, 0xF2, 0x62, 0xA3, 0xF5, 0x62, 0xA3, 
  0xC4, 0x66, 0xA3, 0xC8, 0x67, 0xA3, 0xC0, 0x67, 0xA3, 0xDA, 
  0x66, 0xA1, 0x23, 0x25, 0x2F, 0x63, 0xA3, 0xE9, 0x66, 0xA3, 
  0xF2, 0x71, 0x77, 0x6B, 0x76, 0x6B, 0x77, 0x6B, 0x74, 0xE9, 
  0x62, 0xA3, 0xFB, 0x62, 0xA3, 0xD8, 0xA3, 0xD4, 0x95, 0x2A, 
  0x2A, 0x2A, 0x2A, 0x92, 0x2A, 0x2A, 0x2A, 0x2A, 0xC2, 0x4C, 
  0xD5, 0xD5, 0xD5, 0xE9, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 
};

int main() {
    int src_size = sizeof(src);
    unsigned char* decoded = new unsigned char[src_size];

    for (int i = 0; i < src_size; i++) {
        decoded[i] = src[i] ^ 0x2A;
    }

    for (int i = 0; i < src_size; ++i) {
        printf("%02X ", decoded[i]);
        if ((i + 1) % 16 == 0) {
            cout << endl;
        }
    }

    return 0;
}
```

Here is the result

```bin
41 57 41 56 41 55 41 54 55 53 48 83 EC 08 89 FB
49 89 F5 48 89 D5 E8 89 01 00 00 49 89 C4 83 FB
01 75 57 48 85 C0 78 52 49 89 C7 48 83 F8 04 76
49 49 8D 5D 04 4D 8D 74 05 00 4C 01 ED EB 09 48
83 C3 01 4C 39 F3 74 32 81 7B FC 48 54 42 7B 75
EE 48 89 EE 48 29 DE 48 89 DF E8 2D 00 00 00 85
C0 74 DC 4C 89 FA BE 00 00 00 00 4C 89 EF E8 96
00 00 00 49 C7 C4 FF FF FF FF 4C 89 E0 48 83 C4
08 5B 5D 41 5C 41 5D 41 5E 41 5F C3 48 B8 6C 35
7B 30 76 30 59 37 48 BA 66 56 66 3F 75 3E 7C 3A
48 89 44 24 D8 48 89 54 24 E0 48 B8 3E 7C 3A 4F
21 7C 4C 78 48 BA 21 6F 24 6A 2C 3B 66 00 48 89
44 24 E5 48 89 54 24 ED B8 00 00 00 00 48 8D 4C
24 D8 48 85 F6 74 25 0F B6 14 07 32 14 08 48 0F
BE D2 48 39 C2 75 1C 48 83 C0 01 48 39 C6 74 0D
48 83 F8 1C 75 E1 B8 01 00 00 00 C3 C3 B8 00 00
00 00 C3 B8 00 00 00 00 C3 48 85 D2 74 12 48 89
F8 48 01 D7 40 88 30 48 83 C0 01 48 39 F8 75 F4
C3 41 56 41 55 41 54 55 53 41 89 FB 48 89 74 24
D8 48 89 54 24 E0 48 89 4C 24 E8 4C 89 44 24 F0
4C 89 4C 24 F8 48 8D 44 24 30 48 89 44 24 C0 48
8D 44 24 D0 48 89 44 24 C8 48 89 F3 48 89 D5 49
89 CC 4D 89 C5 C7 44 24 B8 30 00 00 00 4D 89 CE
48 8B 4C 24 C0 48 8D 41 08 48 89 44 24 C0 44 89
D8 48 89 DF 48 89 EE 4C 89 E2 4D 89 EA 4D 89 F0
4C 8B 09 0F 05 49 89 C3 4C 89 D8 5B 5D 41 5C 41
5D 41 5E C3 48 89 D1 48 89 F2 89 FE BF 00 00 00
00 B8 00 00 00 00 E8 66 FF FF FF C3 00 00 00 00
```

Because the function overwrites `read` with `src`, so we know that this is the binary data. Paste the binary on [CyberChef](https://cyberchef.io/#recipe=Disassemble_x86('64','Full%20x86%20architecture',16,0,true,true)) to disassemble it, the result is stored in `disassembled.asm`.

Going through the asm code, we discovered a function named `8C` (based on its offset). This function loads a 28-byte QWORD, puts it in a loop that runs 28 times, xor each byte of the input with the key, then compares it with the loop's counter.

```asm
000000000000008C 48B86C357B3076305937            MOV RAX,37593076307B356C
0000000000000096 48BA6656663F753E7C3A            MOV RDX,3A7C3E753F665666
00000000000000A0 48894424D8                      MOV QWORD PTR [RSP-28],RAX
00000000000000A5 48895424E0                      MOV QWORD PTR [RSP-20],RDX
00000000000000AA 48B83E7C3A4F217C4C78            MOV RAX,784C7C214F3A7C3E
00000000000000B4 48BA216F246A2C3B6600            MOV RDX,00663B2C6A246F21
00000000000000BE 48894424E5                      MOV QWORD PTR [RSP-1B],RAX
00000000000000C3 48895424ED                      MOV QWORD PTR [RSP-13],RDX
00000000000000C8 B800000000                      MOV EAX,00000000
00000000000000CD 488D4C24D8                      LEA RCX,[RSP-28]
00000000000000D2 4885F6                          TEST RSI,RSI
00000000000000D5 7425                            JE 00000000000000FC
00000000000000D7 0FB61407                        MOVZX EDX,BYTE PTR [RDI+RAX] ; take one byte from the input
00000000000000DB 321408                          XOR DL,BYTE PTR [RAX+RCX] ; take one byte from the key and xor it with the input
00000000000000DE 480FBED2                        MOVSX RDX,DL
00000000000000E2 4839C2                          CMP RDX,RAX ; compare it with rax
00000000000000E5 751C                            JNE 0000000000000103
00000000000000E7 4883C001                        ADD RAX,0000000000000001 ; rax++
00000000000000EB 4839C6                          CMP RSI,RAX
00000000000000EE 740D                            JE 00000000000000FD
00000000000000F0 4883F81C                        CMP RAX,000000000000001C ; rax == 28
00000000000000F4 75E1                            JNE 00000000000000D7 ; jump back to the loop
00000000000000F6 B801000000                      MOV EAX,00000001
00000000000000FB C3                              RET
```

Here is the psuedo code for it:

```c
__int64 __fastcall sub_8C(__int64 a1, __int64 a2)
{
  __int64 n28; // rax
  char l5_0v0Y7fVf?u__:O__Lx_o$j__f[40]; // [rsp+0h] [rbp-28h] BYREF

  strcpy(l5_0v0Y7fVf?u__:O__Lx_o$j__f, "l5{0v0Y7fVf?u>|:O!|Lx!o$j,;f");
  n28 = 0LL;
  if ( a2 )
  {
    while ( (char)(l5_0v0Y7fVf?u__:O__Lx_o$j__f[n28] ^ *(_BYTE *)(a1 + n28)) == n28 )
    {
      if ( a2 == ++n28 )
        return 0LL;
      if ( n28 == 28 )
        return 1LL;
    }
    return 0LL;
  }
  return n28;
}
```

We will try to XOR it back to get the input, here is the script to do that:

```py
s = "l5{0v0Y7fVf?u>|:O!|Lx!o$j,;f"
decoded = ''.join(chr(ord(c) ^ i) for i, c in enumerate(s))
print(decoded)
```

Run the script and we got the string `l4y3r5_0n_l4y3r5_0n_l4y3r5!}`, this must be the flag, so we append `HTB{` and submit it!