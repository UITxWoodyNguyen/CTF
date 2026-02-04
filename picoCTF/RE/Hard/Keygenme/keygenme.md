# Keygenme
### Information
* Category: Reverse Engineering
* Point: 300
* Level: Hard

### Description
Can you get the flag?
Reverse engineer this `binary`.

## Solution:

Open `keygenme` in IDA, navigate to function `main`. We can see that the code performs a conditional jump to different output, before that it calls a function named `sub_1209`.

![alt text](image.png)

Here is the decompiled code of `sub_1209`:

```c
__int64 __fastcall sub_1209(const char *a1)
{
  size_t v1; // rax
  size_t v2; // rax
  int v4; // [rsp+18h] [rbp-C8h]
  int v5; // [rsp+18h] [rbp-C8h]
  int i; // [rsp+1Ch] [rbp-C4h]
  int j; // [rsp+20h] [rbp-C0h]
  int k; // [rsp+24h] [rbp-BCh]
  int m; // [rsp+28h] [rbp-B8h]
  char v10[18]; // [rsp+2Eh] [rbp-B2h] BYREF
  _BYTE v11[16]; // [rsp+40h] [rbp-A0h] BYREF
  char s[32]; // [rsp+50h] [rbp-90h] BYREF
  _BYTE v13[18]; // [rsp+70h] [rbp-70h] BYREF
  char v14; // [rsp+82h] [rbp-5Eh]
  char v15; // [rsp+89h] [rbp-57h]
  char v16; // [rsp+8Ah] [rbp-56h]
  _BYTE v17[72]; // [rsp+90h] [rbp-50h] BYREF
  unsigned __int64 v18; // [rsp+D8h] [rbp-8h]

  v18 = __readfsqword(0x28u);
  strcpy(s, "picoCTF{br1ng_y0ur_0wn_k3y_");
  strcpy(v10, "}");
  v1 = strlen(s);
  MD5(s, v1, &v10[2]);
  v2 = strlen(v10);
  MD5(v10, v2, v11);
  v4 = 0;
  for ( i = 0; i <= 15; ++i )
  {
    sprintf(&v13[v4], "%02x", (unsigned __int8)v10[i + 2]);
    v4 += 2;
  }
  v5 = 0;
  for ( j = 0; j <= 15; ++j )
  {
    sprintf(&v17[v5], "%02x", (unsigned __int8)v11[j]);
    v5 += 2;
  }
  for ( k = 0; k <= 26; ++k )
    v17[k + 32] = s[k];
  v17[59] = v14;
  v17[60] = v16;
  v17[61] = v15;
  v17[62] = v13[0];
  v17[63] = v16;
  v17[64] = v14;
  v17[65] = v13[12];
  v17[66] = v16;
  v17[67] = v10[0];
  if ( strlen(a1) != 36 )
    return 0;
  for ( m = 0; m <= 35; ++m )
  {
    if ( a1[m] != v17[m + 32] )
      return 0;
  }
  return 1;
}
```

### This code does several things:

#### Get MD5 hash of the prefix `picoCTF{br1ng_y0ur_0wn_k3y_` as hex and writes it to `v13`, this will cause stack overflow because it tries to write 32 bytes in a 18-byte array:

```c
v1 = strlen(s);
MD5(s, v1, &v10[2]);
v2 = strlen(v10);
MD5(v10, v2, v11);
v4 = 0;
for ( i = 0; i <= 15; ++i )
{
sprintf(&v13[v4], "%02x", (unsigned __int8)v10[i + 2]);
v4 += 2;
}
```

Here is the mapping of the bytes:
- 0 -> 17 bytes written in `v13`.
- 18th byte written in `v14`.
- 19 -> 24 bytes are the padding between `v14` and `v15` based on the stack address (`[rsp+82h]` and `[rsp+89h]`).
- 25th byte written in `v15`.
- 26th byte written in `v16`.
- All of the remaining bytes fall into non-used memory space because the padding between `v16` and `v17` is too long.

#### Construct the flag base on the prefix and the bytes mapped above:

```c
for ( k = 0; k <= 26; ++k )
v17[k + 32] = s[k];
v17[59] = v14;
v17[60] = v16;
v17[61] = v15;
v17[62] = v13[0];
v17[63] = v16;
v17[64] = v14;
v17[65] = v13[12];
v17[66] = v16;
v17[67] = v10[0];
```

#### Validate user's input to the constructed flag:

```c
if ( strlen(a1) != 36 )
return 0;
for ( m = 0; m <= 35; ++m )
{
if ( a1[m] != v17[m + 32] )
    return 0;
}
```

After analysing the code, we can create a Python keygen script named `main.py` to get the flag:

```py
import hashlib

prefix = "picoCTF{br1ng_y0ur_0wn_k3y_"
md5_hash = hashlib.md5(prefix.encode('utf-8')).hexdigest()

v14 = md5_hash[18]
v15 = md5_hash[25]
v16 = md5_hash[26]

print(prefix + v14 + v16 + v15 + md5_hash[0] + v16 + v14 + md5_hash[12] + v16 + "}")
```


Run the script and we got our flag `picoCTF{br1ng_y0ur_0wn_k3y_9d74d90d}`.
