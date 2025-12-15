__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int i; // [rsp+4h] [rbp-91Ch]
  int j; // [rsp+8h] [rbp-918h]
  int v6; // [rsp+Ch] [rbp-914h]
  _QWORD v7[256]; // [rsp+10h] [rbp-910h] BYREF
  char s[264]; // [rsp+810h] [rbp-110h] BYREF
  unsigned __int64 v9; // [rsp+918h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  __isoc99_scanf(&unk_2004, s, a3);
  v6 = strlen(s);
  for ( i = 0; (int)i < v6; ++i )
  {
    sub_11C9(&v7[i], (unsigned int)s[i]);
    sub_126C(&v7[i], i);
    if ( (i & 1) != 0 )
      sub_12A5(&v7[i]);
  }
  for ( j = 0; j < v6; ++j )
    sub_12EE(&v7[j]);
  return 0;
}

_DWORD *__fastcall sub_11C9(void **a1, char a2)
{
  int i; // [rsp+14h] [rbp-Ch]
  _DWORD *v4; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 7; ++i )
  {
    if ( i )
    {
      *(_QWORD *)v4 = malloc(0x10u);
      v4 = *(_DWORD **)v4;
    }
    else
    {
      *a1 = malloc(0x10u);
      v4 = *a1;
    }
    v4[2] = ((a2 >> (7 - i)) & 1) != 0;
  }
  *(_QWORD *)v4 = *a1;
  return v4;
}

__int64 __fastcall sub_126C(_QWORD **a1, int a2)
{
  __int64 result; // rax
  unsigned int i; // [rsp+18h] [rbp-4h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( (int)i >= a2 )
      break;
    *a1 = (_QWORD *)**a1;
  }
  return result;
}

__int64 *__fastcall sub_12A5(__int64 **a1)
{
  __int64 *result; // rax
  __int64 *v2; // [rsp+10h] [rbp-8h]

  v2 = *a1;
  do
  {
    *((_DWORD *)v2 + 2) = *((_DWORD *)v2 + 2) == 0;
    v2 = (__int64 *)*v2;
    result = *a1;
  }
  while ( v2 != *a1 );
  return result;
}

int __fastcall sub_12EE(__int64 **a1)
{
  char v2; // [rsp+17h] [rbp-9h]
  __int64 *v3; // [rsp+18h] [rbp-8h]

  v2 = 0;
  v3 = *a1;
  do
  {
    v2 = *((_DWORD *)v3 + 2) | (2 * v2);
    v3 = (__int64 *)*v3;
  }
  while ( v3 != *a1 );
  return putchar(v2);
}
