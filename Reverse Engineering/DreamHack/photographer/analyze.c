"flag.bmp" --> input
"flag.bmp.enc" --> output 

// This is a photo encode process
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


// Process 1: sub_2A6E((__int64)&v19);
void __fastcall sub_2A6E()
{
  sub_2BFE();
}

void sub_2BFE()
{
  ;
}
// End Process 1


// Process 2: sub_2A44((__int64)v24);
__int64 __fastcall sub_2A44(__int64 a1)
{
  __int64 result; // rax

  *(_QWORD *)a1 = 0;
  result = sub_29EA();
  *(_DWORD *)(a1 + 8) = result;
  return result;
}

__int64 sub_29EA()
{
  return 0xFFFFFFFFLL;
}
// End Process 2


// Process 3: sub_29FA((__int64)v23, v28);
__int64 __fastcall sub_29FA(__int64 a1, _QWORD *a2)
{
  __int64 result; // rax

  *(_QWORD *)a1 = std::ios::rdbuf((char *)a2 + *(_QWORD *)(*a2 - 24LL));
  result = sub_29EA();
  *(_DWORD *)(a1 + 8) = result;
  return result;
}

__int64 sub_29EA()
{
  return 0xFFFFFFFFLL;
}
// End Process 3


// Process 4: sub_2AAE((__int64)v25, v23[0], v23[1], v24[0], v24[1], (__int64)&v19)
unsigned __int64 __fastcall sub_2AAE(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  sub_2C3E(a1, a6);
  sub_2CB5();
  return sub_2CC4(a1, a2, a3, a4, a5);
}

__int64 __fastcall sub_2C3E(__int64 a1, __int64 a2)
{
  return sub_2DF4(a1, a2);
}

_QWORD *__fastcall sub_2DF4(_QWORD *a1, __int64 a2)
{
  sub_300E((__int64)a1, a2);
  return sub_3038(a1);
}

void __fastcall sub_300E()
{
  sub_346A();
}

void sub_346A()
{
  ;
}

_QWORD *__fastcall sub_3038(_QWORD *a1)
{
  *a1 = 0;
  a1[1] = 0;
  a1[2] = 0;
  return a1;
}

void sub_2CB5()
{
  ;
}

unsigned __int64 __fastcall sub_2CC4(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  __int64 v7; // rcx
  _QWORD v9[2]; // [rsp+0h] [rbp-50h] BYREF
  _QWORD v10[3]; // [rsp+10h] [rbp-40h] BYREF
  __int64 v11; // [rsp+28h] [rbp-28h]
  char v12; // [rsp+37h] [rbp-19h] BYREF
  unsigned __int64 v13; // [rsp+38h] [rbp-18h]

  v11 = a1;
  v10[0] = a2;
  v10[1] = a3;
  v7 = a5;
  v9[0] = a4;
  v9[1] = a5;
  v13 = __readfsqword(0x28u);
  while ( (unsigned __int8)((__int64 (__fastcall *)(_QWORD *, _QWORD *, _QWORD *, __int64, __int64, __int64))sub_2E63)(
                             v10,
                             v9,
                             v9,
                             v7,
                             a5,
                             a6) )
  {
    v12 = sub_2EC2((__int64)v10);
    sub_2F12(v11, (__int64)&v12);
    std::istreambuf_iterator<char>::operator++(v10);
  }
  return v13 - __readfsqword(0x28u);
}

__int64 __fastcall sub_2E63(__int64 a1, __int64 a2)
{
  return (unsigned int)sub_309C(a1, a2) ^ 1;
}

bool __fastcall sub_309C(__int64 a1, __int64 a2)
{
  char v2; // bl

  v2 = sub_34AC(a1);
  return v2 == (char)sub_34AC(a2);
}

__int64 __fastcall sub_34AC(__int64 a1)
{
  int v1; // eax

  v1 = (a1);
  return sub_34D1(v1);
}

__int64 __fastcall sub_30D6(__int64 a1)
{
  unsigned int v3; // [rsp+1Ch] [rbp-4h]

  v3 = *(_DWORD *)(a1 + 8);
  if ( *(_QWORD *)a1 )
  {
    if ( (unsigned __int8)sub_34D1(v3) )
    {
      v3 = std::streambuf::sgetc(*(_QWORD *)a1);
      if ( (unsigned __int8)sub_34D1(v3) )
        *(_QWORD *)a1 = 0;
    }
  }
  return v3;
}

bool __fastcall sub_34D1(int a1)
{
  int v2; // [rsp+Ch] [rbp-14h] BYREF
  int v3; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v2 = a1;
  v4 = __readfsqword(0x28u);
  v3 = -1;
  return sub_29C7(&v2, &v3);
}

bool __fastcall sub_29C7(_DWORD *a1, _DWORD *a2)
{
  return *a1 == *a2;
}

__int64 __fastcall sub_2EC2(__int64 a1)
{
  unsigned int v2; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v2 = sub_30D6(a1);
  return sub_29B3(&v2);
}

__int64 __fastcall (__int64 a1)
{
  unsigned int v3; // [rsp+1Ch] [rbp-4h]

  v3 = *(_DWORD *)(a1 + 8);
  if ( *(_QWORD *)a1 )
  {
    if ( (unsigned __int8)sub_34D1(v3) )
    {
      v3 = std::streambuf::sgetc(*(_QWORD *)a1);
      if ( (unsigned __int8)sub_34D1(v3) )
        *(_QWORD *)a1 = 0;
    }
  }
  return v3;
}

__int64 __fastcall sub_29B3(unsigned int *a1)
{
  return *a1;
}

__int64 __fastcall sub_2F12(__int64 *a1, __int64 a2)
{
  __int64 v2; // rax
  __int64 v3; // rbx
  __int64 v4; // rax

  if ( a1[1] == a1[2] )
  {
    v3 = sub_314A(a2);
    v4 = sub_319A((__int64)a1);
    sub_31EA(a1, v4, v3);
  }
  else
  {
    v2 = sub_314A(a2);
    sub_315C(a1, a1[1]++, v2);
  }
  return sub_3390(a1);
}

__int64 __fastcall sub_314A(__int64 a1)
{
  return a1;
}

__int64 __fastcall sub_319A(__int64 a1)
{
  _QWORD v2[2]; // [rsp+10h] [rbp-10h] BYREF

  v2[1] = __readfsqword(0x28u);
  sub_3564(v2, (_QWORD *)(a1 + 8));
  return v2[0];
}

_QWORD *__fastcall sub_3564(_QWORD *a1, _QWORD *a2)
{
  *a1 = *a2;
  return a1;
}

unsigned __int64 __fastcall sub_31EA(__int64 *a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rax
  __int64 v4; // rbx
  _QWORD *v5; // rax
  __int64 v6; // rbx
  _QWORD *v7; // rax
  __int64 v10; // [rsp+10h] [rbp-60h] BYREF
  __int64 *v11; // [rsp+18h] [rbp-58h]
  __int64 v12; // [rsp+20h] [rbp-50h] BYREF
  __int64 v13; // [rsp+28h] [rbp-48h]
  __int64 v14; // [rsp+30h] [rbp-40h]
  __int64 v15; // [rsp+38h] [rbp-38h]
  __int64 v16; // [rsp+40h] [rbp-30h]
  __int64 v17; // [rsp+48h] [rbp-28h]
  __int64 v18; // [rsp+50h] [rbp-20h]
  unsigned __int64 v19; // [rsp+58h] [rbp-18h]

  v11 = a1;
  v10 = a2;
  v19 = __readfsqword(0x28u);
  v13 = sub_3586((__int64)a1, 1u, "vector::_M_realloc_insert");
  v14 = *a1;
  v15 = a1[1];
  v12 = sub_3676(a1);
  v16 = sub_36C2(&v10, &v12);
  v17 = sub_3702(v11, v13);
  v18 = v17;
  v3 = sub_314A(a3);
  sub_315C(v11, v16 + v17, v3);
  v18 = 0;
  v4 = sub_2D9E((__int64)v11);
  v5 = (_QWORD *)sub_3770(&v10);
  v18 = sub_3739(v14, *v5, v17, v4) + 1;
  v6 = sub_2D9E((__int64)v11);
  v7 = (_QWORD *)sub_3770(&v10);
  v18 = sub_3739(*v7, v15, v18, v6);
  sub_2E2A((__int64)v11, v14, v11[2] - v14);
  *v11 = v17;
  v11[1] = v18;
  v11[2] = v13 + v17;
  return v19 - __readfsqword(0x28u);
}

unsigned __int64 __fastcall sub_3586(_QWORD *a1, unsigned __int64 a2, const char *a3)
{
  __int64 v3; // rbx
  __int64 v4; // rbx
  unsigned __int64 v5; // rax
  unsigned __int64 v6; // rax
  unsigned __int64 v9; // [rsp+10h] [rbp-40h] BYREF
  _QWORD *v10; // [rsp+18h] [rbp-38h]
  __int64 v11; // [rsp+28h] [rbp-28h] BYREF
  unsigned __int64 v12; // [rsp+30h] [rbp-20h]
  unsigned __int64 v13; // [rsp+38h] [rbp-18h]

  v10 = a1;
  v9 = a2;
  v13 = __readfsqword(0x28u);
  v3 = sub_37FE(a1);
  if ( v3 - sub_2B92(a1) < a2 )
    std::__throw_length_error(a3);
  v4 = sub_2B92(v10);
  v11 = sub_2B92(v10);
  v12 = v4 + *(_QWORD *)sub_3824(&v11, &v9);
  v5 = sub_2B92(v10);
  if ( v12 >= v5 && (v6 = sub_37FE(v10), v12 <= v6) )
    return v12;
  else
    return sub_37FE(v10);
}

__int64 __fastcall sub_37FE(__int64 a1)
{
  __int64 v1; // rax

  v1 = sub_3920(a1);
  return sub_38B7(v1);
}

__int64 __fastcall sub_3920(__int64 a1)
{
  return a1;
}

__int64 __fastcall sub_38B7(__int64 a1)
{
  __int64 v2; // [rsp+18h] [rbp-18h] BYREF
  _QWORD v3[2]; // [rsp+20h] [rbp-10h] BYREF

  v3[1] = __readfsqword(0x28u);
  v2 = 0x7FFFFFFFFFFFFFFFLL;
  v3[0] = sub_39FD(a1);
  return *(_QWORD *)sub_3A1B(&v2, v3);
}

_QWORD *__fastcall sub_3A1B(_QWORD *a1, _QWORD *a2)
{
  if ( *a2 >= *a1 )
    return a1;
  else
    return a2;
}

__int64 __fastcall sub_39FD(__int64 a1)
{
  return sub_3AB0(a1);
}

__int64 __fastcall sub_3AB0(__int64 a1)
{
  return sub_3932(a1);
}

__int64 sub_3932()
{
  return 0x7FFFFFFFFFFFFFFFLL;
}

__int64 __fastcall sub_2B92(_QWORD *a1)
{
  return a1[1] - *a1;
}

__int64 __fastcall sub_2B92(_QWORD *a1)
{
  return a1[1] - *a1;
}

_QWORD *__fastcall sub_3824(_QWORD *a1, _QWORD *a2)
{
  if ( *a1 >= *a2 )
    return a1;
  else
    return a2;
}

__int64 __fastcall sub_3676(_QWORD *a1)
{
  _QWORD v2[2]; // [rsp+10h] [rbp-10h] BYREF

  v2[1] = __readfsqword(0x28u);
  sub_3564(v2, a1);
  return v2[0];
}

_QWORD *__fastcall sub_3564(_QWORD *a1, _QWORD *a2)
{
  *a1 = *a2;
  return a1;
}

__int64 __fastcall sub_36C2(__int64 a1, __int64 a2)
{
  __int64 v2; // rbx

  v2 = *(_QWORD *)sub_3770(a1);
  return v2 - *(_QWORD *)sub_3770(a2);
}

__int64 __fastcall sub_3770(__int64 a1)
{
  return a1;
}

__int64 __fastcall sub_3702(__int64 a1, __int64 a2)
{
  if ( a2 )
    return sub_3853(a1, a2);
  else
    return 0;
}

__int64 __fastcall sub_3853(__int64 a1, __int64 a2)
{
  return sub_394A(a1, a2, 0);
}

__int64 __fastcall sub_394A(__int64 a1, unsigned __int64 a2)
{
  if ( a2 > sub_3932() )
    std::__throw_bad_alloc();
  return operator new(a2);
}

__int64 sub_3932()
{
  return 0x7FFFFFFFFFFFFFFFLL;
}

__int64 __fastcall sub_314A(__int64 a1)
{
  return a1;
}

__int64 __fastcall sub_315C(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rax

  v3 = sub_314A(a3);
  return sub_3520(a1, a2, v3);
}

__int64 __fastcall sub_314A(__int64 a1)
{
  return a1;
}

_BYTE *__fastcall sub_3520(__int64 a1, __int64 a2, __int64 a3)
{
  char v3; // bl
  _BYTE *result; // rax

  v3 = *(_BYTE *)sub_314A(a3);
  result = (_BYTE *)sub_299D(1, a2);
  *result = v3;
  return result;
}

__int64 __fastcall sub_314A(__int64 a1)
{
  return a1;
}

__int64 __fastcall sub_299D(__int64 a1, __int64 a2)
{
  return a2;
}

__int64 __fastcall sub_2D9E(__int64 a1)
{
  return a1;
}

__int64 __fastcall sub_3770(__int64 a1)
{
  return a1;
}

__int64 __fastcall sub_3739(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  return sub_3881(a1, a2, a3, a4, a5, a6, a4, a3, a2, a1);
}

__int64 __fastcall sub_3881(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  return sub_3996(a1, a2, a3, a4, a5, a6, a4, a3, a2, a1);
}

__int64 __fastcall sub_3996(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  __int64 v4; // r12
  __int64 v5; // rbx
  __int64 v6; // rax

  v4 = sub_3A4A(a3);
  v5 = sub_3A4A(a2);
  v6 = sub_3A4A(a1);
  return sub_3A5C(v6, v5, v4, a4);
}

__int64 __fastcall sub_3A4A(__int64 a1)
{
  return a1;
}

char *__fastcall sub_3A5C(const void *a1, __int64 a2, char *a3)
{
  size_t n; // [rsp+28h] [rbp-8h]

  n = a2 - (_QWORD)a1;
  if ( a2 - (__int64)a1 > 0 )
    memmove(a3, a1, n);
  return &a3[n];
}

__int64 __fastcall sub_2E2A(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 result; // rax

  if ( a2 )
    return sub_306A(a1, a2, a3);
  return result;
}

void __fastcall sub_306A(__int64 a1, void *a2, unsigned __int64 a3)
{
  sub_347E(a1, a2, a3);
}

void __fastcall sub_347E(__int64 a1, void *a2, unsigned __int64 a3)
{
  operator delete(a2, a3);
}

__int64 __fastcall sub_315C(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rax

  v3 = sub_314A(a3);
  return sub_3520(a1, a2, v3);
}

__int64 __fastcall sub_314A(__int64 a1)
{
  return a1;
}

_BYTE *__fastcall sub_3520(__int64 a1, __int64 a2, __int64 a3)
{
  char v3; // bl
  _BYTE *result; // rax

  v3 = *(_BYTE *)sub_314A(a3);
  result = (_BYTE *)sub_299D(1, a2);
  *result = v3;
  return result;
}

__int64 __fastcall sub_314A(__int64 a1)
{
  return a1;
}

__int64 __fastcall sub_299D(__int64 a1, __int64 a2)
{
  return a2;
}

__int64 __fastcall sub_3390(__int64 a1)
{
  __int64 v2; // [rsp+18h] [rbp-18h] BYREF
  _QWORD v3[2]; // [rsp+20h] [rbp-10h] BYREF

  v3[1] = __readfsqword(0x28u);
  v2 = sub_319A(a1);
  v3[0] = sub_3782(&v2, 1);
  return sub_37E8(v3);
}

__int64 __fastcall sub_319A(__int64 a1)
{
  _QWORD v2[2]; // [rsp+10h] [rbp-10h] BYREF

  v2[1] = __readfsqword(0x28u);
  sub_3564(v2, (_QWORD *)(a1 + 8));
  return v2[0];
}

_QWORD *__fastcall sub_3564(_QWORD *a1, _QWORD *a2)
{
  *a1 = *a2;
  return a1;
}

__int64 __fastcall sub_3782(_QWORD *a1, __int64 a2)
{
  __int64 v3; // [rsp+18h] [rbp-18h] BYREF
  _QWORD v4[2]; // [rsp+20h] [rbp-10h] BYREF

  v4[1] = __readfsqword(0x28u);
  v3 = *a1 - a2;
  sub_3564(v4, &v3);
  return v4[0];
}

__int64 __fastcall sub_37E8(__int64 a1)
{
  return *(_QWORD *)a1;
}
// End Process 4


// Process 5 sub_2A8E((__int64)&v19);
void __fastcall sub_2A8E()
{
  sub_2C0E();
}
void sub_2C0E()
{
  ;
}
// End Process 5


// Encode Process: Some function above are used
__int64 __fastcall sub_2BB6(_QWORD *a1, __int64 a2)
{
  return *a1 + a2;
}

__int64 __fastcall sub_2489(unsigned __int8 a1, char a2)
{
  return ((int)a1 >> (a2 & 7)) | (a1 << (8 - (a2 & 7)));
} // IMPORTANT

__int64 __fastcall sub_24C2(unsigned __int8 a1, char a2)
{
  return (a1 << (a2 & 7)) | (unsigned int)((int)a1 >> (8 - (a2 & 7)));
}

__int64 __fastcall sub_2BD6(__int64 *a1)
{
  return sub_2DDE((__int64)a1, *a1);
}

__int64 __fastcall sub_2DDE(__int64 a1, __int64 a2)
{
  return a2;
}
