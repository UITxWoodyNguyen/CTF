__int64 __fastcall sub_1350(__int64 *a1, __int64 a2)
{
  __int64 v3; // rdi
  __int64 v4; // rax
  unsigned __int16 v5; // cx
  __int64 v6; // rdx
  unsigned __int8 v7; // al
  __int64 v8; // rax
  __int64 v9; // rdi
  __int64 result; // rax
  __int16 v11; // dx
  __int16 v12; // cx
  _WORD *v13; // rax
  __int64 v14; // rax
  bool v15; // sf
  __int16 v16; // cx
  __int64 v17; // rdx
  __int64 v18; // rcx
  __int64 v19; // rax
  __int16 v20; // dx
  __int64 v21; // rax
  __int16 v22; // dx
  _WORD *v23; // rdx
  _WORD *v24; // rax
  _WORD *v25; // rax
  __int16 v26; // dx
  _WORD *v27; // rdx
  _WORD *v28; // rax
  __int16 *v29; // rdx
  __int16 v30; // ax
  __int64 v31; // rax
  bool v32; // zf
  __int64 v33; // rax
  __int64 v34; // rax
  bool v35; // cc
  __int64 v36; // rax
  __int16 v37; // dx
  unsigned __int8 v38; // al
  _WORD *v39; // rdx

  v3 = *a1;
  v4 = *((unsigned __int16 *)a1 + 4);
  v5 = v4 + 1;
  v6 = v4;
  *((_WORD *)a1 + 4) = v4 + 1;
  v7 = *(_BYTE *)(v3 + v4);
  switch ( v7 )
  {
    case 0u:
      return 1;
    case 1u:
      result = 0;
      if ( a2 )
      {
        v17 = a1[2];
        *(_BYTE *)a2 = 0;
        v18 = v17 - 2;
        LOWORD(v17) = *(_WORD *)(v17 - 2);
        a1[2] = v18;
        *(_WORD *)(a2 + 2) = v17;
      }
      return result;
    case 2u:
    case 3u:
    case 4u:
    case 5u:
    case 6u:
    case 7u:
    case 8u:
    case 9u:
    case 0xAu:
    case 0xBu:
    case 0xCu:
    case 0xDu:
    case 0xEu:
    case 0xFu:
    case 0x15u:
    case 0x16u:
    case 0x17u:
    case 0x18u:
    case 0x19u:
    case 0x1Au:
    case 0x1Bu:
    case 0x1Cu:
    case 0x1Du:
    case 0x1Eu:
    case 0x1Fu:
    case 0x22u:
    case 0x23u:
    case 0x24u:
    case 0x25u:
    case 0x26u:
    case 0x27u:
    case 0x28u:
    case 0x29u:
    case 0x2Au:
    case 0x2Bu:
    case 0x2Cu:
    case 0x2Du:
    case 0x2Eu:
    case 0x2Fu:
      goto LABEL_11;
    case 0x10u:
      v25 = (_WORD *)a1[2];
      v26 = *(v25 - 1);
      a1[2] = (__int64)(v25 + 1);
      *v25 = v26;
      return 1;
    case 0x11u:
      a1[2] -= 2;
      return 1;
    case 0x12u:
      v36 = a1[2];
      v37 = *(_WORD *)(v36 - 4) + *(_WORD *)(v36 - 2);
      a1[2] = v36 - 2;
      *(_WORD *)(v36 - 4) = v37;
      return 1;
    case 0x13u:
      v19 = a1[2];
      v20 = *(_WORD *)(v19 - 4) - *(_WORD *)(v19 - 2);
      a1[2] = v19 - 2;
      *(_WORD *)(v19 - 4) = v20;
      return 1;
    case 0x14u:
      v21 = a1[2];
      v22 = *(_WORD *)(v21 - 4);
      *(_WORD *)(v21 - 4) = *(_WORD *)(v21 - 2);
      a1[2] = v21;
      *(_WORD *)(v21 - 2) = v22;
      return 1;
    case 0x20u:
      v23 = (_WORD *)(a1[2] - 2);
      a1[2] = (__int64)v23;
      LOWORD(v23) = *v23;
      v24 = (_WORD *)a1[3];
      a1[3] = (__int64)(v24 + 1);
      *v24 = (_WORD)v23;
      return 1;
    case 0x21u:
      v27 = (_WORD *)(a1[3] - 2);
      a1[3] = (__int64)v27;
      LOWORD(v27) = *v27;
      v28 = (_WORD *)a1[2];
      a1[2] = (__int64)(v28 + 1);
      *v28 = (_WORD)v27;
      return 1;
    case 0x30u:
      v29 = (__int16 *)(a1[2] - 2);
      v30 = *v29;
      a1[2] = (__int64)v29;
      *((_WORD *)a1 + 4) = v30;
      return 1;
    case 0x31u:
      v31 = a1[2];
      v32 = *(_WORD *)(v31 - 4) == 0;
      v16 = *(_WORD *)(v31 - 2);
      a1[2] = v31 - 4;
      if ( v32 )
        goto LABEL_25;
      return 1;
    case 0x32u:
      v33 = a1[2];
      v32 = *(_WORD *)(v33 - 4) == 0;
      v16 = *(_WORD *)(v33 - 2);
      a1[2] = v33 - 4;
      if ( !v32 )
        goto LABEL_25;
      return 1;
    case 0x33u:
      v14 = a1[2];
      v15 = *(__int16 *)(v14 - 4) < 0;
      v16 = *(_WORD *)(v14 - 2);
      a1[2] = v14 - 4;
      if ( !v15 )
        return 1;
      goto LABEL_25;
    case 0x34u:
      v34 = a1[2];
      v35 = *(_WORD *)(v34 - 4) <= 0;
      v16 = *(_WORD *)(v34 - 2);
      a1[2] = v34 - 4;
      if ( !v35 )
        return 1;
LABEL_25:
      *((_WORD *)a1 + 4) = v16;
      return 1;
    default:
      if ( v7 == 0xC0 )
      {
        v38 = ((__int64 (__fastcall *)(__int64, __int64, __int64))a1[4])(v3, a2, v6);
        v39 = (_WORD *)a1[2];
        a1[2] = (__int64)(v39 + 1);
        *v39 = v38;
        return 1;
      }
      if ( v7 > 0xC0u )
      {
        if ( v7 == 0xC1 )
        {
          v8 = a1[2];
          v9 = *(unsigned __int8 *)(v8 - 2);
          a1[2] = v8 - 2;
          ((void (__fastcall *)(__int64, __int64))a1[5])(v9, a2);
          return 1;
        }
        goto LABEL_11;
      }
      if ( v7 == 0x80 )
      {
        v11 = v6 + 2;
        v12 = *(char *)(v3 + v5);
        goto LABEL_10;
      }
      if ( v7 == 0x81 )
      {
        v11 = v6 + 3;
        v12 = *(_WORD *)(v3 + v5);
LABEL_10:
        v13 = (_WORD *)a1[2];
        *((_WORD *)a1 + 4) = v11;
        a1[2] = (__int64)(v13 + 1);
        *v13 = v12;
        return 1;
      }
LABEL_11:
      result = 0;
      if ( a2 )
        *(_BYTE *)a2 = 1;
      return result;
  }
}