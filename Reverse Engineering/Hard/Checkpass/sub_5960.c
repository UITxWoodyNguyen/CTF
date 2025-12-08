void __noreturn sub_5960()
{
  __int64 v0; // rbx
  char *v1; // rax
  __int128 *v2; // rbx
  __int64 v3; // rax
  __int128 *v4; // rax
  __int64 v5; // rcx
  __int128 v6; // xmm0
  __int128 v7; // xmm0
  __int64 v8; // rcx
  __int64 v9; // r8
  __int64 v10; // r9
  __int64 v11; // rcx
  __int64 v12; // r8
  __int64 v13; // r9
  __int64 v14; // rcx
  __int64 v15; // r8
  __int64 v16; // r9
  __int128 *v17; // rsi
  _BYTE *v18; // rcx
  __int64 v19; // r9
  __int64 v20; // r8
  __int64 v21; // rdx
  __int64 v22; // rdi
  __int128 v23; // [rsp+0h] [rbp-128h] BYREF
  __int128 v24; // [rsp+10h] [rbp-118h]
  __int128 *v25; // [rsp+20h] [rbp-108h]
  __int64 v26; // [rsp+28h] [rbp-100h]
  char v27; // [rsp+33h] [rbp-F5h]
  char v28; // [rsp+34h] [rbp-F4h]
  char v29; // [rsp+35h] [rbp-F3h]
  char v30; // [rsp+36h] [rbp-F2h]
  char v31; // [rsp+37h] [rbp-F1h]
  char v32; // [rsp+38h] [rbp-F0h]
  char v33; // [rsp+39h] [rbp-EFh]
  char v34; // [rsp+3Ah] [rbp-EEh]
  char v35; // [rsp+3Bh] [rbp-EDh]
  char v36; // [rsp+3Ch] [rbp-ECh]
  char v37; // [rsp+3Dh] [rbp-EBh]
  char v38; // [rsp+3Eh] [rbp-EAh]
  char v39; // [rsp+3Fh] [rbp-E9h]
  char v40; // [rsp+40h] [rbp-E8h]
  char v41; // [rsp+41h] [rbp-E7h]
  char v42; // [rsp+42h] [rbp-E6h]
  char v43; // [rsp+43h] [rbp-E5h]
  char v44; // [rsp+44h] [rbp-E4h]
  char v45; // [rsp+45h] [rbp-E3h]
  char v46; // [rsp+46h] [rbp-E2h]
  char v47; // [rsp+47h] [rbp-E1h]
  char v48; // [rsp+48h] [rbp-E0h] BYREF
  char v49; // [rsp+49h] [rbp-DFh]
  char v50; // [rsp+4Ah] [rbp-DEh]
  char v51; // [rsp+4Bh] [rbp-DDh]
  char v52; // [rsp+4Ch] [rbp-DCh]
  char v53; // [rsp+4Dh] [rbp-DBh]
  char v54; // [rsp+4Eh] [rbp-DAh]
  char v55; // [rsp+4Fh] [rbp-D9h]
  char v56; // [rsp+50h] [rbp-D8h]
  char v57; // [rsp+51h] [rbp-D7h]
  char v58; // [rsp+52h] [rbp-D6h]
  char v59; // [rsp+53h] [rbp-D5h]
  char v60; // [rsp+54h] [rbp-D4h]
  char v61; // [rsp+55h] [rbp-D3h]
  char v62; // [rsp+56h] [rbp-D2h]
  char v63; // [rsp+57h] [rbp-D1h]
  char v64; // [rsp+58h] [rbp-D0h]
  char v65; // [rsp+59h] [rbp-CFh]
  char v66; // [rsp+5Ah] [rbp-CEh]
  char v67; // [rsp+5Bh] [rbp-CDh]
  char v68; // [rsp+5Ch] [rbp-CCh]
  char v69; // [rsp+5Dh] [rbp-CBh]
  char v70; // [rsp+5Eh] [rbp-CAh]
  char v71; // [rsp+5Fh] [rbp-C9h]
  char v72; // [rsp+60h] [rbp-C8h]
  char v73; // [rsp+61h] [rbp-C7h]
  char v74; // [rsp+62h] [rbp-C6h]
  char v75; // [rsp+63h] [rbp-C5h]
  char v76; // [rsp+64h] [rbp-C4h]
  char v77; // [rsp+65h] [rbp-C3h]
  char v78; // [rsp+66h] [rbp-C2h]
  char v79; // [rsp+67h] [rbp-C1h]
  __int128 *v80; // [rsp+68h] [rbp-C0h] BYREF
  __int128 v81; // [rsp+70h] [rbp-B8h]
  __int128 v82; // [rsp+80h] [rbp-A8h] BYREF
  __int128 v83; // [rsp+90h] [rbp-98h]
  __int64 v84; // [rsp+A0h] [rbp-88h] BYREF
  __int64 v85; // [rsp+B0h] [rbp-78h]
  _OWORD v86[2]; // [rsp+B8h] [rbp-70h] BYREF
  _OWORD v87[5]; // [rsp+D8h] [rbp-50h] BYREF

  sub_1F000(&v82);
  v24 = v83;
  v23 = v82;
  ((void (__fastcall *)(__int64 *, __int128 *))sub_6A00)(&v84, &v23);
  if ( v85 == 2 )
  {
    if ( *(_QWORD *)(v84 + 40) == 41 )
    {
      v0 = *(_QWORD *)(v84 + 24);
      if ( (_UNKNOWN *)v0 == &unk_39D78 || *(_QWORD *)v0 == 0x7B4654436F636970LL )
      {
        v1 = (char *)(v0 + 40);
        if ( (_UNKNOWN *)(v0 + 40) == &unk_39D94 || *v1 == 125 )
        {
          if ( *(char *)(v0 + 8) > -65 )
          {
            v2 = (__int128 *)(v0 + 8);
            if ( *v1 > -65 )
            {
              v3 = sub_6DA0(0x20u, 1u);
              if ( !v3 )
                sub_32F80(32, 1);
              v80 = (__int128 *)v3;
              v81 = xmmword_39550;
              sub_6720(&v80, 0, 32);
              v4 = v80;
              v5 = *((_QWORD *)&v81 + 1);
              v6 = *v2;
              *(__int128 *)((char *)v80 + *((_QWORD *)&v81 + 1) + 16) = v2[1];
              *(__int128 *)((char *)v4 + v5) = v6;
              *((_QWORD *)&v81 + 1) = v5 + 32;
              if ( !v5 )
              {
                v7 = *v4;
                v24 = v4[1];
                v23 = v7;
                ((void (__fastcall *)(_OWORD *, __int128 *, _QWORD))sub_54E0)(v86, &v23, 0);
                v24 = v86[1];
                v23 = v86[0];
                ((void (__fastcall *)(_OWORD *, __int128 *, __int64, __int64, __int64, __int64))sub_54E0)(
                  v87,
                  &v23,
                  1,
                  v8,
                  v9,
                  v10);
                v24 = v87[1];
                v23 = v87[0];
                ((void (__fastcall *)(__int128 *, __int128 *, __int64, __int64, __int64, __int64))sub_54E0)(
                  &v82,
                  &v23,
                  2,
                  v11,
                  v12,
                  v13);
                v24 = v83;
                v23 = v82;
                v17 = &v23;
                ((void (__fastcall *)(char *, __int128 *, __int64, __int64, __int64, __int64))sub_54E0)(
                  &v48,
                  &v23,
                  3,
                  v14,
                  v15,
                  v16);
                LOBYTE(v17) = v48;
                v39 = v51;
                v45 = v52;
                v36 = v53;
                v47 = v54;
                v32 = v55;
                v41 = v56;
                LOBYTE(v18) = v57;
                v46 = v58;
                v34 = v59;
                v43 = v61;
                LOBYTE(v19) = v62;
                v31 = v63;
                v35 = v64;
                v42 = v65;
                v44 = v66;
                v38 = v68;
                v37 = v69;
                v33 = v70;
                LOBYTE(v20) = v71;
                LOBYTE(v21) = v72;
                v40 = v76;
                v30 = v78;
                *(_QWORD *)&v23 = 25;
                v22 = 25;
                v27 = v50;
                v28 = v72;
                v29 = v57;
                if ( v73 == byte_39D95[25] )
                {
                  *(_QWORD *)&v23 = 0;
                  v22 = 0;
                  v17 = (__int128 *)byte_39D95;
                  if ( v48 == byte_39D95[0] )
                  {
                    LOBYTE(v17) = v62;
                    *(_QWORD *)&v23 = 14;
                    v22 = 14;
                    if ( v62 == byte_39D95[14] )
                    {
                      LOBYTE(v17) = v67;
                      *(_QWORD *)&v23 = 19;
                      v22 = 19;
                      if ( v67 == byte_39D95[19] )
                      {
                        LOBYTE(v17) = v71;
                        *(_QWORD *)&v23 = 23;
                        v22 = 23;
                        if ( v71 == byte_39D95[23] )
                        {
                          LOBYTE(v18) = v49;
                          *(_QWORD *)&v23 = 1;
                          v22 = 1;
                          v17 = (__int128 *)byte_39D95;
                          if ( v49 == byte_39D95[1] )
                          {
                            *(_QWORD *)&v23 = 29;
                            v22 = 29;
                            v18 = byte_39D95;
                            if ( v77 == byte_39D95[29] )
                            {
                              *(_QWORD *)&v23 = 27;
                              v22 = 27;
                              v18 = byte_39D95;
                              if ( v75 == byte_39D95[27] )
                              {
                                *(_QWORD *)&v23 = 26;
                                v22 = 26;
                                v18 = byte_39D95;
                                if ( v74 == byte_39D95[26] )
                                {
                                  *(_QWORD *)&v23 = 12;
                                  v22 = 12;
                                  v18 = byte_39D95;
                                  if ( v60 == byte_39D95[12] )
                                  {
                                    *(_QWORD *)&v23 = 31;
                                    v22 = 31;
                                    v18 = byte_39D95;
                                    if ( v79 == byte_39D95[31] )
                                    {
                                      *(_QWORD *)&v23 = 6;
                                      v22 = 6;
                                      v18 = byte_39D95;
                                      if ( v47 == byte_39D95[6] )
                                      {
                                        *(_QWORD *)&v23 = 10;
                                        v22 = 10;
                                        v18 = byte_39D95;
                                        if ( v46 == byte_39D95[10] )
                                        {
                                          *(_QWORD *)&v23 = 15;
                                          v22 = 15;
                                          v18 = byte_39D95;
                                          if ( v31 == byte_39D95[15] )
                                          {
                                            *(_QWORD *)&v23 = 30;
                                            v22 = 30;
                                            v18 = byte_39D95;
                                            if ( v30 == byte_39D95[30] )
                                            {
                                              *(_QWORD *)&v23 = 7;
                                              v22 = 7;
                                              v18 = byte_39D95;
                                              if ( v32 == byte_39D95[7] )
                                              {
                                                *(_QWORD *)&v23 = 11;
                                                v22 = 11;
                                                v18 = byte_39D95;
                                                if ( v34 == byte_39D95[11] )
                                                {
                                                  *(_QWORD *)&v23 = 5;
                                                  v22 = 5;
                                                  v18 = byte_39D95;
                                                  if ( v36 == byte_39D95[5] )
                                                  {
                                                    *(_QWORD *)&v23 = 22;
                                                    v22 = 22;
                                                    v18 = byte_39D95;
                                                    if ( v33 == byte_39D95[22] )
                                                    {
                                                      *(_QWORD *)&v23 = 16;
                                                      v22 = 16;
                                                      v18 = byte_39D95;
                                                      if ( v35 == byte_39D95[16] )
                                                      {
                                                        *(_QWORD *)&v23 = 21;
                                                        v22 = 21;
                                                        v18 = byte_39D95;
                                                        if ( v37 == byte_39D95[21] )
                                                        {
                                                          *(_QWORD *)&v23 = 3;
                                                          v22 = 3;
                                                          v18 = byte_39D95;
                                                          if ( v39 == byte_39D95[3] )
                                                          {
                                                            *(_QWORD *)&v23 = 20;
                                                            v22 = 20;
                                                            v18 = byte_39D95;
                                                            if ( v38 == byte_39D95[20] )
                                                            {
                                                              *(_QWORD *)&v23 = 8;
                                                              v22 = 8;
                                                              v18 = byte_39D95;
                                                              if ( v41 == byte_39D95[8] )
                                                              {
                                                                *(_QWORD *)&v23 = 28;
                                                                v22 = 28;
                                                                v18 = byte_39D95;
                                                                if ( v40 == byte_39D95[28] )
                                                                {
                                                                  *(_QWORD *)&v23 = 13;
                                                                  v22 = 13;
                                                                  v18 = byte_39D95;
                                                                  if ( v43 == byte_39D95[13] )
                                                                  {
                                                                    *(_QWORD *)&v23 = 17;
                                                                    v22 = 17;
                                                                    v18 = byte_39D95;
                                                                    if ( v42 == byte_39D95[17] )
                                                                    {
                                                                      *(_QWORD *)&v23 = 2;
                                                                      v22 = 2;
                                                                      v18 = byte_39D95;
                                                                      if ( v27 == byte_39D95[2] )
                                                                      {
                                                                        *(_QWORD *)&v23 = 9;
                                                                        v22 = 9;
                                                                        v18 = byte_39D95;
                                                                        if ( v29 == byte_39D95[9] )
                                                                        {
                                                                          *(_QWORD *)&v23 = 4;
                                                                          v22 = 4;
                                                                          v18 = byte_39D95;
                                                                          if ( v45 == byte_39D95[4] )
                                                                          {
                                                                            *(_QWORD *)&v23 = 24;
                                                                            v22 = 24;
                                                                            v18 = byte_39D95;
                                                                            if ( v28 == byte_39D95[24] )
                                                                            {
                                                                              *(_QWORD *)&v23 = 18;
                                                                              v22 = 18;
                                                                              v18 = byte_39D95;
                                                                              if ( v44 == byte_39D95[18] )
                                                                                sub_66A0(18, byte_39D95, v21);
                                                                            }
                                                                          }
                                                                        }
                                                                      }
                                                                    }
                                                                  }
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
                sub_6650(v22, v17, v21, v18, v20, v19, v23);
              }
              sub_6600();
            }
            sub_34220(v2, 33, 0, 32, &off_248260);
          }
          sub_34220(v0, 41, 8, 41, &off_248260);
        }
      }
      ((void (__noreturn *)(void))sub_6650)();
    }
    sub_6600();
  }
  if ( !v85 )
    sub_356A0(0, 0, &off_248248);
  *(_QWORD *)&v82 = v84;
  *((_QWORD *)&v82 + 1) = sub_54C0;
  *(_QWORD *)&v23 = &off_248228;
  *((_QWORD *)&v23 + 1) = 2;
  *(_QWORD *)&v24 = 0;
  v25 = &v82;
  v26 = 1;
  ((void (__fastcall *)(__int128 *))sub_83B0)(&v23);
  sub_1F1D0(1);
}
