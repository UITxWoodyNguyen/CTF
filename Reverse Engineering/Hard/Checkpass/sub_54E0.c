char __fastcall sub_54E0(__int64 a1, unsigned __int8 *a2, __int64 a3)
{
  __int64 v3; // rdx
  unsigned __int64 v4; // rax
  char result; // al
  _BYTE v6[32]; // [rsp+8h] [rbp-20h]

  v3 = a3 << 8;
  v6[0] = byte_39560[v3 + *a2];
  v6[1] = byte_39560[v3 + a2[1]];
  v6[2] = byte_39560[v3 + a2[2]];
  v6[3] = byte_39560[v3 + a2[3]];
  v6[4] = byte_39560[v3 + a2[4]];
  v6[5] = byte_39560[v3 + a2[5]];
  v6[6] = byte_39560[v3 + a2[6]];
  v6[7] = byte_39560[v3 + a2[7]];
  v6[8] = byte_39560[v3 + a2[8]];
  v6[9] = byte_39560[v3 + a2[9]];
  v6[10] = byte_39560[v3 + a2[10]];
  v6[11] = byte_39560[v3 + a2[11]];
  v6[12] = byte_39560[v3 + a2[12]];
  v6[13] = byte_39560[v3 + a2[13]];
  v6[14] = byte_39560[v3 + a2[14]];
  v6[15] = byte_39560[v3 + a2[15]];
  v6[16] = byte_39560[v3 + a2[16]];
  v6[17] = byte_39560[v3 + a2[17]];
  v6[18] = byte_39560[v3 + a2[18]];
  v6[19] = byte_39560[v3 + a2[19]];
  v6[20] = byte_39560[v3 + a2[20]];
  v6[21] = byte_39560[v3 + a2[21]];
  v6[22] = byte_39560[v3 + a2[22]];
  v6[23] = byte_39560[v3 + a2[23]];
  v6[24] = byte_39560[v3 + a2[24]];
  v6[25] = byte_39560[v3 + a2[25]];
  v6[26] = byte_39560[v3 + a2[26]];
  v6[27] = byte_39560[v3 + a2[27]];
  v6[28] = byte_39560[v3 + a2[28]];
  v6[29] = byte_39560[v3 + a2[29]];
  v6[30] = byte_39560[v3 + a2[30]];
  v6[31] = byte_39560[v3 + a2[31]];
  *(_OWORD *)(a1 + 16) = 0;
  *(_OWORD *)a1 = 0;
  v4 = *(_QWORD *)&asc_39970[v3 + 64];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 8) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 200];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 25) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 216];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 27) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 224];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 28) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 136];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 17) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 112];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 14) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 96];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 12) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 120];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 15) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 16];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 2) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 168];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 21) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 128];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 16) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 72];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 9) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 152];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 19) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 80];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 10) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 104];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 13) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 48];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 6) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 176];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 22) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)a1 = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 240];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 30) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 8];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 1) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 32];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 4) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 208];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 26) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 232];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 29) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 24];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 3) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 248];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 31) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 160];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 20) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 192];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 24) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 56];
  if ( v4 > 0x1F )
    goto LABEL_34;
  *(_BYTE *)(a1 + 7) = v6[v4];
  v4 = *(_QWORD *)&asc_39970[v3 + 88];
  if ( v4 > 0x1F
    || (*(_BYTE *)(a1 + 11) = v6[v4], v4 = *(_QWORD *)&asc_39970[v3 + 184], v4 > 0x1F)
    || (*(_BYTE *)(a1 + 23) = v6[v4], v4 = *(_QWORD *)&asc_39970[v3 + 40], v4 > 0x1F)
    || (*(_BYTE *)(a1 + 5) = v6[v4], v4 = *(_QWORD *)&asc_39970[v3 + 144], v4 >= 0x20) )
  {
LABEL_34:
    sub_356A0(v4, 32, &off_2481F8);
  }
  result = v6[v4];
  *(_BYTE *)(a1 + 18) = result;
  return result;
}
