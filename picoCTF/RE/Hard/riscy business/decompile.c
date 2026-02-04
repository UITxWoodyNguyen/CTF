#include "out.h"



void FUN_00010078(byte *param_1,long param_2,ulong param_3)

{
  byte bVar1;
  ulong uVar2;
  ulong uVar3;
  long lVar4;
  ulong uVar5;
  byte *pbVar6;
  
  ecall();
  lVar4 = 0;
  do {
    param_1[lVar4] = (byte)lVar4;
    lVar4 = lVar4 + 1;
  } while (lVar4 != 0x100);
  uVar2 = 0;
  uVar5 = 0;
  pbVar6 = param_1;
  do {
    uVar3 = uVar2 % param_3;
    bVar1 = *pbVar6;
    uVar2 = uVar2 + 1;
    uVar3 = (ulong)(int)((int)uVar5 + (uint)*(byte *)(uVar3 + param_2) + (uint)bVar1);
    uVar5 = uVar3 & 0xff;
    *pbVar6 = param_1[uVar3 & 0xff];
    param_1[uVar3 & 0xff] = bVar1;
    pbVar6 = pbVar6 + 1;
  } while (uVar2 != 0x100);
  return;
}



void FUN_00010080(byte *param_1,long param_2,ulong param_3)

{
  byte bVar1;
  ulong uVar2;
  ulong uVar3;
  long lVar4;
  ulong uVar5;
  byte *pbVar6;
  
  lVar4 = 0;
  do {
    param_1[lVar4] = (byte)lVar4;
    lVar4 = lVar4 + 1;
  } while (lVar4 != 0x100);
  uVar2 = 0;
  uVar5 = 0;
  pbVar6 = param_1;
  do {
    uVar3 = uVar2 % param_3;
    bVar1 = *pbVar6;
    uVar2 = uVar2 + 1;
    uVar3 = (ulong)(int)((int)uVar5 + (uint)*(byte *)(uVar3 + param_2) + (uint)bVar1);
    uVar5 = uVar3 & 0xff;
    *pbVar6 = param_1[uVar3 & 0xff];
    param_1[uVar3 & 0xff] = bVar1;
    pbVar6 = pbVar6 + 1;
  } while (uVar2 != 0x100);
  return;
}



undefined1 FUN_000100d2(long param_1)

{
  char cVar1;
  char cVar2;
  byte bVar3;
  char *pcVar4;
  char *pcVar5;
  
  bVar3 = *(char *)(param_1 + 0x100) + 1;
  *(byte *)(param_1 + 0x100) = bVar3;
  pcVar4 = (char *)((ulong)bVar3 + param_1);
  cVar1 = *pcVar4;
  bVar3 = *(char *)(param_1 + 0x101) + cVar1;
  *(byte *)(param_1 + 0x101) = bVar3;
  pcVar5 = (char *)((ulong)bVar3 + param_1);
  cVar2 = *pcVar5;
  *pcVar4 = cVar2;
  *pcVar5 = cVar1;
  return *(undefined1 *)(param_1 + (ulong)(byte)(cVar1 + cVar2));
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x00010140)

void entry(void)

{
  byte bVar1;
  long unaff_s0;
  byte *pbVar2;
  byte bVar3;
  byte *pbVar4;
  byte *pbVar5;
  byte local_178 [64];
  undefined1 auStack_138 [272];
  
  ecall();
  pbVar2 = local_178;
  ecall();
  do {
    ecall();
    FUN_00010078(1,"You need to take some more riscs than that.\n",0x2c,0x40);
  } while (unaff_s0 < 8);
  FUN_00010080(auStack_138,pbVar2,8);
  pbVar4 = pbVar2;
  do {
    bVar1 = *pbVar4;
    bVar3 = FUN_000100d2(auStack_138);
    pbVar5 = pbVar4 + 1;
    *pbVar4 = bVar1 ^ bVar3;
    pbVar4 = pbVar5;
  } while (pbVar2 + (unaff_s0 - (long)pbVar5) != (byte *)0x0);
  pbVar4 = &DAT_00010210;
  do {
    bVar1 = *pbVar2;
    bVar3 = *pbVar4;
    pbVar2 = pbVar2 + 1;
    pbVar4 = pbVar4 + 1;
    if (bVar1 != bVar3) goto LAB_000101f2;
  } while (pbVar4 != &UNK_00010244);
  ecall();
  FUN_00010078(0,"Success!\n",9,0x40);
LAB_000101f2:
  ecall();
  FUN_00010078(1,"That was a bit too riscy for me!\n",0x21,0x40);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



