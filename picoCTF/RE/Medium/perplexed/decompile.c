#include "out.h"



int _init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  
  iVar1 = __gmon_start__();
  return iVar1;
}



void FUN_00401020(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = puts(__s);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t strlen(char *__s)

{
  size_t sVar1;
  
  sVar1 = strlen(__s);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int printf(char *__format,...)

{
  int iVar1;
  
  iVar1 = printf(__format);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * fgets(char *__s,int __n,FILE *__stream)

{
  char *pcVar1;
  
  pcVar1 = fgets(__s,__n,__stream);
  return pcVar1;
}



void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  __libc_start_main(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void _dl_relocate_static_pie(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x004010bd)
// WARNING: Removing unreachable block (ram,0x004010c7)

void deregister_tm_clones(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x004010ff)
// WARNING: Removing unreachable block (ram,0x00401109)

void register_tm_clones(void)

{
  return;
}



void __do_global_dtors_aux(void)

{
  if (completed_0 == '\0') {
    deregister_tm_clones();
    completed_0 = 1;
    return;
  }
  return;
}



void frame_dummy(void)

{
  register_tm_clones();
  return;
}



undefined8 check(char *param_1)

{
  size_t sVar1;
  undefined8 uVar2;
  size_t sVar3;
  char local_58 [36];
  uint local_34;
  uint local_30;
  undefined4 local_2c;
  int local_28;
  uint local_24;
  int local_20;
  int local_1c;
  
  sVar1 = strlen(param_1);
  if (sVar1 == 0x1b) {
    local_58[0] = -0x1f;
    local_58[1] = -0x59;
    local_58[2] = '\x1e';
    local_58[3] = -8;
    local_58[4] = 'u';
    local_58[5] = '#';
    local_58[6] = '{';
    local_58[7] = 'a';
    local_58[8] = -0x47;
    local_58[9] = -99;
    local_58[10] = -4;
    local_58[0xb] = 'Z';
    local_58[0xc] = '[';
    local_58[0xd] = -0x21;
    local_58[0xe] = 'i';
    local_58[0xf] = 0xd2;
    local_58[0x10] = -2;
    local_58[0x11] = '\x1b';
    local_58[0x12] = -0x13;
    local_58[0x13] = -0xc;
    local_58[0x14] = -0x13;
    local_58[0x15] = 'g';
    local_58[0x16] = -0xc;
    local_1c = 0;
    local_20 = 0;
    local_2c = 0;
    for (local_24 = 0; local_24 < 0x17; local_24 = local_24 + 1) {
      for (local_28 = 0; local_28 < 8; local_28 = local_28 + 1) {
        if (local_20 == 0) {
          local_20 = 1;
        }
        local_30 = 1 << (7U - (char)local_28 & 0x1f);
        local_34 = 1 << (7U - (char)local_20 & 0x1f);
        if (0 < (int)((int)param_1[local_1c] & local_34) !=
            0 < (int)((int)local_58[(int)local_24] & local_30)) {
          return 1;
        }
        local_20 = local_20 + 1;
        if (local_20 == 8) {
          local_20 = 0;
          local_1c = local_1c + 1;
        }
        sVar3 = (size_t)local_1c;
        sVar1 = strlen(param_1);
        if (sVar3 == sVar1) {
          return 0;
        }
      }
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}



bool main(void)

{
  bool bVar1;
  char local_118 [268];
  int local_c;
  
  local_118[0] = '\0';
  local_118[1] = '\0';
  local_118[2] = '\0';
  local_118[3] = '\0';
  local_118[4] = '\0';
  local_118[5] = '\0';
  local_118[6] = '\0';
  local_118[7] = '\0';
  local_118[8] = '\0';
  local_118[9] = '\0';
  local_118[10] = '\0';
  local_118[0xb] = '\0';
  local_118[0xc] = '\0';
  local_118[0xd] = '\0';
  local_118[0xe] = '\0';
  local_118[0xf] = '\0';
  local_118[0x10] = '\0';
  local_118[0x11] = '\0';
  local_118[0x12] = '\0';
  local_118[0x13] = '\0';
  local_118[0x14] = '\0';
  local_118[0x15] = '\0';
  local_118[0x16] = '\0';
  local_118[0x17] = '\0';
  local_118[0x18] = '\0';
  local_118[0x19] = '\0';
  local_118[0x1a] = '\0';
  local_118[0x1b] = '\0';
  local_118[0x1c] = '\0';
  local_118[0x1d] = '\0';
  local_118[0x1e] = '\0';
  local_118[0x1f] = '\0';
  local_118[0x20] = '\0';
  local_118[0x21] = '\0';
  local_118[0x22] = '\0';
  local_118[0x23] = '\0';
  local_118[0x24] = '\0';
  local_118[0x25] = '\0';
  local_118[0x26] = '\0';
  local_118[0x27] = '\0';
  local_118[0x28] = '\0';
  local_118[0x29] = '\0';
  local_118[0x2a] = '\0';
  local_118[0x2b] = '\0';
  local_118[0x2c] = '\0';
  local_118[0x2d] = '\0';
  local_118[0x2e] = '\0';
  local_118[0x2f] = '\0';
  local_118[0x30] = '\0';
  local_118[0x31] = '\0';
  local_118[0x32] = '\0';
  local_118[0x33] = '\0';
  local_118[0x34] = '\0';
  local_118[0x35] = '\0';
  local_118[0x36] = '\0';
  local_118[0x37] = '\0';
  local_118[0x38] = '\0';
  local_118[0x39] = '\0';
  local_118[0x3a] = '\0';
  local_118[0x3b] = '\0';
  local_118[0x3c] = '\0';
  local_118[0x3d] = '\0';
  local_118[0x3e] = '\0';
  local_118[0x3f] = '\0';
  local_118[0x40] = '\0';
  local_118[0x41] = '\0';
  local_118[0x42] = '\0';
  local_118[0x43] = '\0';
  local_118[0x44] = '\0';
  local_118[0x45] = '\0';
  local_118[0x46] = '\0';
  local_118[0x47] = '\0';
  local_118[0x48] = '\0';
  local_118[0x49] = '\0';
  local_118[0x4a] = '\0';
  local_118[0x4b] = '\0';
  local_118[0x4c] = '\0';
  local_118[0x4d] = '\0';
  local_118[0x4e] = '\0';
  local_118[0x4f] = '\0';
  local_118[0x50] = '\0';
  local_118[0x51] = '\0';
  local_118[0x52] = '\0';
  local_118[0x53] = '\0';
  local_118[0x54] = '\0';
  local_118[0x55] = '\0';
  local_118[0x56] = '\0';
  local_118[0x57] = '\0';
  local_118[0x58] = '\0';
  local_118[0x59] = '\0';
  local_118[0x5a] = '\0';
  local_118[0x5b] = '\0';
  local_118[0x5c] = '\0';
  local_118[0x5d] = '\0';
  local_118[0x5e] = '\0';
  local_118[0x5f] = '\0';
  local_118[0x60] = '\0';
  local_118[0x61] = '\0';
  local_118[0x62] = '\0';
  local_118[99] = '\0';
  local_118[100] = '\0';
  local_118[0x65] = '\0';
  local_118[0x66] = '\0';
  local_118[0x67] = '\0';
  local_118[0x68] = '\0';
  local_118[0x69] = '\0';
  local_118[0x6a] = '\0';
  local_118[0x6b] = '\0';
  local_118[0x6c] = '\0';
  local_118[0x6d] = '\0';
  local_118[0x6e] = '\0';
  local_118[0x6f] = '\0';
  local_118[0x70] = '\0';
  local_118[0x71] = '\0';
  local_118[0x72] = '\0';
  local_118[0x73] = '\0';
  local_118[0x74] = '\0';
  local_118[0x75] = '\0';
  local_118[0x76] = '\0';
  local_118[0x77] = '\0';
  local_118[0x78] = '\0';
  local_118[0x79] = '\0';
  local_118[0x7a] = '\0';
  local_118[0x7b] = '\0';
  local_118[0x7c] = '\0';
  local_118[0x7d] = '\0';
  local_118[0x7e] = '\0';
  local_118[0x7f] = '\0';
  local_118[0x80] = '\0';
  local_118[0x81] = '\0';
  local_118[0x82] = '\0';
  local_118[0x83] = '\0';
  local_118[0x84] = '\0';
  local_118[0x85] = '\0';
  local_118[0x86] = '\0';
  local_118[0x87] = '\0';
  local_118[0x88] = '\0';
  local_118[0x89] = '\0';
  local_118[0x8a] = '\0';
  local_118[0x8b] = '\0';
  local_118[0x8c] = '\0';
  local_118[0x8d] = '\0';
  local_118[0x8e] = '\0';
  local_118[0x8f] = '\0';
  local_118[0x90] = '\0';
  local_118[0x91] = '\0';
  local_118[0x92] = '\0';
  local_118[0x93] = '\0';
  local_118[0x94] = '\0';
  local_118[0x95] = '\0';
  local_118[0x96] = '\0';
  local_118[0x97] = '\0';
  local_118[0x98] = '\0';
  local_118[0x99] = '\0';
  local_118[0x9a] = '\0';
  local_118[0x9b] = '\0';
  local_118[0x9c] = '\0';
  local_118[0x9d] = '\0';
  local_118[0x9e] = '\0';
  local_118[0x9f] = '\0';
  local_118[0xa0] = '\0';
  local_118[0xa1] = '\0';
  local_118[0xa2] = '\0';
  local_118[0xa3] = '\0';
  local_118[0xa4] = '\0';
  local_118[0xa5] = '\0';
  local_118[0xa6] = '\0';
  local_118[0xa7] = '\0';
  local_118[0xa8] = '\0';
  local_118[0xa9] = '\0';
  local_118[0xaa] = '\0';
  local_118[0xab] = '\0';
  local_118[0xac] = '\0';
  local_118[0xad] = '\0';
  local_118[0xae] = '\0';
  local_118[0xaf] = '\0';
  local_118[0xb0] = '\0';
  local_118[0xb1] = '\0';
  local_118[0xb2] = '\0';
  local_118[0xb3] = '\0';
  local_118[0xb4] = '\0';
  local_118[0xb5] = '\0';
  local_118[0xb6] = '\0';
  local_118[0xb7] = '\0';
  local_118[0xb8] = '\0';
  local_118[0xb9] = '\0';
  local_118[0xba] = '\0';
  local_118[0xbb] = '\0';
  local_118[0xbc] = '\0';
  local_118[0xbd] = '\0';
  local_118[0xbe] = '\0';
  local_118[0xbf] = '\0';
  local_118[0xc0] = '\0';
  local_118[0xc1] = '\0';
  local_118[0xc2] = '\0';
  local_118[0xc3] = '\0';
  local_118[0xc4] = '\0';
  local_118[0xc5] = '\0';
  local_118[0xc6] = '\0';
  local_118[199] = '\0';
  local_118[200] = '\0';
  local_118[0xc9] = '\0';
  local_118[0xca] = '\0';
  local_118[0xcb] = '\0';
  local_118[0xcc] = '\0';
  local_118[0xcd] = '\0';
  local_118[0xce] = '\0';
  local_118[0xcf] = '\0';
  local_118[0xd0] = '\0';
  local_118[0xd1] = '\0';
  local_118[0xd2] = '\0';
  local_118[0xd3] = '\0';
  local_118[0xd4] = '\0';
  local_118[0xd5] = '\0';
  local_118[0xd6] = '\0';
  local_118[0xd7] = '\0';
  local_118[0xd8] = '\0';
  local_118[0xd9] = '\0';
  local_118[0xda] = '\0';
  local_118[0xdb] = '\0';
  local_118[0xdc] = '\0';
  local_118[0xdd] = '\0';
  local_118[0xde] = '\0';
  local_118[0xdf] = '\0';
  local_118[0xe0] = '\0';
  local_118[0xe1] = '\0';
  local_118[0xe2] = '\0';
  local_118[0xe3] = '\0';
  local_118[0xe4] = '\0';
  local_118[0xe5] = '\0';
  local_118[0xe6] = '\0';
  local_118[0xe7] = '\0';
  local_118[0xe8] = '\0';
  local_118[0xe9] = '\0';
  local_118[0xea] = '\0';
  local_118[0xeb] = '\0';
  local_118[0xec] = '\0';
  local_118[0xed] = '\0';
  local_118[0xee] = '\0';
  local_118[0xef] = '\0';
  local_118[0xf0] = '\0';
  local_118[0xf1] = '\0';
  local_118[0xf2] = '\0';
  local_118[0xf3] = '\0';
  local_118[0xf4] = '\0';
  local_118[0xf5] = '\0';
  local_118[0xf6] = '\0';
  local_118[0xf7] = '\0';
  local_118[0xf8] = '\0';
  local_118[0xf9] = '\0';
  local_118[0xfa] = '\0';
  local_118[0xfb] = '\0';
  local_118[0xfc] = '\0';
  local_118[0xfd] = '\0';
  local_118[0xfe] = '\0';
  local_118[0xff] = '\0';
  printf("Enter the password: ");
  fgets(local_118,0x100,stdin);
  local_c = check(local_118);
  bVar1 = local_c != 1;
  if (bVar1) {
    puts("Correct!! :D");
  }
  else {
    puts("Wrong :(");
  }
  return !bVar1;
}



void _fini(void)

{
  return;
}



