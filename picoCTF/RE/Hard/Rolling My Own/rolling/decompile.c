#include "out.h"



void _DT_INIT(void)

{
  __gmon_start__();
  return;
}



void FUN_00100940(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int printf(char *__format,...)

{
  int iVar1;
  
  iVar1 = printf(__format);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memset(__s,__c,__n);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strncat(char *__dest,char *__src,size_t __n)

{
  char *pcVar1;
  
  pcVar1 = strncat(__dest,__src,__n);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = puts(__s);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void exit(int __status)

{
                    // WARNING: Subroutine does not return
  exit(__status);
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * malloc(size_t __size)

{
  void *pvVar1;
  
  pvVar1 = malloc(__size);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

FILE * fopen(char *__filename,char *__modes)

{
  FILE *pFVar1;
  
  pFVar1 = fopen(__filename,__modes);
  return pFVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * fgets(char *__s,int __n,FILE *__stream)

{
  char *pcVar1;
  
  pcVar1 = fgets(__s,__n,__stream);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void free(void *__ptr)

{
  free(__ptr);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t strlen(char *__s)

{
  size_t sVar1;
  
  sVar1 = strlen(__s);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int MD5_Final(uchar *md,MD5_CTX *c)

{
  int iVar1;
  
  iVar1 = MD5_Final(md,c);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int MD5_Update(MD5_CTX *c,void *data,size_t len)

{
  int iVar1;
  
  iVar1 = MD5_Update(c,data,len);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void setbuf(FILE *__stream,char *__buf)

{
  setbuf(__stream,__buf);
  return;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int MD5_Init(MD5_CTX *c)

{
  int iVar1;
  
  iVar1 = MD5_Init(c);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * mmap(void *__addr,size_t __len,int __prot,int __flags,int __fd,__off_t __offset)

{
  void *pvVar1;
  
  pvVar1 = mmap(__addr,__len,__prot,__flags,__fd,__offset);
  return pvVar1;
}



void __cxa_finalize(void)

{
  __cxa_finalize();
  return;
}



void processEntry entry(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  __libc_start_main(FUN_00100b6a,param_2,&stack0x00000008,FUN_001010f0,FUN_00101160,param_1,
                    auStack_8);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Removing unreachable block (ram,0x00100aa7)
// WARNING: Removing unreachable block (ram,0x00100ab3)

void FUN_00100a90(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00100af8)
// WARNING: Removing unreachable block (ram,0x00100b04)

void FUN_00100ad0(void)

{
  return;
}



void _FINI_0(void)

{
  if (DAT_00302020 != '\0') {
    return;
  }
  __cxa_finalize(PTR_LOOP_00302008);
  FUN_00100a90();
  DAT_00302020 = 1;
  return;
}



void _INIT_0(void)

{
  FUN_00100ad0();
  return;
}



undefined8 FUN_00100b6a(void)

{
  size_t sVar1;
  void *__ptr;
  code *pcVar2;
  long in_FS_OFFSET;
  int local_100;
  int local_fc;
  int local_e8 [4];
  undefined8 local_d8;
  undefined8 local_d0;
  char local_c8 [47];
  char acStack_99 [65];
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  builtin_strncpy(local_c8,"GpLaMjEWpVOjnnmkRGiledp6Mvcezxls",0x21);
  local_e8[0] = 8;
  local_e8[1] = 2;
  local_e8[2] = 7;
  local_e8[3] = 1;
  memset(acStack_99 + 1,0,0x40);
  memset(local_58,0,0x40);
  printf("Password: ");
  fgets(acStack_99 + 1,0x40,stdin);
  sVar1 = strlen(acStack_99 + 1);
  acStack_99[sVar1] = '\0';
  for (local_100 = 0; local_100 < 4; local_100 = local_100 + 1) {
    strncat(local_58,acStack_99 + (long)(local_100 << 2) + 1,4);
    strncat(local_58,local_c8 + (local_100 << 3),8);
  }
  __ptr = malloc(0x40);
  sVar1 = strlen(local_58);
  FUN_00100e3e(__ptr,local_58,sVar1 & 0xffffffff);
  for (local_100 = 0; local_100 < 4; local_100 = local_100 + 1) {
    for (local_fc = 0; local_fc < 4; local_fc = local_fc + 1) {
      *(undefined1 *)((long)&local_d8 + (long)(local_fc * 4 + local_100)) =
           *(undefined1 *)((long)__ptr + (long)(local_e8[local_fc] + local_fc * 0x10 + local_100));
    }
  }
  pcVar2 = (code *)mmap((void *)0x0,0x10,7,0x22,-1,0);
  *(undefined8 *)pcVar2 = local_d8;
  *(undefined8 *)(pcVar2 + 8) = local_d0;
  (*pcVar2)(FUN_0010102b);
  free(__ptr);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return 0;
}



void FUN_00100e3e(long param_1,void *param_2,int param_3)

{
  int iVar1;
  long in_FS_OFFSET;
  void *local_a8;
  int local_98;
  int local_94;
  int local_90;
  MD5_CTX local_88;
  uchar local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_3 % 0xc == 0) {
    iVar1 = param_3 / 0xc;
  }
  else {
    iVar1 = param_3 / 0xc + 1;
  }
  local_a8 = param_2;
  for (local_98 = 0; local_98 < iVar1; local_98 = local_98 + 1) {
    local_90 = 0xc;
    if ((local_98 == iVar1 + -1) && (param_3 % 0xc != 0)) {
      local_90 = iVar1 % 0xc;
    }
    MD5_Init(&local_88);
    MD5_Update(&local_88,local_a8,(long)local_90);
    local_a8 = (void *)((long)local_a8 + (long)local_90);
    MD5_Final(local_28,&local_88);
    for (local_94 = 0; local_94 < 0x10; local_94 = local_94 + 1) {
      *(uchar *)((local_98 * 0x10 + local_94) % 0x40 + param_1) = local_28[local_94];
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



void FUN_0010102b(long param_1)

{
  FILE *__stream;
  long in_FS_OFFSET;
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 == 0x7b3dc26f1) {
    __stream = fopen("flag","r");
    if (__stream == (FILE *)0x0) {
      puts("Flag file not found. Contact an admin.");
                    // WARNING: Subroutine does not return
      exit(1);
    }
    fgets(local_98,0x80,__stream);
    puts(local_98);
  }
  else {
    puts("Hmmmmmm... not quite");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



void FUN_001010f0(undefined4 param_1,undefined8 param_2,undefined8 param_3)

{
  long lVar1;
  
  _DT_INIT();
  lVar1 = 0;
  do {
    (*(code *)(&__DT_INIT_ARRAY)[lVar1])(param_1,param_2,param_3);
    lVar1 = lVar1 + 1;
  } while (lVar1 != 1);
  return;
}



void FUN_00101160(void)

{
  return;
}



void _DT_FINI(void)

{
  return;
}



