__int64 __fastcall sub_226C0(__int64 a1, __int64 a2)
{
  void (*v2)(int); // rax
  unsigned __int64 v3; // rcx
  __int64 v4; // rbx
  unsigned __int64 v5; // rax
  _QWORD *v6; // rax
  void *v7; // r15
  unsigned __int64 v8; // rbx
  int v9; // ebp
  __int64 v11; // [rsp+8h] [rbp-100h] BYREF
  struct sigaction oact; // [rsp+10h] [rbp-F8h] BYREF
  __int128 v13; // [rsp+B0h] [rbp-58h] BYREF
  unsigned __int64 v14; // [rsp+C0h] [rbp-48h]
  __int128 v15; // [rsp+D0h] [rbp-38h] BYREF
  unsigned __int64 v16; // [rsp+E0h] [rbp-28h]

  if ( signal(13, (__sighandler_t)((char *)&dword_0 + 1)) == (__sighandler_t)-1LL )
    sub_223B0(
      "assertion failed: signal(libc::SIGPIPE, libc::SIG_IGN) != libc::SIG_ERRlibrary/std/src/sys/unix/mod.rsassertion fa"
      "iled: `(left == right)`\n"
      "  left: ``,\n"
      " right: ``library/std/src/sys/unix/condvar.rs",
      71,
      &off_248478);
  sub_1AE10(&v15);
  memset(&oact, 0, sizeof(oact));
  sigaction(11, 0, &oact);
  if ( !oact.sa_handler )
  {
    oact.sa_flags = 134217732;
    oact.sa_handler = (__sighandler_t)sub_276F0;
    sigaction(11, &oact, 0);
    byte_24B218 = 1;
  }
  sigaction(7, 0, &oact);
  if ( !oact.sa_handler )
  {
    oact.sa_flags = 134217732;
    oact.sa_handler = (__sighandler_t)sub_276F0;
    sigaction(7, &oact, 0);
    byte_24B218 = 1;
  }
  qword_24B210 = sub_277D0();
  v2 = (void (*)(int))sub_6DA0(4u, 1u);
  if ( !v2 )
    sub_32F80(4, 1);
  oact.sa_handler = v2;
  *(_OWORD *)oact.sa_mask.__val = xmmword_3A440;
  sub_25510(&oact, 0, 4);
  v3 = oact.sa_mask.__val[1];
  *(_DWORD *)((char *)oact.sa_handler + oact.sa_mask.__val[1]) = 1852399981;
  oact.sa_mask.__val[1] = v3 + 4;
  v4 = sub_21250(&oact);
  v14 = v16;
  v13 = v15;
  v11 = v4;
  v5 = __readfsqword(0);
  if ( *(_DWORD *)(v5 - 88) == 1 )
  {
    v6 = (_QWORD *)(v5 - 80);
  }
  else
  {
    v6 = (_QWORD *)sub_15CF0(v5 - 88);
    if ( !v6 )
      sub_35760(
        "cannot access a Thread Local Storage value during or after destructionlibrary/std/src/thread/local.rslibrary/std/src/io/stdio.rslibrary/std/src/sync/once.rsassertion failed: state_and_queue & STATE_MASK == RUNNINGOnce instance has previously been poisoned",
        70,
        &oact,
        &off_248810,
        &off_248940);
  }
  if ( *v6 + 1LL <= 0 )
    sub_35760(
      "already mutably borrowedcalled `Option::unwrap()` on a `None` value/build/rustc-UHkz09/rustc-1.47.0+dfsg1+llvm/vendor/addr2line/src/lib.rsAccessErrorcannot access a Thread Local Storage value during or after destructionlibrary/std/src/thread/local.rslibrary/std/src/io/stdio.rslibrary/std/src/sync/once.rsassertion failed: state_and_queue & STATE_MASK == RUNNINGOnce instance has previously been poisoned",
      24,
      &oact,
      &off_248830,
      &off_248A40);
  if ( v6[1] != 2 )
    sub_223B0("assertion failed: c.borrow().is_none()", 38, &off_248A58);
  oact.sa_mask.__val[1] = v14;
  *(_OWORD *)&oact.sa_handler = v13;
  oact.sa_mask.__val[2] = v4;
  sub_159E0(&off_2490E0, &oact);
  HIDWORD(oact.sa_sigaction) = (*(__int64 (__fastcall **)(__int64))(a2 + 24))(a1);
  LODWORD(oact.sa_handler) = 0;
  if ( qword_24B208 != 3 )
  {
    LOBYTE(v11) = 1;
    *(_QWORD *)&v13 = &v11;
    sub_16040(&qword_24B208, 0, &v13, &off_248970);
  }
  if ( LODWORD(oact.sa_handler) == 1 )
  {
    v7 = (void *)oact.sa_mask.__val[0];
    v8 = oact.sa_mask.__val[1];
    (*(void (__fastcall **)(unsigned __int64))oact.sa_mask.__val[1])(oact.sa_mask.__val[0]);
    v9 = 101;
    if ( *(_QWORD *)(v8 + 8) )
      j_free(v7);
  }
  else
  {
    return SHIDWORD(oact.sa_sigaction);
  }
  return v9;
}
