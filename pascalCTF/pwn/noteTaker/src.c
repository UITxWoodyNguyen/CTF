int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+4h] [rbp-11Ch] BYREF
  char *v5; // [rsp+8h] [rbp-118h]
  char s[264]; // [rsp+10h] [rbp-110h] BYREF
  unsigned __int64 v7; // [rsp+118h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  init(argc, argv, envp);
  memset(s, 0, 0x100u);
  do
  {
    menu();
    v5 = (char *)malloc(0x10u);
    memset(v5, 0, 0x10u);
    fgets(v5, 16, stdin);
    _isoc99_sscanf(v5, "%d", &v4);
    free(v5);
    switch ( v4 )
    {
      case 2:
        printf("Enter the note: ");
        read(0, s, 0x100u);
        s[strcspn(s, "\n")] = 0;
        break;
      case 3:
        memset(s, 0, 0x100u);
        puts("Note cleared.");
        break;
      case 1:
        printf(s);
        putchar(10);
        break;
    }
  }
  while ( v4 > 0 && v4 <= 4 );
  return 0;
}