# babygame01
### Information
* Category: Binary Exploit
* Level: Medium

### Description
Get the flag and reach the exit.
Welcome to BabyGame! Navigate around the map and see what you can find! The game is available to download here. There is no source available, so you'll have to figure your way around the map. You can connect with it using nc saturn.picoctf.net 64344.

### Hint

- Use 'w','a','s','d' to move around.
- There may be secret commands to make your life easy.

## Solution:

Open `game` in IDA, navigate to function `main`, it does several things:
1. Create the player.
2. Create the map.
3. Print the map.
4. Create a loop that:
    - Get user's input.
    - Update the player's position and the map.
    - Print the updated map.

The loops break once the player's position is (29, 89).
After the loop, the function checks `v6`'s value. If it is non-zero, the flag is printed. So to get the flag, we need to make `v6` becomes non-zero.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+1h] [ebp-AA5h]
  _DWORD v5[2]; // [esp+2h] [ebp-AA4h] BYREF
  char v6; // [esp+Ah] [ebp-A9Ch]
  _BYTE v7[2700]; // [esp+Eh] [ebp-A98h] BYREF
  unsigned int v8; // [esp+A9Ah] [ebp-Ch]
  int *p_argc; // [esp+A9Eh] [ebp-8h]

  p_argc = &argc;
  v8 = __readgsdword(0x14u);
  init_player(v5);
  init_map(v7, v5);
  print_map(v7, v5);
  signal(2, (__sighandler_t)sigint_handler);
  do
  {
    do
    {
      v4 = getchar();
      move_player(v5, v4, (int)v7);
      print_map(v7, v5);
    }
    while ( v5[0] != 29 );
  }
  while ( v5[1] != 89 );                        // breaks when player have come to the end of the map
  puts("You win!");
  if ( v6 )
  {
    puts("flage");
    win();
    fflush(stdout);
  }
  return 0;
}
```

Base on the code, we can calculate the padding between `v6` and `v7` (which is the map's base address), the padding is `3` (`0xA98` – `0xA9C` = `4`, `v6` takes 1 byte). So to modify `v6`, we have to do a buffer underflow attack by setting `v7 - 4` (this will overwrite `v6`) to a non-zero value. Inspecting `move_player`, we found out that it doesn't perform any boundary checks for the map, which is vulnerable to the attack we've mentioned. Moreover, it sets `(a1[1] + a3 + 90 * *a1)` (which is `x + map_base_address + 90y`) to the player's icon, which is non-zero already. Because our target is setting `map_base_address - 4` to non-zero, we will move the player to the position (-4, 0) so `v6` will hold the value `40` (which is our player's icon). We also found out some hidden commands, like `p` for auto finish the game, `l` for changing the player's icon.

```c
_BYTE *__cdecl move_player(_DWORD *a1, char a2, int a3)
{
  _BYTE *result; // eax

  if ( a2 == 108 )
    player_tile = getchar();                    // change player's icon
  if ( a2 == 112 )
    solve_round(a3, a1);                        // auto finish the game
  *(_BYTE *)(a1[1] + a3 + 90 * *a1) = 46;       // x + map_base_address + 90y = '.'
  switch ( a2 )
  {
    case 'w':
      --*a1;
      break;
    case 's':
      ++*a1;
      break;
    case 'a':
      --a1[1];
      break;
    case 'd':
      ++a1[1];
      break;
  }
  result = (_BYTE *)(a1[1] + a3 + 90 * *a1);    // player_pos
  *result = player_tile;
  return result;
}
```

So our final input will be `wwwwaaaaaaaap` (because our player's first position is (4, 4)). Submit it and we got our flag `picoCTF{gamer_m0d3_enabled_ec1f4e25}`.


![alt text](image.png)
