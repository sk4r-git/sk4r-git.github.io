+++
date = '2026-03-26T17:46:27+01:00'
draft = false
title = 'BYO_ECSC_Team'
+++


## Attachments

<a href="/ctf/hackropole/"></a>
<a href="/ctf/hackropole/"></a><br><br>

## Reverse

Heap challenge with multiples possibilities
```bash
-=== Build Your Own Team - ECSC 2019 edition! ===-
1. Show the ECSC 2019 team
2. Show player
3. Select player
4. Add new player
5. Remove player
6. Edit player
7. Exit
```

Let's analyze each of them

### Show team

```C
void show_team(void)
{
  uint local_14;
  
  puts("Behold! Here is your dream ECSC team!");
  for (local_14 = 0; local_14 < 10; local_14 = local_14 + 1) {
    if (*(long *)(players + (ulong)local_14 * 8) != 0) {
      printf("Player #%d\n",(ulong)local_14);
      print_player(*(undefined8 *)(players + (ulong)local_14 * 8));
    }
  }
  return;
}
```
There is a table of 10 players and this function just 'print' each of them

### Show player
```C
void show_player(void)
{
  if (selected_player == 0) {
    puts("[-] No currently selected player");
  }
  else {
    print_player(selected_player);
  }
  return;
}
```
this function also call 'print_player', notice that the check is not the same, there is no verification on the pointer validity, maybe a leak here ?

Let's dive in 'print_player'
```C

void print_player(uint *param_1)

{
  printf("Name: %s\n",*(undefined8 *)(param_1 + 4));
  printf("- Pwn:        %d\n",(ulong)*param_1);
  printf("- Crypto:     %d\n",(ulong)param_1[1]);
  printf("- Web:        %d\n",(ulong)param_1[2]);
  printf("- Stegoguess: %d\n",(ulong)param_1[3]);
  return;
}
```
Yes, obviously a leak
We can think about a first strategie here, make the variable 'selected_player' != 0 but on a free player, this would leak to heap leak and maybe libc leak.

### Select player
```C
   d select_player(void)

{
  char local_f [3];
  uint local_c;
  
  puts("Enter the index of the player you would like to select: ");
  read_input(local_f,3);
  local_c = atoi(local_f);
  if ((local_c < 0xb) && (*(long *)(players + (ulong)local_c * 8) != 0)) {
    selected_player = *(undefined8 *)(players + (ulong)local_c * 8);
    printf("Player at index %u is now selected!\n",(ulong)local_c);
    print_player(selected_player);
  }
  else {
    puts("[-] Invalid Index");
  }
  return;
}
```
Nothing particular, maybe an underflow or a selection of freed player

### Add new player
```C

void add_player(void)

{
  int iVar1;
  int *__s;
  size_t sVar2;
  void *pvVar3;
  long in_FS_OFFSET;
  uint local_a4;
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_a4 = 0;
  while ((local_a4 < 10 && (*(long *)(players + (ulong)local_a4 * 8) != 0))) {
    local_a4 = local_a4 + 1;
  }
  if (local_a4 == 0xb) {
    printf("[-] Your team cannot have more than %u players!",10);
  }
  else {
    printf("[!] Free slot at index %d\n",(ulong)local_a4);
    __s = (int *)malloc(0x18);
    if (__s == (int *)0x0) {
      puts("[-] Allocation error: player struct");
    }
    else {
      memset(__s,0,0x18);
      printf("Enter player name: ");
      fflush(stdout);
      memset(local_98,0,0x80);
      read_input(local_98,0x80);
      sVar2 = strlen(local_98);
      pvVar3 = malloc(sVar2 + 1);
      *(void **)(__s + 4) = pvVar3;
      if (*(long *)(__s + 4) == 0) {
        puts("[-] Allocation error: player name");
      }
      else {
        strcpy(*(char **)(__s + 4),local_98);
        printf("Enter pwn skillz [1-999]: ");
        read_input(local_98,4);
        iVar1 = atoi(local_98);
        *__s = iVar1;
        printf("Enter crypto skillz [1-999]: ");
        read_input(local_98,4);
        iVar1 = atoi(local_98);
        __s[1] = iVar1;
        printf("Enter web skillz [1-999]: ");
        read_input(local_98,4);
        iVar1 = atoi(local_98);
        __s[2] = iVar1;
        printf("Enter stegoguess skillz [1-999]: ");
        read_input(local_98,4);
        iVar1 = atoi(local_98);
        __s[3] = iVar1;
        *(int **)(players + (ulong)local_a4 * 8) = __s;
      }
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

### Remove player
```C
void remove_player(void)

{
  uint uVar1;
  char local_14 [4];
  void *local_10;
  
  printf("Enter the index of the player you would like to remove: ");
  read_input(local_14,4);
  uVar1 = atoi(local_14);
  if ((uVar1 < 0xb) && (*(long *)(players + (ulong)uVar1 * 8) != 0)) {
    local_10 = *(void **)(players + (ulong)uVar1 * 8);
    *(undefined8 *)(players + (ulong)uVar1 * 8) = 0;
    free(*(void **)((long)local_10 + 0x10));
    free(local_10);
    printf("[*] Player at index %u has been removed from the team\n",(ulong)uVar1);
  }
  else {
    puts("[-] Invalid player index");
  }
  return;
}
```

### Edit player
```C


## Solve

Thx.

Sk4r.