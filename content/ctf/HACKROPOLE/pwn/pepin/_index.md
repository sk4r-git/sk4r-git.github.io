+++
date = '2026-03-27T06:49:27+01:00'
draft = false
title = 'Pepin'
+++

## Attachments

You have access to a machine that seems to have a Linux kernel with a particular system call (number 333) that writes to dmesg. Once connected via SSH (credentials: ctf:ctf), use ./wrapper to launch the challenge.

<a href="https://hackropole.fr/challenges/fcsc2020-pwn-pepin/docker-compose.public.yml">docker-compose.yml</a><br><br>

## Reverse

Let's follow the description and just call the syscall 333 before reading dmesg

While launching the vm we have this message:
<div style="border:1px solid #ff0000; padding:15px; margin:20px 0; border-radius:8px;">

To ease your exploit development, a secret folder shared between the host and
the vm will be created. You can access it at /mnt/share within the vm, and at
/tmp/tmp.eIvlcfUQLR in the host. The folder will be deleted afterwards.

</div>

## Solve

### In the host:

```asm
.text

.globl _start

_start:
    mov $333, %rax
    syscall
    mov $0, %rdi
    mov $0x3c, %rax
    syscall
```

```bash
└─$ as sc.S -o sc.o
└─$ ld sc.o -o sc  
cp sc /tmp/tmp.*
```

### In the VM:
```bash
/ $ /mnt/share/sc
/ $ dmesg
...
FLAG
```

Thx.

Sk4r.