+++
date = '2026-03-25T08:33:28+01:00'
draft = false
title = 'A day in Kernel hacking'
+++

## Setup

Befor diving in kernel hacking we must understand 
- what are the files that are generally provided
- how to setup a reliable debug platform 
- and what is our goal.

### Files
 - bzImage
 - iniramfs.xxx
 - chall.ko

#### chall.ko
It's the module which is launched in the kernel, necessarly vulnerable if it's a challenge

As a module it exposed differents endpoints with are trigerrable through IOCTL's. It's like syscalls, just specific to a driver.

Or hooked function that we can trigger through normal system working 

```bash
ffffffffc03162c8 b ref_sys_getdents64	[ecsc]
ffffffffc03162d0 b ref_sys_getdents	[ecsc]
ffffffffc03162c0 b ref_sys_lstat	[ecsc]
ffffffffc03162e0 b my_sys_call_table	[ecsc]
ffffffffc03162d8 b original_cr0	[ecsc]
ffffffffc031436e t ecsc_end	[ecsc]
ffffffffc0316000 d __this_module	[ecsc]
ffffffffc0314150 t ecsc_sys_getdents	[ecsc]
ffffffffc031436e t cleanup_module	[ecsc]
ffffffffc03142a0 t ecsc_sys_lstat	[ecsc]
ffffffffc0314000 t ecsc_sys_getdents64	[ecsc]
```

```bash
c8821000 t tostring_close	[basic1_ch1]
c8821020 t tostring_open	[basic1_ch1]
c8821040 t tostring_read	[basic1_ch1]
c8821080 t tostring_read_dec	[basic1_ch1]
c88210e0 t tostring_read_hexa	[basic1_ch1]
c8821140 t tostring_write	[basic1_ch1]
c88211fc t tostring_exit	[basic1_ch1]
c88211fc t cleanup_module	[basic1_ch1]
```
#### bzImage
This is the kernel that we will work with, generally compressed (and then extractable ;))
```bash
└─$ file bzImage 
bzImage: Linux kernel x86 boot executable, bzImage, version 4.14.167 (root@vps783610) #11 Fri Feb 14 16:47:58 CET 2020, RO-rootFS, Normal VGA, setup size 512*30, syssize 0x2821d, jump 0x268 0x8cd88ec0fc8cd239 instruction, protocol 2.13, from protected-mode code at offset 0x276 0x2540eb bytes gzip compressed, relocatable, legacy 64-bit entry point, can be above 4G, max cmdline size 2047, init_size 0xd89000
```

#### iniramfs

The iniramfs is generaly a cpio archive, this is the base file system that will be used by the kernel

```bash
└─$ file initramfs.example.cpio 
initramfs.example.cpio: ASCII cpio archive (SVR4 with no CRC)
```

### Debug

#### What is launched ?
The cpio archive (initramfs) can be extracted in order to retrieve the file system that will be used

```bash
cpio -idv < ./initramfs

rootf
├── bin
│   ├── [
│   ├── [[
│   ├── acpid
│   ├── add-shell
...
│   ├── zcat
│   └── zcip
├── etc
│   ├── group
│   └── passwd
├── home
│   └── ctf
├── init
└── lib
    └── modules
        └── 4.14.167
            └── ecsc.ko

```

The most important file is the 'init' one, this is the first userland executable that will be run by the kernel. Some interesting information about how to interact with the VM that we will launch can be found in.

We finally launch the kernel via qemu.

```bash
qemu-system-x86_64 \  
-m 128M \  
-kernel bzImage \  
-initrd initramfs.example.cpio \  
-append "console=ttyS0 panic=1 oops=panic quiet" \  
-nographic
```
#### Debugging and symbols
As that we can't really interract or debug the kernel and the vulnerable driver.
We need to have the vmlinux files


There is four available kernel hacking challenge on the hackropole platform:
https://hackropole.fr/fr/challenges/pwn

Let's begin with the easiest one:

### Kernel goals
As we deal with code already runinng in kernel land, we won't interract with it in the same way as in userland pwn.

In userland we generally want to abuse a program in order to get shell, and we can commmunication with this programme through userland entries en classics IPC.

Here the 'program' that we wan't attack is the kernel so we would also have IPC but not classic stdin(out/err).

We will have to write C programs that can open drivers (/dev/xxx) or trigger syscalls.

#### The vulns
Vulns seems to be the same as userland, memory errors that leads to code redirection (stack/heap/and maybe other things).

#### The exploit
Depending on what the modules do the goal can be multiples,

<ol style="margin: 0; padding-left: 20px;">
<li>identify a way to interract with the driver, syscall/ioctl</li>
<li>identify the vulnerability and gain code execution control</li>
<li>either deactivate the module or call specific module function or do the classic kernel ROPchain:</li>
<li>commit_creds(prepare_kernel_creds(0)) which will give root rights to our C program</li>
<li>before calling system("/bin/sh") and have a root shell.</li>
</ol>

## Pépin
Just a docker image is provided for this challenge:

```bash
└─$ cat docker-compose.yml 
services:
  pepin:
    image: anssi/fcsc2020-pwn-pepin:latest
    ports:
      - "2222:22"
```
That we launch with
```bash
└─$ docker compose up
└─$ ssh -p 2222 ctf@localhost (password: ctf)
```

WE have all the files mentionned before :
```bash
ctf@bb5418c1b1fe:~$ ls -la
total 3656
dr-xr-xr-x 1 ctf-admin ctf-admin    4096 Nov 29  2023 .
drwxr-xr-x 1 ctf-admin ctf          4096 Nov 29  2023 ..
-rwxr-xr-x 1 ctf-admin ctf-admin    1312 Oct 25  2023 .start.sh
-rw------- 1 ctf-admin ctf-admin 2678688 Oct 25  2023 bzImage
-rw------- 1 ctf-admin ctf-admin 1026048 Oct 25  2023 initramfs.cpio
-rwsr-x--- 1 ctf-admin ctf         16608 Nov 29  2023 wrapper
-rw-r--r-- 1 ctf-admin ctf           126 Oct 25  2023 wrapper.c
```
We can't extract the bzImage and initramfs on our host... but i hate working in docker

It's possible to refind them in root in the docker overlay:
```bash
┌──(root㉿kali)-[/var/…/e425d2c556db5b9042f348ad2aff0396d2e5ce3edc3b6ec113058400ae2f2201/diff/home/ctf]
└─# ls
bzImage  initramfs.cpio  wrapper  wrapper.c
                                                                                                              
┌──(root㉿kali)-[/var/…/e425d2c556db5b9042f348ad2aff0396d2e5ce3edc3b6ec113058400ae2f2201/diff/home/ctf]
└─# pwd               
/var/lib/docker/overlay2/e425d2c556db5b9042f348ad2aff0396d2e5ce3edc3b6ec113058400ae2f2201/diff/home/ctf
```

We need to briefly modify the start.sh in order to correspond to our filesystem

Let's also extract the initramfs.cpio in order to see the init file

```bash
└─$ cat init                    
#!/bin/sh

export PATH=/bin

[ -d /dev ] || mkdir -m 0755 /dev
[ -d /sys ] || mkdir /sys
[ -d /proc ] || mkdir /proc
[ -d /tmp ] || mkdir /tmp
[ -d /run ] || mkdir /run
[ -d /root ] || mkdir /root
[ -d /etc ] || mkdir /etc
[ -d /home ] || mkdir /home
[ -d /mnt ] || mkdir /mnt

chmod 400 init
chmod -r init

chown -R root:root /
chmod 700 -R /root
chown ctf:ctf /home/ctf
chmod 777 /home/ctf
chmod 755 /dev

mkdir -p /mnt/share
mount -t 9p -o trans=virtio ecsc /mnt/share/ -oversion=9p2000.L,posix,msize=104857600,sync
chmod 777 /mnt/share/

mkdir -p /var/lock
mount -t sysfs -o nodev,noexec,nosuid sysfs /sys
mount -t proc -o nodev,noexec,nosuid proc /proc
ln -sf /proc/mounts /etc/mtab
mount -t devtmpfs -o nosuid,mode=0755 udev /dev
mkdir -p /dev/pts
mount -t devpts -o noexec,nosuid,gid=5,mode=0620 devpts /dev/pts || true
mount -t tmpfs -o "noexec,nosuid,size=10%,mode=0755" tmpfs /run

echo 0 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/perf_event_paranoid
echo 2 > /proc/sys/kernel/randomize_va_space

cat <<EOF
 _______  _______  _______  _______    ___   _  _______  ______    __    _  _______  ___
|       ||       ||       ||       |  |   | | ||       ||    _ |  |  |  | ||       ||   |
|    ___||       ||  _____||       |  |   |_| ||    ___||   | ||  |   |_| ||    ___||   |
|   |___ |       || |_____ |       |  |      _||   |___ |   |_||_ |       ||   |___ |   |
|    ___||      _||_____  ||      _|  |     |_ |    ___||    __  ||  _    ||    ___||   |___
|   |    |     |_  _____| ||     |_   |    _  ||   |___ |   |  | || | |   ||   |___ |       |
|___|    |_______||_______||_______|  |___| |_||_______||___|  |_||_|  |__||_______||_______|
EOF

setsid cttyhack setuidgid 1000 /bin/sh

umount /proc
umount /sys

poweroff -d 0 -f 2>&1 >/dev/null
```

It doesn't seems to have kernel module, let's try to find a interesting syscall:

```bash
/ $ cat /proc/kallsyms | grep -iE 'ecsc|fcsc|flag'
...
ffffffffb8d11e92 T sys_ecsc_getflag
...
```
There is an interesting syscall but we can't know what number trigger it
Maybe we can brute force it but let's read the challenge description:

<div style="border:1px solid #ff0000; padding:15px; margin:20px 0; border-radius:8px;">
You have access to a machine that seems to have a Linux kernel with a particular system call (number 333) that writes to dmesg. Once connected via SSH (credentials: ctf:ctf), use ./wrapper to launch the challenge.
</div>

Ok, easy win, just call the 333 syscall and watch in dmesg

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
└─$ cp sc /tmp/tmp.gOuSa0ILmL 
```

in the vm we can launch this ioctl
```bash
/ $ /mnt/share/sc
/ $ echo $?
0
```
nothing append
but if we watch the kernel logs, the flag appears

```bash
dmesg
...
FCSC{REDACTED}
```
## Hello Rootkitty

## Hello Rootkitty (harder)

## ktruc

