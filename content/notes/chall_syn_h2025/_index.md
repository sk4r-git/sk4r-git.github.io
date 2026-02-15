+++
date = '2026-01-20T18:08:00+01:00'
draft = false
title = 'Challenge Synacktiv Winter 2025'
+++



<br>
Synacktiv invite us to construct a binary following some rules, this binary must
    <ol>
        <li>be a palindrome</li>
        <li>print himself</li>
        <li>be size minimal</li>
    </ol>

**TL;DR;**
<div class="homepage-buttons">
  Attachments:<br>
  <a href="/notes/chall_syn_h2025/check.sh">check.sh</a>
  <a href="/notes/chall_syn_h2025/elf3">ma solution</a>
</div>


```bash
└─$ xxd ../elf
00000000: 7f45 4c46 0100 0000 0000 0000 0000 0100  .ELF............
00000010: 0200 0300 ffff 0000 2000 0100 0400 0000  ........ .......
00000020: b580 01c9 b004 eb06 2c00 2000 0100 43b2  ........,. ...C.
00000030: 6fcd 804b b001 cd80 cd01 b04b 80cd 6fb2  o..K.......K..o.
00000040: 4300 0100 2000 2c06 eb04 b0c9 0180 b500  C... .,.........
00000050: 0000 0400 0100 2000 00ff ff00 0300 0200  ...... .........
00000060: 0100 0000 0000 0000 0000 0146 4c45 7f    ...........FLE.
```
Étonnant mais le ElfHeader contient sa propre taille, permettant ainsi de le tronquer tout en le laissant valide.
On peut ainsi conserver uniquement

- `Elf32_Ehdr` (offset 0x00 à 0x2c), jusqu’à e_phentsize
- `Elf32_Phdr` (offset 0x04 à 0x20), avec p_align tronqué

Les headers tronqués :
```C
typedef struct {
    unsigned char e_ident[16];  
    uint16_t      e_type;    
    uint16_t      e_machine; 
    uint32_t      e_version;  
    uint32_t      e_entry;  // Entry point à 0x18 = 0x00010020
    uint32_t      e_phoff;  // Programme Header à 0x1c = 0x04
    uint32_t      e_shoff;    
    uint32_t      e_flags; 
    uint16_t      e_ehsize; // Taille du ELF Header
    uint16_t      e_phentsize;
} Elf32_Ehdr;

typedef struct {
    uint32_t p_type; 
    uint32_t p_offset; 
    uint32_t p_vaddr;       // Addresse de chargement à 0x0c = 0x00010000
    uint32_t p_paddr;  
    uint32_t p_filesz; 
    uint32_t p_memsz;  
    uint32_t p_flags;  
} Elf32_Phdr;
```
Après avoir imbriqué les headers l'un dans l'autre, 
Nous pouvons modifier les champs 'inutiles' des headers en y insérant notre code.

```
1) Le kernel parse le elf header
2) Grace au elf header il sait où trouver le programme header, qu'il parse 
   aussi
3) Si pas d'erreur il charge le programme en 0x10000 comme spécifié par 
   `Elf32_Phdr->p_vaddr` en 0x0c
4) Regarde l'entrypoint et execute la première instruction en 0x20
5) b580 = mov $0x80, %ch     (ecx = 0x8000)
6) 01c9 = add %ecx, %ecx     (ecx = 0x10000) 
7) b004 = mov $0x4, %al      (eax = 4)    (write syscall)
8) eb06 = jump + 6           (eip = 0x2e)
9) 43 = inc %ebx             (ebx = 1)    (stdout)
10) b26f = mov $0x6f, %dl    (edx = 0x6f) (taill du binaire)
11) cd80 = int $0x80         (syscall write(1, 0x10000, 0x6f))
12) 4b = dec %ebx            (ebx = 0)
13) b001 = mov $1, %al       (eax = 1)
14) cd80 = int $0x80         (syscall exit(0))
```

Résultat :

```bash
└─$ ../check.sh ../elf
[+] First check passed: binary is a byte-wise palindrome.
[+] Second check passed: binary is a true quine, its output matches itself.
[+] Both checks passed: your binary is a very nice quinindrome!
[+] Your score: 111
```

![classement final](./final.png "classement final")

Un grand merci à <a href="https://www.synacktiv.com"><strong>Synacktiv</strong></a> pour l'organisation de ce challenge.
Félicitations à tous les participants, et tout particulièrement à  <a href="https://github.com/fishilico"><strong>ioonag</strong></a> pour sa solution en 81 octets.


<br>

**Explications**

Naïvement, et pour un premier jet :
- Pour le palindrome, il suffit de copier coller 'en mirroir' son binaire -> abcd -> abcddcba
- Pour reduire la taille on va le coder en assembleur
- Et pour l'auto-affichage eh bien nous allons le coder

Avec tout de même deux choix préliminaires, PIE c'est mieux pour savoir quoi afficher
et en 32 bits ça va surement prendre moins de place

```asm
.text

.globl _start

_start:
    mov $0x08048000, %ecx
    inc %ebx
    mov $0x22e0, %edx
    mov $0x4, %eax
    int $0x80
    dec %ebx
    mov $0x1, %eax
    int $0x80
```

```python
f = open("./elf", "rb")
d = f.read()
f.close()

r = open("./elf2", "wb+")
r.write(d)
for i in range(len(d)):
    r.write(d[-i-1].to_bytes())
r.close()
```

Déjà, premier problème,
Notre binaire est assez grand

```bash
00000000: 7f45 4c46 0101 0100 0000 0000 0000 0000  .ELF............
00000010: 0200 0300 0100 0000 0090 0408 3400 0000  ............4...
00000020: a810 0000 0000 0000 3400 2000 0200 2800  ........4. ...(.
00000030: 0500 0400 0100 0000 0000 0000 0080 0408  ................
00000040: 0080 0408 7400 0000 7400 0000 0400 0000  ....t...t.......
00000050: 0010 0000 0100 0000 0010 0000 0090 0408  ................
...
00002280: 0804 9000 0000 1000 0000 0001 0000 1000  ................
00002290: 0000 0004 0000 0074 0000 0074 0804 8000  .......t...t....
000022a0: 0804 8000 0000 0000 0000 0001 0004 0005  ................
000022b0: 0028 0002 0020 0034 0000 0000 0000 10a8  .(... .4........
000022c0: 0000 0034 0804 9000 0000 0001 0003 0002  ...4............
000022d0: 0000 0000 0000 0000 0001 0101 464c 457f  ............FLE.
```

Et avec beaucoup de données inutiles (la moitié au moins)
Donc le kernel ne s'embête pas à tout charger:

```bash
(gdb) b *0
Breakpoint 1 at 0x0
(gdb) r
Starting program: /home/sk4r/GITHUB/Advent_2025/SYNAK/wu/elf2 
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x0

(gdb) info proc map
process 126990
Mapped address spaces:

Start Addr End Addr   Size       Offset     Perms File 
0x08048000 0x0804a000 0x2000     0x0        r-xp  /home/sk4r/GITHUB/Advent_2025/SYNACKTIV/wu/elf2 
0xf7ff6000 0xf7ffa000 0x4000     0x0        r--p  [vvar] 
0xf7ffa000 0xf7ffc000 0x2000     0x0        r--p  [vvar_vclock] 
0xf7ffc000 0xf7ffe000 0x2000     0x0        r-xp  [vdso] 
0xfffdc000 0xffffe000 0x22000    0x0        rwxp  [stack] 
```

Tout n'est pas chargé -> tout n'est pas printable
C'est mort pour cette solution.

Nous allons donc directement modifier les structures.
- structure binaire craft à la main
- payload de code rajouté artificiellement
- et toujours un copié-collé mirroir pour la règle du palindrome

un Elf se base sur deux principales structures pour fonctionner
(j'attends les WU des autres mais je n'ai pas réussi à le faire marcher sans ces deux là)

```C
typedef struct {
    unsigned char e_ident[16]; /* Identification ELF */
    uint16_t      e_type;      /* Type de fichier (REL, EXEC, DYN…) */
    uint16_t      e_machine;   /* Architecture cible (e.g. EM_386) */
    uint32_t      e_version;   /* Version ELF */
    uint32_t      e_entry;     /* Adresse du point d'entrée */
    uint32_t      e_phoff;     /* Offset de la table des en-têtes de segments (program header) */
    uint32_t      e_shoff;     /* Offset de la table des en-têtes de sections (section header) */
    uint32_t      e_flags;     /* Flags spécifiques à l’architecture */
    uint16_t      e_ehsize;    /* Taille de cet en-tête ELF */
    uint16_t      e_phentsize; /* Taille d’une entrée de la table des segments */
    uint16_t      e_phnum;     /* Nombre d’entrées dans la table des segments */
    uint16_t      e_shentsize; /* Taille d’une entrée de la table des sections */
    uint16_t      e_shnum;     /* Nombre d’entrées dans la table des sections */
    uint16_t      e_shstrndx;  /* Index de la section contenant les noms de sections */
} Elf32_Ehdr;

typedef struct {
    uint32_t p_type;   /* Type du segment (LOAD, DYNAMIC, INTERP, NOTE, etc.) */
    uint32_t p_offset; /* Offset du segment dans le fichier */
    uint32_t p_vaddr;  /* Adresse virtuelle où le segment doit être chargé */
    uint32_t p_paddr;  /* Adresse physique (souvent ignorée) */
    uint32_t p_filesz; /* Taille du segment dans le fichier */
    uint32_t p_memsz;  /* Taille du segment en mémoire après chargement */
    uint32_t p_flags;  /* Permissions du segment (R, W, X) */
    uint32_t p_align;  /* Alignement requis du segment */
} Elf32_Phdr;
```

```python
from pwn import *


payload = b"\x90"*12 
# shellcode sans optimisation
payload += b"\xb9\x00\x80\x04\x08\x43\xba\xec\x00\x00\x00\x83\xc0\x04\xcd\x80\x4b\x31\xc0\x40\xcd\x80"

SIZE = len(payload)

''' struct Elf32_Ehdr '''
e_ident = b"\x7fELF\x01\x01\x01\x00" + b"\xff"*8
e_type = p16(2)
e_machine = p16(3)
e_version = p32(0xffffffff)
e_entry = p32(0x08048060) 
e_phoff = p32(0x34)  
e_shoff = p32(0xffffffff)  
e_flags = p32(0xffffffff)
e_ehsize = p16(0x34)        
e_phentsize = p16(0x20)    
e_phnum = p16(1)          
e_shentsize = p16(0x28)      
e_shnum = p16(0)          
e_shstrndx = p16(0)    


''' struct Elf32_Phdr '''

p_type = p32(1)
p_offset = p32(0x60)
p_vaddr = p32(0x08048060)
p_paddr = p32(0x08048060)
p_filesz = p32(SIZE)
p_memsz = p32(SIZE)
p_flags = p32(4)
p_align = p32(16)


def construct_elf_header(buf):
    buf += e_ident 
    buf += e_type 
    buf += e_machine 
    buf += e_version 
    buf += e_entry 
    buf += e_phoff 
    buf += e_shoff 
    buf += e_flags 
    buf += e_ehsize 
    buf += e_phentsize 
    buf += e_phnum 
    buf += e_shentsize 
    buf += e_shnum 
    buf += e_shstrndx 
    return buf

def construct_prog_header(buf):
    buf += p_type
    buf += p_offset
    buf += p_vaddr
    buf += p_paddr
    buf += p_filesz
    buf += p_memsz
    buf += p_flags
    buf += p_align
    return buf


b = open("./elf", "wb+")


bd = b""
bd = construct_elf_header(bd)
bd = construct_prog_header(bd)
bd += payload

b.write(bd)
for i in range(len(bd)):
    b.write(bd[-i-1].to_bytes())
b.close()
```

```bash
└─$ ./elf
ELF������������`4��������4 (```""�������������C����̀K1�@̀��@�1K�������������������"��``( 4���������`������������FLE   
```



```bash
└─$ ../check.sh ./elf
[+] First check passed: binary is a byte-wise palindrome.
[+] Second check passed: binary is a true quine, its output matches itself.
[+] Both checks passed: your binary is a very nice quinindrome!
[+] Your score: 236
```
parfait on a un premier binaire qui marche

plutôt content
...
...
![premier classement](./first.png "premier classement")
plutôt pas content

Bon va falloir faire mieux

notre binaire ressemble à ça:

```bash
└─$ xxd elf
00000000: 7f45 4c46 0101 0100 ffff ffff ffff ffff  .ELF............
00000010: 0200 0300 ffff ffff 6080 0408 3400 0000  ........`...4...
00000020: ffff ffff ffff ffff 3400 2000 0100 2800  ........4. ...(.
00000030: 0000 0000 0100 0000 6000 0000 6080 0408  ........`...`...
00000040: 6080 0408 2200 0000 2200 0000 0400 0000  `..."...".......
00000050: 1000 0000 9090 9090 9090 9090 9090 9090  ................
00000060: b900 8004 0843 baec 0000 0083 c004 cd80  .....C..........
00000070: 4b31 c040 cd80 80cd 40c0 314b 80cd 04c0  K1.@....@.1K....
00000080: 8300 0000 ecba 4308 0480 00b9 9090 9090  ......C.........
00000090: 9090 9090 9090 9090 0000 0010 0000 0004  ................
000000a0: 0000 0022 0000 0022 0804 8060 0804 8060  ..."..."...`...`
000000b0: 0000 0060 0000 0001 0000 0000 0028 0001  ...`.........(..
000000c0: 0020 0034 ffff ffff ffff ffff 0000 0034  . .4...........4
000000d0: 0804 8060 ffff ffff 0003 0002 ffff ffff  ...`............
000000e0: ffff ffff 0001 0101 464c 457f            ........FLE.
```

les \x90 prennent beaucoup de place, et notre code aussi finalement,
la première optimisation a laquelle j'ai pensé a été de mettre le code directement dans les headers car il y a pleins d'endroits qui ne servent à rien. En changeant l'entrypoint et en jumpant de zone inutiles en zones inutiles il y a largement la place pour nore code

