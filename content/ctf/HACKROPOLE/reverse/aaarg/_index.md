+++
date = '2026-03-26T08:17:56+01:00'
draft = false
title = 'Aaarg'
+++

## Attachments

<a href="/ctf/hackropole/reverse/aaarg/aaarg">aaarg</a><br><br>

## Reverse

```C

undefined8 FUN_00401190(int param_1,long param_2)

{
  undefined8 uVar1;
  ulong uVar2;
  char *local_10;
  
  uVar1 = 1;
  if (1 < param_1) {
    uVar2 = strtoul(*(char **)(param_2 + 8),&local_10,10);
    uVar1 = 1;
    if ((*local_10 == '\0') && (uVar1 = 2, uVar2 == (long)-param_1)) {
      uVar2 = 0;
      do {
        putc((int)(char)(&DAT_00402010)[uVar2],stdout);
        uVar2 = uVar2 + 4;
      } while (uVar2 < 0x116);
      putc(10,stdout);
      uVar1 = 0;
    }
  }
  return uVar1;
}
```

Ok it just compare the number of arguments the program have and the first argument we give it.

## Solve
Either

./aaarg -2
or 
./aaarg -3 a

would work:

```bash
┌──(sk4r㉿kali)-[~/GITHUB/HACKROPOLE/re/aaarg]
└─$ ./aaarg -2
FCSC{f9a38adace9dda3a9ae53e7aec180c5a73dbb7c364fe137fc6721d7997c54e8d}
                                                                                                                              
┌──(sk4r㉿kali)-[~/GITHUB/HACKROPOLE/re/aaarg]
└─$ ./aaarg -3 ff
FCSC{f9a38adace9dda3a9ae53e7aec180c5a73dbb7c364fe137fc6721d7997c54e8d}
```

Thx.

Sk4r.