+++
date = '2026-03-26T19:23:15+01:00'
draft = false
title = 'Clair_connu'
+++

## Attachments

```python
import os
from Crypto.Util.number import long_to_bytes
from Crypto.Util.strxor import strxor

FLAG = open("flag.txt", "rb").read()

key = os.urandom(4) * 20
c = strxor(FLAG, key[:len(FLAG)])
print(c.hex())
```
out = d91b7023e46b4602f93a1202a7601304a7681103fd611502fa684102ad6d1506ab6a1059fc6a1459a8691051af3b4706fb691b54ad681b53f93a4651a93a1001ad3c4006a825


## Reverse
The begining of the flag is 'FCSC' and the key is of size 4.

## Solve
```python
from Cryptodome.Util.number import long_to_bytes, bytes_to_long
begin = b"FCSC"
cipher = 0xd91b7023e46b4602f93a1202a7601304a7681103fd611502fa684102ad6d1506ab6a1059fc6a1459a8691051af3b4706fb691b54ad681b53f93a4651a93a1001ad3c4006a825
cipher = long_to_bytes(cipher)

result = b""
for i in range(len(cipher)):
    result += (begin[i%4] ^ cipher[i%4] ^ cipher[i]).to_bytes()

print(result)

```
Thx.

Sk4r.
