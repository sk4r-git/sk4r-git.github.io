+++
date = '2026-03-26T18:59:16+01:00'
draft = false
title = 'Carotte Radis Tomate'
+++

## Attachments

```python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = os.urandom(32)
print("carotte = ", int.from_bytes(key) % 17488856370348678479)
print("radis   = ", int.from_bytes(key) % 16548497022403653709)
print("tomate  = ", int.from_bytes(key) % 17646308379662286151)
print("pomme   = ", int.from_bytes(key) % 14933475126425703583)
print("banane  = ", int.from_bytes(key) % 17256641469715966189)

flag = open("flag.txt", "rb").read()
E = AES.new(key, AES.MODE_ECB)
enc = E.encrypt(pad(flag, 16))
print(f"enc = {enc.hex()}")
```
```bash
carotte =  392278890668246705
radis   =  4588810924820033807
tomate  =  17164682861166542664
pomme   =  12928514648456294931
banane  =  5973470563196845286
enc = 2da1dbe8c3a739d9c4a0dc29a27377fe8abc1c0feacc9475019c5954bbbf74dcedce7ed3dc3ba34fa14a9181d4d7ec0133ca96012b0a9f4aa93c42c61acbeae7640dd101a6d2db9ad4f3b8ccfe285e0d
```

## Reverse

As the title of the challenge suggest it, we will have to use the Chinease Reminder Theorem.

Let's try to remind the reminder theoreme

 - a1 = k % a2
 - b1 = k % b2
 - c1 = k % c2
 - d1 = k % d2
 - e1 = k % e2

<=>

 - a1 = k - (a3*a2)
 - b1 = k - (b3*b2)
 - c1 = k - (c3*c2)
 - d1 = k - (d3*d2)
 - e1 = k - (e3*e2)

OK, I won't remind... let's go on wikipedia

Based on a example solution:

<div style="border:1px solid #ff0000; padding:15px; margin:20px 0; border-radius:8px;" class=0xfun_02_26>
L'exemple de Sun Zi, présenté plus haut dans la section histoire, se réduit à

 - x ≡ 2 ( mod 3 )
 - x ≡ 3 ( mod 5 )
 - x ≡ 2 ( mod 7 )

on obtient alors

 - n = 3 × 5 × 7 = 105 
 - n_1 = 3 et nt1 = 5 × 7 = 35, or 2*nt1 ≡ 1 ( mod 3 ) donc e_1 = 70 
 - n_2 = 5 et nt2 = 3 × 7 = 21, or nt2 ≡ 1 ( mod 5 ) donc e_2 = 21 
 - n_3 = 7 et nt3 = 3 × 5 = 15, or nt3 ≡ 1 ( mod 7 )  donc e_3 = 15 

une solution pour x est alors x = 2 × 70 + 3 × 21 + 2 × 15 = 233

et les solutions sont tous les entiers congrus à 233 modulo 105, c'est-à-dire à 23 modulo 105. 
</div>

## Solve
```python

import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util.number import GCD
from Cryptodome.Util.number import long_to_bytes

a = carotte =  392278890668246705
b = radis   =  4588810924820033807
c = tomate  =  17164682861166542664
d = pomme   =  12928514648456294931
e = banane  =  5973470563196845286

ma = 17488856370348678479
mb = 16548497022403653709
mc = 17646308379662286151
md = 14933475126425703583
me = 17256641469715966189

n = ma * mb * mc * md * me

mat = n // ma
mbt = n // mb
mct = n // mc
mdt = n // md
met = n // me

man = pow(mat, -1, ma)
mbn = pow(mbt, -1, mb)
mcn = pow(mct, -1, mc)
mdn = pow(mdt, -1, md)
men = pow(met, -1, me)

k = 0
k += a * man * mat
k += b * mbn * mbt
k += c * mcn * mct
k += d * mdn * mdt
k += e * men * met
k = k % n

assert(k % ma == a)
assert(k % mb == b)
assert(k % mc == c)
assert(k % md == d)
assert(k % me == e)

print("Everything seems to be OK :D")
print(len(hex(k)))
enc = "2da1dbe8c3a739d9c4a0dc29a27377fe8abc1c0feacc9475019c5954bbbf74dcedce7ed3dc3ba34fa14a9181d4d7ec0133ca96012b0a9f4aa93c42c61acbeae7640dd101a6d2db9ad4f3b8ccfe285e0d"



E = AES.new(long_to_bytes(k), AES.MODE_ECB)
dec = E.decrypt(bytes.fromhex(enc))

flag = unpad(dec, 16)
print(flag)
```

Thx.

Sk4r.