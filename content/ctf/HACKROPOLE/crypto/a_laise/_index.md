+++
date = '2026-03-26T08:39:27+01:00'
draft = false
title = 'A_laise'
+++

## Attachments

In this challenge, you have to decipher an encrypted message using the method invented by Blaise de Vigénère. The key is FCSC and the encrypted message is:

Mgdnt fwcw cygsv! Qqzt fgcv ekxuaqs, kx atw sehghv nv gh
hqmtxg, okqn tg yq apkkdvwclg yjw wsfwtltgwsf fgyygtp
yzgwg gww gfgrkwu ftw jnfapl. Uwg dqm ks Pspygk qs
Chtnn 29lj kqj vmg tglkfpnpy qk agww oauxkgp.

The flag is the name of the city mentioned in this message.

## Reverse

vigenere square is not as complex

```python
key = b"fcsc"

msg = b"Mgdnt fwcw cygsv! Qqzt fgcv ekxuaqs, kx atw sehghv nv gh \
hqmtxg, okqn tg yq apkkdvwclg yjw wsfwtltgwsf fgyygtp \
yzgwg gww gfgrkwu ftw jnfapl. Uwg dqm ks Pspygk qs \
Chtnn 29lj kqj vmg tglkfpnpy qk agww oauxkgp."

new_msg = b""

for i in range(len(msg)):
    if not ((msg[i] > 0x40 and msg[i] < 0x5b) or (msg[i] > 0x60 and msg[i] < 0x7b)):
        new_msg += msg[i].to_bytes()
        continue
    l = msg[i] - 0x61
    if l < 0:
        l += 0x20
    k = key[i%4] - 0x61
    r = (l - k) % 26
    r += 0x41
    new_msg += r.to_bytes()


print(new_msg)
```

```bash
└─$ /bin/python /home/sk4r/GITHUB/HACKROPOLE/cry/a_laise/solve.py
b'HELLO NUXU ATEAT! YOUR DBAD ZIFSVOA, IF VRE NCPECT LQ OF FYKOVO, MSOI BE WY VNSIYTEAGE WEU UNDERGROUND DBWGEON WUEEE EEU ENEMIES DBU HVDVNT. SEE BYK IA KQXWBI ON KFOLV 29TH IYH TUE ROJFDXLKW OF IERU MVSFIBN.'
```
OK beginning is good but spaces seems to doesn't count :

by adding a ctr in the key:

## Solve

```python
key = b"fcsc"

msg = b"Mgdnt fwcw cygsv! Qqzt fgcv ekxuaqs, kx atw sehghv nv gh \
hqmtxg, okqn tg yq apkkdvwclg yjw wsfwtltgwsf fgyygtp \
yzgwg gww gfgrkwu ftw jnfapl. Uwg dqm ks Pspygk qs \
Chtnn 29lj kqj vmg tglkfpnpy qk agww oauxkgp."

new_msg = b""
ctr = 0
for i in range(len(msg)):
    if not ((msg[i] > 0x40 and msg[i] < 0x5b) or (msg[i] > 0x60 and msg[i] < 0x7b)):
        new_msg += msg[i].to_bytes()
        continue
    l = msg[i] - 0x61
    if l < 0:
        l += 0x20
    k = key[ctr%4] - 0x61
    r = (l - k) % 26
    r += 0x41
    new_msg += r.to_bytes()
    ctr += 1


print(new_msg)
```
It's much better:

```bash
└─$ /bin/python /home/sk4r/GITHUB/HACKROPOLE/cry/a_laise/solve.py
b'HELLO DEAR AGENT! YOUR NEXT MISSION, IF YOU ACCEPT IT OF COURSE, WILL BE TO INFILTRATE THE UNDERGROUND NETWORK WHERE OUR ENEMIES ARE HIDING. SEE YOU IN NANTES ON APRIL 29TH FOR THE BEGINNING OF YOUR MISSION.'
```

Thx.

Sk4r.